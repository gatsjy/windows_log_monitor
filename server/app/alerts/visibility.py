"""알림의 조회 범위: 사용자 그룹으로 범위가 정해진 사용자에게 어떤 알림·무음이 보이는가 (ADR-025).

알림은 이벤트가 아니라서 repository.scope_clause 를 쓸 수 없다. 규칙의 분류 조건과 대상(PC)으로 판단한다.
알림 이력·상세·처리·사이드바 숫자·무음 목록이 모두 이 함수를 쓴다 (한 곳에서만 고치기 위해).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from ..auth.service import User
from .builtin import BUILTIN_RULES
from .engine import engine


def _rule_categories(rule_name: str) -> set[str]:
    """규칙이 감시하는 분류 — match.category 뿐 아니라 검색 문장(match.query)의 category: 도 (Rule.categories)."""
    rule = next((r for r in engine.config.rules if r.name == rule_name), None)
    return set(rule.categories) if rule else set()


def alert_host(rule_name: str | None, key: str | None) -> str | None:
    """알림 대상 이름에서 PC 이름. 채널 끊김 규칙(stream_silent)의 대상은 'PC · 채널' 이라 PC 만 떼어 범위와 비교한다 —
    그대로 비교하면 'WS-02' 범위의 사용자가 'WS-02 · Security' 를 보지 못한다(와일드카드면 거꾸로 범위 밖 채널 이름을 본다)."""
    rule = next((r for r in engine.config.rules if r.name == rule_name), None)
    # 규칙을 지우거나 이름을 바꿨으면 종류를 모른다 — 'PC · 채널' 모양이면 PC 부분으로(와일드카드 범위가 채널 글자에 맞지 않게, 검토)
    if key and " · " in key and (rule is None or rule.kind == "stream_silent"):
        return key.rsplit(" · ", 1)[0]
    return key


def alert_visible(user: User, alert: dict[str, Any]) -> bool:
    """조회 범위가 있는 사용자: 그 범위의 분류를 감시하는 규칙이거나, 대상(PC)이 범위의 PC 패턴에 맞는 알림만."""
    if user.scopes is None:
        return True
    if alert["rule"] in BUILTIN_RULES:   # 설정 변경 등 내장 알림은 이 시스템 관리 정보 — 범위가 없는 사용자만 (ADR-043)
        return False
    cats = _rule_categories(alert["rule"])
    rule = next((r for r in engine.config.rules if r.name == alert["rule"]), None)
    # 처음 보는 값(B-47): 대상 이름은 값 조합 — PC 는 payload.terms.host. 목록·숫자·처리는 그 값만 뽑은 terms_host 로(같은 판단,
    # 검토에서 재현: 상세에서는 보이는데 목록·확인·해결에서는 빠졌다). 규칙을 지우거나 이름을 바꿔도 같게 값이 있으면 그것으로.
    # 없으면(몰려온 묶음) PC 범위 사용자에게 안 보임
    terms_host = alert.get("terms_host") or ((alert.get("payload") or {}).get("terms") or {}).get("host")
    if terms_host or (rule is not None and rule.kind == "new_terms"):
        host = terms_host
    else:
        host = alert_host(alert["rule"], alert["group_key"])
    for scope in user.scopes:
        cat_ok = not scope.categories or bool(cats & set(scope.categories))
        host_ok = scope.allows_host(host)
        if cat_ok and host_ok:
            return True
    return False


def silence_visible(user: User, silence: dict[str, Any]) -> bool:
    """조회 범위가 있는 사용자에게는 '내 알림에 걸릴 수 있는' 무음만 보인다 (범위 밖 PC 이름·사유가 새지 않게).
    - 모든 규칙·모든 대상: 누구에게나 (내 알림도 막으므로)
    - 대상만 정함(모든 규칙): 그 대상이 내 PC 범위에 들 때
    - 규칙만 정함(모든 대상): 그 규칙의 분류가 내 범위에 들 때
    - 둘 다 정함: 그 알림이 보일 때"""
    if user.scopes is None:
        return True
    rule, key = silence["rule"], silence["group_key"]
    if rule is None and key is None:
        return True
    if rule is None:
        return any(scope.allows_host(key) for scope in user.scopes)
    if key is None:
        cats = _rule_categories(rule)
        return any(not scope.categories or bool(cats & set(scope.categories)) for scope in user.scopes)
    return alert_visible(user, _as_alert(silence))


def _as_alert(silence: dict[str, Any]) -> dict[str, Any]:
    """규칙·대상을 정한 무음을 알림처럼. PC 로만 맞추는 무음(host_only — 범위가 정해진 사용자가 건 것)은 대상 자리가 PC 라 PC 로 본다
    (처음 보는 값 규칙도 그 PC 의 알림에만 걸린다). 관리자가 건 처음 보는 값 규칙의 무음은 값 조합으로도 맞아 모든 PC 에 걸리므로
    범위가 정해진 사용자에게 안 보인다 — PC 모양인 값(계정 'ws-ops'·IP)으로 범위 밖 PC 의 알림을 막을 수 있었다(검토에서 재현)."""
    rule = next((r for r in engine.config.rules if r.name == silence["rule"]), None)
    if silence.get("host_only") and rule is not None and rule.kind == "new_terms":
        return {"rule": silence["rule"], "group_key": silence["group_key"], "terms_host": silence["group_key"]}
    return silence   # 다른 규칙은 알림처럼(채널 끊김 'PC · 채널' 은 alert_host 가 PC 를 뗀다)


def silence_target_visible(user: User, rule: str | None, group_key: str | None, host_only: bool = True) -> bool:
    """무음을 걸고 풀 수 있는 범위(routers/alerts._check_silence_scope) — 규칙·대상 한 개, 위와 같은 판단. 범위가 정해진 사용자가
    거는 무음은 PC 로만 맞춘다(host_only)."""
    if user.scopes is None:
        return True
    return rule is not None and group_key is not None and alert_visible(
        user, _as_alert({"rule": rule, "group_key": group_key, "host_only": host_only}))


def scrub_silence(user: User, silence: dict[str, Any], alert: dict[str, Any] | None = None) -> dict[str, Any]:
    """범위가 있는 사용자에게 넓은 무음의 '보내지 않은 알림 수'는 감춘다 — 범위 밖 알림까지 센 숫자라서.
    볼 수 없는 무음(처음 보는 값 알림이 여러 PC 의 점검 무음에 걸렸을 때 다른 PC 의 것)은 무음이었다는 것과 기간만 —
    범위 밖 PC 이름·사유·건 사람이 알림 상세로 샜다(검토에서 재현)."""
    # 이 알림의 규칙·대상 그대로 건 무음은 보인다(알림을 보는 사람에게 새 정보가 아니다 — '다른 대상'이라 하면 틀린 말이었다, 검토)
    own = alert is not None and silence["rule"] in (None, alert["rule"]) and silence["group_key"] in (None, alert["group_key"])
    if user.scopes is not None and not own and not silence_visible(user, silence):
        return {"id": silence["id"], "starts_at": silence["starts_at"], "ends_at": silence["ends_at"], "rule": None,
                "group_key": None, "reason": None, "created_by": None, "suppressed": None, "hidden": True}
    if user.scopes is not None and (silence["rule"] is None or silence["group_key"] is None):
        return {**silence, "suppressed": None}
    return silence


def alert_stats_for(user: User, groups: list[dict[str, Any]]) -> dict[str, Any]:
    """repository.alert_rule_groups 결과 → repository.alert_stats 와 같은 모양(by_rule·by_severity·last_fired)을
    이 사용자에게 보이는 알림만으로 (B-27 — 범위가 있는 사용자가 심각도별·규칙별 수로 병원 전체 규모를 짐작하지 않게)."""
    by_rule: dict[str, dict[str, Any]] = {}
    by_severity: Counter[str] = Counter()
    last_fired: dict[str, Any] = {}
    for g in groups:
        if not alert_visible(user, g):
            continue
        rule = g["rule"]
        if g["n"]:
            cur = by_rule.setdefault(rule, {"n": 0, "last_fired_at": None})
            cur["n"] += g["n"]
            cur["last_fired_at"] = max(filter(None, (cur["last_fired_at"], g["last_recent"])), default=None)
            by_severity[g["severity"]] += g["n"]
        last_fired[rule] = max(filter(None, (last_fired.get(rule), g["last_ever"])), default=None)
    return {"by_rule": by_rule, "by_severity": dict(by_severity), "last_fired": last_fired}


def count_by_status(user: User, groups: list[dict[str, Any]]) -> dict[str, int]:
    """repository.alert_group_counts 결과 → 이 사용자에게 보이는 알림의 상태별 수."""
    counts: Counter[str] = Counter({"open": 0, "acked": 0, "resolved": 0})
    for g in groups:
        if alert_visible(user, g):
            counts[g["status"]] += g["n"]
    return dict(counts)
