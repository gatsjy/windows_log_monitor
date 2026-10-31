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
    for scope in user.scopes:
        cat_ok = not scope.categories or bool(cats & set(scope.categories))
        host_ok = scope.allows_host(alert_host(alert["rule"], alert["group_key"]))
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
    return alert_visible(user, silence)


def scrub_silence(user: User, silence: dict[str, Any]) -> dict[str, Any]:
    """범위가 있는 사용자에게 넓은 무음의 '보내지 않은 알림 수'는 감춘다 — 범위 밖 알림까지 센 숫자라서."""
    if user.scopes is not None and (silence["rule"] is None or silence["group_key"] is None):
        return {**silence, "suppressed": None}
    return silence


def count_by_status(user: User, groups: list[dict[str, Any]]) -> dict[str, int]:
    """repository.alert_group_counts 결과 → 이 사용자에게 보이는 알림의 상태별 수."""
    counts: Counter[str] = Counter({"open": 0, "acked": 0, "resolved": 0})
    for g in groups:
        if alert_visible(user, g):
            counts[g["status"]] += g["n"]
    return dict(counts)
