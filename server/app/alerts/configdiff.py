"""알림 설정 판본 사이의 차이와 '탐지를 약하게 하는 변경' 판단 (NEW-M2, ADR-043).

누가 규칙을 끄거나 기준을 올려도 그 규칙의 알림을 받던 사람은 알 수 없었다(알림이 오지 않을 뿐).
여기서 차이를 사람이 읽는 문장으로 만들고, 약해지는 변경이면 엔진이 바뀌기 전 설정의 받는 곳으로 알린다.
약해졌는지 확신할 수 없는 변경(조건·묶음 기준 바꿈)은 약해진 것으로 본다 — 놓치는 쪽이 더 비싸다.
"""

from __future__ import annotations

from datetime import timedelta

from .message import SEVERITY_LABELS
from .rules import SEVERITIES, AlertConfig, Rule

# 무음이 지금부터 이보다 오래 덮으면(또는 모든 규칙·모든 대상이면) 넓은 무음으로 알린다
WIDE_SILENCE = timedelta(hours=24)
RESOLVE_LABELS = {"manual": "사람이 해결", "auto": "조건이 풀리면 자동 해결"}


def rule_key(rule: Rule) -> str:
    # 화면에서 이름을 바꿔도 sid 는 그대로라 같은 규칙으로 본다. sid 없는 규칙(손으로 쓴 것)은 이름으로
    return f"sid:{rule.sid}" if rule.sid is not None else f"name:{rule.name}"


def _dur(delta: timedelta) -> str:
    sec = int(delta.total_seconds())
    for unit, size in (("일", 86400), ("시간", 3600), ("분", 60)):
        if sec % size == 0:
            return f"{sec // size}{unit}"
    return f"{sec}초"


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)   # 0 = critical


def _rule_changes(old: Rule, new: Rule) -> list[tuple[str, str, bool]]:
    """(change, 설명, 약해짐) 목록."""
    out: list[tuple[str, str, bool]] = []
    if old.name != new.name:
        out.append(("renamed", f"이름 '{old.name}' → '{new.name}' (이전 발생 기록과의 연결이 끊김)", False))
    if old.sid != new.sid:
        out.append(("sid", f"규칙 번호 {old.sid or '없음'} → {new.sid or '없음'}", False))
    if old.enabled != new.enabled:
        out.append(("disabled", "끔", True) if not new.enabled else ("enabled", "켬", False))
    if old.kind != new.kind:
        out.append(("kind", f"종류 {old.kind} → {new.kind}", True))
    if old.severity != new.severity:
        lower = _rank(new.severity) > _rank(old.severity)
        text = f"심각도 {SEVERITY_LABELS.get(old.severity, old.severity)} → {SEVERITY_LABELS.get(new.severity, new.severity)}"
        out.append(("severity", text, lower))
    if old.resolve != new.resolve:
        # 사람이 보지 않고 '해결됨'이 된다 — 보안 규칙에 auto 를 달면 보고서에서 사라지므로 약화로 알린다
        out.append(("resolve", f"해결 방식 {RESOLVE_LABELS[old.resolve]} → {RESOLVE_LABELS[new.resolve]}",
                    new.resolve == "auto"))
    removed = [n for n in old.notify if n not in new.notify]
    added = [n for n in new.notify if n not in old.notify]
    if removed:
        out.append(("notify_removed", f"받는 곳에서 뺌: {', '.join(removed)}", True))
    if added:
        out.append(("notify_added", f"받는 곳 추가: {', '.join(added)}", False))
    if old.kind == new.kind == "agent_silent":
        if old.silent_for != new.silent_for:
            out.append(("silent_for", f"끊김 판정 {_dur(old.silent_for)} → {_dur(new.silent_for)}",
                        new.silent_for > old.silent_for))
        if set(old.hosts) != set(new.hosts):
            # 목록 순서는 상관없다(host = ANY). 비어 있으면 모든 PC — PC 를 빼거나 전체에서 목록으로 좁히면 약해진다
            weaker = bool(new.hosts) and (not old.hosts or bool(set(old.hosts) - set(new.hosts)))
            out.append(("hosts", f"대상 PC {', '.join(old.hosts) or '전체'} → {', '.join(new.hosts) or '전체'}", weaker))
        return out
    if old.match != new.match:
        out.append(("match", f"조건 {_match_text(old)} → {_match_text(new)}", True))
    if old.threshold != new.threshold:
        out.append(("threshold", f"건수 기준 {old.threshold:,} → {new.threshold:,}", new.threshold > old.threshold))
    if old.window != new.window:
        out.append(("window", f"집계 기간 {_dur(old.window)} → {_dur(new.window)}", new.window < old.window))
    if old.group_by != new.group_by:
        out.append(("group_by", f"묶음 기준 {old.group_by} → {new.group_by}", True))
    if (old.distinct_field, old.distinct_min) != (new.distinct_field, new.distinct_min):
        before = f"{old.distinct_field} {old.distinct_min}개" if old.distinct_field else "없음"
        after = f"{new.distinct_field} {new.distinct_min}개" if new.distinct_field else "없음"
        # 조건이 없어지면 더 자주 울린다. 생기거나 기준이 오르거나 세는 필드가 바뀌면 덜 울릴 수 있다
        weaker = new.distinct_field is not None and (
            old.distinct_field != new.distinct_field or new.distinct_min > old.distinct_min)
        out.append(("distinct", f"서로 다른 값 수 {before} → {after}", weaker))
    if old.cooldown != new.cooldown:
        out.append(("cooldown", f"재알림 간격 {_dur(old.cooldown)} → {_dur(new.cooldown)}", new.cooldown > old.cooldown))
    return out


def _match_text(rule: Rule) -> str:
    return " ".join(f"{k}={v}" for k, v in sorted(rule.match.items())) or "(모든 이벤트)"


def _label(rule: Rule) -> str:
    return f"'{rule.name}'" + (f"({rule.sid})" if rule.sid is not None else "")


def _change(rule: Rule, key: str | None, change: str, text: str, weakens: bool, name: str | None = None) -> dict:
    """rule = 바뀌기 전 모양(문구의 이름), name = 지금 이름 (무음·재알림 간격이 이 이름으로 걸린다)."""
    return {"rule": name or rule.name, "sid": rule.sid, "key": key, "change": change, "weakens": weakens,
            "text": f"규칙 {_label(rule)} {text}"}


def needs_history(old: AlertConfig | None, new: AlertConfig) -> set[str]:
    """다시 켜거나 다시 추가한 규칙 — 마지막으로 켜져 있던 판본과 비교해야 한다(끄고 → 고치고 → 켜면 바로 앞 판본은 꺼진 모양)."""
    before = {rule_key(r): r for r in old.rules} if old else {}
    return {rule_key(r) for r in new.rules if r.enabled and not (rule_key(r) in before and before[rule_key(r)].enabled)}


def diff(old: AlertConfig | None, new: AlertConfig, last_enabled: dict[str, tuple[Rule, int]] | None = None) -> list[dict]:
    """직전 판본(old) → 새 판본(new) 차이. old 가 None 이면 비교할 수 없다는 한 줄(약해짐으로 봄).
    last_enabled = 규칙 키 → (그 규칙이 마지막으로 켜져 있던 모양, 판본 번호). needs_history 의 키만 엔진이 찾아 준다."""
    if old is None:
        return [{"rule": None, "sid": None, "key": None, "change": "unknown", "weakens": True,
                 "text": "이전 판본을 읽을 수 없어 비교하지 못했습니다 — 규칙 목록을 직접 확인하세요"}]
    last_enabled = last_enabled or {}
    changes: list[dict] = []
    if old.interval_sec != new.interval_sec:
        changes.append({"rule": None, "sid": None, "key": None, "change": "interval",
                        "weakens": new.interval_sec > old.interval_sec,
                        "text": f"평가 주기 {old.interval_sec}초 → {new.interval_sec}초"})
    if old.fallback_notify != new.fallback_notify:
        gone = [n for n in old.fallback_notify if n not in new.fallback_notify]
        changes.append({"rule": None, "sid": None, "key": None, "change": "fallback", "weakens": bool(gone),
                        "text": f"알림 기능 문제를 받는 곳 {', '.join(old.fallback_notify) or '(점검 보고서 받는 곳)'} → "
                                f"{', '.join(new.fallback_notify) or '(점검 보고서 받는 곳)'}"})
    before = {rule_key(r): r for r in old.rules}
    after = {rule_key(r): r for r in new.rules}
    # 같은 이름인데 열쇠가 바뀐 것(sid 없는 규칙을 화면에서 고치면 번호가 붙는다)은 삭제+추가가 아니라 같은 규칙
    added_by_name = {after[k].name: k for k in after if k not in before}
    matched = {k: after[k] for k in before if k in after}
    matched |= {k: after[added_by_name.pop(r.name)] for k, r in before.items()
                if k not in after and r.name in added_by_name}
    for key, rule in before.items():
        new_rule = matched.get(key)
        if new_rule is None:
            changes.append(_change(rule, key, "removed", "삭제", rule.enabled))
            continue
        base = last_enabled.get(rule_key(new_rule)) if not rule.enabled and new_rule.enabled else None
        if base:
            changes.append(_change(rule, key, "enabled", "켬", False, new_rule.name))
            changes += [_change(rule, key, change, f"다시 켬 — 판본 #{base[1]}에서 켜져 있던 때와 비교: {text}", weakens,
                                new_rule.name)
                        for change, text, weakens in _rule_changes(base[0], new_rule) if change not in ("enabled", "disabled")]
            continue
        # 꺼진 채로 고친 것은 지금의 탐지를 약하게 하지 않는다 (켤 때 마지막으로 켜져 있던 모양과 비교한다)
        gate = rule.enabled or new_rule.enabled
        changes += [_change(rule, key, change, text, weakens and gate, new_rule.name)
                    for change, text, weakens in _rule_changes(rule, new_rule)]
    for key in added_by_name.values():
        rule = after[key]
        changes.append(_change(rule, key, "added", "추가" + ("" if rule.enabled else " (꺼짐)"), False))
        if base := (last_enabled.get(key) if rule.enabled else None):
            changes += [_change(rule, key, change, f"다시 추가 — 판본 #{base[1]}에서 켜져 있던 때와 비교: {text}", weakens)
                        for change, text, weakens in _rule_changes(base[0], rule) if change not in ("enabled", "disabled")]
    return changes


def affected(old: AlertConfig | None, new: AlertConfig, changes: list[dict],
             last_enabled: dict[str, tuple[Rule, int]] | None = None) -> list[Rule]:
    """약해진 변경을 알릴 규칙들(바뀌기 전 모양 — 그 받는 곳으로). 꺼진 규칙은 받는 곳·심각도에 넣지 않는다.
    규칙 하나로 좁힐 수 없는 변경(평가 주기·비교 불가)이면 켜진 모든 규칙(이전 판본을 읽을 수 없으면 새 판본의 것)."""
    weak = [c for c in changes if c["weakens"]]
    if any(c["key"] is None for c in weak):
        return [r for r in (old or new).rules if r.enabled]
    keys = {c["key"] for c in weak}
    out = [r for r in (old.rules if old else ()) if rule_key(r) in keys]
    out += [base for key, (base, _) in (last_enabled or {}).items() if key in keys]
    return list({(r.sid, r.name): r for r in out}.values())


def recipients(rules: list[Rule]) -> tuple[str, ...]:
    """그 규칙들의 알림을 받던 곳 (순서 유지, 중복 제거)."""
    return tuple(dict.fromkeys(n for r in rules for n in r.notify))


def severity(rules: list[Rule]) -> str:
    """걸린 규칙 중 가장 높은 심각도 — 받는 곳의 '최소 수준' 설정을 그대로 따르게. 규칙이 없으면 경고."""
    return min((r.severity for r in rules), key=_rank, default="warning")
