"""알림 설정 판본 사이의 차이와 '탐지를 약하게 하는 변경' 판단 (NEW-M2, ADR-043).

누가 규칙을 끄거나 기준을 올려도 그 규칙의 알림을 받던 사람은 알 수 없었다(알림이 오지 않을 뿐).
여기서 차이를 사람이 읽는 문장으로 만들고, 약해지는 변경이면 엔진이 바뀌기 전 설정의 받는 곳으로 알린다.
약해졌는지 확신할 수 없는 변경(조건·묶음 기준 바꿈)은 약해진 것으로 본다 — 놓치는 쪽이 더 비싸다.
"""

from __future__ import annotations

from datetime import timedelta

from . import tactics
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
    if old.mode != new.mode:
        # 관찰 모드는 알림을 기록만 하고 보내지 않는다 — 켜진 규칙을 관찰로 돌리면 끄는 것과 같다(B-52)
        out.append(("observe", "관찰 모드로 (알림을 보내지 않음)", True) if new.mode == "observe"
                   else ("promoted", "관찰 끝 — 알림을 보냄", False))
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
    # 태그·묶음은 경로(B-26)가 받는 곳을 고르는 조건이다 — 바뀐 것을 남기고, 받는 곳이 빠지는지는 diff 가 경로로 따로 본다
    if old.tags != new.tags:
        out.append(("tags", f"태그 {', '.join(old.tags) or '없음'} → {', '.join(new.tags) or '없음'}", False))
    if old.group != new.group:
        out.append(("group", f"묶음 {old.group or '없음'} → {new.group or '없음'}", False))
    if old.kind == new.kind == "stream_silent":
        for attr, label in (("hosts", "대상 PC"), ("channels", "볼 채널")):
            # 채널은 대소문자를 가리지 않고 맞춘다(엔진) — 대소문자만 바꾼 것은 변경이 아니다. PC 는 정확히 맞춘다(SQL)
            fold = str.casefold if attr == "channels" else str
            before, after = {fold(v) for v in getattr(old, attr)}, {fold(v) for v in getattr(new, attr)}
            if before != after:
                # 비어 있으면 전부 — 전부에서 목록으로 좁히거나 목록에서 빼면 약해진다
                weaker = bool(after) and (not before or bool(before - after))
                out.append((attr, f"{label} {', '.join(sorted(before)) or '전체'} → {', '.join(sorted(after)) or '전체'}", weaker))
        return out
    if old.kind == new.kind == "agent_silent":
        if old.silent_for != new.silent_for:
            out.append(("silent_for", f"끊김 판정 {_dur(old.silent_for)} → {_dur(new.silent_for)}",
                        new.silent_for > old.silent_for))
        if set(old.hosts) != set(new.hosts):
            # 목록 순서는 상관없다(host = ANY). 비어 있으면 모든 PC — PC 를 빼거나 전체에서 목록으로 좁히면 약해진다
            weaker = bool(new.hosts) and (not old.hosts or bool(set(old.hosts) - set(new.hosts)))
            out.append(("hosts", f"대상 PC {', '.join(old.hosts) or '전체'} → {', '.join(new.hosts) or '전체'}", weaker))
        return out
    if old.kind == new.kind == "correlation":
        # 상관 알림 (B-67 2단계): 기준 전술 수를 올리거나 기간을 줄이거나 볼 개체를 빼면 덜 울린다
        if old.min_tactics != new.min_tactics:
            out.append(("min_tactics", f"전술 기준 {old.min_tactics}개 → {new.min_tactics}개", new.min_tactics > old.min_tactics))
        if old.window != new.window:
            out.append(("window", f"기간 {_dur(old.window)} → {_dur(new.window)}", new.window < old.window))
        if old.cooldown != new.cooldown:
            out.append(("cooldown", f"재알림 간격 {_dur(old.cooldown)} → {_dur(new.cooldown)}", new.cooldown > old.cooldown))
        if set(old.entities) != set(new.entities):
            out.append(("entities", f"볼 개체 {', '.join(old.entities)} → {', '.join(new.entities)}",
                        bool(set(old.entities) - set(new.entities))))
        if set(old.hub_hosts) != set(new.hub_hosts):
            # PC 로 잇지 않는 서버를 더하면 그 서버의 흐름은 계정·IP 로만 — 약해짐
            out.append(("hub_hosts", f"PC 로 잇지 않는 서버 {', '.join(old.hub_hosts) or '없음'} → {', '.join(new.hub_hosts) or '없음'}",
                        bool(set(new.hub_hosts) - set(old.hub_hosts))))
        return out
    if old.match != new.match:
        out.append(("match", f"조건 {_match_text(old)} → {_match_text(new)}", True))
    if old.kind == new.kind == "new_terms":
        # 처음 보는 값 (B-47): 필드를 바꾸면 처음부터 다시 배운다(그동안 알림 없음), 기간·배우는 기간을 늘리면 덜 새로워진다,
        # 상한·한꺼번에 기준을 줄이면 놓치거나 묶여 하나하나 보지 못한다
        if old.terms_fields != new.terms_fields:
            out.append(("fields", f"볼 값 {', '.join(old.terms_fields)} → {', '.join(new.terms_fields)} (다시 배움)", True))
        for attr, label, weaker_if_more in (("history", "다시 새로 볼 기간", True), ("learn", "배우는 기간(배우는 중이면 바로 적용)", True)):
            before, after = getattr(old, attr), getattr(new, attr)
            if before != after:
                out.append((attr, f"{label} {_dur(before)} → {_dur(after)}", (after > before) == weaker_if_more))
        for attr, label in (("max_terms", "값 조합 상한"), ("burst", "한 번에 하나씩 알릴 수")):
            before, after = getattr(old, attr), getattr(new, attr)
            if before != after:
                out.append((attr, f"{label} {before:,} → {after:,}", after < before))
        return out
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


def _route_changes(old: AlertConfig, new: AlertConfig) -> list[dict]:
    """받는 곳 경로 (B-26): 경로를 빼거나·받는 곳을 빼거나·규칙의 받는 곳을 갈아 끼우게(replace) 바꾸거나·조건을 바꾸면 약해질 수 있다.
    경로는 위에서부터 멈추므로 순서도 뜻이다 — 같지 않으면 약해짐으로 보고 사람이 확인하게 한다(넓힌 것만 아니라고 단정하기 어렵다)."""
    if old.routes == new.routes:
        return []
    before = {r.name: r for r in old.routes}
    after = {r.name: r for r in new.routes}
    out = []
    for name, r in before.items():
        q = after.get(name)
        if q is None:
            out.append(("route_removed", f"경로 '{name}' 삭제", True))
        elif q != r:
            out.append(("route", f"경로 '{name}' 변경", True))
    order = [r.name for r in new.routes]
    for name, r in after.items():
        if name not in before:
            # 새 경로가 받는 곳을 갈아 끼우거나, 멈춰서(continue 아님) 뒤에 있던 기존 경로를 가릴 수 있으면 약해질 수 있다
            shadows = not r.continue_ and any(n in before for n in order[order.index(name) + 1:])
            out.append(("route_added", f"경로 '{name}' 추가", r.replace or shadows))
    # 남아 있는 경로끼리의 순서는 늘 본다 — 새 경로를 더하면서 순서를 바꾸면 '추가'만 보고 지나쳤다(검토에서 재현)
    kept_old = [r.name for r in old.routes if r.name in after]
    kept_new = [r.name for r in new.routes if r.name in before]
    if kept_old != kept_new:
        out.append(("route_order", "경로 순서 변경", True))
    return [{"rule": None, "sid": None, "key": None, "change": c, "weakens": w, "text": t} for c, t, w in out]


def _routed_loss(old: AlertConfig, old_rule: Rule, new: AlertConfig, new_rule: Rule,
                 hosts: tuple[str | None, ...]) -> list[str]:
    """이 규칙의 알림을 받던 곳 중 이제 받지 못하는 곳 (경로 포함, PC 패턴마다) — 규칙의 태그·묶음·심각도·이름을 바꾸면
    맞는 경로가 달라져 팀 하나가 조용히 빠졌다(검토에서 재현)."""
    lost: dict[str, None] = {}
    for host in hosts:
        after = set(new.sample_targets(new_rule, host))
        lost.update(dict.fromkeys(n for n in old.sample_targets(old_rule, host) if n not in after))
    return list(lost)


def _routed_change(old: AlertConfig, base: tuple[Rule, int], new: AlertConfig, new_rule: Rule, hosts: tuple[str | None, ...],
                   key: str, how: str) -> list[dict]:
    """다시 켜거나 다시 추가한 규칙: 마지막으로 켜져 있던 모양(base)과 비교해 경로로 받던 곳이 빠졌나 — 끄고 → 태그를 빼고 → 켜는
    우회로 팀 하나를 조용히 뺐다(검토에서 재현). 경로는 바로 앞 판본(old)의 것으로 본다(그 판본의 경로는 기록에서 다시 읽지 않음)."""
    if not (old.routes or new.routes):
        return []
    removed = set(base[0].notify) - set(new_rule.notify)
    lost = [n for n in _routed_loss(old, base[0], new, new_rule, hosts) if n not in removed]
    if not lost:
        return []
    return [_change(base[0], key, "route_targets", f"{how} — 판본 #{base[1]}에서 켜져 있던 때와 비교: 경로로 받던 곳이 빠짐: "
                    f"{', '.join(lost)}", True, new_rule.name)]


def _escalation_changes(old: AlertConfig, new: AlertConfig) -> list[dict]:
    """에스컬레이션 정책 (B-43): 단계를 빼거나·늦추거나·받는 곳을 빼거나·대상(심각도·규칙)을 좁히면 약해진다 — 새벽 알림이 아침까지 묻힌다."""
    out = []
    before = {p.name: p for p in old.escalations}
    after = {p.name: p for p in new.escalations}
    for name, p in before.items():
        q = after.get(name)
        if q is None:
            out.append(("escalation_removed", f"에스컬레이션 '{name}' 삭제", True))
            continue
        if q == p:
            continue
        # 약해짐 = 옛 단계의 받는 곳 하나라도, 새 정책에서 '그 받는 곳에 같거나 이른 시각·같거나 강한 조건으로' 다시 알리는 단계가 없다.
        # resolved(해결될 때까지)가 acked(확인되면 멈춤)보다 강하다 — resolved → acked 는 확인만 하면 다시 알리지 않게 된다(검토에서 재현)
        rank = {"acked": 0, "resolved": 1}
        weaker = any(not any(n in s2.notify and s2.after <= s.after and rank[s2.unless] >= rank[s.unless] for s2 in q.steps)
                     for s in p.steps for n in s.notify)
        narrower = (bool(q.severities) and (not p.severities or bool(set(p.severities) - set(q.severities)))) or \
                   (bool(q.rules) and (not p.rules or bool(set(p.rules) - set(q.rules))))
        # 확인 시간 초과 (2단계): 없애거나 늘리면 확인만 하고 잊힌 알림이 더 늦게(또는 영영) 다시 열린다. 받는 곳은 첫 단계라 단계 비교가 본다
        later = p.ack_timeout is not None and (q.ack_timeout is None or q.ack_timeout > p.ack_timeout)
        out.append(("escalation", f"에스컬레이션 '{name}' 변경", weaker or narrower or later))
    for name in after:
        if name not in before:
            out.append(("escalation_added", f"에스컬레이션 '{name}' 추가", False))
    return [{"rule": None, "sid": None, "key": None, "change": c, "weakens": w, "text": t} for c, t, w in out]


def diff(old: AlertConfig | None, new: AlertConfig, last_enabled: dict[str, tuple[Rule, int]] | None = None,
         base_configs: dict[int, AlertConfig] | None = None) -> list[dict]:
    """직전 판본(old) → 새 판본(new) 차이. old 가 None 이면 비교할 수 없다는 한 줄(약해짐으로 봄).
    last_enabled = 규칙 키 → (그 규칙이 마지막으로 켜져 있던 모양, 판본 번호). needs_history 의 키만 엔진이 찾아 준다.
    base_configs = 그 판본 번호 → 그 판본의 설정 전체 (다시 켠 상관 규칙이 세던 다른 규칙들과 비교, B-67)."""
    if old is None:
        return [{"rule": None, "sid": None, "key": None, "change": "unknown", "weakens": True,
                 "text": "이전 판본을 읽을 수 없어 비교하지 못했습니다 — 규칙 목록을 직접 확인하세요"}]
    last_enabled = last_enabled or {}
    changes: list[dict] = []
    if old.interval_sec != new.interval_sec:
        changes.append({"rule": None, "sid": None, "key": None, "change": "interval",
                        "weakens": new.interval_sec > old.interval_sec,
                        "text": f"평가 주기 {old.interval_sec}초 → {new.interval_sec}초"})
    if (old.group_wait_sec, old.group_interval_sec) != (new.group_wait_sec, new.group_interval_sec):
        # 묶음 전송 (B-41): 모으는 시간·간격이 늘면 알림이 늦게 간다 — 약해짐. 0(묶지 않음)으로 바꾸는 것은 더 자주 보낼 뿐
        def text(c: AlertConfig) -> str:
            return f"{c.group_wait_sec}초 모음·{c.group_interval_sec}초 간격" if c.group_interval_sec else "묶지 않음"
        changes.append({"rule": None, "sid": None, "key": None, "change": "grouping",
                        "weakens": new.group_interval_sec > 0 and (new.group_wait_sec > old.group_wait_sec
                                                                   or new.group_interval_sec > old.group_interval_sec),
                        "text": f"묶음 전송 {text(old)} → {text(new)}"})
    if old.fallback_notify != new.fallback_notify:
        gone = [n for n in old.fallback_notify if n not in new.fallback_notify]
        changes.append({"rule": None, "sid": None, "key": None, "change": "fallback", "weakens": bool(gone),
                        "text": f"알림 기능 문제를 받는 곳 {', '.join(old.fallback_notify) or '(점검 보고서 받는 곳)'} → "
                                f"{', '.join(new.fallback_notify) or '(점검 보고서 받는 곳)'}"})
    changes += _escalation_changes(old, new)
    changes += _route_changes(old, new)
    hosts = tuple(dict.fromkeys(old.host_samples() + new.host_samples()))
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
            changes += _routed_change(old, base, new, new_rule, hosts, key, "다시 켬")
            continue
        # 꺼진 채로 고친 것은 지금의 탐지를 약하게 하지 않는다 (켤 때 마지막으로 켜져 있던 모양과 비교한다)
        gate = rule.enabled or new_rule.enabled
        changes += [_change(rule, key, change, text, weakens and gate, new_rule.name)
                    for change, text, weakens in _rule_changes(rule, new_rule)]
        if (old.routes or new.routes) and rule.enabled and new_rule.enabled:
            # 규칙의 notify 에서 뺀 곳은 위(notify_removed)에서 이미 말했다 — 경로 때문에 빠진 곳만
            removed = set(rule.notify) - set(new_rule.notify)
            lost = [n for n in _routed_loss(old, rule, new, new_rule, hosts) if n not in removed]
            if lost:
                changes.append(_change(rule, key, "route_targets", f"경로로 받던 곳이 빠짐: {', '.join(lost)}", True,
                                       new_rule.name))
    changes += _feeder_changes(new, before, matched, after, added_by_name, last_enabled, base_configs or {})
    for key in added_by_name.values():
        rule = after[key]
        changes.append(_change(rule, key, "added", "추가" + ("" if rule.enabled else " (꺼짐)"), False))
        if base := (last_enabled.get(key) if rule.enabled else None):
            changes += [_change(rule, key, change, f"다시 추가 — 판본 #{base[1]}에서 켜져 있던 때와 비교: {text}", weakens)
                        for change, text, weakens in _rule_changes(base[0], rule) if change not in ("enabled", "disabled")]
            changes += _routed_change(old, base, new, rule, hosts, key, "다시 추가")
    return changes


def _contributes(rule: Rule | None) -> set[str]:
    """상관 알림(B-67 2단계)에 이 규칙이 보태는 전술 — 켜져 있고 보내는(관찰 아님) 건수·처음 보는 값 규칙의 태그에서."""
    if rule is None or not rule.enabled or rule.mode == "observe" or rule.kind not in ("count", "new_terms"):
        return set()
    return set(tactics.of_tags(rule.tags))


def _lost_text(name: str, lost: set[str]) -> str:
    return f"'{name}' 의 {', '.join(tactics.label(t) for t in sorted(lost, key=tactics.ORDER.__getitem__))}"


def _feeder_changes(new: AlertConfig, before: dict[str, Rule], matched: dict[str, Rule], after: dict[str, Rule],
                    added_by_name: dict[str, str], last_enabled: dict[str, tuple[Rule, int]],
                    base_configs: dict[int, AlertConfig]) -> list[dict]:
    """상관 알림이 세던 규칙에서 전술이 빠짐 — 태그를 지우거나 모르는 기법으로 바꾸거나·끄거나·관찰로 돌리거나·지우면 그 단계가 흐름에서
    빠져 공격 흐름이 기준 아래가 된다. 그 규칙 자체의 변경으로는 약해짐이 아니어도(태그) 상관 규칙의 받는 곳에 알린다(검토에서 재현).
    끄고 → 고치고 → 켜는 우회도 막는다: 다시 켠 규칙은 마지막으로 켜져 있던 모양과, 다시 켠 상관 규칙은 그때 판본의 다른 규칙들과 비교한다."""
    out: list[dict] = []
    watchers = [(k, r) for k, r in before.items() if r.kind == "correlation" and r.enabled]
    if watchers:
        lost_by_rule = []
        for key, rule in before.items():
            new_rule = matched.get(key)
            prev = rule
            if not rule.enabled and new_rule is not None and new_rule.enabled and rule_key(new_rule) in last_enabled:
                prev = last_enabled[rule_key(new_rule)][0]   # 꺼 둔 동안 태그를 고친 규칙을 다시 켬 — 마지막으로 켜져 있던 모양과
            if lost := _contributes(prev) - _contributes(new_rule):
                lost_by_rule.append(_lost_text(rule.name, lost))
        if lost_by_rule:
            text = f"이 세던 전술이 빠짐: {'; '.join(lost_by_rule)}"
            out += [_change(r, k, "feeder_tactics", text, True, matched[k].name if k in matched else r.name) for k, r in watchers]
    # 다시 켜거나 다시 추가한 상관 규칙 — 꺼져(없어져) 있는 동안 다른 규칙의 태그를 지웠으면 그때(마지막으로 켜져 있던 판본)와 비교
    revived = [(k, before[k], matched[k], "다시 켬") for k in matched
               if k in before and not before[k].enabled and matched[k].enabled and matched[k].kind == "correlation"]
    revived += [(k, after[k], after[k], "다시 추가") for k in added_by_name.values()
                if after[k].enabled and after[k].kind == "correlation"]
    now_rules = {rule_key(r): r for r in new.rules}
    for key, rule, new_rule, how in revived:
        base = last_enabled.get(rule_key(new_rule))
        if base is None or (then := base_configs.get(base[1])) is None:
            continue
        lost_by_rule = [_lost_text(r.name, lost) for r in then.rules
                        if (lost := _contributes(r) - _contributes(now_rules.get(rule_key(r))))]
        if lost_by_rule:
            out.append(_change(rule, key, "feeder_tactics", f"{how} — 판본 #{base[1]}에서 켜져 있던 때와 비교: "
                                                              f"이 세던 전술이 빠짐: {'; '.join(lost_by_rule)}", True, new_rule.name))
    return out


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


def recipients(rules: list[Rule], config: AlertConfig | None = None) -> tuple[str, ...]:
    """그 규칙들의 알림을 받던 곳 (순서 유지, 중복 제거): 규칙의 notify 와, config(바뀌기 전 설정)의 경로로 받던 곳.
    경로를 지우거나 경로가 받는 곳을 갈아 끼운 규칙을 끄면, 실제로 받던 팀이 아니라 notify 에만 적힌 곳에 알렸다(검토에서 재현)."""
    hosts = config.host_samples() if config else ()
    return tuple(dict.fromkeys(n for r in rules for n in (*r.notify, *(config.reachable(r, hosts) if config else ()))))


def severity(rules: list[Rule]) -> str:
    """걸린 규칙 중 가장 높은 심각도 — 받는 곳의 '최소 수준' 설정을 그대로 따르게. 규칙이 없으면 경고."""
    return min((r.severity for r in rules), key=_rank, default="warning")
