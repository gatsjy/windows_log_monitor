"""상관 알림 (BACKLOG B-67 2단계, ADR-065): 같은 개체(PC·계정·IP)에서 기간 안에 다른 규칙들의 알림이 서로 다른 전술을 N개 이상
덮으면 한 통 — 랜섬웨어 흐름(무차별 대입 → 로그온 성공 → 새 서비스 → 감사 로그 삭제)이 규칙 4개의 알림으로 흩어져 하나하나는
'경고'로 묻히는 것을 한 사고로 올린다.

- 재료는 로그가 아니라 알림: 개체는 알림의 개체 열(ADR-064), 전술은 그 알림을 낼 때의 태그(payload.tags → tactics.of_tags).
  관찰 모드·무음 중 알림은 빼고(repository.correlation_sources), 계정에서 어느 PC 에나 있는 기본 계정은 뺀다(관련 알림과 같게).
- 서로 다른 전술 수 = 규칙과 전술의 최대 짝짓기(tactics.assign) — 규칙 하나가 여러 전술을 덮어도, 여러 번 울려도 하나로.
- 대상 이름은 'PC DC-01'·'계정 kim'·'IP 10.0.0.5' — 개체 종류가 보이고, 조회 범위의 PC 패턴에 맞지 않는다(상관 알림은 여러 규칙의
  알림을 묶으므로 범위가 없는 사용자만 본다, visibility).
- 재알림: 같은 대상은 재알림 간격(기본 = 기간) 안에 다시 알리지 않고, 묶은 알림이 모두 최근 상관 알림에 이미 들어 있으면
  다른 개체로도 다시 알리지 않는다(같은 흐름이 PC·계정·IP 셋으로 세 번 오지 않게). 새 알림이 섞였으면 알린다.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .. import repository
from ..filters import host_matches
from . import tactics
from .message import AlertMessage, alerts_link
from .rules import Rule

SOURCE_MAX = 5000   # 한 번에 보는 MITRE 태그 알림 수 — 넘으면 최근 것만 이만큼(run.truncated)
ITEMS_MAX = 30      # 알림 본문·payload 에 남길 묶은 알림 수
STEPS_MAX = 2000    # payload 에 남길 (PC, 규칙) 수
ENTITY_LABELS = {"host": "PC", "account": "계정", "ip": "IP"}
COLUMNS = {"host": "entity_hosts", "account": "entity_accounts", "ip": "entity_ips"}


def _by_entity(rows: list[dict[str, Any]], kinds: tuple[str, ...],
               hubs: tuple[str, ...] = ()) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """알림(전술이 있는 것)을 개체마다 — 기본 계정은 잇지 않는다. hubs = 여러 사람의 일이 모이는 서버(도메인 컨트롤러 등)의
    PC 패턴: 그 PC 로는 잇지 않는다(그곳의 일은 계정·IP 로만 잇는다 — 여러 직원의 계정 잠금·새 계정·정책 반영이 한 흐름이 되지 않게)."""
    out: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if not row["tactics"]:
            continue
        for kind in kinds:
            for value in row[COLUMNS[kind]] or []:
                if kind == "account" and repository.machine_account(value):
                    continue
                if kind == "host" and hubs and host_matches(hubs, value):
                    continue
                out.setdefault((kind, value), []).append(row)
    return out


def _picked(items: list[dict[str, Any]]) -> dict[str, str]:
    rule_tactics: dict[str, set[str]] = {}
    for row in items:
        rule_tactics.setdefault(row["rule"], set()).update(row["tactics"])
    return tactics.assign({r: tuple(sorted(t, key=tactics.ORDER.__getitem__)) for r, t in rule_tactics.items()})


def _strongest_first(out: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """PC 흐름부터(그 PC 를 맡은 팀의 PC 경로로 가게), 같은 종류 안에서는 강한 것(전술 수·알림 수)부터. 계정·IP 흐름은 PC 흐름이
    알리지 않은 (PC, 단계)가 있을 때만 다시 알린다(_nothing_new) — 여러 PC 로 번진 것."""
    return sorted(out, key=lambda c: (list(ENTITY_LABELS).index(c["kind"]), -len(c["picked"]), -len(c["rows"]), c["value"]))


def chains(rows: list[dict[str, Any]], kinds: tuple[str, ...], min_tactics: int,
           hubs: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """개체마다 묶어 서로 다른 전술이 min_tactics 개 이상인 것 — 강한 것(전술 수·알림 수)부터. rows 는 기간 안 알림(엔진)."""
    out = []
    for (kind, value), items in _by_entity(rows, kinds, hubs).items():
        picked = _picked(items)
        if len(picked) >= min_tactics:
            out.append({"kind": kind, "value": value, "rows": items, "picked": picked})
    return _strongest_first(out)


def preview(rows: list[dict[str, Any]], kinds: tuple[str, ...], min_tactics: int, window: timedelta,
            hubs: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """미리보기: 지난 알림(rows, 발생 순)에 이 규칙을 적용했다면 — 개체마다 window 를 밀며 처음 기준에 닿은 구간, 그 구간 끝 뒤부터 다시.
    엔진은 주기마다 [지금 - window, 지금] 을 보므로 근사다(재알림 간격은 window 로 본다)."""
    out = []
    for (kind, value), items in _by_entity(rows, kinds, hubs).items():
        i = 0
        while i < len(items):
            end = items[i]["fired_at"] + window
            span = [r for r in items[i:] if r["fired_at"] <= end]
            picked = _picked(span)
            if len(picked) >= min_tactics:
                out.append({"kind": kind, "value": value, "rows": span, "picked": picked})
                i += len(span)   # 발생 순이라 구간은 이어져 있다 — 그 끝 뒤부터
            else:
                i += 1
    return _strongest_first(out)


def steps(chain: dict[str, Any]) -> list[dict[str, Any]]:
    """흐름: 짝지은 (규칙, 전술)을 그 규칙의 첫 알림 시각 순으로 — 사람이 읽는 순서(무차별 대입 → 새 서비스 → 로그 삭제).
    ATT&CK 표 순서로 늘어놓으면 '지속 → 방어 회피 → 자격 증명 접근'처럼 일어난 순서와 거꾸로 보였다."""
    first_of: dict[str, dict[str, Any]] = {}
    for row in chain["rows"]:
        first_of.setdefault(row["rule"], row)
    return sorted(({"tactic": t, "name": tactics.label(t), "rule": r, "alert_id": first_of[r]["id"],
                    "at": first_of[r]["fired_at"]} for r, t in chain["picked"].items()),
                  key=lambda s: (s["at"], tactics.ORDER[s["tactic"]], s["rule"]))


def with_tactics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for row in rows:
        row["tactics"] = tactics.of_tags([str(t) for t in row["tags"] if isinstance(t, str)])
    return rows


def key_of(kind: str, value: str) -> str:
    return f"{ENTITY_LABELS[kind]} {value}"


async def evaluate(engine: Any, rule: Rule, now: datetime, run: Any = None) -> list[int]:
    rows = await repository.correlation_sources(now - rule.window, now, SOURCE_MAX + 1)
    if run is not None:
        run.candidates, run.truncated = min(len(rows), SOURCE_MAX), len(rows) > SOURCE_MAX
    found = chains(with_tactics(rows[-SOURCE_MAX:]), rule.entities, rule.min_tactics, rule.hub_hosts)
    if not found:
        return []
    recent = [{"key": r["group_key"], "ids": set(r["ids"]), "entity": r["entity"], "steps": _parse_steps(r["host_steps"]),
               "id": r["id"], "fired_at": r["fired_at"], "resolved_at": r["resolved_at"], "silenced_until": r["silenced_until"]}
              for r in await repository.recent_correlations(rule.name, now - rule.cooldown)]
    fired = []
    for chain in found:
        key = key_of(chain["kind"], chain["value"])
        # 해결했거나 무음이 끝난 상관 알림은 그 뒤 새 단계가 더해지면 같은 대상의 재알림 간격으로 막지 않는다 — 건수 규칙의 '해결 뒤 재발'(B-35)·
        # '무음이 끝나면 간격을 기다리지 않음'과 같게. 같은 흐름 판단(_nothing_new)에는 그대로 둔다: 빼면 해결 앞의 알림이 새것이 되어 한 단계가
        # PC·계정·IP 로 따로 왔다(검토에서 재현)
        live = [r for r in recent if not _reopened(chain, r, rule.hub_hosts, now)]
        if any(r["key"] == key for r in live) or _nothing_new(chain, recent, rule.hub_hosts):
            continue
        message = _message(rule, chain, key, now)
        if previous := max((r for r in recent if r["key"] == key and r.get("id")), key=lambda r: r["fired_at"], default=None):
            message.previous_id, message.previous_fired_at = previous["id"], previous["fired_at"]
            message.recurred = previous["resolved_at"] is not None
        observed = {k: ([chain["value"]] if k == chain["kind"] else []) for k in COLUMNS}
        alert_id = await engine.fire_rule(rule, message, observed=observed,
                                          host=chain["value"] if chain["kind"] == "host" else None)
        if alert_id:
            fired.append(alert_id)
        recent.append({"key": key, "ids": {row["id"] for row in chain["rows"]}, "entity": (chain["kind"], chain["value"]),
                       "steps": _host_steps(chain["rows"]), "resolved_at": None, "silenced_until": None})
    return fired


def _spread(chain: dict[str, Any]) -> dict[str, set[str]]:
    """흐름이 걸친 PC 와 단계(전술) — 알림에 남겨 보여 주는 것."""
    return {"hosts": {h for row in chain["rows"] for h in row["entity_hosts"] or []},
            "tactics": {t for row in chain["rows"] for t in row["tactics"]}}


def _host_steps(rows: list[dict[str, Any]]) -> dict[str, dict[str, set[str]]]:
    """PC 마다 규칙 → 그 규칙 알림의 전술 (PC 가 없는 알림은 ''). 흐름이 어느 PC 에서 어떤 단계를 했는지."""
    out: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        for host in row["entity_hosts"] or [""]:
            out.setdefault(host, {}).setdefault(row["rule"], set()).update(row["tactics"])
    return out


def _parse_steps(raw: Any) -> dict[str, dict[str, set[str]]]:
    out: dict[str, dict[str, set[str]]] = {}
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, list) and len(item) == 3 and isinstance(item[0], str) and isinstance(item[1], str) and isinstance(item[2], list):
            out.setdefault(item[0], {}).setdefault(item[1], set()).update(t for t in item[2] if t in tactics.ORDER)
    return out


def _count(steps: dict[str, set[str]]) -> int:
    """한 PC 의 서로 다른 단계 수 — 흐름을 셀 때와 같은 규칙(규칙 하나는 전술 하나, tactics.assign)."""
    return len(tactics.assign({r: tuple(sorted(t, key=tactics.ORDER.__getitem__)) for r, t in steps.items() if t}))


def _same_flow(chain: dict[str, Any], ids: set[int], announced: dict[str, Any]) -> bool:
    """이미 알린 흐름과 같은 흐름인가 — 알림을 나누거나, 그 알림의 개체(PC·계정·IP)가 이 흐름의 알림에 걸려 있으면.
    알림 번호로만 보면 오래 이어지는 흐름은 앞 알림의 알림들이 기간 밖으로 나간 뒤 PC → 계정 → IP 로 이름을 바꿔 가며
    재알림 간격마다 다시 왔다(검토에서 재현)."""
    if announced["ids"] & ids:
        return True
    entity = announced["entity"]
    if not entity:
        return False
    kind, value = entity
    return kind in COLUMNS and any(value in (row[COLUMNS[kind]] or []) for row in chain["rows"])


def _grows(before: dict[str, set[str]], add: dict[str, set[str]]) -> bool:
    merged = {name: set(ts) for name, ts in before.items()}
    for name, ts in add.items():
        merged.setdefault(name, set()).update(ts)
    return _count(merged) > _count(before)


def _adds_steps(fresh: list[dict[str, Any]], announced: dict[str, dict[str, set[str]]], hubs: tuple[str, ...]) -> bool:
    """새 알림들이 이미 알린 흐름의 단계를 늘리나 — PC 마다 센 단계 수로(규칙 하나는 전술 하나). 여러 사람의 일이 모이는 서버(hub_hosts)는 PC 로
    보지 않고 흐름 전체의 단계 수로: DC 의 계정 잠금(이미 센 자격 증명 접근)이 'DC 로 번짐'이 되어 같은 흐름을 계정으로 또 알렸다(검토에서 재현).
    DC 에서 처음 생긴 단계(도메인 관리자 추가 등)는 늘어난 것이다."""
    hub_add: dict[str, set[str]] = {}
    for host, rules in _host_steps(fresh).items():
        if host and hubs and host_matches(hubs, host):
            for name, ts in rules.items():
                hub_add.setdefault(name, set()).update(ts)
            continue
        if _grows(announced.get(host, {}), rules):
            return True
    if not hub_add:
        return False
    flow: dict[str, set[str]] = {}
    for rules in announced.values():
        for name, ts in rules.items():
            flow.setdefault(name, set()).update(ts)
    return _grows(flow, hub_add)


def _reopened(chain: dict[str, Any], announced: dict[str, Any], hubs: tuple[str, ...], now: datetime) -> bool:
    """해결했거나 무음이 끝난 상관 알림 뒤에 이 흐름에 새 단계가 더해졌나 — 그 알림이 재알림 간격 동안 같은 대상을 막지 않게(해결 뒤 재발,
    점검이 끝난 뒤 새 단계). 그 앞의 알림은 늘어난 것으로 세지 않는다(이미 처리했거나 점검 중이던 것으로 다시 울리지 않게)."""
    marks = [t for t in (announced.get("resolved_at"),) if t is not None]
    if (until := announced.get("silenced_until")) is not None and until <= now:
        marks.append(until)
    if not marks:
        return False
    since = max(marks)
    after = [row for row in chain["rows"] if row["fired_at"] > since and row["id"] not in announced["ids"]]
    return bool(after) and _adds_steps(after, announced["steps"], hubs)


def _nothing_new(chain: dict[str, Any], recent: list[dict[str, Any]], hubs: tuple[str, ...] = ()) -> bool:
    """이미 알린 흐름(재알림 간격 안)과 같은 흐름이면, 그 흐름에 없던 알림들이 단계를 늘리지 않을 때(_adds_steps) 다른 개체로 다시 알리지 않는다 —
    같은 흐름이 PC·계정·IP 로 세 번 오지 않게. 알림 번호만 보면 같은 PC 의 대입이 한 번 더 나도(봇이 IP 를 바꿈) 또 알렸고, 흐름 전체의 PC·단계
    집합이나 전술을 모두 늘어놓은 (PC, 전술) 짝으로 보면 여러 서버를 적은 알림 하나·여러 전술에 속한 기법(T1078) 하나가 둘째 서버의 침해를
    묻었다(검토에서 재현)."""
    ids = {row["id"] for row in chain["rows"]}
    same = [r for r in recent if _same_flow(chain, ids, r)]
    if not same:
        return False
    seen = set().union(*(r["ids"] for r in same))
    fresh = [row for row in chain["rows"] if row["id"] not in seen]
    if not fresh:
        return True
    announced: dict[str, dict[str, set[str]]] = {}
    for r in same:
        for host, rules in r["steps"].items():
            for name, ts in rules.items():
                announced.setdefault(host, {}).setdefault(name, set()).update(ts)
    return not _adds_steps(fresh, announced, hubs)


def _message(rule: Rule, chain: dict[str, Any], key: str, now: datetime) -> AlertMessage:
    rows = chain["rows"]
    spread = _spread(chain)
    flow = [{k: v for k, v in s.items() if k != "at"} for s in steps(chain)]
    # 보이는 목록: 단계마다 센 알림을 먼저 두고 남은 자리는 최근 것으로(오래된 30개만 두면 앞쪽 무차별 대입 줄만 남고 새 서비스·로그 삭제가
    # 빠졌다, 검토). 다시 알리지 않을지 판단은 ids(전부)로
    keep = {s["alert_id"] for s in flow}
    for row in reversed(rows):
        if len(keep) >= ITEMS_MAX:
            break
        keep.add(row["id"])
    shown = [row for row in rows if row["id"] in keep]
    items = [{"id": row["id"], "rule": row["rule"], "severity": row["severity"], "fired_at": row["fired_at"].isoformat(),
              "group_key": row["group_key"], "tactics": [tactics.label(t) for t in row["tactics"]]}
             for row in shown]
    return AlertMessage(
        rule=rule.name, severity=rule.severity, kind="correlation", group_by=chain["kind"], group_key=key,
        event_count=len(rows), threshold=rule.min_tactics, window_sec=int(rule.window.total_seconds()), fired_at=now,
        description=rule.description, first_event_at=min(r["fired_at"] for r in rows),
        last_event_at=max(r["fired_at"] for r in rows), link=alerts_link(rule.name), tags=list(rule.tags),
        correlation={"entity": {"kind": chain["kind"], "value": chain["value"]}, "tactics": flow, "alerts": items,
                     "count": len(rows), "ids": [row["id"] for row in rows],
                     "hosts": sorted(spread["hosts"]), "tactic_ids": sorted(spread["tactics"], key=tactics.ORDER.__getitem__),
                     # 다시 알리지 않을지 판단용 — PC 마다 규칙과 그 전술 (_nothing_new). 넘치면 자른다(그러면 새것으로 보아 알릴 뿐)
                     "host_steps": [[h, name, sorted(ts, key=tactics.ORDER.__getitem__)]
                                    for h, rules in sorted(_host_steps(rows).items()) for name, ts in sorted(rules.items())][:STEPS_MAX]})
