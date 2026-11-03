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
    return sorted(out, key=lambda c: (-len(c["picked"]), -len(c["rows"]), list(ENTITY_LABELS).index(c["kind"]), c["value"]))


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
    recent = [{"key": r["group_key"], "ids": set(r["ids"]), "hosts": set(r["hosts"]), "tactics": set(r["tactics"])}
              for r in await repository.recent_correlations(rule.name, now - rule.cooldown)]
    fired = []
    for chain in found:
        key = key_of(chain["kind"], chain["value"])
        if any(r["key"] == key for r in recent) or _nothing_new(chain, recent):
            continue
        message = _message(rule, chain, key, now)
        observed = {k: ([chain["value"]] if k == chain["kind"] else []) for k in COLUMNS}
        alert_id = await engine.fire_rule(rule, message, observed=observed,
                                          host=chain["value"] if chain["kind"] == "host" else None)
        if alert_id:
            fired.append(alert_id)
        recent.append({"key": key, "ids": {row["id"] for row in chain["rows"]}, **_spread(chain)})
    return fired


def _spread(chain: dict[str, Any]) -> dict[str, set[str]]:
    """흐름이 걸친 PC 와 단계(전술) — 이미 알린 흐름에 새것이 더해졌는지 볼 때."""
    return {"hosts": {h for row in chain["rows"] for h in row["entity_hosts"] or []},
            "tactics": {t for row in chain["rows"] for t in row["tactics"]}}


def _nothing_new(chain: dict[str, Any], recent: list[dict[str, Any]]) -> bool:
    """이미 알린 흐름(재알림 간격 안)과 알림을 나누는데 새 PC·새 단계가 없으면 다른 개체로 다시 알리지 않는다 — 같은 흐름이 PC·계정·IP 로
    세 번 오지 않게. 알림 번호로만 보면 이미 센 규칙이 같은 PC 에서 한 번 더 울려도(봇이 IP 를 바꿈) 계정으로 같은 흐름을 또 알렸다
    (검토에서 재현). 다른 PC 로 번지거나 새 단계가 더해지면 알린다."""
    ids = {row["id"] for row in chain["rows"]}
    overlap = [r for r in recent if r["ids"] & ids]
    if not overlap:
        return False
    if ids <= set().union(*(r["ids"] for r in overlap)):
        return True   # 묶은 알림이 모두 이미 알린 흐름에 있다
    spread = _spread(chain)
    return (spread["hosts"] <= set().union(*(r["hosts"] for r in overlap))
            and spread["tactics"] <= set().union(*(r["tactics"] for r in overlap)))


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
                     # 다시 알리지 않을지 판단용 (흐름이 걸친 PC·단계 — _nothing_new)
                     "hosts": sorted(spread["hosts"]), "tactic_ids": sorted(spread["tactics"], key=tactics.ORDER.__getitem__)})
