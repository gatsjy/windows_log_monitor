"""규칙별 데이터 유무 (BACKLOG B-37 2단계, ADR-046 보완): 규칙이 보는 로그를 실제로 보내는 PC 가 얼마나 되나.

규칙 팩은 감사 정책(4625 로그온 실패, 4720 계정 생성, 4688 프로세스 등)이 켜져 있다고 가정한다. GPO 부분 적용·예외 PC 가 흔해
'규칙은 켜져 있는데 그 PC 에서는 데이터가 오지 않는' 것이 가장 흔하고 조용한 실패다 — 알림이 없으면 아무 일도 없는 것처럼 보인다.

- 규칙의 조건(소스·채널·이벤트 ID)에서 '필요한 데이터'를 꺼낸다. 수준·분류·메시지만 보는 규칙은 판단하지 않는다(모든 로그가 후보).
- 대상 PC = 최근 7일 살아 있고 그 소스(Windows 이벤트 등)를 보낸 PC, 규칙의 PC 조건에 맞는 것.
- 채널: 그중 그 채널을 7일 안에 보낸 PC — 규칙이 채널을 정하지 않았으면 그 이벤트 ID 가 실제로 오는 채널(4625 → Security).
  빠진 PC 는 수집 설정·감사 정책 문제일 가능성이 크다(같은 소스는 보내므로) — 보고서 '점검 필요'.
- 이벤트: 그중 그 이벤트 ID 를 30일 안에 보낸 PC. 드물게 나는 이벤트(계정 생성 등)는 적어도 정상이라 경고하지 않고 숫자만 보인다.
판단 재료는 수집 때 쌓는 agent_streams(날짜별 채널)·agent_events(이벤트 ID) — 이벤트 표를 다시 읽지 않는다. 10분 동안 재사용한다.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import repository
from .rules import Rule

STREAM_LOOKBACK = timedelta(days=7)
EVENT_LOOKBACK = timedelta(days=30)
CACHE = timedelta(minutes=10)
MISSING_SHOWN = 20


@dataclass(frozen=True)
class Need:
    # 규칙과 같은 뜻으로 — 규칙은 PC·채널을 정확히(대소문자까지) 맞추고 * 를 와일드카드로 쓰지 않는다(repository.where_clause).
    # 다르게 맞추면 'channel: security' 처럼 영영 맞지 않는 규칙을 '데이터 있음'으로 보였다(검토에서 재현)
    sources: frozenset[str]
    channels: frozenset[str]
    event_ids: frozenset[int]
    categories: frozenset[str] = frozenset()
    hosts: frozenset[str] = frozenset()
    excluded_hosts: frozenset[str] = field(default_factory=frozenset)


def need(rule: Rule) -> Need | None:
    """규칙이 필요로 하는 데이터. 건수 규칙이 아니거나 소스·채널·이벤트 ID 를 정하지 않았으면 None (판단하지 않음)."""
    if rule.kind != "count":
        return None
    f = rule.event_filter()
    if f.never or not (f.sources or f.channels or f.event_ids):
        return None
    return Need(sources=frozenset(f.sources), channels=frozenset(f.channels), event_ids=frozenset(f.event_ids),
                categories=frozenset(f.categories), hosts=frozenset(f.hosts),
                excluded_hosts=frozenset(str(h) for h in f.excludes.get("host", [])))


def _host_ok(n: Need, host: str) -> bool:
    return (not n.hosts or host in n.hosts) and host not in n.excluded_hosts


def _sources(n: Need, streams: list[dict[str, Any]], events: list[dict[str, Any]]) -> set[str]:
    """대상 PC 를 고를 소스. 규칙이 정하지 않았으면 그 채널·이벤트 ID 가 실제로 오는 소스 — 4625 는 Windows 이벤트,
    SQL Server 18456 은 ERRORLOG·응용 프로그램 로그. 아무 데서도 본 적이 없으면 이벤트 ID 는 Windows 로 본다(분류만 정한 규칙은 판단 안 함)."""
    if n.sources:
        return set(n.sources)
    seen = {s["source"] for s in streams if s["channel"] in n.channels}
    seen |= {e["source"] for e in events if e["event_id"] in n.event_ids and (not n.channels or e["channel"] in n.channels)}
    if seen:
        return seen
    return {"winevtlog"} if n.event_ids and not n.categories else set()


def evaluate(n: Need, alive: set[str], streams: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    """streams = 최근 7일 (host, source, channel), events = 최근 30일 (host, source, channel, event_id) — 규칙이 쓰는 ID 만."""
    sources = _sources(n, streams, events)
    base = {s["host"] for s in streams if s["source"] in sources and s["host"] in alive and _host_ok(n, s["host"])}
    # 채널: 규칙이 정한 것, 없으면 그 이벤트 ID 가 실제로 오는 채널 (4625 → Security). 기본 팩의 보안 규칙은 이벤트 ID 만 정해서
    # 이것이 없으면 Security 를 보내지 않는 PC 를 영영 짚지 못했다(검토에서 재현)
    channels = set(n.channels) or {e["channel"] for e in events if e["event_id"] in n.event_ids and e["source"] in sources
                                   and e["channel"]}
    out: dict[str, Any] = {"pcs": len(base), "channels": sorted(channels), "channels_implied": not n.channels and bool(channels),
                           "event_ids": sorted(n.event_ids), "channel_pcs": None, "event_pcs": None, "missing": [],
                           "missing_total": 0, "missing_all": []}
    if channels:
        sending = {s["host"] for s in streams if s["host"] in base and s["source"] in sources and s["channel"] in channels}
        missing = sorted(base - sending)
        out.update(channel_pcs=len(sending), missing=missing[:MISSING_SHOWN], missing_total=len(missing), missing_all=missing)
    if n.event_ids:
        out["event_pcs"] = len({e["host"] for e in events if e["host"] in base and e["event_id"] in n.event_ids
                                and e["source"] in sources and (not channels or e["channel"] in channels)})
    return out


_cache: tuple[datetime, tuple[Rule, ...], dict[str, dict[str, Any]]] | None = None


async def current(rules: tuple[Rule, ...], now: datetime | None = None, *, fresh: bool = False) -> dict[str, dict[str, Any]]:
    """규칙 이름 → 데이터 유무 (판단할 수 없는 규칙은 빠진다). 설정이 바뀌면(규칙 목록이 다른 객체) 다시 센다 — 객체를 쥐고
    'is' 로 비교한다(id 만 두면 지워진 설정의 주소를 새 설정이 받아 옛 결과를 돌려줄 수 있다)."""
    global _cache
    now = now or datetime.now(UTC)
    if not fresh and _cache and _cache[1] is rules and timedelta(0) <= now - _cache[0] < CACHE:
        return _cache[2]
    needs = {r.name: n for r in rules if (n := need(r)) is not None}
    result: dict[str, dict[str, Any]] = {}
    if needs:
        alive = await repository.alive_hosts(now - STREAM_LOOKBACK)
        streams = await repository.stream_presence((now - STREAM_LOOKBACK).date())
        wanted = sorted({e for n in needs.values() for e in n.event_ids})
        events = await repository.event_presence(now - EVENT_LOOKBACK, wanted) if wanted else []
        result = {name: evaluate(n, alive, streams, events) for name, n in needs.items()}
    _cache = (now, rules, result)
    return result


def public(c: dict[str, Any] | None) -> dict[str, Any] | None:
    """화면에 보낼 모양 — 빠진 PC 전체 목록(missing_all)은 보고서 묶음에만 쓴다."""
    return None if c is None else {k: v for k, v in c.items() if k != "missing_all"}


def gaps(rules: tuple[Rule, ...], coverage: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """켜진 규칙이 보는 채널을 보내지 않는 PC — 채널마다 묶어 (점검 보고서·화면 공용). 수는 빠진 PC 의 합집합."""
    by_channel: dict[str, dict[str, Any]] = defaultdict(lambda: {"hosts": set(), "rules": set()})
    for rule in rules:
        c = coverage.get(rule.name)
        if not rule.enabled or not c or not c["missing_total"]:
            continue
        g = by_channel[", ".join(c["channels"])]
        g["hosts"].update(c["missing_all"])
        g["rules"].add(rule.name)
    return [{"channel": label, "total": len(g["hosts"]), "hosts": sorted(g["hosts"])[:5], "rules": sorted(g["rules"])}
            for label, g in sorted(by_channel.items(), key=lambda kv: -len(kv[1]["hosts"]))]


def forget() -> None:
    """시험용: 캐시를 비운다."""
    global _cache
    _cache = None
