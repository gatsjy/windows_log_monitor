"""조회 API: 이벤트 검색, 통계(건수/시계열/상위값), 수집 PC, 필드 카탈로그, 실시간 스트림."""

from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from .. import __version__, db, live, repository
from ..auth import service as auth_service
from ..auth.deps import client_ip, require_user
from ..auth.service import User
from ..config import settings
from ..filters import EventFilter, FilterError, parse_duration, parse_time
from ..normalizers import BY_SOURCE
from ..normalizers.base import LEVEL_NAMES
from ..normalizers.categories import CATEGORIES

router = APIRouter(tags=["query"])

# 시계열 자동 간격 후보 (초)
_NICE_STEPS = (10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 604800)
_MAX_BUCKETS = 2000
_MAX_SERIES = 7  # 이보다 많으면 나머지는 '__other__' 로 합친다 (색 구분 한계)


def _filter(request: Request, default_since: str | None = "24h") -> EventFilter:
    try:
        return EventFilter.from_params(request.query_params, default_since=default_since)
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc


def _check_field(field: str) -> str:
    if field in repository.COLUMN_EXPR or (field.startswith("f.") and len(field) > 2):
        return field
    raise HTTPException(400, f"알 수 없는 field: {field} (컬럼명 또는 f.<원본 경로>)")


def agent_status(silent_sec: int) -> str:
    if silent_sec <= settings.heartbeat_online_sec:
        return "online"
    if silent_sec <= settings.heartbeat_stale_sec:
        return "stale"
    return "offline"


# ------------------------------------------------------------------ events

@router.get("/api/events")
async def list_events(request: Request, limit: int = Query(100, ge=1, le=1000), cursor: str | None = None,
                      user: User = Depends(require_user)):
    f = _filter(request)
    position = None
    if cursor:
        try:
            ts_text, id_text = cursor.rsplit("|", 1)
            position = (datetime.fromisoformat(ts_text), int(id_text))
        except ValueError as exc:
            raise HTTPException(400, "cursor 형식 오류") from exc
    rows = await repository.list_events(f, limit + 1, position)
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = f"{rows[-1]['ts'].isoformat()}|{rows[-1]['id']}" if has_more else None
    if cursor is None:
        # 접속기록: 누가 어떤 조건으로 로그를 검색했는지 (다음 페이지 요청은 같은 검색이라 생략)
        conditions = {k: v for k, v in request.query_params.items() if k not in ("limit", "cursor")}
        await db.audit(user.username, "events.search", None, {"query": conditions, "rows": len(rows)},
                       actor_ip=client_ip(request))
    return {"items": rows, "next_cursor": next_cursor}


@router.get("/api/events/{event_id}")
async def get_event(event_id: int, request: Request, user: User = Depends(require_user)):
    row = await repository.get_event(event_id)
    if row is None:
        raise HTTPException(404, "이벤트를 찾을 수 없습니다")
    await db.audit(user.username, "events.view", str(event_id), {"host": row["host"], "event_id": row["event_id"]},
                   actor_ip=client_ip(request))
    return row


# ------------------------------------------------------------------- stats

@router.get("/api/stats/count")
async def stats_count(request: Request, compare: bool = False):
    return await repository.count(_filter(request), compare=compare)


def _auto_step(span: timedelta, buckets: int) -> timedelta:
    target = span.total_seconds() / buckets * 0.99  # since/until 계산 시차(수 ms)로 한 단계 커지는 것 방지
    return timedelta(seconds=next((s for s in _NICE_STEPS if s >= target), _NICE_STEPS[-1]))


@router.get("/api/stats/timeseries")
async def stats_timeseries(
    request: Request,
    group: str = "level",
    interval: str | None = None,
    buckets: int = Query(60, ge=4, le=400),
    tz_offset: int = Query(0, ge=-840, le=840, description="브라우저 시간대(분, UTC 기준 동쪽 +). 일 단위 구간 정렬용"),
):
    if group != "none":
        _check_field(group)
    f = _filter(request)
    now = datetime.now(UTC)
    since = f.since or now - timedelta(hours=24)
    until = f.until or now
    step = parse_duration(interval) if interval else _auto_step(until - since, buckets)
    if step is None or step.total_seconds() < 1:
        raise HTTPException(400, "interval 형식 오류 (예: 30s, 5m, 1h)")
    if math.ceil((until - since) / step) > _MAX_BUCKETS:
        raise HTTPException(400, "구간 수가 너무 많습니다. interval 을 늘리세요")

    origin = datetime(2001, 1, 1, tzinfo=timezone(timedelta(minutes=tz_offset)))
    start = origin + ((since - origin) // step) * step
    axis: list[datetime] = []
    t = start
    while t < until:
        axis.append(t)
        t += step
    index = {bucket: i for i, bucket in enumerate(axis)}

    series: dict[str, list[int]] = {}
    for row in await repository.timeseries(replace(f, since=since), step, origin, group):
        i = index.get(row["bucket"])
        if i is None:
            continue
        key = "" if row["key"] is None else str(row["key"])
        series.setdefault(key, [0] * len(axis))[i] += row["n"]

    if group == "level":
        keys = sorted(series, key=lambda k: int(k) if k.isdigit() else 99)
    else:
        keys = sorted(series, key=lambda k: -sum(series[k]))
        if len(keys) > _MAX_SERIES:
            other = [sum(col) for col in zip(*(series[k] for k in keys[_MAX_SERIES - 1:]))]
            keys = keys[: _MAX_SERIES - 1]
            series["__other__"] = other
            keys.append("__other__")

    return {
        "interval_sec": int(step.total_seconds()),
        "buckets": [b.isoformat() for b in axis],
        "series": [{"key": k, "total": sum(series[k]), "values": series[k]} for k in keys],
    }


@router.get("/api/stats/top")
async def stats_top(request: Request, field: str = "host", limit: int = Query(10, ge=1, le=100)):
    rows = await repository.top(_filter(request), _check_field(field), limit)
    return {"field": field, "items": rows}


@router.get("/api/stats/summary")
async def stats_summary():
    """상단 상태 표시줄용: PC 상태 수 + 최근 수집 속도."""
    return {
        "agents": await repository.agent_counts(settings.heartbeat_online_sec, settings.heartbeat_stale_sec),
        "ingest_per_min": live.ingest_rate.per_minute(60),
        "ingest_per_min_5m": live.ingest_rate.per_minute(300),
        "live_subscribers": live.broadcaster.subscriber_count,
        "alerts_24h": await repository.count_alerts(datetime.now(UTC) - timedelta(hours=24)),
        "server_time": datetime.now(UTC),
    }


# ------------------------------------------------------------ agents/fields

@router.get("/api/agents")
async def list_agents(since: str = "24h"):
    now = datetime.now(UTC)
    try:
        start = parse_time(since, now)
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    rows = await repository.agents(start)
    for row in rows:
        row["status"] = agent_status(row["silent_sec"])
    return {
        "items": rows,
        "thresholds": {"online_sec": settings.heartbeat_online_sec, "stale_sec": settings.heartbeat_stale_sec},
    }


@router.get("/api/fields")
async def list_fields():
    return {"items": await repository.fields()}


@router.get("/api/meta")
async def meta():
    return {
        "version": __version__,
        "levels": LEVEL_NAMES,
        "sources": [*BY_SOURCE, "file"],
        "categories": CATEGORIES,
        "retention_days": settings.retention_days,
        "heartbeat_online_sec": settings.heartbeat_online_sec,
        "heartbeat_stale_sec": settings.heartbeat_stale_sec,
    }


# -------------------------------------------------------------------- live

@router.get("/api/live")
async def live_stream(request: Request):
    """Server-Sent Events. `event: events` 로 정규화된 이벤트 배열을 보낸다 (시간 필터는 무시)."""
    f = _filter(request, default_since=None)
    token = request.state.session_token
    queue = live.broadcaster.subscribe()

    async def stream():
        checked = time.monotonic()
        try:
            yield "retry: 3000\n\n"
            while not await request.is_disconnected():
                # 열려 있는 동안에도 30초마다 세션 확인 → 로그아웃·만료되면 스트림을 끊는다
                if time.monotonic() - checked > 30:
                    checked = time.monotonic()
                    if not await auth_service.session_alive(token):
                        yield "event: logout\ndata: {}\n\n"
                        break
                try:
                    items = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": ping\n\n"
                    continue
                matched = [e for e in items if f.matches(e)][-500:]
                if matched:
                    payload = json.dumps(matched, ensure_ascii=False, default=str)
                    yield f"event: events\ndata: {payload}\n\n"
        finally:
            live.broadcaster.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
