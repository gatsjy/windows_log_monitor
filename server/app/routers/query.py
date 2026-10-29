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
from pydantic import BaseModel, Field

from .. import __version__, db, live, repository
from ..alerts.visibility import count_by_status
from ..auth import service as auth_service
from ..auth.deps import client_ip, require_admin, require_user
from ..auth.service import User
from ..config import settings
from ..filters import (
    MAX_FIELD_FILTERS,
    EventFilter,
    FilterError,
    QueryError,
    field_filters,
    parse_duration,
    parse_time,
    query_text,
    scopes_allow,
)
from ..normalizers import BY_SOURCE
from ..normalizers.base import LEVEL_NAMES
from ..normalizers.categories import CATEGORIES
from ..querylang import format_query, parse_terms


async def read_time_limit() -> None:
    """이 요청의 DB 쿼리마다 시간 상한과 조회 자리 (WLM_SEARCH_TIMEOUT_SEC, ADR-035) — 넘으면 main 이 503 과 안내.
    async 여야 한다: 동기 의존성은 스레드에서 돌아 컨텍스트 변수가 엔드포인트로 넘어오지 않는다."""
    db.limit_statement_time(settings.search_timeout_sec)


async def search_time_limit(request: Request) -> None:
    """조회(GET)에만 상한. PC 삭제 같은 쓰기는 잠금을 기다려서라도 끝내야 해서 걸지 않는다."""
    if request.method == "GET":
        await read_time_limit()


# 이벤트를 읽는 화면 API 는 이 라우터에 모여 있다 → 라우터 전체에 (POST 로 읽는 규칙 미리보기는 read_time_limit 을 직접)
router = APIRouter(tags=["query"], dependencies=[Depends(search_time_limit)])

# 시계열 자동 간격 후보 (초)
_NICE_STEPS = (10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 604800)
_MAX_BUCKETS = 2000
_MAX_SERIES = 7  # 이보다 많으면 나머지는 '__other__' 로 합친다 (색 구분 한계)
_MAX_AGENT_DELETE = 500  # 일괄 삭제 한 번에 받는 PC 수 (실수로 전체를 보내는 요청을 막기 위한 상한)


class QueryRejected(Exception):
    """검색 문장 오류 → 400 {detail: 한 줄 문구, query_error: {param, code, start, end}} (main.py 처리기).
    detail 은 지금처럼 문자열이라 기존 화면·외부 클라이언트는 그대로 동작하고, 화면은 위치로 틀린 곳을 칠한다."""

    def __init__(self, error: QueryError):
        super().__init__(str(error))
        self.error = error

    def body(self) -> dict:
        return {"detail": str(self.error),
                "query_error": {"param": "query", "code": self.error.code, "start": self.error.start,
                                "end": self.error.end, "message": self.error.message}}


def _filter(request: Request, default_since: str | None = "24h") -> EventFilter:
    try:
        f = EventFilter.from_params(request.query_params, default_since=default_since)
    except QueryError as exc:
        raise QueryRejected(exc) from exc
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    # 사용자 그룹의 조회 범위 — 검색·통계·대시보드·실시간 모두 이 필터를 거친다
    user = getattr(request.state, "user", None)
    return replace(f, scopes=user.scopes) if user is not None and user.scopes is not None else f


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
    try:
        rows = await repository.list_events(f, limit + 1, position)
    except db.QueryTimeout as exc:
        # 끝나지 않은 검색도 접속기록에 남긴다 — 시도한 조건이 기록에서 빠지지 않게 (ISMS 2.9.4)
        if cursor is None:
            await _audit_search(request, user, {"timeout_sec": exc.seconds, "busy": exc.busy})
        raise
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = f"{rows[-1]['ts'].isoformat()}|{rows[-1]['id']}" if has_more else None
    if cursor is None:   # 다음 페이지 요청은 같은 검색이라 생략
        await _audit_search(request, user, {"rows": len(rows)}, required=True)
    return {"items": rows, "next_cursor": next_cursor}


async def _audit_search(request: Request, user: User, outcome: dict, required: bool = False) -> None:
    """접속기록: 누가 어떤 조건으로 로그를 검색했는지.
    같은 이름이 여러 번 오면 모두 (실행한 조건과 기록이 어긋나지 않게 — ISMS 2.9.4)."""
    grouped: dict[str, list[str]] = {}
    for k, v in request.query_params.multi_items():
        if k not in ("limit", "cursor"):
            grouped.setdefault(k, []).append(v)
    conditions = {k: v[0] if len(v) == 1 else v for k, v in grouped.items()}
    await db.audit(user.username, "events.search", None, {"query": conditions, **outcome},
                   actor_ip=client_ip(request), required=required)


@router.get("/api/events/{event_id}")
async def get_event(event_id: int, request: Request, user: User = Depends(require_user)):
    row = await repository.get_event(event_id)
    if row is None or not scopes_allow(user.scopes, row.get("category"), row.get("host")):
        raise HTTPException(404, "이벤트를 찾을 수 없습니다")
    # 누구의 기록을 봤는지(정보주체)까지 — 이벤트의 사용자·IP·분류 (ADR-042). 기록하지 못하면 보여 주지 않는다
    await db.audit(user.username, "events.view", str(event_id),
                   {"host": row["host"], "event_id": row["event_id"], "username": row.get("username"),
                    "src_ip": row.get("src_ip"), "category": row.get("category")},
                   actor_ip=client_ip(request), required=True)
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


# 상위 값 목록 중 사람·출발지가 보이는 것은 접속기록에 남긴다 (ADR-042). 원본 필드(f.)는 무엇이든 될 수 있어 함께 본다.
# 대시보드 위젯이 같은 조건으로 몇 분마다 다시 부르므로 같은 사용자·같은 조건은 10분에 한 번만 기록한다
PERSONAL_FIELDS = frozenset({"user", "ip", "username", "src_ip"})
STATS_AUDIT_EVERY = 600.0
_stats_audited: dict[tuple[str, str], float] = {}


async def _audit_stats(request: Request, field: str, rows: int) -> None:
    if field not in PERSONAL_FIELDS and not field.startswith("f."):
        return
    user = request.state.user
    conditions = {k: v for k, v in request.query_params.items() if k not in ("limit",)}
    key = (user.username, json.dumps(conditions, sort_keys=True, ensure_ascii=False))
    now = time.monotonic()
    if now - _stats_audited.get(key, -STATS_AUDIT_EVERY) < STATS_AUDIT_EVERY:
        return
    if len(_stats_audited) > 10000:
        _stats_audited.clear()
    await db.audit(user.username, "events.stats", field, {"query": conditions, "rows": rows},
                   actor_ip=client_ip(request), required=True)
    _stats_audited[key] = now   # 기록에 성공한 뒤에만 (실패하면 다음 조회에서 다시 시도)


@router.get("/api/stats/top")
async def stats_top(request: Request, field: str = "host", limit: int = Query(10, ge=1, le=100)):
    rows = await repository.top(_filter(request), _check_field(field), limit)
    await _audit_stats(request, field, len(rows))
    return {"field": field, "items": rows}


@router.get("/api/stats/summary")
async def stats_summary(request: Request):
    """상단 상태 표시줄용: PC 상태 수 + 최근 수집 속도 + 확인 안 된 알림 수(사이드바 숫자, 조회 범위 반영)."""
    user = request.state.user
    if user.scopes is None:
        alerts_open = await repository.count_open_alerts()
    else:
        alerts_open = count_by_status(user, await repository.alert_group_counts(status="open"))["open"]
    return {
        "agents": await repository.agent_counts(settings.heartbeat_online_sec, settings.heartbeat_stale_sec),
        "ingest_per_min": live.ingest_rate.per_minute(60),
        "ingest_per_min_5m": live.ingest_rate.per_minute(300),
        "live_subscribers": live.broadcaster.subscriber_count,
        "alerts_24h": await repository.count_alerts(datetime.now(UTC) - timedelta(hours=24)),
        "alerts_open": alerts_open,
        "server_time": datetime.now(UTC),
    }


# ------------------------------------------------------------ agents/fields

@router.get("/api/agents")
async def list_agents(request: Request, since: str = "24h"):
    now = datetime.now(UTC)
    try:
        start = parse_time(since, now)
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    rows = await repository.agents(start, request.state.user.scopes)
    for row in rows:
        row["status"] = agent_status(row["silent_sec"])
    # 늘 오던 채널이 끊긴 것 (B-37) — 이 사용자에게 보이는 PC 만
    silent = await repository.silent_streams(now, [r["host"] for r in rows]) if rows else []
    return {
        "items": rows,
        "silent_streams": [{**s, "quiet_limit_sec": int(s.pop("quiet_limit").total_seconds())} for s in silent],
        "thresholds": {"online_sec": settings.heartbeat_online_sec, "stale_sec": settings.heartbeat_stale_sec},
        # 화면이 '평문으로 보내는 PC' 를 경고할지 (TLS 를 켠 서버에서만 의미가 있다, ADR-036)
        "transport": {"tls": settings.tls, "ingest_plain": settings.ingest_plain or not settings.tls},
    }


class AgentDeleteBody(BaseModel):
    hosts: list[str] = Field(min_length=1, max_length=_MAX_AGENT_DELETE)


async def _delete_agents(hosts: list[str], request: Request, admin: User) -> dict:
    rows = await repository.delete_agents(hosts)
    ip = client_ip(request)
    # PC 마다 한 줄씩: 감사로그를 대상(target)으로 검색했을 때 일괄 삭제도 빠짐없이 나오게
    for row in rows:
        await db.audit(admin.username, "agent.delete", row["host"],
                       {k: v for k, v in row.items() if k != "host"}, actor_ip=ip)
    deleted = [r["host"] for r in rows]
    return {
        "ok": True,
        "deleted": deleted,
        "missing": sorted(set(hosts) - set(deleted)),
        # 아직 보내고 있는 PC 는 다음 하트비트(30초)에 다시 등록된다 — 화면에서 알려 주기 위함
        "still_online": [r["host"] for r in rows if agent_status(r["silent_sec"]) == "online"],
    }


# {host:path}: syslog 장비 이름에 '/' 가 들어와도 지울 수 있게
@router.delete("/api/agents/{host:path}")
async def delete_agent(host: str, request: Request, admin: User = Depends(require_admin)):
    """테스트로 생긴 PC·폐기한 PC 를 목록에서 뺀다 (이벤트는 남는다). 다시 보내면 다시 등록된다."""
    result = await _delete_agents([host], request, admin)
    if not result["deleted"]:
        raise HTTPException(404, "목록에 없는 PC 입니다")
    return result


@router.post("/api/agents/delete")
async def delete_agents(body: AgentDeleteBody, request: Request, admin: User = Depends(require_admin)):
    """여러 PC 를 한 번에 목록에서 뺀다. 이미 없는 PC 는 missing 으로 알려 주고 나머지는 진행한다."""
    hosts = sorted({h for h in body.hosts if h})
    if not hosts:
        raise HTTPException(422, "삭제할 PC 를 고르세요")
    return await _delete_agents(hosts, request, admin)


@router.get("/api/agents/problems")
async def ingest_problems(since: str = "7d", _: User = Depends(require_admin)):
    """수집 거절 장부와 격리한 레코드 목록 (B-40). 관리자만 — 격리 레코드는 조회 범위를 거치지 않은 원본 로그다."""
    try:
        start = parse_time(since, datetime.now(UTC))
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"rejections": await repository.list_ingest_rejections(start),
            "quarantine": await repository.list_quarantine(start, 50)}


@router.get("/api/agents/quarantine/{quarantine_id}")
async def quarantine_record(quarantine_id: int, request: Request, admin: User = Depends(require_admin)):
    """격리한 레코드 원본. 원본 로그 열람이라 접속기록을 남기고, 남기지 못하면 내주지 않는다 (ADR-042)."""
    row = await repository.get_quarantine(quarantine_id)
    if row is None:
        raise HTTPException(404, "격리한 레코드를 찾을 수 없습니다")
    # 누구의 기록을 봤는지(정보주체)까지 — events.view 와 같게 (ADR-042)
    await db.audit(admin.username, "events.quarantine.view", f"#{quarantine_id}",
                   {k: row[k] for k in ("host", "source", "username", "src_ip", "category")},
                   actor_ip=client_ip(request), required=True)
    return row


@router.get("/api/fields")
async def list_fields(request: Request):
    items = await repository.fields()
    if request.state.user.scopes is not None:
        # 조회 범위가 있는 사용자에게는 다른 범위의 실제 값이 섞인 예시를 보여 주지 않는다
        for item in items:
            item["sample"] = None
    return {"items": items}


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


# -------------------------------------------------------------------- 검색 문장

@router.get("/api/search/parse")
async def search_parse(request: Request):
    """검색 문장 해석만 (데이터 조회 없음 → 감사 안 함). 실시간 화면은 EventSource 가 400 본문을 못 읽어서
    연결이 끊기면 이것으로 오류 위치·문구를 받아 보여 준다. 옛 파라미터 오류도 같은 400 으로 알린다."""
    f = _filter(request, default_since=None)
    # _filter(from_params) 와 같은 문장·같은 한도로 — 이미 통과했으므로 여기서 다시 틀릴 수 없다
    text = query_text(request.query_params)
    try:
        terms = parse_terms(text, field_budget=MAX_FIELD_FILTERS - len(field_filters(request.query_params))) if text else []
    except QueryError as exc:
        raise QueryRejected(exc) from exc
    return {"ok": True, "terms": [t.to_json() for t in terms], "canonical": format_query(terms), "never": f.never}


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
