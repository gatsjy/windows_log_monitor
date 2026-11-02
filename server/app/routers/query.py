"""조회 API: 이벤트 검색, 통계(건수/시계열/상위값), 수집 PC, 필드 카탈로그, 실시간 스트림."""

from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .. import __version__, accesslog, clock, db, live, repository, wincatalog
from ..alerts.message import LEVEL_LABELS
from ..alerts.visibility import count_by_status
from ..auth import service as auth_service
from ..auth.deps import client_ip, require_admin, require_user
from ..auth.service import User
from ..config import settings
from ..csvexport import csv_response, export_reason
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

EXPORT_MAX_ROWS = 10000   # 이벤트 CSV 한 번에 (넘으면 잘리고 X-WLM-Truncated — 기간을 나눠 받는다)
EVENT_CSV_HEAD = ["발생 시각(UTC)", "수집 시각(UTC)", "PC", "소스", "분류", "채널", "공급자", "이벤트 ID", "수준", "사용자", "IP",
                  "요약", "메시지(앞 400자)"]


def _summarize(rows: list[dict]) -> list[dict]:
    """목록 행에 Windows 한 줄 요약(B-68)을 붙이고 재료(edata)는 뺀다."""
    for r in rows:
        edata = r.pop("edata", None)
        r["summary"] = wincatalog.summarize(r["provider"], r["event_id"], {"EventData": edata}) if edata else None
    return rows


@router.get("/api/events")
async def list_events(request: Request, limit: int = Query(100, ge=1, le=EXPORT_MAX_ROWS), cursor: str | None = None,
                      format: str = Query("json", pattern="^(json|csv)$"), reason: str | None = Query(None, max_length=200),
                      user: User = Depends(require_user)):
    f = _filter(request)
    if format == "csv":
        return await _events_csv(request, user, f, export_reason(reason))
    if limit > 1000:
        raise HTTPException(400, "limit 은 1000 이하 (CSV 는 10000)")
    position = _cursor(cursor) if cursor else None
    try:
        rows = _summarize(await repository.list_events(f, limit + 1, position))
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


async def _events_csv(request: Request, user: User, f, reason: str):
    """이벤트 CSV (B-62): 개인정보가 든 파일이라 사유를 받아 접속기록(events.export)에 함께 — 기록 못 하면 내주지 않는다(ADR-042).
    로그에서 온 값이 엑셀 수식으로 실행되지 않게 csv_response 로."""
    rows = _summarize(await repository.list_events(f, EXPORT_MAX_ROWS + 1))
    truncated = len(rows) > EXPORT_MAX_ROWS
    rows = rows[:EXPORT_MAX_ROWS]
    await db.audit(user.username, "events.export", "events",
                   {"query": accesslog.conditions(request, drop=("limit", "format", "reason")), "rows": len(rows),
                    "truncated": truncated, "reason": reason}, actor_ip=client_ip(request), required=True)
    return csv_response(EVENT_CSV_HEAD,
                        ([r["ts"].isoformat(), r["received_at"].isoformat(), r["host"], r["source"], r["category"] or "",
                          r["channel"] or "", r["provider"] or "", r["event_id"] if r["event_id"] is not None else "",
                          LEVEL_LABELS.get(r["level"], r["level"]), r["username"] or "", r["src_ip"] or "", r["summary"] or "",
                          r["message"] or ""]
                         for r in rows),
                        f"events_{datetime.now(UTC):%Y%m%d_%H%M%S}.csv",
                        headers={"X-WLM-Truncated": "1"} if truncated else None)


def _cursor(text: str) -> tuple[datetime, int]:
    """'발생 시각(ISO)|번호' — 목록 다음 쪽·앞뒤 로그의 이어 보기."""
    try:
        ts_text, id_text = text.rsplit("|", 1)
        return datetime.fromisoformat(ts_text), int(id_text)
    except ValueError as exc:
        raise HTTPException(400, "cursor 형식 오류") from exc


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
    if row["source"] == "winevtlog":   # 한 줄 요약·코드 풀이 (B-68)
        row["summary"] = wincatalog.summarize(row["provider"], row["event_id"], row["raw"])
        row["decoded"] = wincatalog.decode(row["provider"], row["event_id"], row["raw"])
    return row


LOCKOUT_EVENT, LOCKOUT_CAUSES = 4740, [4625, 4771, 4776]   # 계정 잠김 ← 로그온 실패·Kerberos 사전 인증 실패·NTLM 확인 실패
LOCKOUT_BEFORE, LOCKOUT_AFTER = timedelta(minutes=30), timedelta(minutes=5)


@router.get("/api/events/{event_id}/lockout")
async def lockout_cause(event_id: int, request: Request, user: User = Depends(require_user)):
    """계정 잠김(4740)의 원인 추적 (B-68): 같은 사용자의 로그온 실패(4625·4771·4776)를 잠김 30분 전~5분 뒤에서 접속지·PC·이벤트마다 묶는다.
    헬프데스크 최다 문의 — 손으로 4740 → 4771 → 4625 를 따라가던 것. 조회 범위가 붙고 접속기록(events.lockout)."""
    base = await repository.get_event(event_id)
    if base is None or not scopes_allow(user.scopes, base.get("category"), base.get("host")):
        raise HTTPException(404, "이벤트를 찾을 수 없습니다")
    if base["event_id"] != LOCKOUT_EVENT or base["source"] != "winevtlog" or not base.get("username"):
        raise HTTPException(400, "계정 잠김(4740) 이벤트에서만 원인을 찾습니다")
    f = EventFilter(since=base["ts"] - LOCKOUT_BEFORE, until=base["ts"] + LOCKOUT_AFTER, users=[base["username"]],
                    event_ids=LOCKOUT_CAUSES, scopes=user.scopes)
    rows = await repository.group_stats(f, ["ip", "host", "event_id"], [], 51)
    await accesslog.record(request, user.username, "events.lockout", str(event_id),
                           {"username": base["username"], "rows": len(rows)}, key={})
    return {"username": base["username"], "locked_at": base["ts"], "since": f.since, "until": f.until,
            "items": [{"ip": r["k0"], "host": r["k1"], "event_id": int(r["k2"]) if r["k2"] else None, "n": r["n"],
                       "first_ts": r["first_ts"], "last_ts": r["last_ts"]} for r in rows[:50]],
            "truncated": len(rows) > 50}


@router.get("/api/events/{event_id}/context")
async def event_context(event_id: int, request: Request, direction: Literal["before", "after"] = "after",
                        same: Literal["host", "source"] = "host", limit: int = Query(20, ge=1, le=200),
                        cursor: str | None = None, user: User = Depends(require_user)):
    """앞뒤 로그 (B-61): 이 로그와 같은 PC(same=source 면 같은 소스까지)에서 바로 앞·뒤 limit 건. cursor 로 더 앞·더 뒤.
    조회 범위가 붙고(밖의 행은 빠진다), 사용자·IP 가 보이므로 접속기록에 — 같은 로그의 앞뒤를 넘겨 보는 것은 10분에 한 번."""
    base = await repository.get_event(event_id)
    if base is None or not scopes_allow(user.scopes, base.get("category"), base.get("host")):
        raise HTTPException(404, "이벤트를 찾을 수 없습니다")
    position = _cursor(cursor) if cursor else (base["ts"], base["id"])
    rows = _summarize(await repository.event_context(base["host"], base["source"] if same == "source" else None, user.scopes,
                                                     position, direction, limit + 1))
    has_more = len(rows) > limit
    rows = rows[:limit]
    await accesslog.record(request, user.username, "events.context", str(event_id),
                           {"host": base["host"], "same": same, "direction": direction, "rows": len(rows)}, key={"same": same})
    return {"items": rows, "direction": direction,
            "next_cursor": f"{rows[-1]['ts'].isoformat()}|{rows[-1]['id']}" if has_more else None}


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

    await _audit_stats(request, group, len(series))   # 사용자·IP 로 나눈 시계열은 상위 값과 같은 정보 (B-38)
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


# 상위 값·시계열 중 사람·출발지로 나눈 것은 접속기록에 남긴다 (ADR-042, B-38). 원본 필드(f.)는 무엇이든 될 수 있어 함께 본다.
# 대시보드 위젯이 같은 조건으로 몇 분마다 다시 부르므로 같은 사용자·같은 조건은 10분에 한 번만(accesslog)
PERSONAL_FIELDS = frozenset({"user", "ip", "username", "src_ip"})


async def _audit_stats(request: Request, field: str, rows: int) -> None:
    if field not in PERSONAL_FIELDS and not field.startswith("f."):
        return
    conditions = accesslog.conditions(request)
    await accesslog.record(request, request.state.user.username, "events.stats", field, {"query": conditions, "rows": rows},
                           key=conditions)


GROUP_MAX_BY, GROUP_MAX_DISTINCT, GROUP_MAX_ROWS = 3, 2, 1000
STATS_FIELD_LABELS = {"host": "PC", "user": "사용자", "ip": "IP", "event_id": "이벤트 ID", "category": "분류", "source": "소스",
                      "channel": "채널", "provider": "공급자", "level": "수준"}


def _fields(text: str, most: int, what: str) -> list[str]:
    names = [_check_field(n.strip()) for n in text.split(",") if n.strip()]
    if len(names) > most or len(set(names)) != len(names):
        raise HTTPException(400, f"{what}는 서로 다른 필드 {most}개까지")
    return names


@router.get("/api/stats/group")
async def stats_group(request: Request, by: str, distinct: str = "", limit: int = Query(200, ge=1, le=GROUP_MAX_ROWS),
                      format: str = Query("json", pattern="^(json|csv)$"), reason: str | None = Query(None, max_length=200),
                      user: User = Depends(require_user)):
    """검색 '통계' 탭 (B-62): by(최대 3) 조합마다 건수·처음/마지막 발생 시각·distinct(최대 2)의 서로 다른 값 수.
    '계정별 로그온한 PC 수와 처음/마지막', 'IP 별 실패 횟수와 시도한 계정 수' 같은 점검 질문을 표로. 건수 많은 순 limit 행(잘리면 truncated).
    사용자·IP·원본 필드가 들면 접속기록(events.stats, 10분 묶음), CSV 는 사유 필수·events.export."""
    keys, counts = _fields(by, GROUP_MAX_BY, "by"), _fields(distinct, GROUP_MAX_DISTINCT, "distinct")
    if not keys:
        raise HTTPException(400, "by 에 묶을 필드를 하나 이상 주세요 (예: user,host)")
    why = export_reason(reason) if format == "csv" else None   # 사유가 없으면 쿼리를 돌리기 전에 거절
    rows = await repository.group_stats(_filter(request), keys, counts, limit + 1)
    truncated = len(rows) > limit
    items = [{"keys": [r[f"k{i}"] for i in range(len(keys))], "n": r["n"], "first_ts": r["first_ts"], "last_ts": r["last_ts"],
              "distinct": [r[f"d{i}"] for i in range(len(counts))]} for r in rows[:limit]]
    conditions = accesslog.conditions(request, drop=("limit", "format", "reason"))
    label = lambda name: STATS_FIELD_LABELS.get(name, name)
    if format == "csv":
        await db.audit(user.username, "events.export", "stats.group",
                       {"query": conditions, "rows": len(items), "truncated": truncated, "reason": why},
                       actor_ip=client_ip(request), required=True)
        return csv_response([*map(label, keys), "건수", *(f"서로 다른 {label(c)} 수" for c in counts), "처음(UTC)", "마지막(UTC)"],
                            ([*("" if k is None else k for k in i["keys"]), i["n"], *i["distinct"], i["first_ts"].isoformat(),
                              i["last_ts"].isoformat()] for i in items),
                            f"event_stats_{datetime.now(UTC):%Y%m%d_%H%M%S}.csv",
                            headers={"X-WLM-Truncated": "1"} if truncated else None)
    if any(k in PERSONAL_FIELDS or k.startswith("f.") for k in keys + counts):
        await accesslog.record(request, user.username, "events.stats", ",".join(keys), {"query": conditions, "rows": len(items)},
                               key=conditions)
    return {"by": keys, "distinct": counts, "items": items, "truncated": truncated, "limit": limit}


SESSIONS_MAX = 500


@router.get("/api/stats/sessions")
async def stats_sessions(request: Request, limit: int = Query(200, ge=1, le=SESSIONS_MAX),
                         max_hours: int = Query(24, ge=1, le=24 * 30), user: User = Depends(require_user)):
    """로그온 세션 (B-63): 지금 조건의 Windows 로그온(4624)마다 같은 PC 의 로그오프(4634·4647)를 TargetLogonId 로 짝지어
    누가·언제·어느 PC 에·어떤 방식(LogonType)으로·얼마나. 검색 문장에 'event_id:4624 source:winevtlog' 를 더한 것과 같다
    (다른 이벤트 ID 조건이 있으면 결과가 없다). 끝이 없으면 '로그오프 기록 없음' — 아직 접속 중이거나, 기록이 빠졌거나,
    max_hours 를 넘었다. 사용자·IP 를 보이므로 접속기록(events.sessions, 10분 묶음)."""
    f = _filter(request).merged(parse_terms(f"event_id:{repository.SESSION_LOGON} source:winevtlog"))
    rows = await repository.logon_sessions(f, max_hours, limit + 1)
    truncated = len(rows) > limit
    items = [{**r, "duration_sec": int((r["end_ts"] - r["ts"]).total_seconds()) if r["end_ts"] else None} for r in rows[:limit]]
    conditions = accesslog.conditions(request, drop=("limit",))
    await accesslog.record(request, user.username, "events.sessions", None, {"query": conditions, "rows": len(items)},
                           key=conditions)
    return {"items": items, "truncated": truncated, "limit": limit, "max_hours": max_hours}


@router.get("/api/stats/top")
async def stats_top(request: Request, field: str = "host", limit: int = Query(10, ge=1, le=100)):
    rows = await repository.top(_filter(request), _check_field(field), limit)
    await _audit_stats(request, field, len(rows))
    return {"field": field, "items": rows}


@router.get("/api/stats/summary")
async def stats_summary(request: Request):
    """상단 상태 표시줄용: PC 상태 수 + 최근 수집 속도 + 확인 안 된 알림 수(사이드바 숫자).
    조회 범위가 있으면 PC·알림 수는 범위 안만(수집 PC 화면·알림 목록과 같은 기준), 수집 속도·실시간 구독 수는 프로세스 전체 합이라
    나눌 수 없어 보내지 않는다 — 병원 전체 규모를 짐작하지 않게 (B-27, ADR-025)."""
    user = request.state.user
    day_ago = datetime.now(UTC) - timedelta(hours=24)
    if user.scopes is None:
        return {
            "agents": await repository.agent_counts(settings.heartbeat_online_sec, settings.heartbeat_stale_sec),
            "ingest_per_min": live.ingest_rate.per_minute(60),
            "ingest_per_min_5m": live.ingest_rate.per_minute(300),
            "live_subscribers": live.broadcaster.subscriber_count,
            "alerts_24h": await repository.count_alerts(day_ago),
            "alerts_open": await repository.count_open_alerts(),
            "server_time": datetime.now(UTC), "scoped": False,
        }
    agents = await repository.agents(datetime.now(UTC) - timedelta(days=7), user.scopes)
    states = [agent_status(a["silent_sec"]) for a in agents]
    counts = {s: states.count(s) for s in ("online", "stale", "offline")}
    return {
        "agents": {"total": len(agents), **counts},
        "ingest_per_min": None, "ingest_per_min_5m": None, "live_subscribers": None,
        "alerts_24h": sum(count_by_status(user, await repository.alert_group_counts(since=day_ago)).values()),
        "alerts_open": count_by_status(user, await repository.alert_group_counts(status="open"))["open"],
        "server_time": datetime.now(UTC), "scoped": True,
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
        row["clock_level"] = clock.level(row["clock_offset_ms"])   # 시계 차이 (B-57)
    # 늘 오던 채널이 끊긴 것 (B-37) — 이 사용자에게 보이는 PC 만
    silent = await repository.silent_streams(now, [r["host"] for r in rows]) if rows else []
    return {
        "items": rows,
        "silent_streams": [{**s, "quiet_limit_sec": int(s.pop("quiet_limit").total_seconds())} for s in silent],
        # 서버 시계 의심은 모든 PC 를 봐야 하므로 조회 범위가 없는 사용자에게만 (범위 안 PC 몇 대로는 판단하지 않음)
        "clock": clock.assess(rows) if request.state.user.scopes is None else {**clock.assess(rows), "server_suspect": None},
        "thresholds": {"online_sec": settings.heartbeat_online_sec, "stale_sec": settings.heartbeat_stale_sec},
        # 화면이 '평문으로 보내는 PC' 를 경고할지 (TLS 를 켠 서버에서만 의미가 있다, ADR-036)
        "transport": {"tls": settings.tls, "ingest_plain": settings.ingest_plain or not settings.tls},
    }


# 수집 대상 대조 (B-55). '/api/agents/{host:path}' 삭제보다 먼저 등록해야 DELETE /api/agents/assets 가 PC 삭제로 가지 않는다
class AssetsBody(BaseModel):
    text: str = Field(max_length=2_000_000)


@router.get("/api/agents/assets")
async def assets_coverage(_: User = Depends(require_admin)):
    from .. import assets

    return await assets.coverage()


@router.put("/api/agents/assets")
async def save_assets(body: AssetsBody, request: Request, admin: User = Depends(require_admin)):
    from .. import assets

    items, problems = assets.parse(body.text)
    if not items:
        raise HTTPException(400, "; ".join(problems))
    await repository.replace_assets(items)
    await db.audit(admin.username, "agent.assets.save", "assets",
                   {"count": len(items), "critical": sum(1 for i in items if i["grade"] == "critical"), "problems": problems[:5]},
                   actor_ip=client_ip(request))
    return {**await assets.coverage(), "problems": problems}


@router.delete("/api/agents/assets")
async def clear_assets(request: Request, admin: User = Depends(require_admin)):
    await repository.replace_assets([])
    await db.audit(admin.username, "agent.assets.clear", "assets", {}, actor_ip=client_ip(request))
    return {"ok": True}


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
    # 사용자·IP 가 든 이벤트가 그대로 흐른다 — 여는 것을 접속기록에 (B-38). 끊겼다 다시 붙는 것은 10분 묶음
    await accesslog.record(request, request.state.user.username, "events.live", "live", {"query": accesslog.conditions(request)})
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
