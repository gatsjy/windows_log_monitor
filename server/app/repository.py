"""이벤트 저장소 (PostgreSQL). 이벤트 관련 SQL 은 전부 이 파일에만 둔다.

검색 백엔드를 바꾸거나 추가할 때(ClickHouse / OpenSearch 등, docs/DECISIONS.md ADR-004)
이 모듈의 함수 시그니처와 반환 형태를 유지한 채 구현만 교체하면 라우터/UI 는 그대로 동작한다.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg import sql

from . import db, partitions
from .filters import EventFilter
from .normalizers import Event, Heartbeat, IisContext
from .querylang import RAW_ALIAS

log = logging.getLogger(__name__)

# 집계(group/top)에 쓸 수 있는 컬럼. 그 외 이름은 원본 JSON(raw) 경로로 취급한다.
COLUMN_EXPR = {
    "host": "host",
    "channel": "channel",
    "provider": "provider",
    "source": "source",
    "event_id": "event_id::text",
    "level": "level::text",
    "category": "category",
    "user": "username",
    "ip": "src_ip",
}

_LIST_COLUMNS = sql.SQL(
    "id, received_at, ts, host, source, category, channel, provider, event_id, level, username, src_ip,"
    " left(message, 400) AS message"
)


# ------------------------------------------------------------------ filter

def _host_like(pattern: str) -> str:
    escaped = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%")


def scope_clause(scopes, host_column: str | tuple[str, ...] = "host",
                 category_column: str | None = "category") -> tuple[sql.Composable, list[Any]]:
    """사용자 그룹 조회 범위 → (범위1) OR (범위2) … 각 범위 = 분류 AND PC 패턴."""
    ors: list[sql.Composable] = []
    params: list[Any] = []
    for scope in scopes:
        parts: list[sql.Composable] = []
        if scope.categories:
            if category_column is None:
                continue  # 분류 정보가 없는 표(agents)는 PC 조건만으로 판단할 수 없다 → 이 범위는 건너뜀
            parts.append(sql.SQL("{} = ANY(%s::text[])").format(sql.Identifier(category_column)))
            params.append(list(scope.categories))
        if scope.hosts:
            host_id = sql.Identifier(*host_column) if isinstance(host_column, tuple) else sql.Identifier(host_column)
            likes = [sql.SQL("{} ILIKE %s").format(host_id) for _ in scope.hosts]
            params.extend(_host_like(h) for h in scope.hosts)
            parts.append(sql.SQL("({})").format(sql.SQL(" OR ").join(likes)))
        ors.append(sql.SQL("({})").format(sql.SQL(" AND ").join(parts)) if parts else sql.SQL("TRUE"))
    if not ors:
        return sql.SQL("FALSE"), []
    return sql.SQL("({})").format(sql.SQL(" OR ").join(ors)), params


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# 검색 문장의 제외(B-01): 키 → (컬럼, 배열 형). 순서 고정 = SQL 이 늘 같은 모양
_EXCLUDE_COLUMNS = (("host", "host", "text"), ("channel", "channel", "text"), ("provider", "provider", "text"),
                    ("source", "source", "text"), ("category", "category", "text"), ("user", "username", "text"),
                    ("ip", "src_ip", "text"), ("level", "level", "int"), ("event_id", "event_id", "int"))


def where_clause(f: EventFilter) -> tuple[sql.Composable, list[Any]]:
    if f.never:   # 포함 조건이 서로 겹치지 않음 (host:A host:B) — 범위와 상관없이 결과 없음
        return sql.SQL("FALSE"), []
    clauses: list[sql.Composable] = []
    params: list[Any] = []
    if f.since:
        clauses.append(sql.SQL("ts >= %s"))
        params.append(f.since)
    if f.until:
        clauses.append(sql.SQL("ts < %s"))
        params.append(f.until)
    if f.received_since:
        clauses.append(sql.SQL("received_at >= %s"))
        params.append(f.received_since)
    for column, values in (("host", f.hosts), ("channel", f.channels), ("provider", f.providers),
                           ("source", f.sources), ("category", f.categories), ("username", f.users),
                           ("src_ip", f.ips)):
        if values:
            clauses.append(sql.SQL("{} = ANY(%s::text[])").format(sql.Identifier(column)))
            params.append(values)
    if f.levels:
        clauses.append(sql.SQL("level = ANY(%s::int[])"))
        params.append(f.levels)
    if f.event_ids:
        clauses.append(sql.SQL("event_id = ANY(%s::int[])"))
        params.append(f.event_ids)
    # 옛 q 와 문장의 메시지 묶음은 같은 모양: q=a|b 와 query=msg:a,b 는 SQL 이 같다
    for group in ([f.q_terms] if f.q_terms else []) + f.msg_all:
        clauses.append(sql.SQL("({})").format(sql.SQL(" OR ").join(sql.SQL("message ILIKE %s") for _ in group)))
        params.extend(_like(term) for term in group)
    for path, value in f.fields:
        clause, clause_params = _raw_clause("{raw} = %s", path)
        clauses.append(clause)
        params.extend([*clause_params, value])
    for path, values in f.field_any:
        clause, clause_params = _raw_clause("{raw} = ANY(%s::text[])", path)
        clauses.append(clause)
        params.extend([*clause_params, values])
    # 제외: (포함식) IS NOT TRUE — 값이 없는(NULL·경로 없음) 이벤트는 남긴다. NOT IN / <> ALL 은 NULL 행을 버린다
    for key, column, kind in _EXCLUDE_COLUMNS:
        if f.excludes.get(key):
            clauses.append(sql.SQL("({} = ANY(%s::{}[])) IS NOT TRUE").format(sql.Identifier(column), sql.SQL(kind)))
            params.append(f.excludes[key])
    for key, values in f.excludes.items():
        if key.startswith("f."):
            clause, clause_params = _raw_clause("({raw} = ANY(%s::text[])) IS NOT TRUE", key[2:].split("."))
            clauses.append(clause)
            params.extend([*clause_params, values])
    for term in f.msg_not:
        clauses.append(sql.SQL("(message ILIKE %s) IS NOT TRUE"))
        params.append(_like(term))
    if f.scopes is not None:
        scope_sql, scope_params = scope_clause(f.scopes)
        clauses.append(scope_sql)
        params.extend(scope_params)
    if not clauses:
        return sql.SQL("TRUE"), []
    return sql.SQL(" AND ").join(clauses), params


def _raw_clause(template: str, path: list[str]) -> tuple[sql.Composable, list[Any]]:
    """원본 경로의 글자 값을 쓰는 SQL 조각 ({raw} 자리). EventData 처럼 별칭이 있는 경로는 에이전트가 보낸 값이 먼저,
    없으면 서버가 붙인 값(raw.winevtlog.EventData — ADR-038). querylang.raw_field·web/js rawField 와 같은 뜻.
    별칭이 없는 경로는 예전과 같은 SQL 한 덩어리 (test_where_snapshot)."""
    if path and path[0] in RAW_ALIAS:
        expr = "COALESCE(raw #>> %s::text[], raw #>> %s::text[])"
        return sql.SQL(template.replace("{raw}", expr)), [path, [*RAW_ALIAS[path[0]], *path[1:]]]
    return sql.SQL(template.replace("{raw}", "raw #>> %s::text[]")), [path]


def _field_expr(field: str) -> tuple[sql.Composable, list[Any]]:
    if field in COLUMN_EXPR:
        return sql.SQL(COLUMN_EXPR[field]), []
    path = [p for p in field.removeprefix("f.").split(".") if p]
    if not path:
        raise ValueError("field 가 비어 있습니다")
    return _raw_clause("{raw}", path)


# ------------------------------------------------------------------ write

def _json(value: Any) -> str:
    # PostgreSQL jsonb 는 \u0000 을 허용하지 않는다
    return json.dumps(value, ensure_ascii=False, default=str).replace("\\u0000", "")


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _flatten(obj: dict, out: dict[str, Any], prefix: str = "", depth: int = 0) -> None:
    for key, value in obj.items():
        if len(out) >= 300:
            return
        path = f"{prefix}{key}"[:200]
        if isinstance(value, dict) and value and depth < 3:
            _flatten(value, out, path + ".", depth + 1)
        else:
            out[path] = value


def _field_stats(events: list[Event]) -> list[tuple]:
    stats: dict[tuple[str, str], list] = {}
    for event in events:
        flat: dict[str, Any] = {}
        _flatten(event.raw, flat)
        for path, value in flat.items():
            # 원본 키·값의 NUL 은 TEXT 에 넣을 수 없다 — 경로·예시에서 지운다 (raw 자체는 _json 이 뺀다)
            entry = stats.setdefault((event.source, path.replace("\x00", "")), [None, 0, None])
            entry[0] = _json_type(value)
            entry[1] += 1
            entry[2] = (value if isinstance(value, str) else _json(value)).replace("\x00", "")[:200]
    return [(src, path, t, n, sample) for (src, path), (t, n, sample) in sorted(stats.items())]


async def _write(conn, events: list[Event], heartbeats: list[Heartbeat], client_ip: str | None,
                 transport: str | None = None, layouts: dict | None = None) -> None:
    async with conn.cursor() as cur:
        if events:
            async with cur.copy(
                "COPY events (ts, host, source, category, channel, provider, event_id, level, username, src_ip,"
                " message, raw) FROM STDIN"
            ) as copy:
                for e in events:
                    await copy.write_row((e.ts, e.host, e.source, e.category, e.channel, e.provider, e.event_id,
                                          e.level, e.username, e.src_ip, e.message, _json(e.raw)))

            per_host: Counter[str] = Counter(e.host for e in events)
            # syslog 수신기를 거친 경우 실제 장비 IP 는 raw.source_ip 에 있다
            host_ip = {e.host: str(e.raw.get("source_ip") or client_ip or "").replace("\x00", "")[:64] or None
                       for e in events}
            await cur.executemany(
                "INSERT INTO agents AS a (host, last_seen, last_event_at, last_ip, events_total)"
                " VALUES (%s, now(), now(), %s, %s)"
                " ON CONFLICT (host) DO UPDATE SET last_seen = now(), last_event_at = now(),"
                " last_ip = COALESCE(EXCLUDED.last_ip, a.last_ip),"
                " events_total = a.events_total + EXCLUDED.events_total",
                [(host, host_ip[host], n) for host, n in sorted(per_host.items())],
            )
            await cur.executemany(
                "INSERT INTO field_stats AS f (source, path, json_type, seen, sample) VALUES (%s, %s, %s, %s, %s)"
                " ON CONFLICT (source, path) DO UPDATE SET seen = f.seen + EXCLUDED.seen, last_seen = now(),"
                " json_type = EXCLUDED.json_type, sample = EXCLUDED.sample",
                _field_stats(events),
            )

        if heartbeats:
            latest = {hb.host: hb for hb in heartbeats}
            # 전송 방식은 하트비트에서만 — 에이전트가 직접 보낸 것이 확실하다 (이벤트는 수집기를 거쳐 올 수 있다)
            await cur.executemany(
                "INSERT INTO agents AS a (host, last_seen, last_heartbeat_at, last_ip, meta, last_transport)"
                " VALUES (%s, now(), now(), %s, %s::jsonb, %s)"
                " ON CONFLICT (host) DO UPDATE SET last_seen = now(), last_heartbeat_at = now(),"
                " last_ip = COALESCE(EXCLUDED.last_ip, a.last_ip), meta = EXCLUDED.meta,"
                " last_transport = COALESCE(EXCLUDED.last_transport, a.last_transport)",
                [(host, client_ip, _json(hb.meta), transport) for host, hb in sorted(latest.items())],
            )

        if layouts:
            # 이벤트와 같은 트랜잭션 — 이벤트가 거절되면 머리줄도 남지 않고, 에이전트가 청크째 다시 보낼 때 다시 배운다.
            # 잠금 순서는 agents → field_stats → iis_layouts, 같은 표 안에서는 정렬 순서 (동시 요청끼리 교착 방지)
            await cur.executemany(
                "INSERT INTO iis_layouts (host, file, dir, fields) VALUES (%s, %s, %s, %s)"
                " ON CONFLICT (host, file) DO UPDATE SET fields = EXCLUDED.fields, dir = EXCLUDED.dir, seen_at = now()",
                [(host, file, directory, " ".join(fields))
                 for (host, file), (directory, fields) in sorted(layouts.items())],
            )


async def insert_batch(events: list[Event], heartbeats: list[Heartbeat], client_ip: str | None,
                       transport: str | None = None, layouts: dict | None = None) -> None:
    """layouts = IisContext.learned — 이 요청에서 만난 IIS 머리줄 (머리줄만 든 요청도 저장해야 한다)."""
    if not events and not heartbeats and not layouts:
        return
    for attempt in (1, 2):
        try:
            async with db.pool().connection() as conn:
                await _write(conn, events, heartbeats, client_ip, transport, layouts)
            return
        except psycopg.errors.CheckViolation:
            # 이번 달 파티션이 아직 없을 때 (월이 바뀐 직후 등): 만들고 한 번 더 시도
            if attempt == 2:
                raise
            log.warning("파티션 없음 → 생성 후 재시도")
            await partitions.run_maintenance()


# IIS 열 순서 캐시 (ADR-037). 정본은 iis_layouts 표 — 이것은 요청마다 DB 에 묻지 않기 위한 것뿐이라
# 커밋한 뒤에만 넣는다(remember_iis_layouts). None = DB 에도 없음 (그것도 기억해야 매 요청 묻지 않는다).
# 워커 1개 전제(ADR-006) — 여러 워커가 되면 TTL 이 필요하다(B-20)
_IIS_FILE: dict[tuple[str, str], tuple[str, ...] | None] = {}
_IIS_SITE: dict[tuple[str, str], tuple[str, ...] | None] = {}
_IIS_CACHE_MAX = 20000


async def iis_context(keys: set[tuple[str, str, str]]) -> IisContext:
    """(host, file, dir) 들의 저장된 열 순서와 같은 폴더의 최신 열 순서. 캐시에 없는 것만 DB 에 한 번 묻는다."""
    ctx = IisContext()
    if not keys:
        return ctx
    if len(_IIS_FILE) > _IIS_CACHE_MAX or len(_IIS_SITE) > _IIS_CACHE_MAX:
        # 비우는 것은 고르기 전에 — 고른 뒤에 비우면 이미 캐시에 있던 이 요청의 열 순서까지 사라진다(검토에서 재현)
        _IIS_FILE.clear()
        _IIS_SITE.clear()
    missing = sorted(k for k in keys if (k[0], k[1]) not in _IIS_FILE or (k[0], k[2]) not in _IIS_SITE)
    if missing:
        rows = await db.fetch_all(
            "WITH k AS (SELECT * FROM unnest(%s::text[], %s::text[], %s::text[]) AS k(host, file, dir))"
            " SELECT 'file' AS kind, l.host, l.file AS name, l.fields FROM k JOIN iis_layouts l USING (host, file)"
            " UNION ALL"
            " SELECT 'site', d.host, d.dir, s.fields FROM (SELECT DISTINCT host, dir FROM k) d"
            " CROSS JOIN LATERAL (SELECT fields FROM iis_layouts l WHERE l.host = d.host AND l.dir = d.dir"
            "                     ORDER BY seen_at DESC LIMIT 1) s",
            ([k[0] for k in missing], [k[1] for k in missing], [k[2] for k in missing]),
        )
        found = {(r["kind"], r["host"], r["name"]): tuple(r["fields"].split()) for r in rows}
        for host, file, directory in missing:
            # setdefault: 조회하는 사이 다른 요청이 커밋해 넣은 새 값을 이 조회의 '없음'으로 덮지 않는다
            _IIS_FILE.setdefault((host, file), found.get(("file", host, file)))
            _IIS_SITE.setdefault((host, directory), found.get(("site", host, directory)))
    for host, file, directory in keys:
        if stored := _IIS_FILE.get((host, file)):
            ctx.stored[(host, file)] = stored
        if site := _IIS_SITE.get((host, directory)):
            ctx.site[(host, directory)] = site
    return ctx


def remember_iis_layouts(learned: dict[tuple[str, str], tuple[str, tuple[str, ...]]]) -> None:
    """insert_batch 가 커밋한 뒤에 부른다 — 실패한 요청의 머리줄이 캐시에만 남아 DB 와 어긋나지 않게."""
    for (host, file), (directory, fields) in learned.items():
        _IIS_FILE[(host, file)] = fields
        _IIS_SITE[(host, directory)] = fields


def forget_iis_layouts() -> None:
    """캐시 비우기 (시험에서 '서버 재시작'을 흉내 낼 때)."""
    _IIS_FILE.clear()
    _IIS_SITE.clear()


async def purge_iis_layouts(cutoff: datetime) -> int:
    """오래된 열 순서 삭제 — 단, 폴더마다 가장 최근 것은 남긴다(월 단위 파일·나누지 않는 파일은 머리줄이 처음 한 번뿐)."""
    async with db.pool().connection() as conn:
        cur = await conn.execute(
            "DELETE FROM iis_layouts l WHERE l.seen_at < %s AND EXISTS"
            " (SELECT 1 FROM iis_layouts n WHERE n.host = l.host AND n.dir = l.dir AND n.seen_at > l.seen_at)",
            (cutoff,),
        )
        return cur.rowcount


# ------------------------------------------------------------------ read

async def list_events(f: EventFilter, limit: int, cursor: tuple[datetime, int] | None = None) -> list[dict]:
    where, params = where_clause(f)
    if cursor:
        where = sql.SQL("{} AND (ts, id) < (%s, %s)").format(where)
        params = [*params, *cursor]
    query = sql.SQL("SELECT {} FROM events WHERE {} ORDER BY ts DESC, id DESC LIMIT %s").format(_LIST_COLUMNS, where)
    return await db.fetch_all(query, [*params, limit])


async def get_event(event_id: int) -> dict | None:
    return await db.fetch_one("SELECT * FROM events WHERE id = %s LIMIT 1", (event_id,))


async def count(f: EventFilter, compare: bool = False) -> dict[str, int | None]:
    """조건에 맞는 건수. compare=True 면 같은 길이의 직전 기간 건수도 함께."""
    if not (compare and f.since):
        where, params = where_clause(f)
        row = await db.fetch_one(sql.SQL("SELECT count(*) AS n FROM events WHERE {}").format(where), params)
        return {"current": row["n"], "previous": None}
    until = f.until or datetime.now(UTC)
    widened = replace(f, since=f.since - (until - f.since))
    where, params = where_clause(widened)
    row = await db.fetch_one(
        sql.SQL(
            "SELECT count(*) FILTER (WHERE ts >= %s) AS current, count(*) FILTER (WHERE ts < %s) AS previous"
            " FROM events WHERE {}"
        ).format(where),
        [f.since, f.since, *params],
    )
    return {"current": row["current"], "previous": row["previous"]}


async def timeseries(f: EventFilter, step: timedelta, origin: datetime, group: str) -> list[dict]:
    """[{bucket, key, n}] — 빈 구간 채우기는 호출하는 쪽에서."""
    key_expr = sql.SQL("''") if group == "none" else _field_expr(group)[0]
    key_params = [] if group == "none" else _field_expr(group)[1]
    where, params = where_clause(f)
    query = sql.SQL(
        "SELECT date_bin(%s, ts, %s) AS bucket, {} AS key, count(*) AS n FROM events WHERE {} GROUP BY 1, 2"
    ).format(key_expr, where)
    return await db.fetch_all(query, [step, origin, *key_params, *params])


# 값이 없는 로그(로컬 로그온, 시스템 이벤트 등)가 대부분인 필드. 상위 목록에서 '(없음)' 이 1위를 차지하지 않게 뺀다.
TOP_SKIP_EMPTY = ("user", "ip")


async def top(f: EventFilter, field: str, limit: int) -> list[dict]:
    expr, expr_params = _field_expr(field)
    where, params = where_clause(f)
    if field in TOP_SKIP_EMPTY:
        where = sql.SQL("{} AND {} IS NOT NULL").format(where, expr)
    query = sql.SQL(
        "SELECT {} AS value, count(*) AS n FROM events WHERE {} GROUP BY 1 ORDER BY n DESC LIMIT %s"
    ).format(expr, where)
    return await db.fetch_all(query, [*expr_params, *params, limit])


async def agents(since: datetime, scopes=None) -> list[dict]:
    """수집 PC 목록. scopes(사용자 그룹 범위)가 있으면 범위 안의 이벤트만 세고,
    범위 안 이벤트가 있었거나 PC 이름 패턴에 맞는 PC 만 보여 준다."""
    event_scope, params = sql.SQL("TRUE"), [since]
    visible = sql.SQL("")
    if scopes is not None:
        event_scope, scope_params = scope_clause(scopes)
        params += scope_params
        conds = [sql.SQL("c.host IS NOT NULL")]
        host_only = [s for s in scopes if s.hosts and not s.categories]
        if host_only:
            host_sql, host_params = scope_clause(host_only, host_column=("a", "host"), category_column=None)
            conds.append(host_sql)
            params += host_params
        visible = sql.SQL(" WHERE ") + sql.SQL(" OR ").join(conds)
    query = sql.SQL(
        "SELECT a.host, a.first_seen, a.last_seen, a.last_event_at, a.last_heartbeat_at, a.last_ip, a.last_transport,"
        "       a.events_total, a.meta, EXTRACT(EPOCH FROM now() - a.last_seen)::bigint AS silent_sec,"
        "       COALESCE(c.total, 0) AS events, COALESCE(c.critical, 0) AS critical,"
        "       COALESCE(c.errors, 0) AS errors, COALESCE(c.warnings, 0) AS warnings,"
        "       COALESCE(c.sources, ARRAY[]::text[]) AS sources"
        "  FROM agents a"
        "  LEFT JOIN ("
        "       SELECT host, count(*) AS total,"
        "              count(*) FILTER (WHERE level = 1) AS critical,"
        "              count(*) FILTER (WHERE level <= 2) AS errors,"
        "              count(*) FILTER (WHERE level = 3) AS warnings,"
        "              array_agg(DISTINCT source) AS sources"
        "         FROM events WHERE ts >= %s AND {} GROUP BY host"
        "  ) c ON c.host = a.host{}"
        " ORDER BY a.host"
    ).format(event_scope, visible)
    return await db.fetch_all(query, params)


async def delete_agents(hosts: list[str]) -> list[dict]:
    """수집 PC 목록에서만 뺀다. 이벤트는 지우지 않는다 — 로그 삭제는 보관 정책(로테이션)만 한다(ISMS 접속기록 보관).
    에이전트가 다시 보내면 목록에 다시 나타난다.
    지운 행의 요약을 돌려준다: 감사로그에 '무엇을 지웠는지' 남겨야 나중에 되짚을 수 있다(행 자체는 사라지므로)."""
    if not hosts:
        return []
    return await db.fetch_all(
        "DELETE FROM agents WHERE host = ANY(%s)"
        " RETURNING host, last_ip, first_seen::text AS first_seen, last_seen::text AS last_seen,"
        "           events_total, meta->>'config_version' AS config_version,"
        "           EXTRACT(EPOCH FROM now() - last_seen)::bigint AS silent_sec",
        (list(hosts),),
    )


async def agent_counts(online_sec: int, stale_sec: int) -> dict[str, int]:
    row = await db.fetch_one(
        "SELECT count(*) AS total,"
        "       count(*) FILTER (WHERE last_seen >= now() - make_interval(secs => %s)) AS online,"
        "       count(*) FILTER (WHERE last_seen <  now() - make_interval(secs => %s)"
        "                          AND last_seen >= now() - make_interval(secs => %s)) AS stale"
        "  FROM agents",
        (online_sec, online_sec, stale_sec),
    )
    return {"total": row["total"], "online": row["online"], "stale": row["stale"],
            "offline": row["total"] - row["online"] - row["stale"]}


async def fields() -> list[dict]:
    return await db.fetch_all(
        "SELECT source, path, json_type, seen, first_seen, last_seen, sample FROM field_stats ORDER BY source, path"
    )


# ------------------------------------------------------------------ alerts

DISTINCT_SAMPLE = 10   # 알림 본문에 보여 줄 서로 다른 값 수


def _distinct_parts(distinct_field: str | None, distinct_min: int):
    """(SELECT 에 더할 조각, 그 인자, HAVING 에 더할 조각, 그 인자). 서로 다른 값 수 규칙이 아니면 빈 조각.
    count(DISTINCT) 는 NULL 을 세지 않는다 — 값이 없는 이벤트(사용자 없는 로그온 실패 등)는 서로 다른 값으로 치지 않는다(ADR-041)."""
    if not distinct_field:
        return sql.SQL(""), [], sql.SQL(""), []
    expr, expr_params = _field_expr(distinct_field)
    select = sql.SQL(", count(DISTINCT {e}) AS dn, (array_agg(DISTINCT {e} ORDER BY {e}))[1:%s] AS dvals").format(e=expr)
    # {e} 가 세 번 — 인자도 세 번
    select_params = [*expr_params, *expr_params, *expr_params, DISTINCT_SAMPLE]
    having = sql.SQL(" AND count(DISTINCT {}) >= %s").format(expr)
    return select, select_params, having, [*expr_params, distinct_min]


async def alert_candidates(f: EventFilter, group_by: str, threshold: int,
                           distinct_field: str | None = None, distinct_min: int = 0) -> list[dict]:
    """규칙 조건에 맞는 이벤트를 group_by 로 묶어 threshold 이상인 묶음만. distinct_field 면 그 필드의 서로 다른 값도
    distinct_min 개 이상인 묶음만 (dn = 서로 다른 값 수, dvals = 앞의 값 10개)."""
    if group_by == "none":
        key_expr, key_params = sql.SQL("''"), []
    else:
        key_expr, key_params = _field_expr(group_by)
    where, params = where_clause(f)
    where, params = _skip_missing_key(where, params, key_expr, key_params, group_by)
    select, select_params, having, having_params = _distinct_parts(distinct_field, distinct_min)
    query = sql.SQL(
        "SELECT {} AS key, count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts{}"
        " FROM events WHERE {} GROUP BY 1 HAVING count(*) >= %s{} ORDER BY {} DESC LIMIT 100"
    ).format(key_expr, select, where, having, sql.SQL("dn" if distinct_field else "n"))
    return await db.fetch_all(query, [*key_params, *select_params, *params, threshold, *having_params])


def _skip_missing_key(where: sql.Composable, params: list, key_expr: sql.Composable, key_params: list,
                      group_by: str) -> tuple[sql.Composable, list]:
    """묶음 값이 없는(NULL) 이벤트는 알림 후보에서 뺀다 (group_by none 은 그대로).
    IP 없는 로그온 실패(대화형·잠금 해제)가 모든 PC 에서 '빈 출발지' 하나로 합쳐져, 출발지·표본 없는 '무차별 대입'이나
    병원 전체의 오타를 '서로 다른 계정 n개'로 세는 '패스워드 스프레이'가 되었다 (벤치마킹 검토, ADR-041)."""
    if group_by == "none":
        return where, params
    return sql.SQL("{} AND {} IS NOT NULL").format(where, key_expr), [*params, *key_params]


async def rule_preview(f: EventFilter, group_by: str, window_sec: int, threshold: int,
                       distinct_field: str | None = None, distinct_min: int = 0) -> list[dict]:
    """규칙 미리보기: 조건에 맞는 이벤트를 (묶음 값, window 길이 구간)으로 세어 threshold 이상인 구간만.
    엔진은 30초마다 '최근 window' 를 보지만, 미리보기는 겹치지 않는 구간으로 근사한다."""
    if group_by == "none":
        key_expr, key_params = sql.SQL("''"), []
    else:
        key_expr, key_params = _field_expr(group_by)
    where, params = where_clause(f)
    where, params = _skip_missing_key(where, params, key_expr, key_params, group_by)
    if distinct_field:
        expr, expr_params = _field_expr(distinct_field)
        extra, extra_params = sql.SQL(", count(DISTINCT {}) AS dn").format(expr), expr_params
        having, having_params = sql.SQL(" AND count(DISTINCT {}) >= %s").format(expr), [*expr_params, distinct_min]
    else:
        extra, extra_params, having, having_params = sql.SQL(""), [], sql.SQL(""), []
    query = sql.SQL(
        "SELECT {} AS key, floor(extract(epoch FROM received_at) / %s)::bigint AS bucket, count(*) AS n{}"
        " FROM events WHERE {} GROUP BY 1, 2 HAVING count(*) >= %s{} ORDER BY 2 LIMIT 5000"
    ).format(key_expr, extra, where, having)
    return await db.fetch_all(query, [*key_params, window_sec, *extra_params, *params, threshold, *having_params])


async def last_alert(rule: str, group_key: str) -> dict | None:
    """같은 규칙·대상의 마지막 알림: fired_at, silenced_until(무음으로 못 보냈으면 그 무음이 끝나는 시각)."""
    return await db.fetch_one(
        "SELECT a.fired_at, s.ends_at AS silenced_until FROM alerts a"
        " LEFT JOIN alert_silences s ON s.id = a.silence_id"
        " WHERE a.rule = %s AND a.group_key = %s ORDER BY a.fired_at DESC LIMIT 1",
        (rule, group_key),
    )


async def silent_agents(cutoff: datetime, hosts: tuple[str, ...]) -> list[dict]:
    if hosts:
        return await db.fetch_all(
            "SELECT host, last_seen FROM agents WHERE last_seen < %s AND host = ANY(%s::text[])", (cutoff, list(hosts))
        )
    return await db.fetch_all("SELECT host, last_seen FROM agents WHERE last_seen < %s", (cutoff,))


async def insert_alert(message: dict, notifiers: tuple[str, ...], silence: dict | None = None) -> int:
    """alerts 한 줄 + 알림 대상별 alert_deliveries 를 넣고 새 id 를 돌려준다.
    무음(silence) 중이면 전송 상태를 처음부터 skipped(사유: 무음)로 둔다 — 발생 기록은 남기고 보내지만 않는다."""
    status, reason = ("skipped", f"무음 #{silence['id']}: {silence['reason']}") if silence else ("pending", None)
    async with db.pool().connection() as conn:
        cur = await conn.execute(
            "INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, first_event_at, last_event_at,"
            " payload, silence_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s) RETURNING id",
            (message["fired_at"], message["rule"], message["severity"], message["group_key"],
             message["event_count"], message["first_event_at"], message["last_event_at"], _json(message),
             silence["id"] if silence else None),
        )
        alert_id = (await cur.fetchone())["id"]
        async with conn.cursor() as c:
            await c.executemany(
                "INSERT INTO alert_deliveries (alert_id, notifier, status, last_error) VALUES (%s, %s, %s, %s)",
                [(alert_id, name, status, reason) for name in notifiers],
            )
    return alert_id


async def mark_delivery(alert_id: int, notifier: str, status: str, error: str | None = None) -> None:
    await db.fetch_one(
        "UPDATE alert_deliveries SET status = %s, last_error = %s, attempts = attempts + 1, updated_at = now(),"
        " sent_at = CASE WHEN %s = 'sent' THEN now() ELSE sent_at END"
        " WHERE alert_id = %s AND notifier = %s RETURNING alert_id",
        (status, error, status, alert_id, notifier),
    )


async def skip_delivery(alert_id: int, notifier: str, reason: str) -> None:
    await db.fetch_one(
        "UPDATE alert_deliveries SET status = 'skipped', last_error = %s, updated_at = now()"
        " WHERE alert_id = %s AND notifier = %s RETURNING alert_id",
        (reason, alert_id, notifier),
    )


async def give_up_delivery(alert_id: int, notifier: str) -> None:
    await db.fetch_one(
        "UPDATE alert_deliveries SET status = 'gave_up', updated_at = now()"
        " WHERE alert_id = %s AND notifier = %s RETURNING alert_id",
        (alert_id, notifier),
    )


async def failed_deliveries() -> list[dict]:
    return await db.fetch_all(
        "SELECT d.alert_id, d.notifier, d.attempts, d.updated_at, a.payload"
        "  FROM alert_deliveries d JOIN alerts a ON a.id = d.alert_id"
        " WHERE d.status = 'failed' ORDER BY d.updated_at LIMIT 200"
    )


_ALERT_COLUMNS = (
    "a.id, a.fired_at, a.rule, a.severity, a.group_key, a.event_count, a.first_event_at, a.last_event_at,"
    " a.status, a.acked_by, a.acked_at, a.resolved_by, a.resolved_at, a.silence_id,"
    " (SELECT count(*) FROM alert_notes n WHERE n.alert_id = a.id AND n.action = 'note') AS note_count,"
    " (SELECT COALESCE(json_agg(json_build_object('notifier', d.notifier, 'status', d.status,"
    "        'attempts', d.attempts, 'last_error', d.last_error, 'sent_at', d.sent_at) ORDER BY d.notifier), '[]')"
    "    FROM alert_deliveries d WHERE d.alert_id = a.id) AS deliveries"
)

# 처리 상태 필터: unresolved = 처리 안 됨 + 확인함 (아직 해결 안 된 것 전부)
ALERT_STATUS_FILTERS = {
    "open": "a.status = 'open'",
    "acked": "a.status = 'acked'",
    "resolved": "a.status = 'resolved'",
    "unresolved": "a.status <> 'resolved'",
}


async def list_alerts(since: datetime, limit: int, rule: str | None = None, severity: str | None = None,
                      group_key: str | None = None, status: str | None = None,
                      pairs: list[tuple[str, str]] | None = None) -> list[dict]:
    """pairs: 조회 범위가 있는 사용자에게 보이는 (규칙, 대상) 목록. LIMIT 전에 걸러야 오래된 내 알림이 잘리지 않는다."""
    if pairs is not None and not pairs:
        return []
    clauses, params = ["a.fired_at >= %s"], [since]
    for column, value in (("rule", rule), ("severity", severity), ("group_key", group_key)):
        if value:
            clauses.append(f"a.{column} = %s")
            params.append(value)
    if status:
        clauses.append(ALERT_STATUS_FILTERS[status])
    if pairs is not None:
        clauses.append("(a.rule, a.group_key) IN (SELECT * FROM unnest(%s::text[], %s::text[]))")
        params += [[p[0] for p in pairs], [p[1] for p in pairs]]
    return await db.fetch_all(
        # 같은 평가 주기의 알림은 발생 시각이 같다 → id 로 순서를 고정 (새로고침 사이에 행이 뒤바뀌지 않게)
        f"SELECT {_ALERT_COLUMNS} FROM alerts a WHERE {' AND '.join(clauses)} ORDER BY a.fired_at DESC, a.id DESC LIMIT %s",
        [*params, limit],
    )


async def get_alert(alert_id: int) -> dict | None:
    """상세: 목록 칸 + payload + 처리 기록(notes) + 무음 정보 + 같은 규칙·대상의 해결 안 된 다른 알림 수."""
    row = await db.fetch_one(f"SELECT {_ALERT_COLUMNS}, a.payload FROM alerts a WHERE a.id = %s", (alert_id,))
    if row is None:
        return None
    row["notes"] = (await alert_notes_for([alert_id])).get(alert_id, [])
    row["silence"] = await get_silence(row["silence_id"]) if row["silence_id"] else None
    related = await db.fetch_one(
        "SELECT count(*) AS n FROM alerts WHERE rule = %s AND group_key = %s AND status <> 'resolved' AND id <> %s",
        (row["rule"], row["group_key"], alert_id),
    )
    row["related_unresolved"] = related["n"]
    return row


async def alert_refs(ids: list[int]) -> list[dict]:
    """처리 권한 확인용 최소 정보."""
    return await db.fetch_all("SELECT id, rule, group_key, status FROM alerts WHERE id = ANY(%s)", (ids,))


async def alert_notes_for(ids: list[int]) -> dict[int, list[dict]]:
    rows = await db.fetch_all(
        "SELECT id, alert_id, at, author, action, text FROM alert_notes WHERE alert_id = ANY(%s) ORDER BY at, id", (ids,)
    )
    out: dict[int, list[dict]] = {}
    for r in rows:
        out.setdefault(r.pop("alert_id"), []).append(r)
    return out


# 처리 동작 → (바꿀 칸, 바꿀 수 있는 지금 상태). 해결은 확인을 겸한다(확인한 사람이 없으면 해결한 사람으로).
# 다시 열기는 확인함에서도 된다 — 누구나 할 수 있는 '확인'으로 알림을 대기열에서 치운 경우 담당자가 되돌릴 수 있게
_HANDLE_SQL = {
    "ack": ("status = 'acked', acked_by = %(actor)s, acked_at = now()", "status = 'open'"),
    "resolve": (("status = 'resolved', resolved_by = %(actor)s, resolved_at = now(),"
                 " acked_by = COALESCE(acked_by, %(actor)s), acked_at = COALESCE(acked_at, now())"),
                "status <> 'resolved'"),
    "reopen": ("status = 'open', acked_by = NULL, acked_at = NULL, resolved_by = NULL, resolved_at = NULL",
               "status <> 'open'"),
}


async def handle_alerts(ids: list[int], action: str, actor: str, note: str = "", with_related: bool = False) -> list[int]:
    """확인·해결·다시 열기. 지금 상태에서 할 수 있는 알림만 바꾸고(두 사람이 동시에 눌러도 한 번만) 바뀐 id 를 돌려준다.
    with_related: 같은 규칙·대상의 다른 알림도 함께 (개수 제한 없이 서버에서 한 문장으로 — 재발이 많아도 실패하지 않게).
    처리 기록(alert_notes)을 같은 트랜잭션에 남긴다 — 다시 열어도 이전 확인·해결 기록은 타임라인에 그대로 있다."""
    set_sql, when = _HANDLE_SQL[action]
    target = "id = ANY(%(ids)s)"
    if with_related:
        target = "(id = ANY(%(ids)s) OR (rule, group_key) IN (SELECT rule, group_key FROM alerts WHERE id = ANY(%(ids)s)))"
    async with db.pool().connection() as conn, conn.transaction():
        cur = await conn.execute(
            f"UPDATE alerts SET {set_sql} WHERE {target} AND {when} RETURNING id", {"actor": actor, "ids": ids}
        )
        changed = sorted(r["id"] for r in await cur.fetchall())
        if changed:
            await conn.execute(
                "INSERT INTO alert_notes (alert_id, author, action, text) SELECT unnest(%s::bigint[]), %s, %s, %s",
                (changed, actor, action, note),
            )
    return changed


async def add_alert_note(alert_id: int, author: str, text: str) -> dict:
    return await db.fetch_one(
        "INSERT INTO alert_notes (alert_id, author, action, text) VALUES (%s, %s, 'note', %s)"
        " RETURNING id, at, author, action, text",
        (alert_id, author, text),
    )


async def alert_group_counts(since: datetime | None = None, status: str | None = None) -> list[dict]:
    """(규칙, 대상, 상태)별 알림 수. 조회 범위가 있는 사용자의 숫자는 라우터가 이 묶음 단위로 걸러서 센다."""
    clauses, params = ["TRUE"], []
    if since is not None:
        clauses.append("a.fired_at >= %s")
        params.append(since)
    if status:
        clauses.append(ALERT_STATUS_FILTERS[status])
    return await db.fetch_all(
        f"SELECT a.rule, a.group_key, a.status, count(*) AS n FROM alerts a WHERE {' AND '.join(clauses)}"
        " GROUP BY 1, 2, 3",
        params,
    )


# ------------------------------------------------------------------ alert silences (무음)

_SILENCE_COLUMNS = (
    "s.id, s.rule, s.group_key, s.starts_at, s.ends_at, s.reason, s.created_by, s.created_at, s.ended_by,"
    " (SELECT count(*) FROM alerts a WHERE a.silence_id = s.id) AS suppressed"
)


async def active_silence(rule: str, group_key: str, at: datetime) -> dict | None:
    """이 규칙·대상에 걸린 무음 (여러 개면 가장 늦게 끝나는 것). rule·group_key 가 NULL 인 무음은 전부에 걸린다."""
    return await db.fetch_one(
        "SELECT id, reason, ends_at FROM alert_silences WHERE starts_at <= %s AND ends_at > %s"
        " AND (rule IS NULL OR rule = %s) AND (group_key IS NULL OR group_key = %s) ORDER BY ends_at DESC LIMIT 1",
        (at, at, rule, group_key),
    )


async def list_silences(ended_since: datetime) -> list[dict]:
    """적용 중·예정인 무음과 ended_since 이후에 끝난 무음."""
    return await db.fetch_all(
        f"SELECT {_SILENCE_COLUMNS} FROM alert_silences s WHERE s.ends_at >= %s ORDER BY s.starts_at DESC, s.id DESC"
        " LIMIT 500",
        (ended_since,),
    )


async def get_silence(silence_id: int) -> dict | None:
    return await db.fetch_one(f"SELECT {_SILENCE_COLUMNS} FROM alert_silences s WHERE s.id = %s", (silence_id,))


async def insert_silence(rule: str | None, group_key: str | None, starts_at: datetime, ends_at: datetime,
                         reason: str, created_by: str) -> int:
    row = await db.fetch_one(
        "INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
        " VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (rule, group_key, starts_at, ends_at, reason, created_by),
    )
    return row["id"]


async def end_silence(silence_id: int, actor: str) -> bool:
    """일찍 해제: 행은 남기고 끝 시각을 지금으로 (시작 전이면 길이 0 = 취소). 이미 끝났거나 취소됐거나 없으면 False.
    길이 0 인 무음은 끝 시각이 아직 미래라도 끝난 것으로 본다 — 두 번 취소해 해제한 사람이 바뀌지 않게."""
    row = await db.fetch_one(
        "UPDATE alert_silences SET ends_at = GREATEST(starts_at, now()), ended_by = %s"
        " WHERE id = %s AND ended_by IS NULL AND ends_at > now() AND ends_at > starts_at RETURNING id",
        (actor, silence_id),
    )
    return row is not None


async def active_silence_refs(at: datetime) -> list[dict]:
    """지금 적용 중인 무음의 범위 (화면 상단 '무음 N개 적용 중' — 라우터가 조회 범위로 걸러서 센다)."""
    return await db.fetch_all(
        "SELECT rule, group_key FROM alert_silences WHERE starts_at <= %s AND ends_at > %s", (at, at)
    )


async def alert_stats(since: datetime) -> dict[str, Any]:
    by_rule = await db.fetch_all(
        "SELECT rule, count(*) AS n, max(fired_at) AS last_fired_at FROM alerts WHERE fired_at >= %s GROUP BY rule",
        (since,),
    )
    by_severity = await db.fetch_all(
        "SELECT severity, count(*) AS n FROM alerts WHERE fired_at >= %s GROUP BY severity", (since,)
    )
    last_ever = await db.fetch_all("SELECT rule, max(fired_at) AS t FROM alerts GROUP BY rule")
    return {
        "by_rule": {r["rule"]: {"n": r["n"], "last_fired_at": r["last_fired_at"]} for r in by_rule},
        "by_severity": {r["severity"]: r["n"] for r in by_severity},
        "last_fired": {r["rule"]: r["t"] for r in last_ever},
    }


async def count_alerts(since: datetime) -> int:
    row = await db.fetch_one("SELECT count(*) AS n FROM alerts WHERE fired_at >= %s", (since,))
    return row["n"]


async def count_open_alerts() -> int:
    """아무도 확인하지 않은 알림 수 (사이드바 숫자)."""
    row = await db.fetch_one("SELECT count(*) AS n FROM alerts WHERE status = 'open'")
    return row["n"]


async def purge_alerts(cutoff: datetime) -> tuple[int, int]:
    """보관기간 만료 알림 삭제 (전송 상태·처리 기록은 함께 지워진다). 그 전에 끝난 무음도 정리한다.
    (지운 알림 수, 지운 무음 수) — 무음도 증적이라 몇 개 지웠는지 감사로그에 남긴다."""
    alerts = await db.fetch_all("DELETE FROM alerts WHERE fired_at < %s RETURNING id", (cutoff,))
    silences = await db.fetch_all("DELETE FROM alert_silences WHERE ends_at < %s RETURNING id", (cutoff,))
    return len(alerts), len(silences)


# ---------------------------------------------------------------- audit log

async def list_audit(since: datetime, limit: int, actor: str | None = None, action: str | None = None,
                     q: str | None = None) -> list[dict]:
    clauses, params = ["at >= %s"], [since]
    if actor:
        clauses.append("actor = %s")
        params.append(actor)
    if action:
        # 'auth.' 처럼 점으로 끝나면 접두어 검색
        if action.endswith("."):
            clauses.append("action LIKE %s")
            params.append(action.replace("%", r"\%") + "%")
        else:
            clauses.append("action = %s")
            params.append(action)
    if q:
        clauses.append("(target ILIKE %s OR detail::text ILIKE %s OR actor_ip ILIKE %s)")
        pattern = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
        params += [pattern, pattern, pattern]
    return await db.fetch_all(
        f"SELECT id, at, actor, actor_ip, action, target, detail FROM audit_log WHERE {' AND '.join(clauses)}"
        " ORDER BY at DESC, id DESC LIMIT %s",
        [*params, limit],
    )


async def latest_audit(actions: list[str]) -> dict[str, dict]:
    """행위별 가장 최근 감사로그 한 줄 (백업 상태·보관 파일 무결성 확인 등). (action, at) 인덱스를 탄다."""
    rows = await db.fetch_all(
        "SELECT a.action, l.at, l.actor, l.target, l.detail FROM unnest(%s::text[]) AS a(action)"
        " CROSS JOIN LATERAL (SELECT at, actor, target, detail FROM audit_log WHERE action = a.action"
        "                     ORDER BY at DESC LIMIT 1) l",
        (actions,),
    )
    return {r.pop("action"): r for r in rows}


async def backup_audit() -> dict[str, Any]:
    """백업 상태(화면 '로그 보관'·점검 보고서): 행위별 최근 기록 + 마지막 성공한 복구 시험 + 첫 백업 시각.
    backup 서비스가 남긴 audit_log 를 읽는다 — 백업 파일은 api 컨테이너에서 보이지 않아도 된다."""
    latest = await latest_audit(["backup.create", "backup.failed", "backup.verify", "backup.restore"])
    verify_ok = await db.fetch_one(
        "SELECT at, target, detail FROM audit_log WHERE action = 'backup.verify' AND detail->>'ok' = 'true'"
        " ORDER BY at DESC LIMIT 1"
    )
    verify_failed = await db.fetch_one(
        "SELECT at, target, detail FROM audit_log WHERE action = 'backup.verify' AND detail->>'ok' = 'false'"
        " ORDER BY at DESC LIMIT 1"
    )
    # 실패한 복구 시험은 그 뒤에 '같은 파일이나 더 새 백업'이 성공해야 풀린다. 옛 백업을 직접 시험해 성공한 것으로는
    # 최신 백업의 실패가 가려지지 않게. 파일 이름(wlm-YYYYMMDD-HHMMSS)은 만든 순서대로 정렬된다 (before-*·(없음) 은 그보다 앞)
    superseded = verify_failed is not None and await db.fetch_one(
        "SELECT 1 AS ok FROM audit_log WHERE action = 'backup.verify' AND detail->>'ok' = 'true' AND at > %s"
        " AND target COLLATE \"C\" >= %s LIMIT 1",
        (verify_failed["at"], verify_failed["target"]),
    ) is not None
    first = await db.fetch_one("SELECT min(at) AS at FROM audit_log WHERE action = 'backup.create'")
    return {"latest": latest, "verify_ok": verify_ok, "verify_failed": verify_failed,
            "verify_failed_superseded": superseded, "first_backup_at": first["at"] if first else None}


async def audit_actions() -> list[str]:
    rows = await db.fetch_all("SELECT DISTINCT action FROM audit_log ORDER BY action")
    return [r["action"] for r in rows]


async def purge_audit(cutoff: datetime) -> int:
    """보관기간 만료분 삭제. append-only 트리거의 예외 스위치를 이 트랜잭션에서만 켠다.
    알림 설정 판본(ADR-043)도 같은 보관기간 — 단 마지막 판본은 남긴다(파일이 깨진 채 다시 시작할 때 쓰는 설정)."""
    async with db.pool().connection() as conn:
        await conn.execute("SET LOCAL wlm.audit_purge = 'on'")
        cur = await conn.execute("DELETE FROM audit_log WHERE at < %s", (cutoff,))
        await conn.execute("DELETE FROM alert_config_versions WHERE applied_at < %s"
                           " AND id < (SELECT max(id) FROM alert_config_versions)", (cutoff,))
        return cur.rowcount


# ---------------------------------------------------------------- 알림 설정 판본 (ADR-043)

async def latest_alert_config_version() -> dict[str, Any] | None:
    return await db.fetch_one("SELECT id, applied_at, source, actor, sha256, yaml FROM alert_config_versions"
                              " ORDER BY id DESC LIMIT 1")


async def insert_alert_config_version(source: str, actor: str, sha256: str, yaml_text: str,
                                      changes: list[dict[str, Any]], weakened: bool) -> int:
    row = await db.fetch_one(
        "INSERT INTO alert_config_versions (source, actor, sha256, yaml, changes, weakened)"
        " VALUES (%s, %s, %s, %s, %s::jsonb, %s) RETURNING id",
        (source, actor, sha256, yaml_text.replace("\x00", ""), _json(changes), weakened))
    return row["id"]


async def alert_config_history(limit: int) -> list[dict[str, Any]]:
    """최근 판본부터 (다시 켠 규칙이 마지막으로 켜져 있던 모양을 찾을 때)."""
    return await db.fetch_all("SELECT id, yaml FROM alert_config_versions ORDER BY id DESC LIMIT %s", (limit,))


async def silenced_rule_names(now: datetime, names: list[str]) -> set[str]:
    """그 이름에 지금 걸려 있거나 앞으로 걸릴 무음이 있는 규칙 이름."""
    rows = await db.fetch_all("SELECT DISTINCT rule FROM alert_silences WHERE rule = ANY(%s) AND ends_at > %s"
                              " AND ends_at > starts_at AND ended_by IS NULL", (names, now))
    return {r["rule"] for r in rows}


async def report_config_changes(start: datetime, end: datetime) -> list[dict[str, Any]]:
    """기간 안에 적용한 알림 설정 변경 (처음 기준 판본 — 차이 없음 — 은 빼고)."""
    return await db.fetch_all(
        "SELECT id, applied_at, source, actor, weakened, changes FROM alert_config_versions"
        " WHERE applied_at >= %s AND applied_at < %s AND changes <> '[]'::jsonb ORDER BY id", (start, end))


async def covering_silences(rule: str | None, group_key: str | None, now: datetime) -> list[dict[str, Any]]:
    """이 (규칙, 대상)을 덮는 — 같거나 더 넓은 범위의 — 아직 끝나지 않은 무음 (NULL = 모두)."""
    return await db.fetch_all(
        "SELECT starts_at, ends_at FROM alert_silences WHERE ends_at > %s AND ends_at > starts_at"
        " AND (rule IS NULL OR rule = %s) AND (group_key IS NULL OR group_key = %s)", (now, rule, group_key))


async def report_wide_silences(start: datetime, end: datetime) -> list[dict[str, Any]]:
    """기간 안에 건 넓은 무음 — 걸 때 판단해 감사로그에 남긴 것(이어 붙인 무음까지 합쳐 잰 값, ADR-043)."""
    return await db.fetch_all(
        "SELECT (detail->>'id')::bigint AS id, detail->>'rule' AS rule, detail->>'group_key' AS group_key,"
        " (detail->>'starts_at')::timestamptz AS starts_at,"
        " COALESCE(detail->>'covered_until', detail->>'ends_at')::timestamptz AS ends_at,"
        " detail->>'reason' AS reason, actor AS created_by FROM audit_log"
        " WHERE action = 'alerts.silence.create' AND at >= %s AND at < %s AND (detail->>'wide')::boolean"
        " ORDER BY id", (start, end))


# ---------------------------------------------------------------- reports (정기 점검 보고서, ADR-032)

async def report_alert_summary(start: datetime, end: datetime) -> dict[str, Any]:
    """기간 안에 발생한 알림의 심각도·처리 상태별 수, 보고서를 만들 때 해결 안 된 알림, 해결까지 걸린 시간(중앙값)."""
    fired = await db.fetch_all(
        "SELECT severity, status, count(*) AS n FROM alerts WHERE fired_at >= %s AND fired_at < %s GROUP BY 1, 2",
        (start, end),
    )
    open_by_severity = await db.fetch_all(
        "SELECT severity, count(*) AS n FROM alerts WHERE status <> 'resolved' AND fired_at < %s GROUP BY 1", (end,)
    )
    # 심각한 것부터, 같은 심각도는 오래된 것부터 — 점검자가 먼저 볼 순서
    oldest = await db.fetch_all(
        "SELECT id, fired_at, rule, severity, group_key, status FROM alerts WHERE status <> 'resolved' AND fired_at < %s"
        " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'error' THEN 2 WHEN 'warning' THEN 3 ELSE 4 END, fired_at"
        " LIMIT 10",
        (end,),
    )
    resolved = await db.fetch_one(
        "SELECT count(*) AS n, percentile_cont(0.5) WITHIN GROUP"
        " (ORDER BY extract(epoch FROM resolved_at - fired_at)) AS median_sec"
        " FROM alerts WHERE resolved_at >= %s AND resolved_at < %s",
        (start, end),
    )
    return {"fired": fired, "open_by_severity": open_by_severity, "oldest_unresolved": oldest,
            "resolved_in_period": resolved["n"], "median_resolve_sec": resolved["median_sec"]}


_REPORT_LIST_COLUMNS = (
    "id, kind, scheduled, period_start, period_end, created_at, created_by, attention, deliveries,"
    " reviewed_by, reviewed_at, review_note, payload->>'title' AS title"
)


async def insert_report(kind: str, scheduled: bool, start: datetime, end: datetime, payload: dict,
                        attention: int, created_by: str, deliveries: list[dict] | None = None) -> int | None:
    """정기 보고서는 같은 기간이 이미 있으면 None (여러 인스턴스·재시작에도 한 번만).
    deliveries: 보낼 곳을 '보내는 중'(pending)으로 같이 적어 둔다 — 보내다가 멈추면 다음 주기에 이어서 보낸다."""
    row = await db.fetch_one(
        "INSERT INTO reports (kind, scheduled, period_start, period_end, payload, attention, created_by, deliveries)"
        " VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb)"
        " ON CONFLICT (kind, period_start) WHERE scheduled DO NOTHING RETURNING id",
        (kind, scheduled, start, end, _json(payload), attention, created_by, _json(deliveries or [])),
    )
    return row["id"] if row else None


async def scheduled_report_exists(kind: str, start: datetime) -> bool:
    row = await db.fetch_one(
        "SELECT 1 AS x FROM reports WHERE scheduled AND kind = %s AND period_start = %s", (kind, start)
    )
    return row is not None


async def add_report_deliveries(report_id: int, results: list[dict]) -> None:
    """보낸 결과를 덧붙인다. 이전 결과(정기 발송의 성공·실패)는 지우지 않고, 이번에 보낸 곳의 '보내는 중'만 지운다
    — 다시 보내기가 첫 발송 기록을 덮어쓰지 않게 (언제 누구에게 갔는지의 기록)."""
    names = [r["target"] for r in results]
    await db.fetch_one(
        "UPDATE reports SET deliveries = (SELECT coalesce(jsonb_agg(d ORDER BY o), '[]'::jsonb)"
        "   FROM jsonb_array_elements(deliveries) WITH ORDINALITY AS t(d, o)"
        "  WHERE NOT (d->>'status' = 'pending' AND d->>'target' = ANY(%s))) || %s::jsonb"
        " WHERE id = %s RETURNING id",
        (names, _json(results), report_id),
    )


async def reports_pending_delivery(since: datetime) -> list[dict]:
    """보내는 중에 서버가 멈춰 '보내는 중'으로 남은 보고서 (since 이후에 만든 것만)."""
    return await db.fetch_all(
        "SELECT id, payload, deliveries FROM reports"
        " WHERE created_at >= %s AND deliveries @> '[{\"status\": \"pending\"}]'::jsonb ORDER BY id",
        (since,),
    )


async def expire_pending_deliveries(before: datetime, error: str) -> int:
    """오래된 '보내는 중'은 실패로 바꾼다 (며칠 지난 보고서를 뒤늦게 보내지 않는다)."""
    rows = await db.fetch_all(
        "UPDATE reports SET deliveries = (SELECT jsonb_agg(CASE WHEN d->>'status' = 'pending'"
        "   THEN d || jsonb_build_object('status', 'failed', 'error', %s::text, 'at', now()) ELSE d END ORDER BY o)"
        "   FROM jsonb_array_elements(deliveries) WITH ORDINALITY AS t(d, o))"
        " WHERE created_at < %s AND deliveries @> '[{\"status\": \"pending\"}]'::jsonb RETURNING id",
        (error, before),
    )
    return len(rows)


async def list_reports(limit: int) -> list[dict]:
    return await db.fetch_all(f"SELECT {_REPORT_LIST_COLUMNS} FROM reports ORDER BY created_at DESC, id DESC LIMIT %s",
                              (limit,))


async def get_report(report_id: int) -> dict | None:
    return await db.fetch_one(f"SELECT {_REPORT_LIST_COLUMNS}, payload FROM reports WHERE id = %s", (report_id,))


async def review_report(report_id: int, actor: str, note: str) -> bool:
    """점검 확인은 한 번만 (두 사람이 동시에 눌러도). 이미 확인했으면 False."""
    row = await db.fetch_one(
        "UPDATE reports SET reviewed_by = %s, reviewed_at = now(), review_note = %s"
        " WHERE id = %s AND reviewed_at IS NULL RETURNING id",
        (actor, note, report_id),
    )
    return row is not None


async def count_unreviewed_reports(since: datetime) -> int:
    row = await db.fetch_one("SELECT count(*) AS n FROM reports WHERE reviewed_at IS NULL AND created_at >= %s", (since,))
    return row["n"]


async def purge_reports(cutoff: datetime) -> int:
    """보관기간 만료 보고서 삭제. 삭제 방지 트리거의 예외 스위치를 이 트랜잭션에서만 켠다 (감사로그와 같은 방식)."""
    async with db.pool().connection() as conn, conn.transaction():
        await conn.execute("SET LOCAL wlm.report_purge = 'on'")
        cur = await conn.execute("DELETE FROM reports WHERE created_at < %s", (cutoff,))
        return cur.rowcount
