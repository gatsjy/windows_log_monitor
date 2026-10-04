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
from .normalizers import Event, Heartbeat

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


def where_clause(f: EventFilter) -> tuple[sql.Composable, list[Any]]:
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
    if f.q_terms:
        likes = []
        for term in f.q_terms:
            escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            likes.append(sql.SQL("message ILIKE %s"))
            params.append(f"%{escaped}%")
        clauses.append(sql.SQL("({})").format(sql.SQL(" OR ").join(likes)))
    for path, value in f.fields:
        clauses.append(sql.SQL("raw #>> %s::text[] = %s"))
        params.extend([path, value])
    if f.scopes is not None:
        scope_sql, scope_params = scope_clause(f.scopes)
        clauses.append(scope_sql)
        params.extend(scope_params)
    if not clauses:
        return sql.SQL("TRUE"), []
    return sql.SQL(" AND ").join(clauses), params


def _field_expr(field: str) -> tuple[sql.Composable, list[Any]]:
    if field in COLUMN_EXPR:
        return sql.SQL(COLUMN_EXPR[field]), []
    path = [p for p in field.removeprefix("f.").split(".") if p]
    if not path:
        raise ValueError("field 가 비어 있습니다")
    return sql.SQL("raw #>> %s::text[]"), [path]


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
            entry = stats.setdefault((event.source, path), [None, 0, None])
            entry[0] = _json_type(value)
            entry[1] += 1
            entry[2] = (value if isinstance(value, str) else _json(value))[:200]
    return [(src, path, t, n, sample) for (src, path), (t, n, sample) in sorted(stats.items())]


async def _write(conn, events: list[Event], heartbeats: list[Heartbeat], client_ip: str | None) -> None:
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
            host_ip = {e.host: str(e.raw.get("source_ip") or client_ip or "") or None for e in events}
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
            await cur.executemany(
                "INSERT INTO agents AS a (host, last_seen, last_heartbeat_at, last_ip, meta)"
                " VALUES (%s, now(), now(), %s, %s::jsonb)"
                " ON CONFLICT (host) DO UPDATE SET last_seen = now(), last_heartbeat_at = now(),"
                " last_ip = COALESCE(EXCLUDED.last_ip, a.last_ip), meta = EXCLUDED.meta",
                [(host, client_ip, _json(hb.meta)) for host, hb in sorted(latest.items())],
            )


async def insert_batch(events: list[Event], heartbeats: list[Heartbeat], client_ip: str | None) -> None:
    if not events and not heartbeats:
        return
    for attempt in (1, 2):
        try:
            async with db.pool().connection() as conn:
                await _write(conn, events, heartbeats, client_ip)
            return
        except psycopg.errors.CheckViolation:
            # 이번 달 파티션이 아직 없을 때 (월이 바뀐 직후 등): 만들고 한 번 더 시도
            if attempt == 2:
                raise
            log.warning("파티션 없음 → 생성 후 재시도")
            await partitions.run_maintenance()


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
        "SELECT a.host, a.first_seen, a.last_seen, a.last_event_at, a.last_heartbeat_at, a.last_ip,"
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

async def alert_candidates(f: EventFilter, group_by: str, threshold: int) -> list[dict]:
    """규칙 조건에 맞는 이벤트를 group_by 로 묶어 threshold 이상인 묶음만."""
    if group_by == "none":
        key_expr, key_params = sql.SQL("''"), []
    else:
        key_expr, key_params = _field_expr(group_by)
    where, params = where_clause(f)
    query = sql.SQL(
        "SELECT {} AS key, count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts"
        " FROM events WHERE {} GROUP BY 1 HAVING count(*) >= %s ORDER BY n DESC LIMIT 100"
    ).format(key_expr, where)
    return await db.fetch_all(query, [*key_params, *params, threshold])


async def rule_preview(f: EventFilter, group_by: str, window_sec: int, threshold: int) -> list[dict]:
    """규칙 미리보기: 조건에 맞는 이벤트를 (묶음 값, window 길이 구간)으로 세어 threshold 이상인 구간만.
    엔진은 30초마다 '최근 window' 를 보지만, 미리보기는 겹치지 않는 구간으로 근사한다."""
    if group_by == "none":
        key_expr, key_params = sql.SQL("''"), []
    else:
        key_expr, key_params = _field_expr(group_by)
    where, params = where_clause(f)
    query = sql.SQL(
        "SELECT {} AS key, floor(extract(epoch FROM received_at) / %s)::bigint AS bucket, count(*) AS n"
        " FROM events WHERE {} GROUP BY 1, 2 HAVING count(*) >= %s ORDER BY 2 LIMIT 5000"
    ).format(key_expr, where)
    return await db.fetch_all(query, [*key_params, window_sec, *params, threshold])


async def last_alert_at(rule: str, group_key: str) -> datetime | None:
    row = await db.fetch_one(
        "SELECT max(fired_at) AS t FROM alerts WHERE rule = %s AND group_key = %s", (rule, group_key)
    )
    return row["t"] if row else None


async def silent_agents(cutoff: datetime, hosts: tuple[str, ...]) -> list[dict]:
    if hosts:
        return await db.fetch_all(
            "SELECT host, last_seen FROM agents WHERE last_seen < %s AND host = ANY(%s::text[])", (cutoff, list(hosts))
        )
    return await db.fetch_all("SELECT host, last_seen FROM agents WHERE last_seen < %s", (cutoff,))


async def insert_alert(message: dict, notifiers: tuple[str, ...]) -> int:
    """alerts 한 줄 + 알림 대상별 alert_deliveries(pending). 새 id 반환."""
    async with db.pool().connection() as conn:
        cur = await conn.execute(
            "INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, first_event_at, last_event_at, payload)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb) RETURNING id",
            (message["fired_at"], message["rule"], message["severity"], message["group_key"],
             message["event_count"], message["first_event_at"], message["last_event_at"], _json(message)),
        )
        alert_id = (await cur.fetchone())["id"]
        async with conn.cursor() as c:
            await c.executemany(
                "INSERT INTO alert_deliveries (alert_id, notifier) VALUES (%s, %s)",
                [(alert_id, name) for name in notifiers],
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
    " (SELECT COALESCE(json_agg(json_build_object('notifier', d.notifier, 'status', d.status,"
    "        'attempts', d.attempts, 'last_error', d.last_error, 'sent_at', d.sent_at) ORDER BY d.notifier), '[]')"
    "    FROM alert_deliveries d WHERE d.alert_id = a.id) AS deliveries"
)


async def list_alerts(since: datetime, limit: int, rule: str | None = None,
                      severity: str | None = None, group_key: str | None = None) -> list[dict]:
    clauses, params = ["a.fired_at >= %s"], [since]
    for column, value in (("rule", rule), ("severity", severity), ("group_key", group_key)):
        if value:
            clauses.append(f"a.{column} = %s")
            params.append(value)
    return await db.fetch_all(
        f"SELECT {_ALERT_COLUMNS} FROM alerts a WHERE {' AND '.join(clauses)} ORDER BY a.fired_at DESC LIMIT %s",
        [*params, limit],
    )


async def get_alert(alert_id: int) -> dict | None:
    return await db.fetch_one(f"SELECT {_ALERT_COLUMNS}, a.payload FROM alerts a WHERE a.id = %s", (alert_id,))


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


async def purge_alerts(cutoff: datetime) -> int:
    rows = await db.fetch_all("DELETE FROM alerts WHERE fired_at < %s RETURNING id", (cutoff,))
    return len(rows)


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


async def audit_actions() -> list[str]:
    rows = await db.fetch_all("SELECT DISTINCT action FROM audit_log ORDER BY action")
    return [r["action"] for r in rows]


async def purge_audit(cutoff: datetime) -> int:
    """보관기간 만료분 삭제. append-only 트리거의 예외 스위치를 이 트랜잭션에서만 켠다."""
    async with db.pool().connection() as conn:
        await conn.execute("SET LOCAL wlm.audit_purge = 'on'")
        cur = await conn.execute("DELETE FROM audit_log WHERE at < %s", (cutoff,))
        return cur.rowcount
