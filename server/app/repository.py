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
    latest = await latest_audit(["backup.create", "backup.failed", "backup.verify"])
    verify_ok = await db.fetch_one(
        "SELECT at, target, detail FROM audit_log WHERE action = 'backup.verify' AND detail->>'ok' = 'true'"
        " ORDER BY at DESC LIMIT 1"
    )
    first = await db.fetch_one("SELECT min(at) AS at FROM audit_log WHERE action = 'backup.create'")
    return {"latest": latest, "verify_ok": verify_ok, "first_backup_at": first["at"] if first else None}


async def audit_actions() -> list[str]:
    rows = await db.fetch_all("SELECT DISTINCT action FROM audit_log ORDER BY action")
    return [r["action"] for r in rows]


async def purge_audit(cutoff: datetime) -> int:
    """보관기간 만료분 삭제. append-only 트리거의 예외 스위치를 이 트랜잭션에서만 켠다."""
    async with db.pool().connection() as conn:
        await conn.execute("SET LOCAL wlm.audit_purge = 'on'")
        cur = await conn.execute("DELETE FROM audit_log WHERE at < %s", (cutoff,))
        return cur.rowcount


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
                        attention: int, created_by: str) -> int | None:
    """정기 보고서는 같은 기간이 이미 있으면 None (여러 인스턴스·재시작에도 한 번만)."""
    row = await db.fetch_one(
        "INSERT INTO reports (kind, scheduled, period_start, period_end, payload, attention, created_by)"
        " VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)"
        " ON CONFLICT (kind, period_start) WHERE scheduled DO NOTHING RETURNING id",
        (kind, scheduled, start, end, _json(payload), attention, created_by),
    )
    return row["id"] if row else None


async def scheduled_report_exists(kind: str, start: datetime) -> bool:
    row = await db.fetch_one(
        "SELECT 1 AS x FROM reports WHERE scheduled AND kind = %s AND period_start = %s", (kind, start)
    )
    return row is not None


async def set_report_deliveries(report_id: int, deliveries: list[dict]) -> None:
    await db.fetch_one("UPDATE reports SET deliveries = %s::jsonb WHERE id = %s RETURNING id",
                       (_json(deliveries), report_id))


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
