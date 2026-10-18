"""events 테이블 월별 파티션 관리 + 로그 로테이션(보관기간 관리).

- 이번 달 ~ N개월 뒤 파티션을 미리 만든다 (WLM_PARTITION_MONTHS_AHEAD).
- DB 보관기간(WLM_DB_RETENTION_DAYS)이 지난 파티션은 압축 파일로 옮긴 뒤 DROP (app/archive.py).
- 전체 보관기간(WLM_RETENTION_DAYS)이 지난 보관 파일은 삭제.
  모든 이동·삭제는 audit_log 에 남긴다 (ISMS: 로그 보관·파기 기록).
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta

from psycopg import errors, sql

from . import db
from .config import settings

log = logging.getLogger(__name__)

_NAME_RE = re.compile(r"^events_(\d{4})_(\d{2})$")
_LOCK_ID = 727_002
# 파티션 만들기·지우기는 events 전체에 배타 잠금이 필요하다. 백업(pg_dump)이 events 를 읽는 동안 이 잠금을 기다리면
# 그 뒤에 오는 수집 INSERT·검색이 모두 줄을 서서 멈춘다 → 잠깐만 기다리고 다음 주기(1시간)에 다시 한다.
# 파티션은 미리(WLM_PARTITION_MONTHS_AHEAD) 만들어 두므로 한두 번 미뤄져도 수집에는 문제가 없다.
DDL_LOCK_TIMEOUT = "5s"


def _month_start(year: int, month: int) -> datetime:
    return datetime(year, month, 1, tzinfo=UTC)


def _add_months(dt: datetime, months: int) -> datetime:
    index = dt.year * 12 + (dt.month - 1) + months
    return _month_start(index // 12, index % 12 + 1)


async def ensure_partitions(conn, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    first = _month_start(now.year, now.month)
    for i in range(settings.partition_months_ahead + 1):
        start = _add_months(first, i)
        end = _add_months(start, 1)
        name = f"events_{start:%Y_%m}"
        try:
            await conn.execute(
                sql.SQL("CREATE TABLE IF NOT EXISTS {} PARTITION OF events FOR VALUES FROM ({}) TO ({})").format(
                    sql.Identifier(name), sql.Literal(start), sql.Literal(end)
                )
            )
        except errors.LockNotAvailable:
            log.warning("파티션 %s 만들기를 미룸: events 잠금을 얻지 못함 (백업 중일 수 있음) — 다음 주기에 다시 시도", name)


def archiving_enabled() -> bool:
    return 0 < settings.db_retention_days < settings.retention_days


async def list_partitions(conn) -> list[dict]:
    """events 의 월 파티션: 이름, 범위, 예상 행 수, 크기, 보존 연장(hold) 여부."""
    cur = await conn.execute(
        "SELECT c.relname AS name, c.reltuples::bigint AS rows_estimate,"
        "       pg_total_relation_size(c.oid) AS bytes, h.hold_until"
        "  FROM pg_inherits i"
        "  JOIN pg_class c ON c.oid = i.inhrelid"
        "  JOIN pg_class p ON p.oid = i.inhparent"
        "  LEFT JOIN partition_holds h ON h.name = c.relname"
        " WHERE p.relname = 'events' ORDER BY c.relname"
    )
    out = []
    for row in await cur.fetchall():
        m = _NAME_RE.match(row["name"])
        if not m:
            continue
        start = _month_start(int(m.group(1)), int(m.group(2)))
        out.append({**row, "rows_estimate": max(row["rows_estimate"], 0), "from": start, "to": _add_months(start, 1)})
    return out


async def drop_expired(conn, now: datetime | None = None) -> list[str]:
    """로그 로테이션: DB 보관기간이 지난 파티션 → (보관 파일로 옮긴 뒤) DROP.

    전체 보관기간까지 지난 파티션은 파일로 옮기지 않고 바로 지운다. 복원해서 hold 중인 파티션은 건너뛴다.
    파일로 옮기다 실패하면 지우지 않는다 (다음 주기에 재시도).
    """
    from . import archive  # 순환 import 방지

    now = now or datetime.now(UTC)
    total_cutoff = now - timedelta(days=settings.retention_days)
    db_cutoff = now - timedelta(days=min(settings.db_retention_days or settings.retention_days,
                                         settings.retention_days))
    dropped = []
    for part in await list_partitions(conn):
        if part["to"] > db_cutoff or (part["hold_until"] and part["hold_until"] > now):
            continue
        name = part["name"]
        archived = archive.data_path(name).exists() and archive.meta_path(name).exists()
        if archiving_enabled() and part["to"] > total_cutoff and not archived:
            try:
                meta = await archive.archive_partition(name, part["from"], part["to"])
            except Exception as exc:
                log.exception("보관 파일 만들기 실패: %s", name)
                await db.audit("system", "retention.archive_failed", name, {"error": str(exc)[:500]})
                continue
            await db.audit("system", "retention.archive_partition", meta["file"],
                           {k: meta[k] for k in ("partition", "rows", "sha256", "bytes", "from", "to")})
            archived = True
        try:
            await conn.execute(sql.SQL("DROP TABLE {}").format(sql.Identifier(name)))
        except errors.LockNotAvailable:
            log.warning("파티션 %s 삭제를 미룸: events 잠금을 얻지 못함 (백업 중일 수 있음) — 다음 주기에 다시 시도", name)
            continue
        await conn.execute("DELETE FROM partition_holds WHERE name = %s", (name,))
        dropped.append(name)
        log.warning("DB 보관기간 만료 파티션 삭제: %s (약 %s건, 보관 파일 %s)", name, part["rows_estimate"],
                    "있음" if archived else "없음")
        await db.audit("system", "retention.drop_partition", name, {
            "db_retention_days": settings.db_retention_days, "retention_days": settings.retention_days,
            "rows_estimate": part["rows_estimate"], "partition_end": part["to"].isoformat(), "archived": archived,
        })
    if archiving_enabled():
        await archive.delete_expired(total_cutoff)
    return dropped


async def purge_alerts(now: datetime | None = None) -> None:
    """알림 이력도 로그와 같은 보관기간을 적용한다."""
    from . import repository  # 순환 import 방지

    cutoff = (now or datetime.now(UTC)) - timedelta(days=settings.retention_days)
    deleted, silences = await repository.purge_alerts(cutoff)
    if deleted or silences:
        log.warning("보관기간 만료 알림 이력 삭제: 알림 %s건, 끝난 무음 %s건", deleted, silences)
        await db.audit("system", "retention.purge_alerts", "alerts",
                       {"deleted": deleted, "silences_deleted": silences, "retention_days": settings.retention_days,
                        "cutoff": cutoff.isoformat()})


async def purge_audit(now: datetime | None = None) -> None:
    """감사로그 보관기간도 로그와 같다 (최소 1년 권장). 삭제 사실 자체를 다시 감사로그에 남긴다."""
    from . import repository

    cutoff = (now or datetime.now(UTC)) - timedelta(days=settings.retention_days)
    deleted = await repository.purge_audit(cutoff)
    if deleted:
        log.warning("보관기간 만료 감사로그 삭제: %s건", deleted)
        await db.audit("system", "retention.purge_audit", "audit_log",
                       {"deleted": deleted, "retention_days": settings.retention_days, "cutoff": cutoff.isoformat()})


async def purge_reports(now: datetime | None = None) -> None:
    """점검 보고서도 로그와 같은 보관기간 (ISMS 점검 증적). 지운 사실은 감사로그에 남긴다."""
    from . import repository

    cutoff = (now or datetime.now(UTC)) - timedelta(days=settings.retention_days)
    deleted = await repository.purge_reports(cutoff)
    if deleted:
        log.warning("보관기간 만료 점검 보고서 삭제: %s건", deleted)
        await db.audit("system", "retention.purge_reports", "reports",
                       {"deleted": deleted, "retention_days": settings.retention_days, "cutoff": cutoff.isoformat()})


IIS_LAYOUT_KEEP_DAYS = 35  # 하루 단위 파일이면 한 달 남짓 — 그보다 오래된 파일에 줄이 다시 올 일은 드물다


async def purge_iis_layouts(now: datetime | None = None) -> None:
    """IIS 열 순서(ADR-037)는 로그가 아니라 해석용 문맥이라 감사로그를 남기지 않는다."""
    from . import repository

    cutoff = (now or datetime.now(UTC)) - timedelta(days=IIS_LAYOUT_KEEP_DAYS)
    deleted = await repository.purge_iis_layouts(cutoff)
    if deleted:
        log.info("오래된 IIS 열 순서 %s건 삭제 (폴더마다 최신 1건은 남김)", deleted)


async def purge_sessions() -> None:
    from .auth import service

    await service.purge_sessions()


async def run_maintenance() -> None:
    async with await db.connect_autocommit() as conn:
        cur = await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (_LOCK_ID,))
        if not (await cur.fetchone())["ok"]:
            return  # 다른 인스턴스가 실행 중
        try:
            await conn.execute(sql.SQL("SET lock_timeout = {}").format(sql.Literal(DDL_LOCK_TIMEOUT)))
            await ensure_partitions(conn)
            await drop_expired(conn)
            await purge_alerts()
            await purge_audit()
            await purge_reports()
            await purge_iis_layouts()
            await purge_sessions()
        finally:
            await conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))
