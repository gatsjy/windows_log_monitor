"""events 테이블 월별 파티션 관리 + 로그 로테이션(보관기간 관리).

- 이번 달 ~ N개월 뒤 파티션을 미리 만든다 (WLM_PARTITION_MONTHS_AHEAD).
- DB 보관기간(WLM_DB_RETENTION_DAYS)이 지난 파티션은 압축 파일로 옮긴 뒤 DROP (app/archive.py).
- 전체 보관기간(WLM_RETENTION_DAYS, 보관 등급이 있으면 등급마다 — app/retention.py)이 지난 보관 파일은 삭제.
  모든 이동·삭제는 audit_log 에 남긴다 (ISMS: 로그 보관·파기 기록).
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import errors, sql

from . import db, retention
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
            await account_statistics(conn, name)
        except errors.LockNotAvailable:
            log.warning("파티션 %s 만들기를 미룸: events 잠금을 얻지 못함 (백업 중일 수 있음) — 다음 주기에 다시 시도", name)


def archiving_enabled(config: retention.Config | None = None) -> bool:
    """DB 보관기간 뒤에 보관 파일로 둘 기간이 있나 — 등급 중 하나라도 DB 보다 길면."""
    config = config or retention.load()
    return 0 < settings.db_retention_days < config.max_keep_days()


async def _config_error(config: retention.Config, now: datetime) -> None:
    """보관 등급 설정이 틀리면 보관·삭제를 멈춘다(로그는 DB 에 그대로). 감사로그는 하루 한 번 — 시간마다 돈다."""
    from . import repository

    last = (await repository.latest_audit_by_id(["retention.archive_failed"])).get("retention.archive_failed")
    if last is None or last["target"] != "retention.yaml" or now - last["at"] >= timedelta(hours=23):
        await db.audit("system", "retention.archive_failed", "retention.yaml",
                       {"error": f"보관 등급 설정 오류 — 보관 파일 만들기·삭제를 멈췄습니다: {config.error}"[:500]})


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
    config = retention.load()
    if config.error:
        # 틀린 설정으로 접속기록을 짧은 등급에 넣거나 일찍 지우지 않게 — 고칠 때까지 DB 에 둔다 (화면·준비도가 알린다)
        await _config_error(config, now)
        return []
    longest = config.max_keep_days()   # 보관 파일이 가장 오래 남는 기간 (등급이 없으면 WLM_RETENTION_DAYS)
    total_cutoff = now - timedelta(days=longest)
    db_cutoff = now - timedelta(days=min(settings.db_retention_days or longest, longest))
    dropped = []
    for part in await list_partitions(conn):
        if part["to"] > db_cutoff or (part["hold_until"] and part["hold_until"] > now):
            continue
        name = part["name"]
        archived = archive.is_archived(name)   # 완료 표시 — 복원한 달은 보존 기간 뒤 다시 보관하지 않고 지운다(그 파일은 그대로)
        if archiving_enabled(config) and part["to"] > total_cutoff and not archived:
            try:
                meta = await archive.archive_partition(name, part["from"], part["to"], config)
            except Exception as exc:
                log.exception("보관 파일 만들기 실패: %s", name)
                await db.audit("system", "retention.archive_failed", name, {"error": str(exc)[:500]})
                continue
            await db.audit("system", "retention.archive_partition", meta["file"] or name,   # 기본 파일 없이 등급 파일만인 달
                           {**{k: meta[k] for k in ("partition", "rows", "sha256", "bytes", "from", "to")},
                            **({"tiers": meta["tiers"], "skipped": meta["skipped"]} if meta["tiers"] or meta["skipped"] else {})})
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
            "db_retention_days": settings.db_retention_days, "retention_days": longest,
            "rows_estimate": part["rows_estimate"], "partition_end": part["to"].isoformat(), "archived": archived,
        })
    if archiving_enabled(config):
        await archive.delete_expired(now, config)
    return dropped


# 법정 최소 보관기간 (개인정보의 안전성 확보조치 기준) — 짧게 설정하면 기동 로그·로그 보관 화면·점검 보고서가 알린다
LEGAL_MIN_LOG_DAYS = 365          # 제8조: 접속기록 1년 이상 (민감정보·고유식별정보·5만 명 이상이면 2년)
LEGAL_SENSITIVE_LOG_DAYS = 730
LEGAL_MIN_AUDIT_DAYS = 1095       # 제5조: 권한 부여·변경·말소 내역 최소 3년


def retention_warnings() -> list[str]:
    """보관기간이 법정 최소보다 짧은 설정. 어떤 로그가 '접속기록'인지는 사이트가 판단하므로 2년 기준은 안내만 한다."""
    out = []
    config = retention.load()
    # 민감정보 처리 시스템의 접속기록만 2년 등급으로 두는 것이 B-70 의 권장 방법 — 그런 등급이 있으면 2년 미달로 보지 않는다(화면 안내로 확인)
    if settings.sensitive_access_log and settings.retention_days < LEGAL_SENSITIVE_LOG_DAYS and not retention.sensitive_tier(config):
        out.append(f"로그 보관 {settings.retention_days}일 — 민감정보(진료정보) 처리 시스템의 접속기록 법정 최소 2년(730일)보다 "
                   "짧습니다 (WLM_RETENTION_DAYS, WLM_SENSITIVE_ACCESS_LOG=on)")
    elif settings.retention_days < LEGAL_MIN_LOG_DAYS:
        out.append(f"로그 보관 {settings.retention_days}일 — 접속기록 법정 최소 1년(365일)보다 짧습니다 (WLM_RETENTION_DAYS)")
    if settings.audit_retention_days < LEGAL_MIN_AUDIT_DAYS:
        out.append(f"감사로그 보관 {settings.audit_retention_days}일 — 권한 부여·변경·말소 기록 법정 최소 3년(1095일)보다 "
                   "짧습니다 (WLM_AUDIT_RETENTION_DAYS)")
    if settings.report_retention_days < LEGAL_MIN_LOG_DAYS:
        out.append(f"점검 보고서 보관 {settings.report_retention_days}일 — 점검 증적을 1년 이상 남기세요 (WLM_REPORT_RETENTION_DAYS)")
    if config.error:
        out.append(f"보관 등급 설정(config/retention.yaml) 오류 — 고칠 때까지 보관 파일 만들기·삭제를 멈춥니다(로그는 DB 에 그대로): {config.error}")
    return out


async def purge_agent_streams(now: datetime | None = None) -> None:
    """채널별 수신 집계는 '평소'를 보는 데만 쓴다 (B-37) — 한 달 남짓만 둔다(로그 자체가 아니라 감사 대상 아님)."""
    from . import repository

    now = now or datetime.now(UTC)
    await repository.purge_agent_streams(now.date() - timedelta(days=repository.STREAM_KEEP_DAYS))
    await repository.purge_agent_events(now - timedelta(days=repository.EVENT_KEEP_DAYS))


async def purge_ingest_problems(now: datetime | None = None) -> None:
    """격리한 수집 레코드는 원본 로그라 로그 보관기간까지, 수집 거절 장부도 같은 기간 조용하면 지운다 (B-40).
    격리 레코드는 보관 등급(B-70)의 가장 긴 기간까지 — 등급 문장이 보는 칸(수준·메시지·f.…)이 격리 표에 없어 어느 등급인지 가릴 수 없다.
    로그 보관기간으로 지우면 2년 등급의 진료정보 시스템 접속기록이 격리됐을 때 1년 만에 사라졌다(검토에서 재현). 설정이 틀리면 격리는 지우지 않는다."""
    from . import repository

    now = now or datetime.now(UTC)
    config = retention.load()
    keep = None if config.error else config.max_keep_days()
    cutoff = now - timedelta(days=settings.retention_days)
    quarantined, rejections = await repository.purge_ingest_problems(
        now - timedelta(days=keep) if keep else None, cutoff)
    if quarantined or rejections:
        await db.audit("system", "retention.purge_ingest", "ingest_quarantine",
                       {"quarantined_deleted": quarantined, "rejections_deleted": rejections,
                        "retention_days": settings.retention_days, "quarantine_keep_days": keep, "cutoff": cutoff.isoformat()})


async def purge_alerts(now: datetime | None = None) -> None:
    """알림 이력(처리 기록·끝난 무음 포함)은 알림 보관기간(기본 = 로그 보관기간)."""
    from . import repository  # 순환 import 방지

    cutoff = (now or datetime.now(UTC)) - timedelta(days=settings.alert_retention_days)
    deleted, silences = await repository.purge_alerts(cutoff)
    if deleted or silences:
        log.warning("보관기간 만료 알림 이력 삭제: 알림 %s건, 끝난 무음 %s건", deleted, silences)
        await db.audit("system", "retention.purge_alerts", "alerts",
                       {"deleted": deleted, "silences_deleted": silences, "retention_days": settings.alert_retention_days,
                        "cutoff": cutoff.isoformat()})


async def purge_audit(now: datetime | None = None) -> None:
    """감사로그는 감사로그 보관기간(기본 3년 — 권한 부여·변경·말소 기록, 제5조). 삭제 사실(지운 마지막 번호·해시)은 repository 가
    같은 트랜잭션에 감사로그로 남긴다(B-71). 지울 행이 체인과 맞지 않으면 지우지 않는다 — 변조를 만료로 세탁하지 않게."""
    from . import integrity, repository

    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=settings.audit_retention_days)
    result = await repository.purge_audit(cutoff, settings.audit_retention_days, await integrity.purge_check(now))
    if result.get("refused"):
        log.error("감사로그 만료 삭제를 멈춤 — 지울 행이 체인과 맞지 않음: %s", "; ".join(result["refused"][:3]))
        last = (await repository.latest_audit_by_id(["retention.purge_audit_refused"])).get("retention.purge_audit_refused")
        if last is None or now - last["at"] >= timedelta(hours=23):   # 시간마다 다시 보지만 기록은 하루 한 번
            await db.audit("system", "retention.purge_audit_refused", "audit_log",
                           {"cutoff": cutoff.isoformat(), "upto_id": result["upto_id"], "problems": result["refused"][:5]})
    elif result["deleted"]:
        log.warning("보관기간 만료 감사로그 삭제: %s건", result["deleted"])


async def purge_reports(now: datetime | None = None) -> None:
    """점검 보고서는 보고서 보관기간(기본 3년 — ISMS 점검 증적). 지운 사실은 감사로그에 남긴다."""
    from . import repository

    cutoff = (now or datetime.now(UTC)) - timedelta(days=settings.report_retention_days)
    deleted = await repository.purge_reports(cutoff)
    if deleted:
        log.warning("보관기간 만료 점검 보고서 삭제: %s건", deleted)
        await db.audit("system", "retention.purge_reports", "reports",
                       {"deleted": deleted, "retention_days": settings.report_retention_days, "cutoff": cutoff.isoformat()})


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


async def lock_dormant_accounts() -> None:
    """장기 미사용 계정 끄기 (B-72 1단계) — 끈 것이 있으면 다른 관리자에게 '관리 작업 알림'(누가 왜 못 들어오는지 알게)."""
    from datetime import UTC, datetime

    from .alerts import adminwatch
    from .auth import service
    from .config import display_zone, settings

    locked = await service.lock_dormant(datetime.now(UTC))
    if locked:
        zone = display_zone()
        await adminwatch.notify("system", f"장기 미사용 계정 {len(locked)}개를 껐습니다 — {settings.dormant_days}일 동안 로그인하지 않음",
                                [f"{u['username']} (마지막 사용 {u['last_used'].astimezone(zone):%Y-%m-%d})" for u in locked])


ACCOUNT_INDEX = "events_account_ts_idx"   # 마이그레이션 038 — 부모 색인(ON ONLY)
OLD_USER_INDEX = "events_user_ts_idx"      # 마이그레이션 007 — 계정 색인이 다 붙으면 지운다(user: 도 계정 색인으로 찾는다)
_INDEX_LOCK_ID = 727_007
INDEX_BUILD_EVERY_SEC = 3600


async def account_statistics(conn, partition: str) -> bool:
    """계정 열쇠 식의 통계 (B-54). 부분 색인(WHERE username IS NOT NULL)의 통계는 플래너가 쓰지 않아 account:·user: 가 늘 0.5% 로 어림됐다 —
    'SYSTEM' 처럼 40% 인 값도 색인으로 훑어 느렸다(검토에서 재현). 파티션마다(가지치기 뒤에는 부모 통계를 쓰지 않는다). 새로 만들었으면 True."""
    stx = f"{partition}_account_stx"
    cur = await conn.execute("SELECT 1 FROM pg_statistic_ext WHERE stxname = %s", (stx,))
    if await cur.fetchone():
        return False
    await conn.execute(sql.SQL("CREATE STATISTICS IF NOT EXISTS {} ON (wlm_user_key(username)) FROM {}").format(
        sql.Identifier(stx), sql.Identifier(partition)))
    return True


async def account_index_status(conn) -> dict[str, Any]:
    """계정 표기 색인(B-54): 부모 색인이 유효한가, 월 파티션 중 붙은 것 몇 개. 마이그레이션 전이면 None 들."""
    cur = await conn.execute(
        "SELECT x.indisvalid AS valid FROM pg_class c JOIN pg_index x ON x.indexrelid = c.oid WHERE c.relname = %s", (ACCOUNT_INDEX,))
    row = await cur.fetchone()
    if row is None:
        return {"valid": None, "attached": 0, "partitions": 0, "missing": []}
    missing = await _partitions_without_account_index(conn)
    cur = await conn.execute("SELECT count(*) AS n FROM pg_inherits WHERE inhparent = 'events'::regclass")
    total = (await cur.fetchone())["n"]
    return {"valid": row["valid"], "attached": total - len(missing), "partitions": total, "missing": missing}


async def _partitions_without_account_index(conn) -> list[str]:
    cur = await conn.execute(
        "SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'events'::regclass"
        " AND NOT EXISTS (SELECT 1 FROM pg_inherits ii JOIN pg_index x ON x.indexrelid = ii.inhrelid"
        "                 WHERE ii.inhparent = %s::regclass AND x.indrelid = c.oid)"
        " ORDER BY c.relname DESC", (ACCOUNT_INDEX,))
    return [r["name"] for r in await cur.fetchall()]


async def build_account_indexes() -> int:
    """있던 월 파티션마다 계정 표기 색인을 CONCURRENTLY 로 만들어 부모 색인에 붙인다 (B-54, ADR-062). 최신 달부터, 수집·검색을 막지 않고.
    마이그레이션 트랜잭션에서 한꺼번에 만들면 행 1억 개에 기동이 몇십 분 멈춰 설치 스크립트의 기동 대기를 넘었다. 다 붙으면 부모 색인이 유효해진다.
    중간에 멈춰 남은 INVALID 조각은 지우고 다시 만든다. 붙인 파티션 수를 돌려준다."""
    built = 0
    async with await db.connect_autocommit() as conn:
        cur = await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (_INDEX_LOCK_ID,))
        if not (await cur.fetchone())["ok"]:
            return 0
        try:
            await conn.execute("SET statement_timeout = 0")
            status = await account_index_status(conn)
            if status["valid"] is None:
                return 0
            for name in status["missing"]:
                index = f"{name}_account_ts_idx"
                try:
                    cur = await conn.execute("SELECT x.indisvalid AS valid FROM pg_class c JOIN pg_index x ON x.indexrelid = c.oid"
                                             " WHERE c.relname = %s", (index,))
                    leftover = await cur.fetchone()
                    if leftover is not None and not leftover["valid"]:
                        await conn.execute(sql.SQL("DROP INDEX CONCURRENTLY IF EXISTS {}").format(sql.Identifier(index)))
                    # 식·조건은 부모 색인(마이그레이션 038)과 같아야 붙는다
                    await conn.execute(sql.SQL("CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON {} (wlm_user_key(username), ts DESC)"
                                               " WHERE username IS NOT NULL").format(sql.Identifier(index), sql.Identifier(name)))
                    # 붙이기는 그 색인에 배타 잠금 — 백업(pg_dump)이 이 파티션을 읽는 동안 기다리면 뒤의 수집·검색이 모두 줄을 섰다(검토).
                    # 잠깐만 기다리고 다음 주기에 (만든 색인은 남아 있어 다시 만들지 않는다)
                    await conn.execute(sql.SQL("SET lock_timeout = {}").format(sql.Literal(DDL_LOCK_TIMEOUT)))
                    try:
                        await conn.execute(sql.SQL("ALTER INDEX {} ATTACH PARTITION {}").format(sql.Identifier(ACCOUNT_INDEX),
                                                                                                sql.Identifier(index)))
                    finally:
                        await conn.execute("SET lock_timeout = 0")
                    built += 1
                    log.info("계정 표기 색인: %s 완료", name)
                except errors.LockNotAvailable:
                    log.warning("계정 표기 색인 붙이기를 미룸: %s 잠금을 얻지 못함 (백업 중일 수 있음)", name)
                except errors.UndefinedTable:
                    continue   # 그 사이 로테이션이 지운 파티션
                except Exception:
                    log.exception("계정 표기 색인 만들기 실패: %s — 다음 주기에 다시", name)
            # 식 통계 — 있던 파티션은 새로 만든 뒤 ANALYZE (값이 바뀌지 않는 옛 달은 자동 분석이 다시 오지 않는다)
            cur = await conn.execute("SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
                                     " WHERE i.inhparent = 'events'::regclass ORDER BY c.relname DESC")
            for row in await cur.fetchall():
                try:
                    if await account_statistics(conn, row["name"]):
                        await conn.execute(sql.SQL("ANALYZE {}").format(sql.Identifier(row["name"])))
                except errors.UndefinedTable:
                    continue
            if (await account_index_status(conn))["valid"]:
                await _drop_old_user_index(conn)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(%s)", (_INDEX_LOCK_ID,))
    return built


async def _drop_old_user_index(conn) -> None:
    """계정 표기 색인이 모든 파티션에 붙은 뒤에만 예전 username 색인을 지운다 — 그 전에는 user: 가 예전 색인으로 찾는다.
    파티션 색인은 CONCURRENTLY 로 지울 수 없어 잠깐 events 를 잠근다 — 백업이 읽는 중이면 기다리지 않고 다음 주기에(DDL_LOCK_TIMEOUT)."""
    cur = await conn.execute("SELECT 1 FROM pg_class WHERE relname = %s AND relkind = 'I'", (OLD_USER_INDEX,))
    if await cur.fetchone() is None:
        return
    try:
        await conn.execute(sql.SQL("SET lock_timeout = {}").format(sql.Literal(DDL_LOCK_TIMEOUT)))
        await conn.execute(sql.SQL("DROP INDEX IF EXISTS {}").format(sql.Identifier(OLD_USER_INDEX)))
        log.warning("예전 사용자 색인 %s 을(를) 지웠습니다 — user:·account: 모두 계정 표기 색인으로 찾습니다", OLD_USER_INDEX)
    except errors.LockNotAvailable:
        log.warning("예전 사용자 색인 지우기를 미룸: events 잠금을 얻지 못함 (백업 중일 수 있음)")
    finally:
        await conn.execute("SET lock_timeout = 0")


async def account_index_loop() -> None:
    """기동 1분 뒤부터 한 시간마다 — 다 붙어 있으면 카탈로그만 보고 끝난다."""
    await asyncio.sleep(60)
    while True:
        try:
            await build_account_indexes()
        except Exception:
            log.exception("계정 표기 색인 점검 실패")
        await asyncio.sleep(INDEX_BUILD_EVERY_SEC)


async def run_maintenance(with_integrity: bool = True) -> None:
    """with_integrity=False: 기동 중(수집·화면을 열기 전)이나 수집 요청 안(새 달 파티션)에서 부를 때 — 감사로그 전체 검증·앵커(B-71)는
    건너뛰고 다음 정기 실행에서 한다(행이 많으면 기동이 그만큼 늦어 설치 스크립트의 기동 대기를 넘었다 — 검토에서 측정)."""
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
            await purge_ingest_problems()
            await purge_agent_streams()
            if with_integrity:
                from . import (
                    integrity,  # 감사로그 해시 체인 검증·앵커 (B-71) — repository 와 순환 import 를 피해 여기서
                )

                # 장기 미사용 잠금(B-72)도 정기 실행에서만 — 기동 중에는 알림 설정을 아직 읽지 않아 관리 작업 알림이 아무에게도
                # 가지 않았다(검토에서 재현)
                await lock_dormant_accounts()
                await integrity.daily()
        finally:
            await conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))
