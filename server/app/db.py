"""PostgreSQL 연결 풀, 마이그레이션, 공용 조회 헬퍼."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .config import settings

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
_MIGRATION_LOCK_ID = 727_001

_pool: AsyncConnectionPool | None = None
POOL_MAX = 10
# 시간 상한이 걸린 화면 조회가 한꺼번에 쓸 수 있는 연결 수. 나머지(4개)는 수집·알림 엔진·상태 확인 몫으로 늘 남긴다 —
# 쿼리마다 상한을 걸어도 느린 조회가 풀을 다 잡으면 수집이 PoolTimeout(30초)으로 실패하기 때문 (ADR-035)
SEARCH_SLOTS = 6
_search_slots: asyncio.Semaphore | None = None


async def open_pool() -> None:
    global _pool, _search_slots
    _pool = AsyncConnectionPool(
        settings.database_url,
        min_size=1,
        max_size=POOL_MAX,
        kwargs={"row_factory": dict_row},
        open=False,
    )
    # 이벤트 루프마다 새로 (시험은 TestClient 마다 루프가 바뀐다)
    _search_slots = asyncio.Semaphore(SEARCH_SLOTS)
    await _pool.open(wait=True, timeout=60)


async def close_pool() -> None:
    if _pool is not None:
        await _pool.close()


def pool() -> AsyncConnectionPool:
    if _pool is None:
        raise RuntimeError("DB 풀이 열리지 않았습니다")
    return _pool


async def connect_autocommit() -> psycopg.AsyncConnection:
    """마이그레이션/유지보수처럼 트랜잭션을 직접 관리할 때 쓰는 단독 연결."""
    # connect_timeout: 잠금용 연결(알림 엔진·전송기)이 네트워크 문제로 끝없이 매달리지 않게
    return await psycopg.AsyncConnection.connect(
        settings.database_url, autocommit=True, row_factory=dict_row, connect_timeout=10
    )


# 지금 작업의 쿼리마다 걸 시간 상한(초, 0 = 없음). 화면 조회 요청만 켠다(routers/query.search_time_limit).
# 요청은 저마다 자기 작업(task)의 컨텍스트에서 돌아 다른 요청·알림 엔진·수집으로 번지지 않는다 (ADR-035)
_statement_timeout: ContextVar[int] = ContextVar("wlm_statement_timeout", default=0)
# 알림 규칙 평가의 쿼리 시간 상한 (ADR-045). 화면 조회와 달리 조회 자리(SEARCH_SLOTS)를 얻지 않는다 — 화면 검색이 자리를
# 다 쓰고 있어도 알림 평가가 기다리지 않게. 쓰기(insert_alert·audit 는 pool() 을 바로 씀)에는 걸리지 않는다
_background_timeout: ContextVar[int] = ContextVar("wlm_background_timeout", default=0)


class QueryTimeout(Exception):
    """시간 상한을 넘겨 PostgreSQL 이 쿼리를 취소했거나(busy=False), 조회 자리가 나지 않았다(busy=True).
    main 이 503 과 고치는 방법 안내로 바꾼다."""

    def __init__(self, seconds: int, busy: bool = False):
        super().__init__(f"조회 자리를 {seconds}초 안에 얻지 못했습니다" if busy else f"쿼리가 {seconds}초를 넘겼습니다")
        self.seconds = seconds
        self.busy = busy


def limit_statement_time(seconds: int) -> None:
    """지금 작업에서 이후의 fetch_all/fetch_one 에 시간 상한을 건다 (0 = 없음)."""
    _statement_timeout.set(max(0, seconds))


@contextlib.contextmanager
def background_time_limit(seconds: int):
    """with 안의 fetch_all/fetch_one 에 시간 상한 (0 = 없음). 같은 작업 안에서는 await 를 지나도 유지되고 나가면 되돌린다."""
    token = _background_timeout.set(max(0, seconds))
    try:
        yield
    finally:
        _background_timeout.reset(token)


@contextlib.asynccontextmanager
async def _connection():
    """풀 연결. 시간 상한이 켜진 작업이면 먼저 조회 자리(SEARCH_SLOTS)를 얻는다 — 기다리는 시간에도 같은 상한."""
    seconds = _statement_timeout.get()
    if not seconds or _search_slots is None:
        async with pool().connection() as conn:
            yield conn
        return
    try:
        async with asyncio.timeout(seconds):
            await _search_slots.acquire()
    except TimeoutError:
        raise QueryTimeout(seconds, busy=True) from None
    try:
        async with pool().connection() as conn:
            yield conn
    finally:
        _search_slots.release()


async def _execute(conn: psycopg.AsyncConnection, query: Any, params: list | tuple | None) -> psycopg.AsyncCursor:
    seconds = _statement_timeout.get() or _background_timeout.get()
    if not seconds:
        return await conn.execute(query, params)
    # set_config(…, true) = SET LOCAL — 이 트랜잭션에만 걸린다. 풀에 돌려줄 때 트랜잭션이 끝나므로
    # 같은 연결을 다음에 쓰는 수집·알림 엔진에는 남지 않는다
    await conn.execute("SELECT set_config('statement_timeout', %s, true)", (f"{seconds}s",))
    started = time.monotonic()
    try:
        return await conn.execute(query, params)
    except psycopg.errors.QueryCanceled as exc:
        # 관리자의 pg_cancel_backend 같은 다른 취소는 그대로 올린다(엉뚱한 '시간 초과' 안내 방지).
        # 서버 메시지 언어(lc_messages)에 기대지 않게 걸린 시간으로도 본다
        if "statement timeout" in (exc.diag.message_primary or "") or time.monotonic() - started >= seconds - 0.05:
            raise QueryTimeout(seconds) from exc
        raise


async def fetch_all(query: Any, params: list | tuple | None = None) -> list[dict]:
    async with _connection() as conn:
        cur = await _execute(conn, query, params)
        return await cur.fetchall()


async def fetch_one(query: Any, params: list | tuple | None = None) -> dict | None:
    async with _connection() as conn:
        cur = await _execute(conn, query, params)
        return await cur.fetchone()


class AuditError(Exception):
    """접속기록을 남기지 못했다 — required 기록이면 조회 결과를 돌려주지 않는다 (main 의 처리기가 503)."""


async def audit(actor: str, action: str, target: str | None = None,
                detail: dict | None = None, actor_ip: str | None = None, *, required: bool = False) -> None:
    """audit_log 에 한 줄 기록한다. 보통은 실패해도 본 작업을 막지 않도록 예외는 로그만 남긴다.
    required=True(개인정보가 보이는 조회·내려받기의 접속기록)는 실패하면 AuditError — 기록 없이 개인정보를 내주지 않는다 (ADR-042)."""
    try:
        async with pool().connection() as conn:
            await conn.execute(
                "INSERT INTO audit_log (actor, actor_ip, action, target, detail) VALUES (%s, %s, %s, %s, %s)",
                (actor, actor_ip, action, target, json.dumps(detail or {}, ensure_ascii=False)),
            )
    except Exception as exc:
        log.exception("audit_log 기록 실패: %s %s", action, target)
        if required:
            raise AuditError(action) from exc


async def migrate() -> None:
    """migrations/*.sql 중 아직 적용되지 않은 파일을 이름순으로 적용한다."""
    async with await connect_autocommit() as conn:
        await conn.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_ID,))
        try:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                " version TEXT PRIMARY KEY,"
                " applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
            cur = await conn.execute("SELECT version FROM schema_migrations")
            applied = {row["version"] for row in await cur.fetchall()}
            for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
                if path.stem in applied:
                    continue
                log.info("마이그레이션 적용: %s", path.name)
                async with conn.transaction():
                    await conn.execute(path.read_text(encoding="utf-8"))
                    await conn.execute(
                        "INSERT INTO schema_migrations (version) VALUES (%s)", (path.stem,)
                    )
        finally:
            await conn.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_ID,))
