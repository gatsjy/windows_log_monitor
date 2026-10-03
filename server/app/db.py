"""PostgreSQL 연결 풀, 마이그레이션, 공용 조회 헬퍼."""

from __future__ import annotations

import json
import logging
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


async def open_pool() -> None:
    global _pool
    _pool = AsyncConnectionPool(
        settings.database_url,
        min_size=1,
        max_size=10,
        kwargs={"row_factory": dict_row},
        open=False,
    )
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
    return await psycopg.AsyncConnection.connect(
        settings.database_url, autocommit=True, row_factory=dict_row
    )


async def fetch_all(query: Any, params: list | tuple | None = None) -> list[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute(query, params)
        return await cur.fetchall()


async def fetch_one(query: Any, params: list | tuple | None = None) -> dict | None:
    async with pool().connection() as conn:
        cur = await conn.execute(query, params)
        return await cur.fetchone()


async def audit(actor: str, action: str, target: str | None = None,
                detail: dict | None = None, actor_ip: str | None = None) -> None:
    """audit_log 에 한 줄 기록한다. 실패해도 본 작업을 막지 않도록 예외는 로그만 남긴다."""
    try:
        async with pool().connection() as conn:
            await conn.execute(
                "INSERT INTO audit_log (actor, actor_ip, action, target, detail) VALUES (%s, %s, %s, %s, %s)",
                (actor, actor_ip, action, target, json.dumps(detail or {}, ensure_ascii=False)),
            )
    except Exception:
        log.exception("audit_log 기록 실패: %s %s", action, target)


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
