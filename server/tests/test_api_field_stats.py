"""필드 카탈로그 (ADR-068): 수집 트랜잭션 밖에서 메모리에 모았다가 field_stats 에 더한다 — 단위 + 통합 시험.

회귀: 수집 요청마다 같은 트랜잭션에서 field_stats 를 upsert 해 같은 소스의 요청이 모두 같은 줄 잠금에 줄을 섰다
(에이전트 1000대에서 초당 약 300건에서 멈춤, PERFORMANCE.md §2.12). 이제 수집은 그 표를 잠그지 않는다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from app import fieldstats

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
T0 = datetime(2026, 11, 19, 1, 0, tzinfo=UTC)


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


@pytest.fixture(autouse=True)
def _empty():
    fieldstats.forget()
    yield
    fieldstats.forget()


# ------------------------------------------------------------------ 단위

def test_counts_merge_and_the_latest_shape_wins():
    fieldstats.note([("winevtlog", "EventID", "number", 2, "4625")], T0)
    fieldstats.note([("winevtlog", "EventID", "string", 3, "x")], T0 + timedelta(seconds=5))
    fieldstats.note([("winevtlog", "EventID", "number", 1, "old")], T0 - timedelta(seconds=5))   # 늦게 온 옛 값은 모양을 못 바꾼다
    assert fieldstats._pending[("winevtlog", "EventID")] == ["string", 6, "x", T0 - timedelta(seconds=5),
                                                             T0 + timedelta(seconds=5)]


def test_new_paths_over_the_limit_are_dropped_but_known_ones_still_count(monkeypatch):
    monkeypatch.setattr(fieldstats, "MAX_KEYS", 2)
    fieldstats.note([("s", "a", "string", 1, None), ("s", "b", "string", 1, None)], T0)
    fieldstats.note([("s", "c", "string", 1, None), ("s", "a", "string", 4, None)], T0)
    assert set(fieldstats._pending) == {("s", "a"), ("s", "b")}
    assert fieldstats._pending[("s", "a")][1] == 5 and fieldstats._dropped == 1


def test_failed_flush_keeps_what_was_collected(monkeypatch):
    import asyncio

    from app import repository

    async def down(rows):
        raise psycopg.OperationalError("DB 꺼짐 (시험)")

    monkeypatch.setattr(repository, "add_field_stats", down)
    fieldstats.note([("s", "a", "string", 2, "v")], T0)
    with pytest.raises(psycopg.OperationalError):
        asyncio.run(fieldstats.flush())
    fieldstats.note([("s", "a", "string", 1, "w")], T0 + timedelta(seconds=1))   # 실패한 사이 새로 센 것과 합쳐진다
    assert fieldstats._pending[("s", "a")] == ["string", 3, "w", T0, T0 + timedelta(seconds=1)]


# ------------------------------------------------------------------ 통합

@pytest.fixture(scope="module")
def client():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        yield c


def _rec(host, **extra):
    return {"date": datetime.now(UTC).isoformat(), "log": "hello", "agent_host": host, "log_source": "fieldtest",
            **extra}


def _stats(path):
    return sql("SELECT json_type, seen, sample FROM field_stats WHERE source = 'fieldtest' AND path = %s", (path,))


def test_ingest_is_not_blocked_by_a_locked_field_stats_row(client):
    """다른 트랜잭션이 field_stats 줄을 쥐고 있어도 수집은 끝난다 — 예전에는 그 커밋까지 기다렸다."""
    import threading

    client.post("/api/ingest", json=[_rec("FS-0", Held=1)], headers=KEY)
    client.portal.call(fieldstats.flush)
    done = []
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as holder:
        holder.execute("SELECT 1 FROM field_stats WHERE source = 'fieldtest' FOR UPDATE")
        worker = threading.Thread(target=lambda: done.append(
            client.post("/api/ingest", json=[_rec("FS-0", Held=2)], headers=KEY).status_code))
        worker.start()
        worker.join(10)
        finished = not worker.is_alive()
        holder.rollback()   # 예전 코드여도 시험이 멈추지 않게 풀어 준다
    worker.join()
    assert finished and done == [200]


def test_counts_reach_field_stats_on_flush(client):
    assert client.post("/api/ingest", json=[_rec("FS-1", Code=1), _rec("FS-2", Code=2)], headers=KEY).status_code == 200
    client.portal.call(fieldstats.flush)
    assert _stats("Code") == [("number", 2, "2")]
    client.post("/api/ingest", json=[_rec("FS-1", Code="x")], headers=KEY)
    client.portal.call(fieldstats.flush)
    assert _stats("Code") == [("string", 3, "x")]     # 수는 더하고 모양·예시는 마지막 것


def test_fields_screen_flushes_first(client):
    client.post("/api/ingest", json=[_rec("FS-3", Fresh="yes")], headers=KEY)
    items = client.get("/api/fields", headers=CSRF).json()["items"]
    assert {"source": "fieldtest", "path": "Fresh", "seen": 1} in [
        {k: i[k] for k in ("source", "path", "seen")} for i in items]


def test_quarantined_records_are_not_counted(client, monkeypatch):
    from app import repository

    real = repository._write

    async def write(conn, events, *args, **kwargs):
        if any(e.host.startswith("BAD") for e in events):
            raise psycopg.errors.NumericValueOutOfRange("integer out of range (시험)")
        return await real(conn, events, *args, **kwargs)

    monkeypatch.setattr(repository, "_write", write)
    r = client.post("/api/ingest", json=[_rec("BAD-1", Poison=1), _rec("FS-4", Clean=1)], headers=KEY)
    assert r.json()["quarantined"] == 1
    client.portal.call(fieldstats.flush)
    assert _stats("Poison") == [] and _stats("Clean") == [("number", 1, "1")]
