"""다 찬 월 파티션 색인 다시 만들기 (ADR-067) — DB 시험: 받는 순서로 넣은 (값, ts DESC) 색인이 반쯤 빈 것을 한 번 다시 만들어 줄이고,
부모 색인에 붙은 채로 남는다. 이번 달·곧 지울 달·복원해 잠시 두는 달·낮 시간은 건너뛰고, 중간에 멈춘 조각은 지운다."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
NOW = datetime.now(UTC)
THIS_MONTH = NOW.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
LAST_MONTH = (THIS_MONTH - timedelta(days=1)).replace(day=1)
LAST = f"events_{LAST_MONTH:%Y_%m}"
CURRENT = f"events_{THIS_MONTH:%Y_%m}"
NIGHT = THIS_MONTH + timedelta(days=1, hours=17)   # 다음 날 02시 (Asia/Seoul) — 달이 바뀐 지 6시간이 넘음


def sql(query, params=None):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _fill(partition_start: datetime, n: int) -> None:
    """받는 순서(시각이 느는 순서)로 작은 묶음씩 — 수집과 같은 모양이라 ts DESC 색인 잎이 반쯤 빈다."""
    for lo in range(0, n, 500):
        sql("INSERT INTO events (received_at, ts, host, source, level, category, event_id, message, raw)"
            " SELECT %(start)s + make_interval(secs => g), %(start)s + make_interval(secs => g), 'PC-' || mod(g, 40), 'winevtlog', 4,"
            "        (ARRAY['auth','system','account'])[1 + mod(g, 3)], 4624 + mod(g, 5),"
            "        'logon of user' || mod(g, 97) || ' from host ' || mod(g, 40), '{}'"
            "   FROM generate_series(%(lo)s::int, %(hi)s::int) g",
            {"start": partition_start, "lo": lo, "hi": min(lo + 499, n - 1)})


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
        sql(f"CREATE TABLE IF NOT EXISTS {LAST} PARTITION OF events FOR VALUES FROM ('{LAST_MONTH:%Y-%m-%d}') TO ('{THIS_MONTH:%Y-%m-%d}')")
        _fill(LAST_MONTH, 20_000)
        _fill(THIS_MONTH, 2_000)
        yield c


def _indexes(partition: str) -> dict:
    rows = sql("SELECT count(*), count(*) FILTER (WHERE x.indisvalid), count(ih.inhparent), pg_indexes_size(%s::regclass)"
               "  FROM pg_index x LEFT JOIN pg_inherits ih ON ih.inhrelid = x.indexrelid WHERE x.indrelid = %s::regclass",
               (partition, partition))
    n, valid, attached, size = rows[0]
    return {"n": n, "valid": valid, "attached": attached, "bytes": size}


def test_daytime_does_nothing(client):
    from app import partitions

    noon = THIS_MONTH + timedelta(days=1, hours=3)   # 12시 (Asia/Seoul)
    assert client.portal.call(partitions.compact_closed_partitions, noon) == []
    assert sql("SELECT count(*) FROM partition_compactions") == [(0,)]


def test_leftover_of_a_stopped_reindex_is_dropped(client):
    """REINDEX CONCURRENTLY 가 중간에 멈추면 INVALID 조각(…_ccnew)이 남아 수집 때마다 거기에도 쓴다 — 다음 번에 지운다."""
    sql(f"CREATE INDEX {LAST}_host_ts_idx_ccnew ON {LAST} (host, ts DESC)")
    sql("UPDATE pg_index SET indisvalid = false WHERE indexrelid = %s::regclass", (f"{LAST}_host_ts_idx_ccnew",))
    sql(f"INSERT INTO partition_holds (name, hold_until, created_by) VALUES ('{LAST}', now() + interval '1 day', 'admin')")
    from app import partitions

    # 복원해 잠시 두는 달은 건너뛴다 (조각도 그대로 — 그 달을 다시 만들 때 지운다)
    assert client.portal.call(partitions.compact_closed_partitions, NIGHT) == []
    sql("DELETE FROM partition_holds")
    assert sql("SELECT count(*) FROM pg_class WHERE relname = %s", (f"{LAST}_host_ts_idx_ccnew",)) == [(1,)]


def test_soon_dropped_month_is_skipped(client, monkeypatch):
    from app import partitions
    from app.config import settings

    # 일주일 안에 보관 파일로 옮겨 지울 달
    monkeypatch.setattr(partitions, "settings", replace(settings, db_retention_days=5))
    assert client.portal.call(partitions.compact_closed_partitions, NIGHT) == []


def test_closed_month_is_rebuilt_once_and_stays_attached(client):
    from app import partitions

    before, current = _indexes(LAST), _indexes(CURRENT)
    assert before["n"] == before["valid"] + 1 == before["attached"] + 1   # 남은 조각은 부모 색인에 붙지 않은 INVALID
    assert client.portal.call(partitions.compact_closed_partitions, NIGHT) == [LAST]
    after = _indexes(LAST)
    assert after["n"] == after["valid"] == after["attached"] == before["attached"]   # 조각은 지우고 붙은 색인은 그대로
    assert after["bytes"] < before["bytes"] * 0.75, (before, after)   # 실측 약 40% 줄어듦
    rows = sql("SELECT name, index_bytes_before, index_bytes_after FROM partition_compactions")
    # 기록의 '전' 크기는 조각을 지운 뒤에 잰 것 (조각 크기만큼 시험의 '전'보다 작다)
    assert [(n, a) for n, _, a in rows] == [(LAST, after["bytes"])] and after["bytes"] < rows[0][1] < before["bytes"]
    # 이번 달은 아직 받는 중이라 그대로, 같은 달은 두 번 하지 않는다
    assert _indexes(CURRENT) == current
    assert client.portal.call(partitions.compact_closed_partitions, NIGHT) == []
    # 다시 만든 뒤에도 검색은 같은 색인으로 같은 결과
    n = sql(f"SELECT count(*) FROM events WHERE category = 'auth' AND received_at < '{THIS_MONTH:%Y-%m-%d}'")[0][0]
    assert n == len([g for g in range(20_000) if g % 3 == 0])


def test_record_of_a_dropped_month_is_forgotten(client):
    """로테이션이 지운(또는 복원으로 다시 만든) 달의 기록은 지운다 — 같은 이름의 새 파티션은 새 oid 라 다시 한다."""
    from app import partitions

    sql(f"DROP TABLE {LAST}")
    assert client.portal.call(partitions.compact_closed_partitions, NIGHT) == []
    assert sql("SELECT count(*) FROM partition_compactions") == [(0,)]
