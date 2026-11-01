"""하트비트로 PC 시계 차이 (BACKLOG B-57 1단계) — 통합 시험.

차이 = 받은 시각 − PC 시각 = 시계 차이 + 전송 지연. 지연은 0 이상이라 창 두 개(15분씩)의 최솟값을 시계 차이로 본다.
에이전트는 이미 하트비트에 date(PC 시계)를 넣어 보낸다 — 정규화기가 버리던 값이라 에이전트를 다시 설치할 필요가 없다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


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


def _beat(client, host, behind_sec=None):
    """behind_sec: PC 시계가 서버보다 이만큼 늦게 찍은 하트비트(음수면 빠름). None 이면 date 없음."""
    hb = {"type": "heartbeat", "host": host, "config_version": "0.4.1"}
    if behind_sec is not None:
        hb["date"] = (datetime.now(UTC) - timedelta(seconds=behind_sec)).isoformat().replace("+00:00", "Z")
    assert client.post("/api/ingest", json=[hb], headers=KEY).status_code == 200


def _offset(client, host):
    return next(a for a in client.get("/api/agents").json()["items"] if a["host"] == host)["clock_offset_ms"]


def test_offset_is_minimum_over_two_windows(client):
    _beat(client, "PC-A", 90)
    assert abs(_offset(client, "PC-A") - 90_000) < 3_000
    _beat(client, "PC-A", 200)            # 재시도로 늦게 온 하트비트 — 시계 차이가 커진 것이 아니다
    assert abs(_offset(client, "PC-A") - 90_000) < 3_000
    _beat(client, "PC-A")                 # 시각 없는 하트비트는 값을 바꾸지 않는다
    assert abs(_offset(client, "PC-A") - 90_000) < 3_000
    # 창이 바뀌어도 앞 창의 최솟값이 남는다 → 창이 막 바뀐 직후 지연 큰 값 하나로 튀지 않음
    sql("UPDATE agents SET clock_window_at = now() - interval '16 minutes' WHERE host = 'PC-A'")
    _beat(client, "PC-A", 150)
    assert abs(_offset(client, "PC-A") - 90_000) < 3_000
    # 한 창이 더 지나면 옛 값(90초)은 빠진다
    sql("UPDATE agents SET clock_window_at = now() - interval '16 minutes' WHERE host = 'PC-A'")
    _beat(client, "PC-A", 120)
    assert abs(_offset(client, "PC-A") - 120_000) < 3_000
    # PC 시계를 고치면 바로 작은 값이 최솟값이 된다
    _beat(client, "PC-A", 0)
    assert abs(_offset(client, "PC-A")) < 3_000


def test_pc_ahead_and_unknown(client):
    _beat(client, "PC-B", -400)           # PC 시계가 6분 40초 빠름
    item = next(a for a in client.get("/api/agents").json()["items"] if a["host"] == "PC-B")
    assert item["clock_offset_ms"] < -390_000 and item["clock_level"] == "bad"
    _beat(client, "PC-C")                 # 옛 에이전트처럼 date 가 없으면 모름
    assert _offset(client, "PC-C") is None
    sql("UPDATE agents SET last_heartbeat_at = now() - interval '31 minutes' WHERE host = 'PC-B'")
    assert _offset(client, "PC-B") is None   # 하트비트가 오래 끊기면 모른다(옛 값을 보이지 않음)


def test_server_clock_suspected(client):
    for i in range(5):
        _beat(client, f"PC-S{i}", 130)
    body = client.get("/api/agents").json()
    assert body["clock"]["server_suspect"] and "서버 시계" in body["clock"]["server_suspect"]["text"]
    from app import readiness

    items = {i.key: i for i in readiness.judge(client.portal.call(readiness.collect))}
    assert items["clock"].status == "bad" and "서버" in items["clock"].detail
