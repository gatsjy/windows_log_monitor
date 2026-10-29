"""수집 완전성 1단계: 늘 오던 채널이 끊긴 것 (B-37, ADR-046) — 통합 시험.

회귀: GPO 변경 등으로 DC 의 Security 수집만 끊겨도 하트비트·System 로그는 계속 와서 '연락 끊김'은 조용했고,
점검 보고서는 전체 0건·절반 이하만 봤다. 규칙은 켜져 있는데 데이터가 없는 상태가 가장 흔하고 조용한 실패다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
NOW = datetime.now(UTC)


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _history(host, channel, per_day, days, last_at, source="winevtlog"):
    """지난 며칠의 채널별 수신 (어제까지). 마지막 날의 마지막 수신 시각을 정한다."""
    for i in range(days, 0, -1):
        day = (NOW - timedelta(days=i)).date()
        last = last_at if i == 1 else datetime.combine(day, datetime.min.time(), UTC) + timedelta(hours=23)
        sql("INSERT INTO agent_streams (host, source, channel, day, n, first_at, last_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (host, source, channel, day, per_day, datetime.combine(day, datetime.min.time(), UTC), last))


def _win(host, channel, event_id):
    return {"date": NOW.isoformat(), "EventID": event_id, "Channel": channel, "Computer": host, "agent_host": host,
            "log_source": "winevtlog", "Message": "m"}


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
        # DC-01: System 로그는 지금도 오는데 Security 는 어제 저녁부터 조용하다
        assert c.post("/api/ingest", json=[_win("DC-01", "System", 7036), _win("WS-02", "System", 7036)],
                      headers=KEY).status_code == 200
        _history("DC-01", "Security", 5000, 6, NOW - timedelta(hours=7))
        _history("DC-01", "Application", 20, 6, NOW - timedelta(hours=7))   # 하루 20건 — 7시간 조용한 것은 평소
        _history("WS-02", "Security", 3000, 3, NOW - timedelta(hours=9))     # 사흘치뿐 — 평소를 말할 수 없다
        _history("OFF-1", "Security", 4000, 6, NOW - timedelta(hours=30))    # PC 자체가 끊김 — '연락 끊김'이 따로 알린다
        sql("INSERT INTO agents (host, last_seen) VALUES ('OFF-1', %s)", (NOW - timedelta(hours=30),))
        yield c


def test_ingest_counts_each_channel_per_day(client):
    assert client.post("/api/ingest", json=[_win("CNT-1", "Security", 4624)] * 3 + [_win("CNT-1", "System", 7036)],
                       headers=KEY).status_code == 200
    assert client.post("/api/ingest", json=[_win("CNT-1", "Security", 4625)], headers=KEY).status_code == 200
    rows = sql("SELECT channel, n FROM agent_streams WHERE host = 'CNT-1' AND day = %s ORDER BY channel", (NOW.date(),))
    assert rows == [("Security", 4), ("System", 1)]


def test_only_the_usual_channel_that_went_quiet_is_flagged(client):
    from app import repository

    rows = client.portal.call(repository.silent_streams, datetime.now(UTC))
    assert [(r["host"], r["channel"]) for r in rows] == [("DC-01", "Security")]
    assert rows[0]["days"] == 6 and rows[0]["quiet_limit"] == timedelta(hours=6)
    items = client.get("/api/agents", params={"since": "24h"}, headers=CSRF).json()["silent_streams"]
    assert [(s["host"], s["channel"], s["quiet_limit_sec"]) for s in items] == [("DC-01", "Security", 6 * 3600)]


def test_scoped_users_see_only_their_pcs(client):
    from fastapi.testclient import TestClient

    from app.main import app

    temp = client.post("/api/users", json={"username": "ward", "role": "viewer"}, headers=CSRF).json()
    assert client.post("/api/user-groups", json={"name": "병동", "scope_hosts": ["WS-*"], "member_ids": [temp["user"]["id"]]},
                       headers=CSRF).status_code == 200
    ward = TestClient(app)
    ward.post("/api/auth/login", json={"username": "ward", "password": temp["temp_password"]}, headers=CSRF)
    ward.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": "Scope#Member2026"},
              headers=CSRF)
    assert ward.get("/api/agents", params={"since": "24h"}, headers=CSRF).json()["silent_streams"] == []


def test_report_points_at_the_quiet_channel(client):
    from app.reports import builder, render

    payload = client.portal.call(builder.build, "daily", NOW - timedelta(days=1), NOW + timedelta(minutes=1))
    assert payload["agents"]["silent_streams_total"] == 1
    assert payload["agents"]["silent_streams"][0] | {"last_at": None} == {
        "host": "DC-01", "source": "winevtlog", "channel": "Security", "last_at": None, "per_day": 5000}
    texts = [a["text"] for a in payload["attention"]]
    assert "늘 오던 로그가 끊긴 채널 1개: DC-01 Security — 감사 정책·에이전트 설정을 확인하세요" in texts
    assert "늘 오던 로그가 끊긴 채널" in render.html(payload)


def test_old_counts_are_purged(client):
    from app import partitions

    client.portal.call(partitions.purge_agent_streams, NOW + timedelta(days=40))
    assert sql("SELECT count(*) FROM agent_streams") == [(0,)]
