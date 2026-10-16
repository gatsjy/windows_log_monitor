"""수집 → 정규화 → 검색·통계 통합 테스트 (분류, 공통 필드 사용자·IP, IIS·MSSQL)."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def _win(host, event_id, data, channel="Security", provider="Microsoft-Windows-Security-Auditing", message="m"):
    now = datetime.now(UTC)
    return {"date": now.isoformat(), "TimeCreated": now.strftime("%Y-%m-%d %H:%M:%S +0000"), "EventID": event_id,
            "Level": 0, "Keywords": "0x8010000000000000", "Channel": channel, "ProviderName": provider,
            "Computer": host, "Message": message, "EventData": data, "agent_host": host, "log_source": "winevtlog"}


def _mssql(text, process="Logon"):
    # ERRORLOG 시각에는 시간대가 없어 WLM_DISPLAY_TZ(기본 Asia/Seoul)로 해석된다
    stamp = datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S.00")
    return {"log": f"{stamp} {process:<11} {text}", "agent_host": "DB-T", "log_source": "mssql", "file": "ERRORLOG"}


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
        records = [_win("WIN-T", 4625, {"TargetUserName": "kim", "IpAddress": "203.0.113.7", "LogonType": "10"})
                   for _ in range(3)]
        records += [_win("WIN-T", 4624, {"TargetUserName": "PC01$", "IpAddress": "-"}) for _ in range(5)]
        records += [
            {"log": "#Fields: date time c-ip cs-method cs-uri-stem sc-status time-taken", "file": "W3SVC1\\u.log",
             "agent_host": "WEB-T", "log_source": "iis"},
            {"log": f"{datetime.now(UTC):%Y-%m-%d %H:%M:%S} 203.0.113.7 GET /x 500 12", "file": "W3SVC1\\u.log",
             "agent_host": "WEB-T", "log_source": "iis"},
            _mssql("Error: 18456, Severity: 14, State: 8."),
            _mssql("Login failed for user 'sa'. Reason: x [CLIENT: 198.51.100.1]"),
        ]
        r = c.post("/api/ingest", json=records, headers=KEY)
        assert r.status_code == 200 and r.json()["accepted"] == len(records) - 1  # IIS 머리줄은 저장 안 함
        yield c


def _items(client, **params):
    r = client.get("/api/events", params={"since": "1h", **params}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_category_and_common_fields(client):
    fails = _items(client, user="kim")
    assert len(fails) == 3 and {(e["category"], e["src_ip"]) for e in fails} == {("security", "203.0.113.7")}
    assert len(_items(client, ip="203.0.113.7")) == 4  # Windows 3 + IIS 1 — 소스를 가로질러 같은 IP
    assert len(_items(client, category="iis,mssql")) == 3
    assert len(_items(client, **{"f.EventData.LogonType": "10"})) == 3


def test_mssql_error_header_not_counted_twice(client):
    assert len(_items(client, event_id="18456")) == 1


def test_top_user_and_ip_skip_empty(client):
    r = client.get("/api/stats/top", params={"since": "1h", "field": "user"}, headers=CSRF)
    assert [(i["value"], i["n"]) for i in r.json()["items"]] == [("kim", 3), ("sa", 1)]
    r = client.get("/api/stats/top", params={"since": "1h", "field": "host"}, headers=CSRF)
    assert {i["value"] for i in r.json()["items"]} == {"WIN-T", "WEB-T", "DB-T"}


def test_search_requires_login(client):
    from fastapi.testclient import TestClient

    from app.main import app

    assert TestClient(app).get("/api/events").status_code == 401


def test_search_time_limit(client, monkeypatch):
    """화면 조회 쿼리는 WLM_SEARCH_TIMEOUT_SEC 를 넘으면 멈추고 503 + 그 화면에 맞는 안내 (ADR-035).
    상한은 그 요청에만 걸린다 — 같은 연결을 다음에 쓰는 수집·알림 엔진에는 남지 않는다."""
    import time
    from dataclasses import replace

    from app import db, repository
    from app.routers import query

    monkeypatch.setattr(query, "settings", replace(query.settings, search_timeout_sec=1))

    async def slow(*_args, **_kwargs):
        await db.fetch_one("SELECT pg_sleep(3)")

    monkeypatch.setattr(repository, "count", slow)
    started = time.monotonic()
    r = client.get("/api/stats/count", params={"since": "1h"}, headers=CSRF)
    assert r.status_code == 503 and "1초" in r.json()["detail"] and "따옴표" in r.json()["detail"]
    assert time.monotonic() - started < 2.5
    # 검색 문장 칸이 없는 화면에는 그 화면에서 할 수 있는 안내만
    monkeypatch.setattr(repository, "agents", slow)
    r = client.get("/api/agents", params={"since": "30d"}, headers=CSRF)
    assert r.status_code == 503 and "기간을 줄여" in r.json()["detail"] and "따옴표" not in r.json()["detail"]
    # 끝나지 않은 검색도 접속기록에 남는다 (ISMS 2.9.4)
    monkeypatch.setattr(repository, "list_events", slow)
    r = client.get("/api/events", params={"since": "1h", "query": "user:timeout-check"}, headers=CSRF)
    assert r.status_code == 503
    row = client.portal.call(db.fetch_one, "SELECT detail FROM audit_log WHERE action = 'events.search'"
                                           " ORDER BY id DESC LIMIT 1")
    assert row["detail"]["query"]["query"] == "user:timeout-check" and row["detail"]["timeout_sec"] == 1
    # 요청 밖(알림 엔진·보고서처럼 앱 안의 작업)은 상한 없음, 풀의 연결마다 SET LOCAL 이 남지 않음
    assert client.portal.call(db.fetch_one, "SELECT 1 AS ok FROM pg_sleep(1.2)")["ok"] == 1
    for _ in range(10):
        assert client.portal.call(db.fetch_one, "SHOW statement_timeout")["statement_timeout"] == "0"
    # 상한 안이면 그대로
    monkeypatch.undo()
    assert client.get("/api/stats/count", params={"since": "1h"}, headers=CSRF).status_code == 200


def test_search_slots_keep_connections_for_ingest(client):
    """상한이 걸린 조회는 SEARCH_SLOTS 개까지만 연결을 쓴다 — 느린 검색이 몰려도 수집·엔진 몫(4개)은 남는다.
    자리를 못 얻으면 상한 시간 뒤 '몰림' 안내. 자리는 시험이 직접 잡아 시간에 기대지 않는다."""
    import time

    from app import db

    async def limited(sql):
        db.limit_statement_time(1)
        return await db.fetch_one(sql)

    async def hold(n):
        for _ in range(n):
            await db._search_slots.acquire()

    async def free(n):
        for _ in range(n):
            db._search_slots.release()

    client.portal.call(hold, db.SEARCH_SLOTS)
    try:
        started = time.monotonic()
        with pytest.raises(db.QueryTimeout) as info:
            client.portal.call(limited, "SELECT 1")
        assert info.value.busy and 0.9 < time.monotonic() - started < 2
        # 상한 없는 작업(수집·알림 엔진)은 자리와 무관하게 바로
        started = time.monotonic()
        assert client.portal.call(db.fetch_one, "SELECT 1 AS ok")["ok"] == 1
        assert time.monotonic() - started < 0.5
    finally:
        client.portal.call(free, db.SEARCH_SLOTS)
    assert client.portal.call(limited, "SELECT 1 AS ok")["ok"] == 1
    assert db.POOL_MAX - db.SEARCH_SLOTS >= 4


def test_other_cancel_is_not_a_timeout(client):
    """관리자의 pg_cancel_backend 같은 다른 취소는 '시간 초과' 안내로 바꾸지 않는다."""
    import asyncio

    import psycopg

    from app import db

    async def run():
        db.limit_statement_time(30)

        async def cancel_soon():
            await asyncio.sleep(0.5)
            async with await db.connect_autocommit() as conn:
                await conn.execute("SELECT pg_cancel_backend(pid) FROM pg_stat_activity"
                                   " WHERE query = 'SELECT pg_sleep(5)' AND pid <> pg_backend_pid()")

        task = asyncio.create_task(cancel_soon())
        try:
            await db.fetch_one("SELECT pg_sleep(5)")
        finally:
            await task

    with pytest.raises(psycopg.errors.QueryCanceled) as info:
        client.portal.call(run)
    assert not isinstance(info.value, db.QueryTimeout)


def test_search_routes_have_time_limit(client, monkeypatch):
    """이벤트를 읽는 화면 API 는 모두 시간 상한을 건다. 수집·로그인·쓰기(PC 삭제)는 걸지 않는다 (실제로 불러서 확인)."""
    from app import db

    seen = []
    monkeypatch.setattr(db, "limit_statement_time", seen.append)

    def limited(method, path, **kw):
        seen.clear()
        client.request(method, path, **{"headers": CSRF, **kw})
        return bool(seen)

    for path in ("/api/events?since=1h", "/api/events/999999", "/api/stats/count?since=1h",
                 "/api/stats/timeseries?since=1h", "/api/stats/top?since=1h&field=host", "/api/stats/summary",
                 "/api/agents", "/api/fields", "/api/search/parse?query=host:A"):
        assert limited("GET", path), path
    rule = {"name": "미리보기", "severity": "error", "match": {"event_id": "4625"}, "group_by": "ip",
            "window_sec": 600, "threshold": 2, "cooldown_sec": 3600}
    assert limited("POST", "/api/alerts/rules/preview", json={"rule": rule})
    assert not limited("POST", "/api/ingest", json=[], headers=KEY)
    assert not limited("GET", "/api/auth/me")
    # 쓰기는 잠금을 기다려서라도 끝낸다
    assert not limited("DELETE", "/api/agents/NO-SUCH-PC")
    assert not limited("POST", "/api/agents/delete", json={"hosts": ["NO-SUCH-PC"]})
