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
