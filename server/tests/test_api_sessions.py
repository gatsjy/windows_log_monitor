"""로그온 세션 보기 (BACKLOG B-63) — 통합 시험.

4624 를 같은 PC 의 4634/4647 과 TargetLogonId 로 짝짓는다. Logon ID 는 재부팅 뒤 다시 쓰일 수 있어 PC·최대 시간·
'그 사이 같은 ID 의 새 로그온' 경계가 필요하다. 레코드는 실제 에이전트 모양(StringInserts 만 — 이름은 서버가 붙인다, ADR-038).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
T0 = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=40)


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _win(host, event_id, at, **fields):
    from app.normalizers.win_templates import SECURITY, TEMPLATES

    names = TEMPLATES[(SECURITY, event_id)]
    inserts = [fields.get(n, "-") for n in names]
    return {"date": at.isoformat(), "EventID": event_id, "Version": 0, "Channel": "Security", "Computer": host,
            "ProviderName": "Microsoft-Windows-Security-Auditing", "agent_host": host, "log_source": "winevtlog",
            "Message": f"{event_id}", "StringInserts": inserts}


def _logon(host, at, lid, user="kim", logon_type=10, ip="10.0.0.9"):
    return _win(host, 4624, at, TargetUserName=user, TargetLogonId=lid, LogonType=logon_type, IpAddress=ip)


def _logoff(host, at, lid, event_id=4634, user="kim"):
    return _win(host, event_id, at, TargetUserName=user, TargetLogonId=lid, LogonType=10)


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

    m = lambda n: T0 + timedelta(minutes=n)
    records = [
        _logon("PC-1", m(0), "0x1"), _logoff("PC-1", m(30), "0x1"),                       # 30분
        _logon("PC-1", m(5), "0x2", user="lee", logon_type=3),                             # 로그오프 없음
        _logon("PC-1", m(10), "0x3"), _logon("PC-1", m(20), "0x3"),                        # 재부팅 뒤 같은 ID
        _logoff("PC-1", m(25), "0x3"),                                                     # → 두 번째 것의 끝
        _logon("PC-1", m(40), "0x4"), _logoff("PC-1", m(55), "0x4", event_id=4647),        # 사용자가 시작한 로그오프
        _logon("PC-2", m(0), "0x5"), _logoff("PC-1", m(10), "0x5"),                        # 다른 PC 의 같은 ID 는 짝 아님
        _logon("PC-2", m(1), "0x6"), _logoff("PC-2", m(60 * 30), "0x6"),                   # 30시간 뒤
    ]
    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        assert c.post("/api/ingest", json=records, headers=KEY).json()["accepted"] == len(records)
        yield c


def _sessions(client, **params):
    r = client.get("/api/stats/sessions", params={"since": "3d", **params})
    assert r.status_code == 200, r.text
    return r.json()


def _by_id(body):
    return {s["logon_id"]: s for s in body["items"]}


def test_pairs_by_host_and_logon_id(client):
    s = _by_id(_sessions(client))
    assert s["0x1"]["end_event"] == 4634 and s["0x1"]["duration_sec"] == 1800
    assert s["0x1"]["username"] == "kim" and s["0x1"]["src_ip"] == "10.0.0.9" and s["0x1"]["logon_type"] == "10"
    assert s["0x2"]["end_ts"] is None and s["0x2"]["duration_sec"] is None and s["0x2"]["logon_type"] == "3"
    assert s["0x4"]["end_event"] == 4647 and s["0x4"]["duration_sec"] == 900
    assert s["0x5"]["end_ts"] is None                     # PC-1 의 로그오프는 PC-2 로그온의 끝이 아니다


def test_reused_logon_id_ends_at_the_next_logon(client):
    rows = [r for r in _sessions(client)["items"] if r["logon_id"] == "0x3"]
    first, second = sorted(rows, key=lambda r: r["ts"])
    assert first["end_ts"] is None                        # 그 사이 같은 ID 의 새 로그온 → 첫 로그온의 끝이 아님
    assert second["duration_sec"] == 300


def test_max_hours_and_conditions(client):
    assert _by_id(_sessions(client))["0x6"]["end_ts"] is None
    assert _by_id(_sessions(client, max_hours=48))["0x6"]["duration_sec"] == 30 * 3600 - 60
    assert {r["host"] for r in _sessions(client, query="host:PC-2")["items"]} == {"PC-2"}
    assert {r["username"] for r in _sessions(client, query="-user:kim")["items"]} == {"lee"}
    assert _sessions(client, query="event_id:4625")["items"] == []     # 다른 이벤트 ID 조건과는 겹치지 않음
    body = _sessions(client, limit=2)
    assert len(body["items"]) == 2 and body["truncated"] is True
    assert client.get("/api/stats/sessions", params={"since": "3d", "max_hours": 0}).status_code == 422


def test_access_logged(client):
    sql("SET session_replication_role = origin")
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'events.sessions' ORDER BY id LIMIT 1")
    assert detail["query"]["since"] == "3d" and detail["rows"] >= 6
