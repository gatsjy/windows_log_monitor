"""Windows 이벤트 해석 (BACKLOG B-68) — 목록·상세·실시간의 한 줄 요약과 계정 잠김 원인 추적. 통합 시험."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
NOW = datetime.now(UTC).replace(microsecond=0)


def _win(event_id, data, minutes_ago, host="DC-01"):
    at = NOW - timedelta(minutes=minutes_ago)
    return {"date": at.isoformat(), "TimeCreated": at.strftime("%Y-%m-%d %H:%M:%S +0000"), "EventID": event_id, "Level": 0,
            "Keywords": "0x8010000000000000", "Channel": "Security", "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": host, "Message": "긴 Windows 메시지", "EventData": data, "agent_host": host, "log_source": "winevtlog"}


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
        records = [
            # 잠김 20분 전부터: 사무실 PC(10.0.0.5)의 오래된 비밀번호로 Kerberos 실패 3번, 다른 곳에서 NTLM 실패 1번
            *[_win(4771, {"TargetUserName": "kim", "Status": "0x18", "IpAddress": "::ffff:10.0.0.5"}, 20 - n) for n in range(3)],
            _win(4776, {"TargetUserName": "kim", "Workstation": "LAPTOP-9", "Status": "0xc000006a"}, 15),
            _win(4625, {"TargetUserName": "lee", "Status": "0xc000006d", "SubStatus": "0xc000006a", "LogonType": "3",
                        "IpAddress": "10.0.0.7"}, 14),                      # 다른 사용자 — 섞이지 않아야
            _win(4771, {"TargetUserName": "kim", "Status": "0x18", "IpAddress": "10.0.0.5"}, 120),   # 30분 창 밖
            _win(4740, {"TargetUserName": "kim", "TargetDomainName": "PC-OFFICE-1", "SubjectUserName": "DC-01$"}, 10),
        ]
        assert c.post("/api/ingest", json=records, headers=KEY).json()["accepted"] == len(records)
        yield c


def _items(client, **params):
    r = client.get("/api/events", params={"since": "6h", **params}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_list_and_detail_show_summary_and_decoded_codes(client):
    [lock] = _items(client, query="event_id:4740")
    assert lock["summary"] == "kim 계정 잠김 — 잠금을 일으킨 PC PC-OFFICE-1" and "edata" not in lock
    [failed] = _items(client, query="event_id:4625")
    assert failed["summary"] == "lee 로그온 실패 — 비밀번호가 틀림, 네트워크(공유 폴더·원격 관리 등), 접속지 10.0.0.7"
    detail = client.get(f"/api/events/{failed['id']}", headers=CSRF).json()
    assert detail["summary"] == failed["summary"]
    assert {d["field"]: d["meaning"] for d in detail["decoded"]} == {
        "Status": "사용자 이름 또는 인증 정보가 틀림", "SubStatus": "비밀번호가 틀림", "LogonType": "네트워크(공유 폴더·원격 관리 등)"}


def test_live_events_carry_the_summary():
    from app.normalizers import normalize

    ev = normalize(_win(4771, {"TargetUserName": "kim", "Status": "0x18", "IpAddress": "10.0.0.5"}, 1), NOW)
    assert ev.to_live(NOW)["summary"].startswith("kim Kerberos 사전 인증 실패")


def test_lockout_cause_groups_failures_around_the_lock(client):
    [lock] = _items(client, query="event_id:4740")
    r = client.get(f"/api/events/{lock['id']}/lockout", headers=CSRF)
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["username"] == "kim"
    rows = {(i["ip"], i["event_id"]): i["n"] for i in res["items"]}
    assert rows == {("10.0.0.5", 4771): 3, (None, 4776): 1}          # 30분 창 밖·다른 사용자는 빠진다
    assert res["items"][0]["ip"] == "10.0.0.5"                        # 가장 많은 곳 먼저
    [other] = _items(client, query="event_id:4625")
    assert client.get(f"/api/events/{other['id']}/lockout", headers=CSRF).status_code == 400
    [(n,)] = psycopg.connect(os.environ["WLM_DATABASE_URL"]).execute(
        "SELECT count(*) FROM audit_log WHERE action = 'events.lockout'").fetchall()
    assert n == 1
