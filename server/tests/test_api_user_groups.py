"""사용자 그룹: 기능 권한과 조회 범위가 서버 API 에서 실제로 적용되는지."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Team#Member2026"


def _win(host, event_id, channel="Security", provider="Microsoft-Windows-Security-Auditing"):
    now = datetime.now(UTC)
    return {"date": now.isoformat(), "TimeCreated": now.strftime("%Y-%m-%d %H:%M:%S +0000"), "EventID": event_id,
            "Level": 4, "Channel": channel, "ProviderName": provider, "Computer": host, "Message": "m",
            "agent_host": host, "log_source": "winevtlog"}


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    # 다른 테스트 모듈이 남긴 규칙 파일(지금 DB 에 없는 수신 그룹을 참조할 수 있음)을 비우고 시작
    from pathlib import Path

    Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as admin:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        stamp = datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S.00")
        events = [_win("MED-01", 4625), _win("med-02", 4624), _win("WEB-T", 7036, "System", "Service Control Manager"),
                  {"log": f"{stamp} Logon       Login failed for user 'sa'. [CLIENT: 10.0.0.5]",
                   "agent_host": "DB-T", "log_source": "mssql", "file": "ERRORLOG"}]
        assert admin.post("/api/ingest", json=events, headers={"X-API-Key": "test-key"}).json()["accepted"] == 4

        users, clients = {}, {}
        for name in ("db-user", "med-user", "sec-user", "both-user"):
            temp = admin.post("/api/users", json={"username": name, "role": "viewer"}, headers=CSRF).json()
            users[name] = temp["user"]["id"]
            c = TestClient(app)
            c.post("/api/auth/login", json={"username": name, "password": temp["temp_password"]}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD}, headers=CSRF)
            clients[name] = c

        def group(name, **kw):
            r = admin.post("/api/user-groups", json={"name": name, **kw}, headers=CSRF)
            assert r.status_code == 200, r.text
            return r.json()

        group("DB팀", scope_categories=["mssql"], member_ids=[users["db-user"], users["both-user"]])
        group("의료정보과", scope_hosts=["MED-*"], member_ids=[users["med-user"], users["both-user"]])
        group("보안팀", permissions=["alerts.manage", "audit.view"], member_ids=[users["sec-user"]])
        yield admin, clients


def hosts(client, **params):
    r = client.get("/api/events", params={"since": "1h", **params}, headers=CSRF)
    assert r.status_code == 200, r.text
    return sorted({e["host"] for e in r.json()["items"]})


def test_scope_by_category(ctx):
    _, c = ctx
    assert hosts(c["db-user"]) == ["DB-T"]
    top = c["db-user"].get("/api/stats/top", params={"field": "host", "since": "1h"}, headers=CSRF).json()["items"]
    assert [t["value"] for t in top] == ["DB-T"]
    assert [a["host"] for a in c["db-user"].get("/api/agents", headers=CSRF).json()["items"]] == ["DB-T"]


def test_scope_by_host_pattern_is_case_insensitive(ctx):
    _, c = ctx
    assert hosts(c["med-user"]) == ["MED-01", "med-02"]
    other = hosts(ctx[0], host="WEB-T")
    assert other == ["WEB-T"]
    web_id = ctx[0].get("/api/events", params={"since": "1h", "host": "WEB-T"}, headers=CSRF).json()["items"][0]["id"]
    assert c["med-user"].get(f"/api/events/{web_id}", headers=CSRF).status_code == 404


def test_multiple_groups_union_and_unscoped(ctx):
    admin, c = ctx
    assert hosts(c["both-user"]) == ["DB-T", "MED-01", "med-02"]
    assert hosts(c["sec-user"]) == ["DB-T", "MED-01", "WEB-T", "med-02"]   # 범위 없는 그룹 → 전체
    assert hosts(admin) == ["DB-T", "MED-01", "WEB-T", "med-02"]


def test_permissions(ctx):
    _, c = ctx
    rule = {"name": "보안팀 규칙", "match": {"event_id": "4625"}, "notify": ["운영팀"], "window_sec": 300, "threshold": 1}
    assert c["db-user"].put("/api/alerts/rules", json={"rule": rule}, headers=CSRF).status_code == 403
    saved = c["sec-user"].put("/api/alerts/rules", json={"rule": rule}, headers=CSRF)
    assert saved.status_code == 200, saved.text
    assert c["sec-user"].get("/api/audit", headers=CSRF).status_code == 200
    assert c["db-user"].get("/api/audit", headers=CSRF).status_code == 403
    assert c["sec-user"].get("/api/users", headers=CSRF).status_code == 403          # 사용자 관리는 관리자만
    assert c["sec-user"].get("/api/settings/contacts", headers=CSRF).status_code == 403
    me = c["both-user"].get("/api/auth/me", headers=CSRF).json()
    assert me["groups"] == ["DB팀", "의료정보과"] and me["scope"] and me["permissions"] == []


def test_group_validation_and_listing(ctx):
    admin, _ = ctx
    assert admin.post("/api/user-groups", json={"name": "DB팀"}, headers=CSRF).status_code == 409
    assert admin.post("/api/user-groups", json={"name": "x", "permissions": ["users.manage"]}, headers=CSRF).status_code == 400
    assert admin.post("/api/user-groups", json={"name": "x", "scope_hosts": ["A%"]}, headers=CSRF).status_code == 400
    listing = admin.get("/api/user-groups", headers=CSRF).json()
    assert {g["name"] for g in listing["items"]} == {"DB팀", "의료정보과", "보안팀"} and "alerts.manage" in listing["permissions"]
    users = {u["username"]: u["groups"] for u in admin.get("/api/users", headers=CSRF).json()["items"]}
    assert users["both-user"] == ["DB팀", "의료정보과"]
