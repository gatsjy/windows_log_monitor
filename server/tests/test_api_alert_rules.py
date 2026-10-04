"""규칙 관리 API 통합 테스트: 추가 → 수정(이름 변경) → 켜기/끄기 → 미리보기 → 삭제, 검증 오류."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULE = {"name": "RDP 실패", "group": "계정·인증 공격", "severity": "error", "match": {"event_id": "4625"},
        "group_by": "ip", "window_sec": 600, "threshold": 2, "cooldown_sec": 3600,
        "tags": "MITRE T1110, ISMS 2.11.3", "notify": ["운영팀"]}


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
        now = datetime.now(UTC).isoformat()
        events = [{"date": now, "EventID": 4625, "Channel": "Security", "agent_host": "PC-T", "log_source": "winevtlog",
                   "EventData": {"TargetUserName": "kim", "IpAddress": "203.0.113.9"}} for _ in range(3)]
        assert c.post("/api/ingest", json=events, headers={"X-API-Key": "test-key"}).status_code == 200
        yield c


def rules(client):
    return {r["name"]: r for r in client.get("/api/alerts/config", headers=CSRF).json()["rules"]}


def test_rule_lifecycle(client):
    r = client.put("/api/alerts/rules", json={"rule": RULE}, headers=CSRF)
    assert r.status_code == 200, r.text
    saved = rules(client)["RDP 실패"]
    assert (saved["sid"], saved["group"], saved["threshold"], saved["group_by"]) == (1000001, "계정·인증 공격", 2, "ip")
    assert saved["tags"] == ["MITRE T1110", "ISMS 2.11.3"]

    r = client.put("/api/alerts/rules", json={"original": "RDP 실패", "rule": {**RULE, "name": "RDP 실패 급증", "sid": 1000001}},
                   headers=CSRF)
    assert r.status_code == 200, r.text
    assert set(rules(client)) == {"RDP 실패 급증"}

    assert client.post("/api/alerts/rules/enabled", json={"names": ["RDP 실패 급증"], "enabled": False},
                       headers=CSRF).status_code == 200
    assert rules(client)["RDP 실패 급증"]["enabled"] is False

    p = client.post("/api/alerts/rules/preview", json={"rule": RULE}, headers=CSRF).json()
    assert p["matched"] == 3 and p["fires"] == 1 and p["groups"][0]["key"] == "203.0.113.9"

    assert client.delete("/api/alerts/rules/RDP 실패 급증", headers=CSRF).status_code == 200
    assert rules(client) == {}


def test_validation_errors(client):
    assert client.put("/api/alerts/rules", json={"rule": {**RULE, "notify": ["없는그룹"]}}, headers=CSRF).status_code == 422
    assert client.put("/api/alerts/rules", json={"rule": {**RULE, "match": {"bogus": "1"}}}, headers=CSRF).status_code == 422
    assert client.put("/api/alerts/rules", json={"rule": {**RULE, "name": ""}}, headers=CSRF).status_code == 422
    assert client.put("/api/alerts/rules", json={"rule": RULE}, headers=CSRF).status_code == 200
    assert client.put("/api/alerts/rules", json={"rule": RULE}, headers=CSRF).status_code == 409
    assert client.delete("/api/alerts/rules/없는 규칙", headers=CSRF).status_code == 404


def test_audit_records_rule_changes(client):
    actions = {a["action"] for a in client.get("/api/audit", params={"since": "1h"}, headers=CSRF).json()["items"]}
    assert {"alerts.rule.save", "alerts.rule.toggle", "alerts.rule.delete"} <= actions
