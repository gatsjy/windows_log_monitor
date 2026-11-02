"""받는 곳 경로 (BACKLOG B-26) — 통합 시험: 엔진이 경로로 받는 곳을 정하고 payload 에 경로 이름을 남김, 저장 검증, 화면 요약."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패 급증
    enabled: false
    match: { event_id: "4625" }
    threshold: 1
    severity: warning
    tags: [MITRE T1110]
    notify: [운영팀]
routes:
  - name: 보안 태그
    match: { tags: [MITRE T1110] }
    notify: [보안팀]
"""


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

    from app.alerts.engine import engine
    from app.main import app

    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            assert c.post("/api/settings/groups", json={"name": "보안팀"}, headers=CSRF).status_code == 200
            Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
            engine.reload(force=True)
            event = {"date": datetime.now(UTC).isoformat(), "EventID": 4625, "Channel": "Security", "Computer": "PC-1",
                     "agent_host": "PC-1", "log_source": "winevtlog", "Message": "x", "EventData": {"TargetUserName": "kim"}}
            assert c.post("/api/ingest", json=[event], headers=KEY).json()["accepted"] == 1
            yield c
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def test_engine_uses_routed_targets_and_records_route(client):
    from app.alerts.engine import engine

    [alert_id] = client.portal.call(engine.evaluate, engine.config.rules[0], datetime.now(UTC))
    assert sorted(n for (n,) in sql("SELECT notifier FROM alert_deliveries WHERE alert_id = %s", (alert_id,))) == ["보안팀", "운영팀"]
    assert client.get(f"/api/alerts/{alert_id}").json()["payload"]["routes"] == ["보안 태그"]
    config = client.get("/api/alerts/config").json()
    assert config["routes"][0]["name"] == "보안 태그" and config["routes"][0]["notify"] == ["보안팀"]


def test_unknown_route_target_is_rejected(client):
    r = client.put("/api/alerts/config", content=RULES.replace("notify: [보안팀]", "notify: [없는팀]").encode(),
                   headers={**CSRF, "Content-Type": "text/plain"})
    assert r.status_code == 422 and "없는팀" in r.text
