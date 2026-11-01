"""수집 대상 대조 (BACKLOG B-55) — 통합 시험.

회귀: 수집 PC 화면은 한 번이라도 보낸 PC 만 보여, 에이전트를 설치하지 않은 중요 서버는 어디에도 나타나지 않았다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Viewer#Pass2026"


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _event(host):
    return {"date": datetime.now(UTC).isoformat(), "EventID": 4624, "Level": 4, "Channel": "Security", "Computer": host,
            "agent_host": host, "ProviderName": "Microsoft-Windows-Security-Auditing", "log_source": "winevtlog", "Message": "m"}


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as admin:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        # 짧은 이름·FQDN·목록에 없는 PC, 그리고 8일 전에 끊긴 PC
        events = [_event("DC-01"), _event("db-01.corp.local"), _event("OTHER-PC"), _event("WEB-01")]
        assert admin.post("/api/ingest", json=events, headers={"X-API-Key": "test-key"}).json()["accepted"] == 4
        sql("UPDATE agents SET last_seen = now() - interval '8 days' WHERE host = 'WEB-01'")
        temp = admin.post("/api/users", json={"username": "viewer", "role": "viewer"}, headers=CSRF).json()
        viewer = TestClient(app)
        viewer.post("/api/auth/login", json={"username": "viewer", "password": temp["temp_password"]}, headers=CSRF)
        viewer.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD}, headers=CSRF)
        yield {"admin": admin, "viewer": viewer}


def test_no_list_means_nothing_to_compare(ctx):
    cov = ctx["admin"].get("/api/agents/assets", headers=CSRF).json()
    assert cov["total"] == 0 and cov["percent"] is None and cov["unexpected"] == 4


def test_list_is_compared_with_the_pcs_that_send(ctx):
    admin = ctx["admin"]
    r = admin.put("/api/agents/assets", json={"text": "DC-01,중요\nDB-01,중요\nWEB-01\nEMR-01,중요\n<bad>\n"}, headers=CSRF)
    assert r.status_code == 200, r.text
    cov = r.json()
    assert (cov["total"], cov["collecting"], cov["missing_total"], cov["critical_missing"], cov["unexpected"]) == (4, 2, 2, 1, 1)
    assert cov["percent"] == 50.0 and len(cov["problems"]) == 1
    # 중요하고 한 번도 안 온 것이 맨 앞
    assert [(m["name"], m["status"]) for m in cov["missing"]] == [("EMR-01", "never"), ("WEB-01", "silent")]
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'agent.assets.save'")
    assert detail["count"] == 4 and detail["critical"] == 3


def test_report_and_readiness_show_missing_systems(ctx):
    from app import readiness
    from app.reports import builder, render

    now = datetime.now(UTC)
    payload = ctx["admin"].portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    listed = payload["agents"]["assets"]
    assert listed["total"] == 4 and listed["critical_missing"] == 1
    assert any("로그가 오지 않는 중요 시스템 1대: EMR-01" in a["text"] for a in payload["attention"])
    page = render.html(payload, 1)
    assert "수집 대상 대조" in page and "EMR-01" in page and "한 번도 없음" in page
    old = {**payload, "agents": {k: v for k, v in payload["agents"].items() if k != "assets"}}
    assert "수집 대상 대조" not in render.html(old, 1)   # B-55 이전 보고서
    items = {i.key: i for i in readiness.judge(ctx["admin"].portal.call(readiness.collect))}
    assert items["assets"].status == "bad" and "EMR-01" in items["assets"].detail


def test_admin_only_and_clear(ctx):
    assert ctx["viewer"].get("/api/agents/assets", headers=CSRF).status_code == 403
    assert ctx["viewer"].put("/api/agents/assets", json={"text": "X"}, headers=CSRF).status_code == 403
    assert ctx["admin"].put("/api/agents/assets", json={"text": "<bad>"}, headers=CSRF).status_code == 400
    assert ctx["admin"].get("/api/agents/assets", headers=CSRF).json()["total"] == 4    # 잘못된 목록은 저장하지 않는다
    assert ctx["admin"].delete("/api/agents/assets", headers=CSRF).status_code == 200
    assert ctx["admin"].get("/api/agents/assets", headers=CSRF).json()["total"] == 0
    assert sql("SELECT count(*) FROM agents")[0][0] == 4    # PC 삭제(/api/agents/{host})로 가지 않았다
