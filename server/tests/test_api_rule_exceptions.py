"""알림 규칙 예외 (BACKLOG B-46) — 통합 시험.

백업·의료장비 연동 서비스 계정, 유지보수 업체 IP 같은 영구적·필드 단위 제외를 규칙 문장에 직접 쓰면 누가·왜·언제까지 뺐는지 남지 않았다.
예외는 조건 하나, 엔진이 규칙 문장에 제외 항으로 합친다(값이 없는 이벤트는 남기는 검색 문장의 제외 의미).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Viewer#Pass2026x"
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패 급증
    enabled: false
    match: { query: "event_id:4625" }
    window: 10m
    threshold: 3
    group_by: host
    cooldown: 1h
    severity: warning
    notify: [없는대상]
  - name: PC 끊김
    kind: agent_silent
    enabled: false
    silent_for: 1h
    notify: [없는대상]
"""


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _event(host, user):
    data = {"TargetUserName": user} if user else {}
    return {"date": datetime.now(UTC).isoformat(), "EventID": 4625, "Channel": "Security", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": "로그온 실패", "EventData": data}


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.alerts.engine import engine
    from app.main import app

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    try:
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            events = ([_event("BACKUP-01", "svc_backup") for _ in range(4)] + [_event("PC-07", "kim") for _ in range(3)]
                      + [_event("PC-09", None) for _ in range(3)])        # 사용자가 없는 이벤트 — 제외 조건에 걸리지 않는다
            assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == len(events)
            temp = admin.post("/api/users", json={"username": "viewer", "role": "viewer"}, headers=CSRF).json()
            viewer = TestClient(app)
            viewer.post("/api/auth/login", json={"username": "viewer", "password": temp["temp_password"]}, headers=CSRF)
            viewer.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD},
                        headers=CSRF)
            yield {"admin": admin, "viewer": viewer}
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _fired_hosts(client):
    """규칙을 지금 평가해 알림이 난 PC (재알림 간격에 걸리지 않게 앞 알림은 지운다 — 시험 DB)."""
    from app.alerts.engine import engine

    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute("DELETE FROM alert_notes")
        conn.execute("DELETE FROM alert_deliveries")
        conn.execute("DELETE FROM alerts")
    client.portal.call(engine.evaluate, engine.config.rules[0], datetime.now(UTC))
    return sorted(r[0] for r in sql("SELECT group_key FROM alerts WHERE rule = '로그온 실패 급증'"))


def _add(client, **body):
    return client.post("/api/alerts/exceptions", json={"rule": "로그온 실패 급증", **body}, headers=CSRF)


def test_validation(ctx):
    admin = ctx["admin"]
    assert _add(admin, term="user:svc_backup host:BACKUP-01", reason="두 조건").status_code == 400   # 조건 하나만
    assert _add(admin, term="-user:svc_backup", reason="제외 기호").status_code == 400
    assert _add(admin, term="user:", reason="빈 값").status_code == 400
    assert _add(admin, term="user:svc_backup", reason="").status_code == 400                          # 사유 필수
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    assert _add(admin, term="user:svc_backup", reason="백업 계정", expires_at=past).status_code == 400
    assert admin.post("/api/alerts/exceptions", json={"rule": "없는 규칙", "term": "user:x", "reason": "사유"},
                      headers=CSRF).status_code == 404
    assert admin.post("/api/alerts/exceptions", json={"rule": "PC 끊김", "term": "host:x", "reason": "사유"},
                      headers=CSRF).status_code == 400
    assert ctx["viewer"].get("/api/alerts/exceptions", headers=CSRF).status_code == 403
    assert sql("SELECT count(*) FROM rule_exceptions")[0][0] == 0


def test_exception_stops_alerts_only_for_that_value(ctx):
    admin = ctx["admin"]
    assert _fired_hosts(admin) == ["BACKUP-01", "PC-07", "PC-09"]
    preview = admin.post("/api/alerts/exceptions/preview", json={"rule": "로그온 실패 급증", "term": "user:svc_backup"},
                         headers=CSRF).json()
    assert preview["removed"] == 4 and preview["matched"] == 10
    r = _add(admin, term="user:svc_backup", reason="백업 서비스 계정 — 매일 02시 정상 로그온",
             review_at=(datetime.now(UTC) + timedelta(days=90)).isoformat())
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "active" and r.json()["removed"] == 4 and r.json()["term"] == "user:svc_backup"
    assert sql("SELECT count(*) FROM alerts WHERE rule = '관리 작업 알림'")[0][0] == 1     # 탐지 약화 — 다른 관리자에게
    assert _fired_hosts(admin) == ["PC-07", "PC-09"]          # 사용자가 없는 PC-09 는 남는다
    rule = {"name": "로그온 실패 급증", "match": {"query": "event_id:4625"}, "window": "10m", "threshold": 3,
            "group_by": "host", "severity": "warning"}
    rules = admin.post("/api/alerts/rules/preview", json={"rule": rule, "hours": 1}, headers=CSRF)
    assert rules.status_code == 200 and rules.json()["matched"] == 6, rules.text   # 규칙 미리보기도 예외를 반영
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'alerts.exception.add'")
    assert detail["term"] == "user:svc_backup" and detail["removed_24h"] == 4


def test_end_and_expiry_and_immutability(ctx):
    admin = ctx["admin"]
    [(eid,)] = sql("SELECT id FROM rule_exceptions WHERE ended_at IS NULL")
    with pytest.raises(psycopg.errors.RaiseException):
        sql("UPDATE rule_exceptions SET term = 'user:x'")
    with pytest.raises(psycopg.errors.RaiseException):
        sql("DELETE FROM rule_exceptions")
    r = admin.post(f"/api/alerts/exceptions/{eid}/end", json={"reason": "계정 정리"}, headers=CSRF)
    assert r.status_code == 200 and r.json()["state"] == "ended"
    assert admin.post(f"/api/alerts/exceptions/{eid}/end", json={}, headers=CSRF).status_code == 404   # 한 번만
    assert _fired_hosts(admin) == ["BACKUP-01", "PC-07", "PC-09"]
    # 만료된 예외는 걸리지 않는다
    soon = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()
    assert _add(admin, term="host:PC-07", reason="점검 중", expires_at=soon).status_code == 200
    import time
    time.sleep(2.5)
    assert _fired_hosts(admin) == ["BACKUP-01", "PC-07", "PC-09"]
    items = {i["term"]: i["state"] for i in admin.get("/api/alerts/exceptions", headers=CSRF).json()["items"]}
    assert items == {"user:svc_backup": "ended", "host:PC-07": "expired"}


def test_report_lists_exceptions_needing_attention(ctx):
    """점검 보고서: 검토일이 지난 예외는 '점검 필요', 만료 임박·만료 없는 예외는 표로 (옛 보고서도 그림)."""
    from app.reports import builder, render

    admin = ctx["admin"]
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    assert _add(admin, term="ip:10.0.0.5", reason="유지보수 업체 IP", review_at=past).status_code == 200
    soon = (datetime.now(UTC) + timedelta(days=3)).isoformat()
    assert _add(admin, term="host:PC-09", reason="장비 교체 중", expires_at=soon).status_code == 200
    now = datetime.now(UTC)
    payload = admin.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    rx = payload["rule_exceptions"]
    assert rx["active"] == 2 and [x["term"] for x in rx["review_due"]] == ["ip:10.0.0.5"]
    assert [x["term"] for x in rx["expiring"]] == ["host:PC-09"] and [x["term"] for x in rx["no_expiry"]] == ["ip:10.0.0.5"]
    assert any("검토일이 지난 알림 규칙 예외 1건" in a["text"] for a in payload["attention"])
    page = render.html(payload, 1)
    assert ">알림 규칙 예외</h2>" in page and "유지보수 업체 IP" in page
    assert ">알림 규칙 예외</h2>" not in render.html({k: v for k, v in payload.items() if k != "rule_exceptions"}, 1)
