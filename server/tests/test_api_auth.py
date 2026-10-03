"""인증 통합 테스트 — 실제 PostgreSQL(테스트 전용 DB)에 붙어 앱 전체를 띄운다.

DB 에 접속할 수 없으면 건너뛴다. 실행: docker compose exec api python -m pytest
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
ADMIN_INITIAL = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
ADMIN_PASSWORD = "Root#Changed2026"
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]  # conftest.py 가 정한 테스트 DB


def _recreate_test_db() -> None:
    with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')


@pytest.fixture(scope="module")
def client():
    try:
        _recreate_test_db()
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


def sql(query: str, params=None):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password}, headers=CSRF)


def logged_in_admin(client):
    client.cookies.clear()
    r = login(client, "admin", ADMIN_PASSWORD)
    assert r.status_code == 200, r.text
    return client


# ------------------------------------------------------------------ tests (순서대로 실행됨)

def test_api_requires_login(client):
    assert client.get("/api/stats/summary").status_code == 401
    assert client.get("/api/events").status_code == 401
    assert client.get("/healthz").status_code == 200          # 공개
    assert client.get("/api/auth/info").status_code == 200    # 공개
    assert client.post("/api/ingest", json=[], headers={"X-API-Key": "test-key"}).status_code == 200


def test_login_requires_csrf_header(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_INITIAL})
    assert r.status_code == 403


def test_bootstrap_admin_must_change_password(client):
    r = login(client, "admin", ADMIN_INITIAL)
    assert r.status_code == 200, r.text
    assert r.json()["must_change_password"] is True
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    # 비밀번호를 바꾸기 전에는 일반 API 사용 불가
    r = client.get("/api/stats/summary")
    assert r.status_code == 403 and r.headers["x-wlm-reason"] == "password_change_required"
    # 정책 위반
    r = client.post("/api/auth/password", json={"current_password": ADMIN_INITIAL, "new_password": "weak"},
                    headers=CSRF)
    assert r.status_code == 400
    r = client.post("/api/auth/password", json={"current_password": ADMIN_INITIAL, "new_password": ADMIN_PASSWORD},
                    headers=CSRF)
    assert r.status_code == 200, r.text
    assert client.get("/api/stats/summary").status_code == 200


def test_unsafe_request_without_csrf_header_is_rejected(client):
    logged_in_admin(client)
    r = client.put("/api/dashboards/x", json={"widgets": []})
    assert r.status_code == 403
    r = client.put("/api/dashboards/x", json={"widgets": []}, headers=CSRF)
    assert r.status_code == 200


def test_viewer_cannot_change_settings(client):
    logged_in_admin(client)
    r = client.post("/api/users", json={"username": "viewer1", "display_name": "조회자", "role": "viewer"},
                    headers=CSRF)
    assert r.status_code == 200, r.text
    temp = r.json()["temp_password"]

    client.cookies.clear()
    assert login(client, "viewer1", temp).status_code == 200
    client.post("/api/auth/password", json={"current_password": temp, "new_password": "Viewer#Pass2026"},
                headers=CSRF)
    assert client.get("/api/stats/summary").status_code == 200
    assert client.put("/api/dashboards/x", json={"widgets": []}, headers=CSRF).status_code == 403
    assert client.get("/api/users").status_code == 403
    assert client.get("/api/audit").status_code == 403
    assert client.get("/api/alerts/config").json()["yaml"] is None   # 규칙 원본은 관리자만


def test_lockout_after_repeated_failures(client):
    client.cookies.clear()
    for _ in range(4):
        assert login(client, "viewer1", "wrong-password").status_code == 401
    r = login(client, "viewer1", "wrong-password")
    assert r.status_code == 423
    # 잠긴 동안에는 맞는 비밀번호도 거부
    assert login(client, "viewer1", "Viewer#Pass2026").status_code == 423
    actions = [r[0] for r in sql("SELECT action FROM audit_log WHERE target = 'viewer1' ORDER BY id")]
    assert "auth.account_locked" in actions

    logged_in_admin(client)
    user_id = sql("SELECT id FROM users WHERE username = 'viewer1'")[0][0]
    assert client.post(f"/api/users/{user_id}/unlock", headers=CSRF).status_code == 200
    client.cookies.clear()
    assert login(client, "viewer1", "Viewer#Pass2026").status_code == 200


def test_unknown_user_gets_same_message(client):
    client.cookies.clear()
    a = login(client, "nobody", "whatever-123")
    b = login(client, "admin", "whatever-123")
    assert a.status_code == b.status_code == 401
    assert a.json()["detail"] == b.json()["detail"]
    sql("UPDATE users SET failed_count = 0 WHERE username = 'admin'")


def test_idle_session_expires(client):
    logged_in_admin(client)
    assert client.get("/api/auth/me").status_code == 200
    sql("UPDATE sessions SET last_activity_at = %s", (datetime.now(UTC) - timedelta(hours=2),))
    assert client.get("/api/auth/me").status_code == 401
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'auth.session_expired'")[0][0] >= 1


def test_background_requests_do_not_extend_session(client):
    logged_in_admin(client)
    before = datetime.now(UTC) - timedelta(minutes=10)
    sql("UPDATE sessions SET last_activity_at = %s", (before,))
    # 사용자가 20분 동안 조작하지 않은 상태의 자동 새로고침
    client.get("/api/stats/summary", headers={"X-WLM-Idle-Sec": "1200"})
    latest = "SELECT last_activity_at FROM sessions ORDER BY created_at DESC LIMIT 1"  # 지금 로그인한 세션
    assert sql(latest)[0][0] <= before + timedelta(seconds=1)
    # 방금 조작한 요청은 연장
    client.get("/api/stats/summary", headers={"X-WLM-Idle-Sec": "0"})
    assert sql(latest)[0][0] > before + timedelta(minutes=5)


def test_cannot_demote_last_admin_or_self(client):
    logged_in_admin(client)
    admin_id = sql("SELECT id FROM users WHERE username = 'admin'")[0][0]
    r = client.patch(f"/api/users/{admin_id}", json={"role": "viewer"}, headers=CSRF)
    assert r.status_code == 400


def test_disabling_user_kills_sessions(client):
    logged_in_admin(client)
    user_id = sql("SELECT id FROM users WHERE username = 'viewer1'")[0][0]
    sql("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('x', %s, now() + interval '1 hour')",
        (user_id,))
    assert client.patch(f"/api/users/{user_id}", json={"is_active": False}, headers=CSRF).status_code == 200
    assert sql("SELECT count(*) FROM sessions WHERE user_id = %s", (user_id,))[0][0] == 0
    client.cookies.clear()
    assert login(client, "viewer1", "Viewer#Pass2026").status_code == 401


def test_event_access_is_audited(client):
    logged_in_admin(client)
    client.get("/api/events", params={"host": "WEB-01", "level": "2"})
    row = sql("SELECT actor, detail FROM audit_log WHERE action = 'events.search' ORDER BY id DESC LIMIT 1")[0]
    assert row[0] == "admin" and row[1]["query"]["host"] == "WEB-01"


def test_audit_log_is_append_only(client):
    with pytest.raises(psycopg.Error, match="append-only"):
        sql("UPDATE audit_log SET actor = 'hacker'")
    with pytest.raises(psycopg.Error, match="append-only"):
        sql("DELETE FROM audit_log")
    with pytest.raises(psycopg.Error, match="append-only"):
        sql("TRUNCATE audit_log")


def test_audit_csv_export(client):
    logged_in_admin(client)
    r = client.get("/api/audit", params={"format": "csv", "since": "1d"})
    assert r.status_code == 200
    assert r.text.startswith("﻿번호,")
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'audit.export'")[0][0] == 1


def test_logout_invalidates_session(client):
    logged_in_admin(client)
    assert client.post("/api/auth/logout", headers=CSRF).status_code == 200
    assert client.get("/api/auth/me").status_code == 401
