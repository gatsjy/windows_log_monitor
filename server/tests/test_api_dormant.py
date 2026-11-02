"""장기 미사용 계정 자동 잠금 (BACKLOG B-72 1단계, ISMS 2.5.6) — 통합 시험."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


@pytest.fixture(scope="module")
def admin():
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
        for name, role in (("old-viewer", "viewer"), ("fresh-viewer", "viewer"), ("old-admin", "admin"), ("never", "viewer")):
            assert c.post("/api/users", json={"username": name, "role": role}, headers=CSRF).status_code == 200
        sql("UPDATE users SET last_login_at = now() - interval '200 days', created_at = now() - interval '300 days'"
            " WHERE username IN ('old-viewer', 'old-admin')")
        sql("UPDATE users SET last_login_at = now() - interval '5 days' WHERE username = 'fresh-viewer'")
        sql("UPDATE users SET last_login_at = NULL, created_at = now() - interval '120 days' WHERE username = 'never'")
        yield c


def _active(name):
    return sql("SELECT is_active, disabled_reason FROM users WHERE username = %s", (name,))[0]


def test_dormant_accounts_are_disabled_and_reported(admin):
    from app import partitions

    admin.portal.call(partitions.lock_dormant_accounts)
    assert _active("old-viewer") == (False, "dormant")
    assert _active("never") == (False, "dormant")          # 만든 뒤 한 번도 로그인하지 않은 계정도 만든 날부터 센다
    assert _active("old-admin") == (False, "dormant")      # 다른 관리자(admin)가 있으므로
    assert _active("fresh-viewer") == (True, None)
    assert _active("admin")[0] is True
    targets = {t for (t,) in sql("SELECT target FROM audit_log WHERE action = 'user.dormant_lock'")}
    assert targets == {"old-viewer", "never", "old-admin"}
    # 관리자 계정을 만든 알림(B-36)도 있으므로 장기 미사용 알림만
    [(desc,)] = sql("SELECT payload->>'description' FROM alerts WHERE rule = '관리 작업 알림'"
                    " AND payload->>'description' LIKE '장기 미사용%%'")
    assert "장기 미사용 계정 3개" in desc
    users = {u["username"]: u for u in admin.get("/api/users").json()["items"]}
    assert users["old-viewer"]["disabled_reason"] == "dormant"


def test_reenabled_account_counts_from_reenable(admin):
    from app import partitions

    uid = sql("SELECT id FROM users WHERE username = 'old-viewer'")[0][0]
    assert admin.patch(f"/api/users/{uid}", json={"is_active": True}, headers=CSRF).status_code == 200
    assert _active("old-viewer") == (True, None)
    admin.portal.call(partitions.lock_dormant_accounts)      # 옛 마지막 로그인으로 바로 다시 잠기지 않는다
    assert _active("old-viewer") == (True, None)


def test_last_admin_is_kept(admin):
    from app.auth import service

    sql("UPDATE users SET last_login_at = now() - interval '200 days', reenabled_at = NULL WHERE username = 'admin'")
    locked = admin.portal.call(service.lock_dormant, datetime.now(UTC))
    assert "admin" not in {u["username"] for u in locked} and _active("admin")[0] is True


def test_startup_run_does_not_lock_and_cli_recovery_reenables(admin):
    """기동 중 정리(알림 설정을 읽기 전)에서는 끄지 않는다 — 관리 작업 알림이 아무에게도 가지 않았다. cli 복구는 다시 켠다 (검토)."""
    from app import partitions
    from app.auth import service

    sql("UPDATE users SET last_login_at = now() - interval '200 days', reenabled_at = NULL, created_at = now() - interval '300 days'"
        " WHERE username = 'fresh-viewer'")
    admin.portal.call(partitions.run_maintenance, False)
    assert _active("fresh-viewer") == (True, None)
    admin.portal.call(partitions.lock_dormant_accounts)
    assert _active("fresh-viewer") == (False, "dormant")
    uid = sql("SELECT id FROM users WHERE username = 'fresh-viewer'")[0][0]
    assert admin.portal.call(service.reenable_dormant, uid, "cli") is True
    assert _active("fresh-viewer") == (True, None)
    assert admin.portal.call(service.reenable_dormant, uid, "cli") is False     # 이미 켜진 계정은 그대로
