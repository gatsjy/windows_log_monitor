"""운영 준비도 점검표 (BACKLOG B-75) — 판정은 DB 없이, API 는 통합 시험.

회귀: 1~2명이고 보안 전문가가 아닌 팀은 무엇이 아직 안 됐는지 몰랐다 — 신호가 여러 화면·서버 로그에 흩어져 있었다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from app import readiness

NOW = datetime(2026, 10, 31, 3, 0, tzinfo=UTC)
CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def _facts(**overrides):
    facts = {
        "admins": [{"username": "admin", "must_change_password": False, "mfa_enabled_at": NOW},
                   {"username": "kim", "must_change_password": False, "mfa_enabled_at": NOW}],
        "mfa_required": "privileged", "secret_key": True,
        "health": {"status": "ok", "problems": []},
        "enabled_rules": 20, "unknown_targets": [], "broken_targets": {}, "used_targets": ["운영팀", "당직"],
        "fallback": ["당직"], "email_targets": ["운영팀"], "smtp_host": "relay.hosp.local",
        "tests": {"운영팀": {"at": NOW, "ok": True}, "당직": {"at": NOW, "ok": True}},
        "report_targets": ["운영팀"],
        "tls": {"enabled": True, "days_left": 400, "errors": []}, "plain_pcs": [], "ingest_plain": False,
        "offline_pcs": [], "silent_streams": 0, "coverage_gaps": [], "retention_warnings": [],
        "backup": {"problems": []}, "replica": True, "weakened": [],
    }
    facts.update(overrides)
    return facts


def _status(items):
    return {i.key: i.status for i in items}


def test_a_finished_install_is_all_green():
    items = readiness.judge(_facts())
    assert set(_status(items).values()) == {"ok"}
    assert all(i.link.startswith("#/") and i.doc for i in items)


@pytest.mark.parametrize(("overrides", "key", "status", "text"), [
    ({"admins": [{"username": "admin", "must_change_password": True, "mfa_enabled_at": None}]}, "admin_password", "bad", "admin"),
    ({"admins": [{"username": "admin", "must_change_password": False, "mfa_enabled_at": NOW}]}, "personal_admins", "warn", "공용 admin"),
    ({"mfa_required": "off"}, "mfa", "warn", "필수가 아닙니다"),
    ({"secret_key": False}, "mfa", "bad", "WLM_SECRET_KEY"),
    ({"admins": [{"username": "admin", "must_change_password": False, "mfa_enabled_at": NOW},
                 {"username": "lee", "must_change_password": False, "mfa_enabled_at": None}]}, "mfa", "warn", "lee"),
    ({"health": {"status": "down", "problems": [{"text": "알림 전송이 멈춰 있습니다"}]}}, "alerting", "bad", "멈춰"),
    ({"tests": {"운영팀": {"at": NOW, "ok": False}}}, "targets", "bad", "실패한 곳: 운영팀"),
    ({"tests": {"운영팀": {"at": NOW, "ok": True}}}, "targets", "warn", "시험 전송한 적 없는 곳: 당직"),
    ({"unknown_targets": ["없는곳"]}, "targets", "bad", "없는곳"),
    ({"enabled_rules": 0}, "targets", "bad", "아무에게도"),
    ({"smtp_host": ""}, "smtp", "bad", "메일 서버가 없는데"),
    ({"fallback": []}, "fallback", "warn", "메신저 웹훅"),
    ({"report_targets": []}, "report", "warn", "아무에게도"),
    ({"tls": {"enabled": False, "days_left": None, "errors": []}}, "tls", "warn", "평문"),
    ({"tls": {"enabled": True, "days_left": 5, "errors": []}}, "tls", "bad", "5일 뒤"),
    ({"plain_pcs": ["WS-01"], "ingest_plain": True}, "tls", "warn", "WS-01"),
    ({"coverage_gaps": [{"channel": "Security", "total": 3, "hosts": ["WS-02"], "rules": ["a"]}]}, "coverage", "warn", "Security"),
    ({"offline_pcs": ["PC-1"], "silent_streams": 2}, "agents", "warn", "채널 2개"),
    ({"retention_warnings": ["감사로그 보관이 3년보다 짧습니다"]}, "retention", "bad", "3년"),
    ({"backup": {"problems": ["마지막 백업이 실패했습니다: disk full"]}}, "backup", "bad", "disk full"),
    ({"replica": False}, "replica", "warn", "이 서버 디스크에만"),
    ({"backup": {"problems": ["마지막 외부 저장소 복제가 40시간 전입니다"]}}, "replica", "bad", "40시간"),
    ({"weakened": [{"id": 7, "actor": "kim"}]}, "weakened", "warn", "#7 kim"),
])
def test_each_gap_is_called_out(overrides, key, status, text):
    items = {i.key: i for i in readiness.judge(_facts(**overrides))}
    assert items[key].status == status and text in items[key].detail


def test_no_email_targets_means_no_smtp_item():
    assert "smtp" not in _status(readiness.judge(_facts(email_targets=[])))


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
        yield c


def test_api_is_admin_only_and_reports_a_fresh_install(client):
    r = client.get("/api/readiness")
    assert r.status_code == 200, r.text
    data = r.json()
    items = {i["key"]: i for i in data["items"]}
    # 새 설치: 개인 관리자 없음·받는 곳 없음·보고서 받는 곳 없음·복제 꺼짐 — 고칠 것이 보인다
    assert items["personal_admins"]["status"] == "warn" and items["targets"]["status"] == "bad"
    assert items["admin_password"]["status"] == "ok"   # 방금 바꿨다
    assert data["summary"]["bad"] >= 1 and sum(data["summary"].values()) == len(data["items"])
    viewer = client.post("/api/users", json={"username": "seeonly", "role": "viewer"}, headers=CSRF).json()
    from fastapi.testclient import TestClient

    from app.main import app

    other = TestClient(app)
    other.post("/api/auth/login", json={"username": "seeonly", "password": viewer["temp_password"]}, headers=CSRF)
    other.post("/api/auth/password", json={"current_password": viewer["temp_password"], "new_password": "Viewer#Only2026"},
               headers=CSRF)
    assert other.get("/api/readiness").status_code == 403
    assert timedelta(0) <= datetime.now(UTC) - datetime.fromisoformat(data["checked_at"]) < timedelta(minutes=1)
