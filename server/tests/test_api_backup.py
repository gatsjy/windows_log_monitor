"""DB 백업 상태 (BACKLOG B-16, ADR-031): backup 서비스가 audit_log 에 남긴 기록으로 화면 상태와 경고를 만든다.

백업·복원 자체는 postgres 컨테이너 안의 deploy/backup/backup.sh 가 하고, 그 시험은 스크립트의 selftest 로 한다:
  docker compose run --rm backup selftest
여기서는 감사로그 기록 → 상태·경고 판단만 시험한다 (시각을 앞뒤로 옮겨 가며).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
NOW = datetime.now(UTC).replace(microsecond=0)


def audit(action, at, detail, target="wlm-x.dump"):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("INSERT INTO audit_log (at, actor, action, target, detail) VALUES (%s, 'system', %s, %s, %s)",
                     (at, action, target, json.dumps(detail)))


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


def status(client, at=NOW):
    from app.backups import backup_status

    return client.portal.call(backup_status, at)


def test_backup_status_problems_over_time(client):
    # 아직 아무 기록이 없으면: 서비스가 안 떠 있을 수 있다
    first = client.get("/api/settings/retention").json()["backup"]
    assert first["last_backup"] is None and "백업 기록이 없습니다" in first["problems"][0]
    assert first["schedule"] == {"time": "02:30", "keep": 14, "tz": "Asia/Seoul", "verify_weekday": 7, "verify_day": "일"}

    # 10일 전부터 백업했고 오늘도 백업했지만, 성공한 복구 시험이 9일 전이 마지막 → 복구 시험 경고만
    audit("backup.create", NOW - timedelta(days=10), {"bytes": 1, "seconds": 1, "sha256": "a"}, "wlm-old.dump")
    audit("backup.verify", NOW - timedelta(days=9), {"ok": True, "counts": {"events": 1}})
    audit("backup.create", NOW - timedelta(hours=1), {"bytes": 2048, "seconds": 3, "sha256": "b" * 64}, "wlm-new.dump")
    s = status(client)
    assert s["problems"] == ["최근 8일 안에 성공한 복구 시험이 없습니다"]
    assert s["last_backup"]["file"] == "wlm-new.dump" and s["last_backup"]["bytes"] == 2048

    # 복구 시험이 성공하면 문제 없음
    audit("backup.verify", NOW - timedelta(minutes=10), {"ok": True, "counts": {"events": 5}, "seconds": 2})
    s = status(client)
    assert s["problems"] == [] and s["last_verify"]["ok"] is True and s["last_verify"]["counts"] == {"events": 5}

    # 마지막 백업 뒤에 실패가 있으면 경고, 그 뒤에 다시 성공하면 경고가 사라진다
    audit("backup.failed", NOW, {"stage": "dump", "error": "pg_dump: error: connection refused"}, "wlm-fail.dump")
    assert any("마지막 백업이 실패했습니다: pg_dump: error" in p for p in status(client)["problems"])
    audit("backup.create", NOW + timedelta(minutes=1), {"bytes": 3, "seconds": 1, "sha256": "c"}, "wlm-retry.dump")
    assert status(client, NOW + timedelta(minutes=2))["problems"] == []

    # 복구 시험 실패는 사유와 함께 경고
    audit("backup.verify", NOW + timedelta(minutes=3), {"ok": False, "reason": "해시가 다릅니다"})
    later = status(client, NOW + timedelta(minutes=4))
    assert later["problems"] == ["마지막 복구 시험이 실패했습니다: 해시가 다릅니다"]
    assert later["last_verify_ok_at"] is not None  # 마지막 '성공' 시각은 따로 남는다

    # 하루 반이 지나도록 백업이 없으면 경고 (backup 서비스가 멈춘 경우)
    stale = status(client, NOW + timedelta(hours=41, minutes=1))  # 마지막 백업(NOW+1분)에서 41시간
    assert any("마지막 백업이 41시간 전입니다" in p for p in stale["problems"])


def test_verify_stale_warning_can_be_turned_off(client, monkeypatch):
    from dataclasses import replace

    from app import backups

    # 설정 객체는 바꿀 수 없어서(frozen) 이 모듈이 보는 설정만 바꿔 끼운다
    monkeypatch.setattr(backups, "settings", replace(backups.settings, backup_verify_weekday=0))
    s = status(client, NOW + timedelta(days=20))
    assert not any("복구 시험이 없습니다" in p for p in s["problems"]) and s["schedule"]["verify_day"] is None


def test_backup_actions_have_audit_labels(client):
    labels = client.get("/api/audit", params={"since": "30d"}, headers=CSRF).json()["labels"]
    assert {labels[a] for a in ("backup.create", "backup.failed", "backup.verify")} == {"DB 백업", "DB 백업 실패", "백업 복구 시험"}
