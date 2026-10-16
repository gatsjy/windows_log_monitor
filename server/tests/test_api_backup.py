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
    assert later["problems"] == ["복구 시험이 실패했습니다 (wlm-x.dump): 해시가 다릅니다"]
    assert later["last_verify_ok_at"] is not None  # 마지막 '성공' 시각은 따로 남는다

    # 하루 반이 지나도록 백업이 없으면 경고 (backup 서비스가 멈춘 경우)
    stale = status(client, NOW + timedelta(hours=41, minutes=1))  # 마지막 백업(NOW+1분)에서 41시간
    assert any("마지막 백업이 41시간 전입니다" in p for p in stale["problems"])


def test_verify_failure_is_cleared_only_by_same_or_newer_backup(client):
    """옛 백업을 직접 시험해 성공해도 최신 백업의 복구 시험 실패는 가려지지 않는다."""
    t = NOW + timedelta(hours=2)
    audit("backup.create", t, {"bytes": 1, "seconds": 1, "sha256": "d"}, "wlm-20261017-020000.dump")
    audit("backup.verify", t + timedelta(minutes=1), {"ok": False, "reason": "복원 실패: end of file"}, "wlm-20261017-020000.dump")
    failing = ["복구 시험이 실패했습니다 (wlm-20261017-020000.dump): 복원 실패: end of file"]
    assert status(client, t + timedelta(minutes=2))["problems"] == failing
    audit("backup.verify", t + timedelta(minutes=2), {"ok": True}, "wlm-20261016-020000.dump")  # 하루 전 백업
    s = status(client, t + timedelta(minutes=3))
    assert s["problems"] == failing and s["last_verify"]["ok"] is True
    audit("backup.verify", t + timedelta(minutes=3), {"ok": True}, "wlm-20261017-020000.dump")  # 그 백업을 다시 시험해 성공
    assert status(client, t + timedelta(minutes=4))["problems"] == []


def test_status_after_restore(client):
    """복원하면 감사로그가 백업 시점으로 돌아간다 → '백업이 멈췄다'는 잘못된 경고 대신 복원 시각부터 잰다."""
    r = NOW + timedelta(hours=3)
    audit("backup.restore", r, {"file": "wlm-20261016-020000.dump", "safety_dump": "before-restore-x.dump"},
          "wlm-20261016-020000.dump")
    s = status(client, r + timedelta(hours=30))  # 마지막 backup.create(NOW+2h)에서는 31시간
    assert s["problems"] == [] and s["last_restore"]["file"] == "wlm-20261016-020000.dump"
    assert s["last_restore"]["safety_dump"] == "before-restore-x.dump"
    assert status(client, r + timedelta(hours=37))["problems"][0].startswith("백업으로 복원한 뒤 37시간 동안 새 백업이 없습니다")
    audit("backup.create", r + timedelta(hours=38), {"bytes": 1, "seconds": 1, "sha256": "e"}, "wlm-20261018-020000.dump")
    s = status(client, r + timedelta(hours=39))
    assert s["problems"] == [] and s["last_restore"] is None


def test_verify_stale_warning_can_be_turned_off(client, monkeypatch):
    from dataclasses import replace

    from app import backups

    # 이 테스트만 따로 돌려도 되게 필요한 기록을 직접 넣는다: 12일 전부터 백업, 어제도 백업, 성공한 복구 시험은 없거나 오래됨
    c = NOW + timedelta(days=30)
    audit("backup.create", c - timedelta(days=12), {"bytes": 1, "seconds": 1, "sha256": "f"}, "wlm-20991201-000000.dump")
    audit("backup.create", c - timedelta(hours=1), {"bytes": 1, "seconds": 1, "sha256": "g"}, "wlm-20991212-000000.dump")
    audit("backup.verify", c - timedelta(days=9), {"ok": False, "reason": "공간 부족"}, "wlm-20991203-000000.dump")
    on = status(client, c)["problems"]
    assert "최근 8일 안에 성공한 복구 시험이 없습니다" in on
    assert "복구 시험이 실패했습니다 (wlm-20991203-000000.dump): 공간 부족" in on

    # 설정 객체는 바꿀 수 없어서(frozen) 이 모듈이 보는 설정만 바꿔 끼운다
    monkeypatch.setattr(backups, "settings", replace(backups.settings, backup_verify_weekday=0))
    s = status(client, c)
    # 자동 복구 시험을 끄면: '없음' 경고도, 8일 지난 옛 실패도 남지 않는다 (끈 뒤에는 새 시험이 없어 영영 남으므로)
    assert s["problems"] == [] and s["schedule"]["verify_day"] is None
    # 8일 안의 실패는 끈 뒤에도 보인다 (직접 시험해 실패한 경우)
    assert status(client, c - timedelta(days=2))["problems"] == ["복구 시험이 실패했습니다 (wlm-20991203-000000.dump): 공간 부족"]


def test_backup_actions_have_audit_labels(client):
    labels = client.get("/api/audit", params={"since": "30d"}, headers=CSRF).json()["labels"]
    assert {labels[a] for a in ("backup.create", "backup.failed", "backup.verify")} == {"DB 백업", "DB 백업 실패", "백업 복구 시험"}
