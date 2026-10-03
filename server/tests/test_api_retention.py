"""로그 로테이션 통합 테스트: DB 보관기간 지난 파티션 → 압축 보관 파일(+SHA-256) → DROP → 복원 → 보존 연장."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
ARCHIVE = Path(os.environ["WLM_ARCHIVE_DIR"])


def _month(offset: int) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    index = now.year * 12 + now.month - 1 + offset
    start = datetime(index // 12, index % 12 + 1, 1, tzinfo=UTC)
    index += 1
    return start, datetime(index // 12, index % 12 + 1, 1, tzinfo=UTC)


OLD = _month(-5)        # DB 보관(90일)은 지났고 전체 보관(365일)은 안 지남 → 파일로 보관
ANCIENT = _month(-14)   # 전체 보관기간도 지남 → 그냥 삭제
OLD_NAME = f"events_{OLD[0]:%Y_%m}"
ANCIENT_NAME = f"events_{ANCIENT[0]:%Y_%m}"


def sql(query, params=None):
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

    from app.main import app

    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        for name, (start, end), rows in ((OLD_NAME, OLD, 3), (ANCIENT_NAME, ANCIENT, 1)):
            sql(f"CREATE TABLE {name} PARTITION OF events FOR VALUES FROM ('{start:%Y-%m-%d}') TO ('{end:%Y-%m-%d}')")
            for i in range(rows):
                sql("INSERT INTO events (received_at, ts, host, source, level, message, raw)"
                    " VALUES (%s, %s, 'OLD-PC', 'winevtlog', 2, %s, %s::jsonb)",
                    (start.replace(day=2), start.replace(day=2), f"옛 로그 {i}", json.dumps({"n": i, "한글": "값"})))
        yield c


def partitions():
    return {r[0] for r in sql("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid")}


def test_rotation_archives_then_drops(client):
    r = client.post("/api/settings/retention/rotate", headers=CSRF)
    assert r.status_code == 200, r.text
    assert OLD_NAME not in partitions() and ANCIENT_NAME not in partitions()
    meta = json.loads((ARCHIVE / f"{OLD_NAME}.meta.json").read_text())
    assert meta["rows"] == 3 and len(meta["sha256"]) == 64
    assert not (ARCHIVE / f"{ANCIENT_NAME}.jsonl.gz").exists()  # 전체 보관기간 지난 것은 파일로 남기지 않음
    actions = {r[0]: r[1] for r in sql("SELECT target, detail FROM audit_log WHERE action = 'retention.drop_partition'")}
    assert actions[OLD_NAME]["archived"] is True and actions[ANCIENT_NAME]["archived"] is False
    logged = sql("SELECT detail FROM audit_log WHERE action = 'retention.archive_partition'")[0][0]
    assert logged["sha256"] == meta["sha256"]  # 감사로그의 해시와 대조 가능


def test_status_and_verify(client):
    status = client.get("/api/settings/retention").json()
    assert status["policy"] == {"db_retention_days": 90, "retention_days": 365, "archiving": True,
                                "archive_dir": str(ARCHIVE)}
    assert [a["partition"] for a in status["archives"]] == [OLD_NAME]
    result = client.post("/api/settings/retention/verify", headers=CSRF).json()["items"]
    assert result[0]["ok"]


def test_restore_and_hold(client):
    r = client.post("/api/settings/retention/restore", json={"partition": OLD_NAME, "hold_days": 7}, headers=CSRF)
    assert r.status_code == 200 and r.json()["rows"] == 3, r.text
    assert sql(f"SELECT count(*) FROM {OLD_NAME}")[0][0] == 3
    assert sql(f"SELECT raw->>'한글' FROM {OLD_NAME} LIMIT 1")[0][0] == "값"
    # 다시 로테이션해도 보존 연장 중이라 남는다
    client.post("/api/settings/retention/rotate", headers=CSRF)
    assert OLD_NAME in partitions()
    # 같은 파티션을 또 복원하면 거부
    assert client.post("/api/settings/retention/restore", json={"partition": OLD_NAME}, headers=CSRF).status_code == 400


def test_tampered_archive_is_detected(client):
    path = ARCHIVE / f"{OLD_NAME}.jsonl.gz"
    data = bytearray(path.read_bytes())
    data[-10] ^= 0xFF
    path.write_bytes(bytes(data))
    result = client.post("/api/settings/retention/verify", headers=CSRF).json()["items"][0]
    assert not result["ok"] and "해시" in result["problem"]
    sql(f"DROP TABLE {OLD_NAME}")
    r = client.post("/api/settings/retention/restore", json={"partition": OLD_NAME}, headers=CSRF)
    assert r.status_code == 400 and "해시" in r.json()["detail"]
