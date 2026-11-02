"""이벤트 보관 등급 (BACKLOG B-70, ADR-061) 통합 시험: 보관 파일을 만들 때 등급마다 나눔 → 등급마다 만료·파기 기록 → 복원은 그 달 전부,
설정이 틀리면 보관·삭제를 멈춤 (로그는 DB 에 그대로)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
ARCHIVE = Path(os.environ["WLM_ARCHIVE_DIR"])
CONFIG = Path(os.environ["WLM_RETENTION_CONFIG"])
TIERS = """
tiers:
  - id: access
    name: 진료정보 시스템 접속기록
    query: 'host:EMR-01'
    keep_days: 730
  - id: web
    name: 웹 요청
    query: 'source:iis'
    keep_days: 200
  - id: tmp
    name: 임시 PC
    query: 'host:TMP-01'
    keep_days: 30
"""


def _month(offset: int) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    index = now.year * 12 + now.month - 1 + offset
    start = datetime(index // 12, index % 12 + 1, 1, tzinfo=UTC)
    index += 1
    return start, datetime(index // 12, index % 12 + 1, 1, tzinfo=UTC)


# 다른 시험 모듈(test_api_retention: -5·-14, test_api_archive_columns: -7·-8)과 겹치지 않는 달
RECENT, OLD, ANCIENT = _month(-6), _month(-16), _month(-27)   # DB 90일 지남 / 기본 365일 지남 / 가장 긴 등급 730일도 지남
NAMES = {n: f"events_{m[0]:%Y_%m}" for n, m in (("recent", RECENT), ("old", OLD), ("ancient", ANCIENT))}
ROWS = {   # 달 → (host, source)
    "recent": [("EMR-01", "winevtlog"), ("WEB-01", "iis"), ("TMP-01", "syslog"), ("PC-01", "winevtlog"), ("EMR-01", "iis")],
    "old": [("EMR-01", "winevtlog"), ("PC-01", "winevtlog")],
    "ancient": [("EMR-01", "winevtlog")],
}


def sql(query, params=None):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _mine():
    return sorted(p for p in ARCHIVE.glob("events_*") if any(p.name.startswith(n + ".") for n in NAMES.values()))


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

    CONFIG.write_text(TIERS, encoding="utf-8")
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            for key, (start, end) in (("recent", RECENT), ("old", OLD), ("ancient", ANCIENT)):
                sql(f"CREATE TABLE IF NOT EXISTS {NAMES[key]} PARTITION OF events FOR VALUES FROM ('{start:%Y-%m-%d}') TO ('{end:%Y-%m-%d}')")
                for host, source in ROWS[key]:
                    at = start + timedelta(days=2)
                    sql("INSERT INTO events (received_at, ts, host, source, level, message, raw) VALUES (%s, %s, %s, %s, 4, 'x', '{}'::jsonb)",
                        (at, at, host, source))
            yield c
    finally:
        CONFIG.unlink(missing_ok=True)   # 다른 시험 모듈은 등급 없이
        for path in _mine():
            path.unlink()


def _meta(name):
    return json.loads((ARCHIVE / name).read_text(encoding="utf-8"))


def _rows(name):
    import gzip

    with gzip.open(ARCHIVE / name, "rt", encoding="utf-8") as fh:
        return sorted((r["host"], r["source"]) for r in map(json.loads, fh))


def test_archive_splits_by_tier(client):
    assert client.post("/api/settings/retention/rotate", headers=CSRF).status_code == 200
    parts = {r[0] for r in sql("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid")}
    assert not parts & set(NAMES.values())
    r = NAMES["recent"]
    assert [p.name for p in _mine() if p.name.startswith(r)] == [f"{r}.access.jsonl.gz", f"{r}.access.meta.json", f"{r}.jsonl.gz",
                                                                 f"{r}.meta.json", f"{r}.web.jsonl.gz", f"{r}.web.meta.json"]
    assert _rows(f"{r}.access.jsonl.gz") == [("EMR-01", "iis"), ("EMR-01", "winevtlog")]   # 두 등급에 맞으면 긴 쪽(730)
    assert _rows(f"{r}.web.jsonl.gz") == [("WEB-01", "iis")]
    assert _rows(f"{r}.jsonl.gz") == [("PC-01", "winevtlog")]
    base = _meta(f"{r}.meta.json")
    assert base["total_rows"] == 5 and base["skipped"] == {"tmp": 1}   # 30일 등급은 만들 때 이미 끝남 → 쓰지 않음
    assert {t["tier"]: t["rows"] for t in base["tiers"]} == {"access": 2, "web": 1}
    web = _meta(f"{r}.web.meta.json")
    assert (web["tier"], web["keep_days"], web["query"], web["tier_name"]) == ("web", 200, "source:iis", "웹 요청")
    # 기본 365일이 지난 달: 등급(730일) 파일만 — 기본 파일은 만들자마자 지워질 것이라 만들지 않고 메타는 완료 표시로(file 없음)
    o = NAMES["old"]
    assert [p.name for p in _mine() if p.name.startswith(o)] == [f"{o}.access.jsonl.gz", f"{o}.access.meta.json", f"{o}.meta.json"]
    assert _meta(f"{o}.meta.json")["file"] is None and _meta(f"{o}.meta.json")["skipped"] == {"default": 1}
    assert _rows(f"{o}.access.jsonl.gz") == [("EMR-01", "winevtlog")]
    # 가장 긴 등급도 지난 달은 파일 없이 지움 (예전과 같음)
    assert not [p for p in _mine() if p.name.startswith(NAMES["ancient"])]
    logged = {t: d for t, d in sql("SELECT target, detail FROM audit_log WHERE action = 'retention.archive_partition'")}
    assert logged[f"{r}.jsonl.gz"]["skipped"] == {"tmp": 1} and len(logged[f"{r}.jsonl.gz"]["tiers"]) == 2
    assert logged[o]["skipped"] == {"default": 1} and logged[o]["sha256"] is None   # 기본 파일 없는 달은 파티션 이름으로
    dropped = {t: d for t, d in sql("SELECT target, detail FROM audit_log WHERE action = 'retention.drop_partition'")}
    assert dropped[NAMES["ancient"]]["archived"] is False and dropped[NAMES["old"]]["retention_days"] == 730


def test_status_lists_tiers_and_expiry(client):
    status = client.get("/api/settings/retention").json()
    p = status["policy"]
    assert [t["id"] for t in p["tiers"]] == ["access", "web", "tmp"] and p["max_keep_days"] == 730 and p["tier_error"] is None
    assert any("임시 PC" in n for n in p["tier_notes"]) and any("웹 요청" in n for n in p["tier_notes"])
    mine = {a["file"]: a for a in status["archives"] if a["partition"] in NAMES.values()}
    web = mine[f"{NAMES['recent']}.web.jsonl.gz"]
    assert web["tier"] == "web" and web["keep_days"] == 200
    assert web["expires_at"][:10] == (RECENT[1] + timedelta(days=200)).date().isoformat()
    result = client.post("/api/settings/retention/verify", headers=CSRF).json()["items"]
    assert all(i["ok"] for i in result if i["partition"] in NAMES.values()) and len([i for i in result if i["partition"] in NAMES.values()]) == 4


def test_expired_tier_file_is_deleted_with_its_tier_in_the_record(client):
    """등급 파일은 등급 기간으로 지운다 — 파기 기록에 등급·기간 (외부 복제본은 이 기록을 보고 지운다, backup.sh)."""
    r = NAMES["recent"]
    meta = _meta(f"{r}.web.meta.json")
    (ARCHIVE / f"{r}.web.meta.json").write_text(json.dumps({**meta, "to": (datetime.now(UTC) - timedelta(days=201)).isoformat()}),
                                                encoding="utf-8")
    assert client.post("/api/settings/retention/rotate", headers=CSRF).status_code == 200
    assert not (ARCHIVE / f"{r}.web.jsonl.gz").exists() and (ARCHIVE / f"{r}.access.jsonl.gz").exists()
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'retention.delete_archive' AND target = %s", (f"{r}.web.jsonl.gz",))
    assert (detail["tier"], detail["retention_days"], detail["rows"]) == ("web", 200, 1)
    # DB 를 백업으로 되돌려 이 기록이 사라져도 외부 복제본이 지워지게 — 지운 표시 파일 (backup.sh)
    assert json.loads((ARCHIVE / f"{r}.web.destroyed.json").read_text(encoding="utf-8"))["file"] == f"{r}.web.jsonl.gz"


def test_destroy_record_comes_first(client, monkeypatch):
    """파기 기록을 남기지 못하면 지우지 않는다 — 기록 없이 지우면 증적도 없고 외부 복제본도 안 지워졌다(검토에서 재현)."""
    from app import archive, db, retention

    r = NAMES["recent"]
    meta = _meta(f"{r}.meta.json")
    (ARCHIVE / f"{r}.meta.json").write_text(json.dumps({**meta, "to": (datetime.now(UTC) - timedelta(days=400)).isoformat()}), encoding="utf-8")

    async def broken(*args, **kwargs):
        raise db.AuditError("DB 끊김")

    monkeypatch.setattr(db, "audit", broken)
    assert client.portal.call(archive.delete_expired, datetime.now(UTC), retention.load()) == []
    assert (ARCHIVE / f"{r}.jsonl.gz").exists()
    monkeypatch.undo()
    (ARCHIVE / f"{r}.meta.json").write_text(json.dumps(meta), encoding="utf-8")


def test_restore_brings_back_every_file_of_the_month(client):
    o = NAMES["old"]
    res = client.post("/api/settings/retention/restore", json={"partition": o, "hold_days": 1}, headers=CSRF)
    assert res.status_code == 200 and res.json()["rows"] == 1, res.text
    assert sql(f"SELECT host FROM {o}") == [("EMR-01",)]
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'retention.restore_archive' AND target = %s", (o,))
    assert [f["file"] for f in detail["files"]] == [f"{o}.access.jsonl.gz"]   # 기본 파일이 없는 달도 등급 파일로


def test_restored_month_is_not_archived_again(client):
    """기본 파일 없이 등급 파일만 있는 달을 복원했다가 보존 기간이 끝나면 지금 설정으로 다시 보관해 등급 파일을 덮어썼다 — 등급 문장을 좁혔으면
    행이 사라지고 기간을 줄였으면 약속한 기간보다 일찍 지워졌다(검토에서 재현). 이제 완료 표시가 있으면 다시 보관하지 않고 지우기만 한다."""
    o = NAMES["old"]   # 앞 시험에서 복원해 둔 달 (hold 1일)
    before = (ARCHIVE / f"{o}.access.jsonl.gz").read_bytes(), _meta(f"{o}.access.meta.json")
    CONFIG.write_text(TIERS.replace("'host:EMR-01'", "'host:EMR-02'").replace("730", "400"), encoding="utf-8")
    try:
        sql("UPDATE partition_holds SET hold_until = now() - interval '1 minute' WHERE name = %s", (o,))
        assert client.post("/api/settings/retention/rotate", headers=CSRF).status_code == 200
        parts = {r[0] for r in sql("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid")}
        assert o not in parts                                               # 지웠다
        assert (ARCHIVE / f"{o}.access.jsonl.gz").read_bytes() == before[0]  # 파일은 그대로 (행·기간 그대로)
        assert _meta(f"{o}.access.meta.json") == before[1]
        assert not sql("SELECT 1 FROM audit_log WHERE action = 'integrity.events_mismatch' AND target = %s", (o,))
    finally:
        CONFIG.write_text(TIERS, encoding="utf-8")


def test_default_meta_stays_as_marker_while_tier_files_remain(client):
    """기본 파일이 먼저 만료돼도 그 달의 등급 파일이 남아 있으면 기본 메타는 완료 표시로 남는다 — 마지막 등급 파일을 지울 때 함께 지운다."""
    from app import archive, retention

    r = NAMES["recent"]
    now = datetime.now(UTC)
    client.portal.call(archive.delete_expired, now + timedelta(days=400), retention.load())   # 기본 365일만 지남 (access 730일은 남음)
    marker = _meta(f"{r}.meta.json")
    assert marker["file"] is None and marker["expired_default"]["rows"] == 1 and not (ARCHIVE / f"{r}.jsonl.gz").exists()
    assert archive.is_archived(r) and (ARCHIVE / f"{r}.access.jsonl.gz").exists()
    assert r not in {a["partition"] for a in archive.list_archives() if a["tier"] is None}   # 화면·검증에는 파일만
    client.portal.call(archive.delete_expired, now + timedelta(days=800), retention.load())
    left = [p.name for p in _mine() if p.name.startswith(r)]
    assert left == [f"{r}.access.destroyed.json", f"{r}.web.destroyed.json"]   # 지운 표시만 남는다 (완료 표시도 함께 지움)


def test_bad_config_stops_archiving_and_deleting(client):
    """틀린 설정으로 접속기록을 짧은 등급에 넣거나 일찍 지우지 않게 — 고칠 때까지 DB 에 둔다. 감사로그는 하루 한 번."""
    from app import partitions

    start, end = _month(-9)
    name = f"events_{start:%Y_%m}"
    sql(f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF events FOR VALUES FROM ('{start:%Y-%m-%d}') TO ('{end:%Y-%m-%d}')")
    CONFIG.write_text(TIERS.replace("'source:iis'", "'hots:x'"), encoding="utf-8")
    try:
        for _ in range(2):
            assert client.post("/api/settings/retention/rotate", headers=CSRF).status_code == 200
        parts = {r[0] for r in sql("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid")}
        assert name in parts and not (ARCHIVE / f"{name}.meta.json").exists()
        logged = sql("SELECT detail->>'error' FROM audit_log WHERE action = 'retention.archive_failed' AND target = 'retention.yaml'")
        assert len(logged) == 1 and "hots" in logged[0][0]
        assert any("retention.yaml" in w for w in partitions.retention_warnings())
        assert client.get("/api/settings/retention").json()["policy"]["tier_error"].startswith("tiers[1].query")
    finally:
        CONFIG.write_text(TIERS, encoding="utf-8")
    assert client.post("/api/settings/retention/rotate", headers=CSRF).status_code == 200   # 고치면 이어서
    assert (ARCHIVE / f"{name}.meta.json").exists()
    for path in ARCHIVE.glob(f"{name}.*"):
        path.unlink()
