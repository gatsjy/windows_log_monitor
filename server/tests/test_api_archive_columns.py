"""보관 파일의 공통 필드(category·username·src_ip) — 형식 v2 는 그대로 넣고, v1(옛 파일)은 복원할 때 원본에서 다시 구한다.

회귀(벤치마킹 조사에서 발견): archive.COLUMNS 에 마이그레이션 007 의 세 컬럼이 빠져, 보관했다가 복원한 달에서는
user:/ip:/분류 검색이 0건이고 분류로 범위를 정한 사용자에게 보이지 않았다.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
ARCHIVE = Path(os.environ["WLM_ARCHIVE_DIR"])
HERE = Path(__file__).resolve().parent


def _month(offset: int) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    index = now.year * 12 + now.month - 1 + offset
    start = datetime(index // 12, index % 12 + 1, 1, tzinfo=UTC)
    index += 1
    return start, datetime(index // 12, index % 12 + 1, 1, tzinfo=UTC)


V2, V1 = _month(-7), _month(-8)
V2_NAME, V1_NAME = f"events_{V2[0]:%Y_%m}", f"events_{V1[0]:%Y_%m}"


def sql(query, params=None):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _events():
    """소스마다 실제 모양 레코드를 정규화한 이벤트 (저장되는 값 그대로)."""
    from app.normalizers import IisContext, normalize

    now = datetime.now(UTC)
    win = next(r for r in map(json.loads, (HERE / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl")
                               .read_text(encoding="utf-8").splitlines()) if r["EventID"] == 4625)
    ctx = IisContext()
    iis_file = r"C:\inetpub\logs\LogFiles\W3SVC2\u_ex261019.log"
    fields = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status time-taken"
    normalize({"log": fields, "file": iis_file, "agent_host": "WEB-A", "log_source": "iis"}, now, ctx)
    records = [
        {**win, "agent_host": "WIN-A", "log_source": "winevtlog"},
        {"log": "2026-10-04 01:02:03 10.0.0.10 GET /login - 443 lee 198.51.100.9 Mozilla/5.0 401 15", "file": iis_file,
         "agent_host": "WEB-A", "log_source": "iis"},
        {"log": "2026-10-04 10:15:22.53 Logon       Login failed for user 'sa'. Reason: x [CLIENT: 198.51.100.20]",
         "agent_host": "DB-A", "log_source": "mssql", "file": "ERRORLOG"},
        {"pri": 38, "host": "lnx-a", "ident": "sshd", "log_source": "syslog",
         "message": "Failed password for invalid user admin from 203.0.113.45 port 40022 ssh2"},
    ]
    events = [normalize(r, now, ctx) for r in records]
    assert [(e.category, e.username, e.src_ip) for e in events] == [
        ("security", "wlmci", None), ("iis", "lee", "198.51.100.9"), ("mssql", "sa", "198.51.100.20"),
        ("syslog", "admin", "203.0.113.45")]
    return events


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
    for name in (V2_NAME, V1_NAME):
        for suffix in (".jsonl.gz", ".meta.json"):
            (ARCHIVE / f"{name}{suffix}").unlink(missing_ok=True)


def _stored(name: str) -> list[tuple]:
    return sql(f"SELECT host, category, username, src_ip FROM {name} ORDER BY id")


def test_v2_archive_keeps_the_common_fields(client):
    from app import archive

    sql(f"CREATE TABLE {V2_NAME} PARTITION OF events FOR VALUES FROM ('{V2[0]:%Y-%m-%d}') TO ('{V2[1]:%Y-%m-%d}')")
    at = V2[0].replace(day=2)
    for e in _events():
        sql("INSERT INTO events (received_at, ts, host, source, category, channel, provider, event_id, level, username,"
            " src_ip, message, raw) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
            (at, at, e.host, e.source, e.category, e.channel, e.provider, e.event_id, e.level, e.username, e.src_ip,
             e.message, json.dumps(e.raw, ensure_ascii=False)))
    before = _stored(V2_NAME)
    meta = client.portal.call(archive.archive_partition, V2_NAME, V2[0], V2[1])
    assert meta["format"] == "wlm-events-jsonl-v2" and meta["rows"] == 4
    with gzip.open(ARCHIVE / f"{V2_NAME}.jsonl.gz", "rt", encoding="utf-8") as fh:
        first = json.loads(fh.readline())
    assert {"category", "username", "src_ip"} <= set(first)
    sql(f"DROP TABLE {V2_NAME}")
    r = client.post("/api/settings/retention/restore", json={"partition": V2_NAME, "hold_days": 1}, headers=CSRF)
    assert r.status_code == 200 and r.json()["rows"] == 4, r.text
    assert _stored(V2_NAME) == before
    # 복원한 달에서 공통 필드로 찾을 수 있다
    since = V2[0].isoformat()
    until = V2[1].isoformat()
    found = client.get("/api/events", params={"since": since, "until": until, "query": "ip:198.51.100.9"}, headers=CSRF)
    assert [i["host"] for i in found.json()["items"]] == ["WEB-A"]


def test_v1_archive_restores_with_the_common_fields_derived(client):
    # 형식 v1(옛 파일): 세 컬럼 없이 저장되었다 — 복원할 때 원본에서 다시 구한다
    old_columns = ("id", "received_at", "ts", "host", "source", "channel", "provider", "event_id", "level", "message", "raw")
    at = V1[0].replace(day=3).isoformat()
    rows = []
    for i, e in enumerate(_events(), 1):
        # ADR-038 이전에 저장된 Windows 이벤트처럼 서버가 붙인 이름(raw.winevtlog) 없이
        raw = {k: v for k, v in e.raw.items() if k != "winevtlog"}
        row = {"id": 900000 + i, "received_at": at, "ts": at, "host": e.host, "source": e.source, "channel": e.channel,
               "provider": e.provider, "event_id": e.event_id, "level": e.level, "message": e.message, "raw": raw}
        rows.append(json.dumps({k: row[k] for k in old_columns}, ensure_ascii=False))
    path = ARCHIVE / f"{V1_NAME}.jsonl.gz"
    ARCHIVE.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(rows) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (ARCHIVE / f"{V1_NAME}.meta.json").write_text(json.dumps({
        "partition": V1_NAME, "from": V1[0].isoformat(), "to": V1[1].isoformat(), "rows": len(rows), "sha256": digest,
        "bytes": path.stat().st_size, "created_at": at, "format": "wlm-events-jsonl-v1", "file": path.name}), encoding="utf-8")
    r = client.post("/api/settings/retention/restore", json={"partition": V1_NAME, "hold_days": 1}, headers=CSRF)
    assert r.status_code == 200 and r.json()["rows"] == 4, r.text
    assert [s[1:] for s in _stored(V1_NAME)] == [
        ("security", "wlmci", None), ("iis", "lee", "198.51.100.9"), ("mssql", "sa", "198.51.100.20"),
        ("syslog", "admin", "203.0.113.45")]
    # 복원한 달에서도 f.EventData.<이름> 이 맞게 이름을 붙였다
    assert sql(f"SELECT raw->'winevtlog'->'EventData'->>'TargetUserName' FROM {V1_NAME} WHERE source = 'winevtlog'") \
        == [("wlmci",)]


def test_archive_has_every_events_column(client):
    # events 에 열을 더하면 보관 파일에도 넣어야 한다 — 빠지면 복원한 달에서 그 열이 비어 검색·범위가 어긋난다
    from app import archive

    columns = {r[0] for r in sql("SELECT column_name FROM information_schema.columns WHERE table_name = 'events'")}
    assert columns == set(archive.COLUMNS)
