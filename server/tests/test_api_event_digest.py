"""수집 로그(접속기록)의 시간별 다이제스트 (BACKLOG B-71 2단계) — 통합 시험.

회귀: 감사로그에는 해시 체인이 있지만 events 에는 없어, DB 슈퍼유저가 로그를 고치거나 지우거나 끼워 넣어도 드러나지 않았다.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from functools import partial

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
NOW = datetime.now(UTC)
HOUR = NOW.replace(day=1, hour=0, minute=0, second=0, microsecond=0)   # 이번 달 첫 시간 — 언제 돌려도 이번 달 파티션 안


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _event(i):
    return {"date": NOW.isoformat(), "EventID": 4624, "Level": 4, "Channel": "Security", "Computer": "DIGEST-PC",
            "agent_host": "DIGEST-PC", "ProviderName": "Microsoft-Windows-Security-Auditing", "log_source": "winevtlog",
            "Message": f"로그온 {i}", "EventData": {"TargetUserName": f"user{i}", "IpAddress": "10.0.0.5", "숫자": 1.5}}


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from app import archive, integrity
    from app.main import app

    folder = str(tmp_path_factory.mktemp("archive"))
    saved = integrity.settings, archive.settings
    integrity.settings = replace(saved[0], archive_dir=folder)
    archive.settings = replace(saved[1], archive_dir=folder)
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            assert c.post("/api/ingest", json=[_event(i) for i in range(30)], headers={"X-API-Key": "test-key"}).json()["accepted"] == 30
            # 그 시간에 받은 것처럼 (수신 시각은 서버가 정한다 — 시험에서만 옮긴다)
            sql("UPDATE events SET received_at = %s + (id %% 50) * interval '1 minute' WHERE host = 'DIGEST-PC'", (HOUR,))
            yield c
    finally:
        integrity.settings, archive.settings = saved


def _digest(client):
    from app import eventdigest

    return client.portal.call(eventdigest.digest_closed_hours, HOUR + timedelta(hours=1, minutes=11))


def _check(client):
    from app import eventdigest

    return client.portal.call(eventdigest.check, HOUR, HOUR + timedelta(hours=1))


def test_closed_hour_is_digested_once_into_the_audit_chain(client):
    [d] = _digest(client)
    assert d["hour"] == HOUR.isoformat() and d["rows"] == 30 and len(d["sha256"]) == 64
    assert _digest(client) == []                                        # 한 번만
    [(detail, row_hash)] = sql("SELECT detail, row_hash FROM audit_log WHERE action = 'integrity.events_digest'")
    assert detail["hours"] == [d] and row_hash                          # 체인이 지키는 기록
    assert _check(client) == []


def test_db_and_archive_file_give_the_same_digest(client):
    """보관 파일(수신 시각 순·JSON)과 DB(번호 순·jsonb)가 같은 값을 낸다 — 다르면 보관할 때마다 거짓 경보."""
    from app import eventdigest

    rows = sql("SELECT id, received_at, ts, host, source, category, channel, provider, event_id, level, username, src_ip,"
               " message, raw FROM events WHERE host = 'DIGEST-PC' ORDER BY received_at, id")
    keys = ("id", "received_at", "ts", "host", "source", "category", "channel", "provider", "event_id", "level", "username",
            "src_ip", "message", "raw")
    acc = eventdigest.Hours()
    for r in rows:   # 보관 파일처럼 JSON 으로 한 번 갔다 온 값
        row = json.loads(json.dumps(dict(zip(keys, r, strict=True)), default=str))
        acc.add(row)
    want = client.portal.call(eventdigest.recorded, HOUR, HOUR + timedelta(hours=1))
    assert eventdigest.compare(acc, want) == []


@pytest.mark.parametrize(("change", "word"), [
    ("UPDATE events SET message = '고친 메시지' WHERE id = (SELECT min(id) FROM events WHERE host = 'DIGEST-PC')", "고쳐짐"),
    ("UPDATE events SET raw = raw || '{{\"x\": 1}}' WHERE id = (SELECT min(id) FROM events WHERE host = 'DIGEST-PC')", "고쳐짐"),
    ("UPDATE events SET src_ip = NULL WHERE id = (SELECT min(id) FROM events WHERE host = 'DIGEST-PC')", "고쳐짐"),
    ("DELETE FROM events WHERE id = (SELECT max(id) FROM events WHERE host = 'DIGEST-PC')", "지워짐"),
    (("INSERT INTO events (received_at, ts, host, source, level, message, raw)"
      " VALUES ('{h}'::timestamptz + interval '30 minutes', now(), 'GHOST', 'winevtlog', 4, '끼운 로그', '{{}}')"), "끼워짐"),
])
def test_tampering_with_collected_logs_is_detected(client, change, word):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:   # 바꾸고 확인한 뒤 되돌린다 (트랜잭션 안에서 다른 연결이 보도록 커밋)
        before = conn.execute("SELECT * FROM events WHERE host IN ('DIGEST-PC', 'GHOST') ORDER BY id").fetchall()
    sql(change.format(h=HOUR.isoformat()))
    try:
        problems = _check(client)
        assert len(problems) == 1 and word in problems[0] and f"{HOUR:%Y-%m-%d %H}시" in problems[0], problems
    finally:
        sql("DELETE FROM events WHERE host IN ('DIGEST-PC', 'GHOST')")
        cols = len(before[0])
        with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
            names = [d.name for d in conn.execute("SELECT * FROM events LIMIT 0").description]
            with conn.cursor().copy(f"COPY events ({', '.join(names)}) FROM STDIN") as copy:
                for row in before:
                    copy.write_row([json.dumps(v, ensure_ascii=False) if isinstance(v, dict) else v for v in row][:cols])
    assert _check(client) == []


def test_daily_verify_includes_recent_digests_and_cli_window(client):
    from app import integrity

    window = datetime.now(UTC) - HOUR + timedelta(hours=1)
    result = client.portal.call(partial(integrity.verify, None, (), window))
    assert result["ok"], result["problems"]
    assert result["events_hours"] == 1
    sql("UPDATE events SET message = '다시 고침' WHERE id = (SELECT min(id) FROM events WHERE host = 'DIGEST-PC')")
    result = client.portal.call(partial(integrity.verify, None, (), window))
    assert not result["ok"] and any("수집 로그" in p and "고쳐짐" in p for p in result["problems"])


def test_archiving_a_tampered_month_is_flagged(client):
    """보관 파일을 만들 때 그 달 전체를 맞춰 본다 — 파티션을 지우기 전 마지막 기회. 보관은 하되(파일 = 지금 DB) 빨갛게 알린다."""
    from app import archive, integrity

    partition = f"events_{HOUR:%Y_%m}"
    end = (HOUR + timedelta(days=32)).replace(day=1)
    meta = client.portal.call(archive.archive_partition, partition, HOUR, end)
    assert meta["digest_hours"] == 1 and meta["digest_problems"] == 1   # 앞 시험에서 고친 행
    [(target, detail)] = sql("SELECT target, detail FROM audit_log WHERE action = 'integrity.events_mismatch'")
    assert target == partition and "고쳐짐" in detail["problems"][0]
    notices = client.portal.call(integrity.status)["notices"]
    assert any(n["level"] == "bad" and partition in n["text"] for n in notices)
