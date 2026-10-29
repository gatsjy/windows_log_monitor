"""수집 견고성 (B-40): 문제 레코드 격리와 수집 거절 장부 — 통합 시험.

회귀: 레코드 하나의 값(INTEGER 범위를 넘는 EventID 등) 때문에 저장이 실패하면 그 요청의 다른 레코드·하트비트까지 거절(500)되고,
에이전트는 같은 청크를 끝없이 다시 보내 그 PC 의 로그가 멈췄다. 서버가 거절한 요청(옛 API 키 등)은 어디에도 남지 않았다.
알려진 값 오류는 이제 정규화에서 막으므로, 격리(모르는 값 오류)는 특정 PC 의 레코드에서 DB 값 오류를 일으켜 시험한다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _win(host, event_id=4625):
    return {"date": datetime.now(UTC).isoformat(), "EventID": event_id, "Channel": "Security", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": "로그온 실패",
            "EventData": {"TargetUserName": "kim", "IpAddress": "203.0.113.5"}}


def _forget_ledger(client, status):
    """이 시험이 일부러 만든 거절은 장부에서 지운다 (아래 장부 시험이 정확한 목록을 본다)."""
    from app import rejects

    client.portal.call(rejects.flush)
    sql("DELETE FROM ingest_rejections WHERE status = %s", (status,))


def _ledger():
    """시간 줄을 합친 (보낸 곳, 상태, 사유, 횟수) — 시험이 정시를 넘겨 돌아도 같게."""
    return sql("SELECT client_ip, status, reason, sum(count)::int FROM ingest_rejections GROUP BY 1, 2, 3 ORDER BY 2, 3, 1")


@pytest.fixture
def poison(monkeypatch):
    """host 가 BAD 로 시작하는 이벤트가 든 COPY 는 DB 의 값 오류로 실패한다 (저장점 안이라 진짜와 같게 되돌려진다)."""
    from app import repository

    real = repository._write

    async def write(conn, events, *args, **kwargs):
        if any(e.host.startswith("BAD") for e in events):
            raise psycopg.errors.NumericValueOutOfRange("integer out of range (시험)")
        return await real(conn, events, *args, **kwargs)

    monkeypatch.setattr(repository, "_write", write)


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


def test_one_bad_record_is_quarantined_and_the_rest_is_stored(client, poison):
    records = [_win("Q-OK1"), _win("BAD-Q"), _win("Q-OK2"),
               {"type": "heartbeat", "agent_host": "Q-HB", "config_version": "0.4.0"}]
    r = client.post("/api/ingest", json=records, headers=KEY)
    assert r.status_code == 200, r.text
    assert r.json() == {"accepted": 2, "heartbeats": 1, "quarantined": 1}
    assert sorted(h for (h,) in sql("SELECT host FROM events")) == ["Q-OK1", "Q-OK2"]
    assert sql("SELECT host FROM agents WHERE last_heartbeat_at IS NOT NULL") == [("Q-HB",)]
    [(host, source, user, error, record)] = sql("SELECT host, source, username, error, record FROM ingest_quarantine")
    assert (host, source, user) == ("BAD-Q", "winevtlog", "kim") and "NumericValueOutOfRange" in error
    assert '"Computer": "BAD-Q"' in record   # 원본 그대로


def test_several_bad_records_in_a_large_batch(client, poison):
    records = [_win(f"QB-{i}") for i in range(40)]
    records[3] = _win("BAD-A")
    records[31] = _win("BAD-B")
    r = client.post("/api/ingest", json=records, headers=KEY)
    assert r.json()["accepted"] == 38 and r.json()["quarantined"] == 2
    assert sql("SELECT count(*) FROM events WHERE host LIKE 'QB-%%'") == [(38,)]
    assert sorted(h for (h,) in sql("SELECT host FROM ingest_quarantine WHERE host IN ('BAD-A', 'BAD-B')")) == ["BAD-A", "BAD-B"]


def test_a_later_failure_rolls_back_the_whole_request(client, poison, monkeypatch):
    """반쯤 커밋한 뒤 500 이면 에이전트가 청크째 다시 보내 앞부분이 두 번 저장됐다(검토에서 재현) — 한 트랜잭션."""
    from app import repository

    async def broken(conn, bad, client_ip):
        raise psycopg.OperationalError("연결 끊김 (시험)")

    monkeypatch.setattr(repository, "_quarantine", broken)
    records = [_win("RB-1"), _win("BAD-RB"), _win("RB-2"), {"type": "heartbeat", "agent_host": "RB-HB"}]
    with pytest.raises(psycopg.OperationalError):
        client.post("/api/ingest", json=records, headers=KEY)
    assert sql("SELECT count(*) FROM events WHERE host LIKE 'RB-%%'") == [(0,)]
    assert sql("SELECT count(*) FROM agents WHERE host = 'RB-HB'") == [(0,)]
    _forget_ledger(client, 500)


def test_too_many_bad_records_are_refused_not_hammered(client, poison, monkeypatch):
    """값 오류 레코드만 잔뜩 보내 레코드 수에 비례해 DB 를 두드리게 할 수 없다 (검토에서 재현) — 시도 상한을 넘으면 400."""
    from app import repository

    monkeypatch.setattr(repository, "ISOLATE_BUDGET", 3)
    r = client.post("/api/ingest", json=[_win(f"BAD-{i}") for i in range(20)] + [_win("TM-OK")], headers=KEY)
    assert r.status_code == 400 and "너무 많아" in r.text
    assert sql("SELECT count(*) FROM events WHERE host = 'TM-OK'") == [(0,)]
    _forget_ledger(client, 400)


def test_values_that_used_to_fail_are_now_stored(client):
    """범위 밖 EventID·NaN·깊게 겹친 서로게이트·UTC 로 옮기면 범위를 벗어나는 시각 — 모두 레코드 하나가 요청을 막았다."""
    deep = "\\ud800"
    for _ in range(1500):
        deep = f"[{deep}]" if deep.startswith("[") else f'["{deep}"]' if not deep.startswith('"') else f"[{deep}]"
    now = datetime.now(UTC).isoformat()
    body = "[" + ",".join([
        (f'{{"date": "{now}", "EventID": 99999999999, "Channel": "Security", "Computer": "V-EID", "agent_host": "V-EID",'
         ' "log_source": "winevtlog", "Message": "m"}'),
        '{"log_source": "file", "agent_host": "V-NAN", "message": "nan", "score": NaN, "x": -Infinity}',
        f'{{"log_source": "file", "agent_host": "V-DEEP", "message": "deep", "d": {deep}}}',
        ('{"log_source": "syslog", "pri": 38, "host": "V-TIME", "agent_host": "V-TIME", "ident": "sshd",'
         ' "time": "0001-01-01T00:00:00+09:00", "message": "Failed password for root from 203.0.113.5 port 22 ssh2"}'),
    ]) + "]"
    r = client.post("/api/ingest", content=body, headers={**KEY, "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["accepted"] == 4, r.text
    rows = dict(sql("SELECT host, raw FROM events WHERE host LIKE 'V-%%'"))
    assert rows["V-EID"]["EventID"] == 99999999999 and sql("SELECT event_id FROM events WHERE host = 'V-EID'") == [(None,)]
    assert (rows["V-NAN"]["score"], rows["V-NAN"]["x"]) == ("NaN", "-Infinity")
    assert sql("SELECT message, src_ip FROM events WHERE host = 'V-TIME'") == [
        ("Failed password for root from 203.0.113.5 port 22 ssh2", "203.0.113.5")]


def test_rejected_requests_are_kept_in_the_ledger(client):
    from app import rejects

    client.post("/api/ingest", json=[_win("R-1")], headers={"X-API-Key": "old-key"})
    client.post("/api/ingest", json=[_win("R-1")], headers={"X-API-Key": "old-key"})
    client.post("/api/ingest", json=[_win("R-1")])
    client.post("/api/ingest", content=b"{not json", headers={**KEY, "Content-Type": "application/json"})
    client.portal.call(rejects.flush)
    client.post("/api/ingest", json=[_win("R-1")], headers={"X-API-Key": "old-key"})
    client.portal.call(rejects.flush)   # 두 번째 기록은 같은 줄에 더한다
    rows = _ledger()
    assert [(s, n) for _, s, _, n in rows] == [(400, 1), (401, 1), (401, 3)]
    assert [r for _, _, r, _ in rows][1:] == ["API 키(X-API-Key)가 없습니다", "API 키가 올바르지 않습니다"]
    assert rows[0][2].startswith("JSON 형식 오류") and {ip for ip, *_ in rows} == {"testclient"}


def test_non_ascii_key_is_a_key_error_not_a_server_error(client):
    """붙여 넣다 섞인 글자(é 등) 하나로 hmac 비교가 TypeError → 500 '서버 오류'가 됐다(검토에서 재현)."""
    from app import rejects

    r = client.post("/api/ingest", json=[_win("R-2")], headers={"X-API-Key": "caf\u00e9-key".encode("latin-1")})
    assert r.status_code == 401, r.text
    client.portal.call(rejects.flush)
    assert ("testclient", 401, "API 키가 올바르지 않습니다", 4) in _ledger()


def test_disconnect_is_not_a_server_error(client, monkeypatch):
    from starlette.requests import ClientDisconnect

    from app import rejects
    from app.routers import ingest

    async def gone(request):
        raise ClientDisconnect()

    monkeypatch.setattr(ingest, "_read_body", gone)
    with pytest.raises(ClientDisconnect):
        client.post("/api/ingest", json=[_win("R-3")], headers=KEY)
    monkeypatch.undo()
    client.portal.call(rejects.flush)
    assert ("testclient", 499, "보내는 쪽이 연결을 끊음", 1) in _ledger()
    assert not [r for r in _ledger() if r[1] == 500]


def test_ledger_keeps_counts_when_writing_fails(client, monkeypatch):
    from app import rejects, repository

    rejects.note("10.0.0.7", 401, "API 키가 올바르지 않습니다")

    async def broken(rows):
        raise RuntimeError("DB 끊김")

    monkeypatch.setattr(repository, "add_ingest_rejections", broken)
    with pytest.raises(RuntimeError):
        client.portal.call(rejects.flush)
    rejects.note("10.0.0.7", 401, "API 키가 올바르지 않습니다")
    monkeypatch.undo()
    client.portal.call(rejects.flush)
    assert sql("SELECT sum(count)::int FROM ingest_rejections WHERE client_ip = '10.0.0.7'") == [(2,)]


def test_ledger_memory_stays_bounded_and_survives_cancel(client, monkeypatch):
    """DB 가 멈춘 동안 되돌려 놓으며 상한을 넘던 것, 종료로 취소된 기록이 사라지던 것(검토에서 재현)."""
    import asyncio

    from app import rejects, repository

    monkeypatch.setattr(rejects, "MAX_KEYS", 2)
    rejects.note("10.9.0.1", 401, "API 키가 올바르지 않습니다")
    rejects.note("10.9.0.2", 401, "API 키가 올바르지 않습니다")

    async def broken(rows):
        for i in range(3, 8):   # 기록이 기다리는 사이 새 IP 들이 거절된다
            rejects.note(f"10.9.0.{i}", 401, "API 키가 올바르지 않습니다")
        raise RuntimeError("DB 끊김")

    monkeypatch.setattr(repository, "add_ingest_rejections", broken)
    with pytest.raises(RuntimeError):
        client.portal.call(rejects.flush)
    ips = {k[0] for k in rejects._pending}
    assert len(ips - {rejects.OTHER_IP}) <= 2 and sum(v[0] for v in rejects._pending.values()) == 7

    async def cancelled(rows):
        raise asyncio.CancelledError

    monkeypatch.setattr(repository, "add_ingest_rejections", cancelled)
    with pytest.raises(BaseException, match="") as caught:   # 포털을 건너오며 concurrent.futures 의 취소로 바뀐다
        client.portal.call(rejects.flush)
    assert "Cancelled" in type(caught.value).__name__
    assert sum(v[0] for v in rejects._pending.values()) == 7   # 취소돼도 버리지 않는다
    monkeypatch.undo()
    client.portal.call(rejects.flush)
    assert sql("SELECT sum(count)::int FROM ingest_rejections WHERE client_ip LIKE '10.9.0.%%' OR client_ip = %s",
               (rejects.OTHER_IP,)) == [(7,)]
    sql("DELETE FROM ingest_rejections WHERE client_ip LIKE '10.9.0.%%' OR client_ip = %s", (rejects.OTHER_IP,))


def test_problems_screen_and_original_record_are_admin_only_and_logged(client):
    from fastapi.testclient import TestClient

    from app.main import app

    body = client.get("/api/agents/problems", params={"since": "1h"}, headers=CSRF).json()
    assert {r["status"] for r in body["rejections"]} == {400, 401, 499}
    assert all("record" not in q for q in body["quarantine"]) and len(body["quarantine"]) == 3
    qid = body["quarantine"][-1]["id"]
    record = client.get(f"/api/agents/quarantine/{qid}", headers=CSRF).json()["record"]
    assert '"Computer": "BAD-Q"' in record
    assert sql("SELECT target, detail->>'host', detail->>'username', detail->>'src_ip' FROM audit_log"
               " WHERE action = 'events.quarantine.view'") == [(f"#{qid}", "BAD-Q", "kim", "203.0.113.5")]

    temp = client.post("/api/users", json={"username": "viewer", "role": "viewer"}, headers=CSRF).json()
    viewer = TestClient(app)
    viewer.post("/api/auth/login", json={"username": "viewer", "password": temp["temp_password"]}, headers=CSRF)
    viewer.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": "Look#Member2026"},
                headers=CSRF)
    assert viewer.get("/api/agents/problems", headers=CSRF).status_code == 403
    assert viewer.get(f"/api/agents/quarantine/{qid}", headers=CSRF).status_code == 403


def test_report_points_at_rejections_and_quarantine(client):
    from app.reports import builder, render

    now = datetime.now(UTC)
    payload = client.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    rejected = {r["status"]: (r["n"], r["ips"]) for r in payload["ingest"]["rejected"]}
    assert payload["ingest"]["quarantined"] == 3 and rejected[400] == (1, 1) and rejected[401] == (7, 2) and rejected[499] == (1, 1)
    texts = [a["text"] for a in payload["attention"]]
    assert "저장하지 못해 격리한 수집 레코드 3건 — 수집 PC 화면에서 확인하세요" in texts
    assert "API 키가 틀리거나 없어 거절된 수집 요청 7건 (보낸 곳 2곳) — 키를 바꾼 뒤 옛 설치 묶음으로 보내는 PC" in texts
    assert not [t for t in texts if t.startswith("499")]   # 보내는 쪽이 끊은 것은 점검 필요가 아니다
    assert "수집 거절·격리" in render.html(payload)


def test_purge_after_the_log_retention(client):
    from app import partitions

    client.portal.call(partitions.purge_ingest_problems, datetime.now(UTC) + timedelta(days=400))
    assert sql("SELECT count(*) FROM ingest_quarantine") == [(0,)]
    assert sql("SELECT count(*) FROM ingest_rejections") == [(0,)]
    assert sql("SELECT action FROM audit_log WHERE action = 'retention.purge_ingest'") == [("retention.purge_ingest",)]
