"""수집 → 정규화 → 검색·통계 통합 테스트 (분류, 공통 필드 사용자·IP, IIS·MSSQL)."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def _win(host, event_id, data, channel="Security", provider="Microsoft-Windows-Security-Auditing", message="m"):
    now = datetime.now(UTC)
    return {"date": now.isoformat(), "TimeCreated": now.strftime("%Y-%m-%d %H:%M:%S +0000"), "EventID": event_id,
            "Level": 0, "Keywords": "0x8010000000000000", "Channel": channel, "ProviderName": provider,
            "Computer": host, "Message": message, "EventData": data, "agent_host": host, "log_source": "winevtlog"}


def _mssql(text, process="Logon"):
    # ERRORLOG 시각에는 시간대가 없어 WLM_DISPLAY_TZ(기본 Asia/Seoul)로 해석된다
    stamp = datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S.00")
    return {"log": f"{stamp} {process:<11} {text}", "agent_host": "DB-T", "log_source": "mssql", "file": "ERRORLOG"}


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
        records = [_win("WIN-T", 4625, {"TargetUserName": "kim", "IpAddress": "203.0.113.7", "LogonType": "10"})
                   for _ in range(3)]
        records += [_win("WIN-T", 4624, {"TargetUserName": "PC01$", "IpAddress": "-"}) for _ in range(5)]
        records += [
            {"log": "#Fields: date time c-ip cs-method cs-uri-stem sc-status time-taken", "file": "W3SVC1\\u.log",
             "agent_host": "WEB-T", "log_source": "iis"},
            {"log": f"{datetime.now(UTC):%Y-%m-%d %H:%M:%S} 203.0.113.7 GET /x 500 12", "file": "W3SVC1\\u.log",
             "agent_host": "WEB-T", "log_source": "iis"},
            _mssql("Error: 18456, Severity: 14, State: 8."),
            _mssql("Login failed for user 'sa'. Reason: x [CLIENT: 198.51.100.1]"),
        ]
        r = c.post("/api/ingest", json=records, headers=KEY)
        assert r.status_code == 200 and r.json()["accepted"] == len(records) - 1  # IIS 머리줄은 저장 안 함
        yield c


def _items(client, **params):
    r = client.get("/api/events", params={"since": "1h", **params}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_category_and_common_fields(client):
    fails = _items(client, user="kim")
    assert len(fails) == 3 and {(e["category"], e["src_ip"]) for e in fails} == {("security", "203.0.113.7")}
    assert len(_items(client, ip="203.0.113.7")) == 4  # Windows 3 + IIS 1 — 소스를 가로질러 같은 IP
    assert len(_items(client, category="iis,mssql")) == 3
    assert len(_items(client, **{"f.EventData.LogonType": "10"})) == 3


def test_mssql_error_header_not_counted_twice(client):
    assert len(_items(client, event_id="18456")) == 1


def test_top_user_and_ip_skip_empty(client):
    r = client.get("/api/stats/top", params={"since": "1h", "field": "user"}, headers=CSRF)
    assert [(i["value"], i["n"]) for i in r.json()["items"]] == [("kim", 3), ("sa", 1)]
    r = client.get("/api/stats/top", params={"since": "1h", "field": "host"}, headers=CSRF)
    assert {i["value"] for i in r.json()["items"]} == {"WIN-T", "WEB-T", "DB-T"}


def test_search_requires_login(client):
    from fastapi.testclient import TestClient

    from app.main import app

    assert TestClient(app).get("/api/events").status_code == 401


def test_search_time_limit(client, monkeypatch):
    """화면 조회 쿼리는 WLM_SEARCH_TIMEOUT_SEC 를 넘으면 멈추고 503 + 그 화면에 맞는 안내 (ADR-035).
    상한은 그 요청에만 걸린다 — 같은 연결을 다음에 쓰는 수집·알림 엔진에는 남지 않는다."""
    import time
    from dataclasses import replace

    from app import db, repository
    from app.routers import query

    monkeypatch.setattr(query, "settings", replace(query.settings, search_timeout_sec=1))

    async def slow(*_args, **_kwargs):
        await db.fetch_one("SELECT pg_sleep(10)")   # 상한(1초)보다 훨씬 길게 — 느린 CI 에서도 '멈췄는지'만 본다

    monkeypatch.setattr(repository, "count", slow)
    started = time.monotonic()
    r = client.get("/api/stats/count", params={"since": "1h"}, headers=CSRF)
    assert r.status_code == 503 and "1초" in r.json()["detail"] and "따옴표" in r.json()["detail"]
    assert time.monotonic() - started < 6
    # 검색 문장 칸이 없는 화면에는 그 화면에서 할 수 있는 안내만
    monkeypatch.setattr(repository, "agents", slow)
    r = client.get("/api/agents", params={"since": "30d"}, headers=CSRF)
    assert r.status_code == 503 and "기간을 줄여" in r.json()["detail"] and "따옴표" not in r.json()["detail"]
    # 끝나지 않은 검색도 접속기록에 남는다 (ISMS 2.9.4)
    monkeypatch.setattr(repository, "list_events", slow)
    r = client.get("/api/events", params={"since": "1h", "query": "user:timeout-check"}, headers=CSRF)
    assert r.status_code == 503
    row = client.portal.call(db.fetch_one, "SELECT detail FROM audit_log WHERE action = 'events.search'"
                                           " ORDER BY id DESC LIMIT 1")
    assert row["detail"]["query"]["query"] == "user:timeout-check" and row["detail"]["timeout_sec"] == 1
    # 요청 밖(알림 엔진·보고서처럼 앱 안의 작업)은 상한 없음, 풀의 연결마다 SET LOCAL 이 남지 않음
    assert client.portal.call(db.fetch_one, "SELECT 1 AS ok FROM pg_sleep(1.2)")["ok"] == 1
    for _ in range(10):
        assert client.portal.call(db.fetch_one, "SHOW statement_timeout")["statement_timeout"] == "0"
    # 상한 안이면 그대로
    monkeypatch.undo()
    assert client.get("/api/stats/count", params={"since": "1h"}, headers=CSRF).status_code == 200


def test_search_slots_keep_connections_for_ingest(client):
    """상한이 걸린 조회는 SEARCH_SLOTS 개까지만 연결을 쓴다 — 느린 검색이 몰려도 수집·엔진 몫(4개)은 남는다.
    자리를 못 얻으면 상한 시간 뒤 '몰림' 안내. 자리는 시험이 직접 잡아 시간에 기대지 않는다."""
    import time

    from app import db

    async def limited(sql):
        db.limit_statement_time(1)
        return await db.fetch_one(sql)

    async def hold(n):
        for _ in range(n):
            await db._search_slots.acquire()

    async def free(n):
        for _ in range(n):
            db._search_slots.release()

    client.portal.call(hold, db.SEARCH_SLOTS)
    try:
        started = time.monotonic()
        with pytest.raises(db.QueryTimeout) as info:
            client.portal.call(limited, "SELECT 1")
        assert info.value.busy and 0.9 < time.monotonic() - started < 6
        # 상한 없는 작업(수집·알림 엔진)은 자리와 무관하게 바로 (잘못 자리를 기다리면 여기서 멈춘다)
        started = time.monotonic()
        assert client.portal.call(db.fetch_one, "SELECT 1 AS ok")["ok"] == 1
        assert time.monotonic() - started < 3
    finally:
        client.portal.call(free, db.SEARCH_SLOTS)
    assert client.portal.call(limited, "SELECT 1 AS ok")["ok"] == 1
    assert db.POOL_MAX - db.SEARCH_SLOTS >= 4


def test_other_cancel_is_not_a_timeout(client):
    """관리자의 pg_cancel_backend 같은 다른 취소는 '시간 초과' 안내로 바꾸지 않는다."""
    import asyncio

    import psycopg

    from app import db

    async def run():
        db.limit_statement_time(30)

        async def cancel_when_running():
            # 쿼리가 실제로 돌기 시작한 뒤에 취소한다 (정해 둔 시간만 기다리면 느린 CI 에서 취소가 먼저 와 빗나간다)
            async with await db.connect_autocommit() as conn:
                for _ in range(200):
                    cur = await conn.execute("SELECT pg_cancel_backend(pid) AS ok FROM pg_stat_activity"
                                             " WHERE query = 'SELECT pg_sleep(30)' AND state = 'active'"
                                             " AND pid <> pg_backend_pid()")
                    if await cur.fetchone():
                        return
                    await asyncio.sleep(0.05)

        task = asyncio.create_task(cancel_when_running())
        try:
            await db.fetch_one("SELECT pg_sleep(30)")
        finally:
            await task

    with pytest.raises(psycopg.errors.QueryCanceled) as info:
        client.portal.call(run)
    assert not isinstance(info.value, db.QueryTimeout)


def test_search_routes_have_time_limit(client, monkeypatch):
    """이벤트를 읽는 화면 API 는 모두 시간 상한을 건다. 수집·로그인·쓰기(PC 삭제)는 걸지 않는다 (실제로 불러서 확인)."""
    from app import db

    seen = []
    monkeypatch.setattr(db, "limit_statement_time", seen.append)

    def limited(method, path, **kw):
        seen.clear()
        client.request(method, path, **{"headers": CSRF, **kw})
        return bool(seen)

    for path in ("/api/events?since=1h", "/api/events/999999", "/api/stats/count?since=1h",
                 "/api/stats/timeseries?since=1h", "/api/stats/top?since=1h&field=host", "/api/stats/summary",
                 "/api/agents", "/api/fields", "/api/search/parse?query=host:A"):
        assert limited("GET", path), path
    rule = {"name": "미리보기", "severity": "error", "match": {"event_id": "4625"}, "group_by": "ip",
            "window_sec": 600, "threshold": 2, "cooldown_sec": 3600}
    assert limited("POST", "/api/alerts/rules/preview", json={"rule": rule})
    assert not limited("POST", "/api/ingest", json=[], headers=KEY)
    assert not limited("GET", "/api/auth/me")
    # 쓰기는 잠금을 기다려서라도 끝낸다
    assert not limited("DELETE", "/api/agents/NO-SUCH-PC")
    assert not limited("POST", "/api/agents/delete", json={"hosts": ["NO-SUCH-PC"]})


def test_agent_transport_from_heartbeat(client):
    """하트비트가 들어온 전송 방식(TLS 리스너·신뢰 프록시면 https)을 PC 마다 기록 — 평문 수집을 닫을 근거 (ADR-036).
    이벤트만 오면(수집기를 거친 syslog 등) 바꾸지 않는다."""
    hb = {"type": "heartbeat", "agent_host": "TLS-PC", "config_version": "0.3.0"}
    assert client.post("https://testserver/api/ingest", json=[hb], headers=KEY).status_code == 200
    plain_hb = {**hb, "agent_host": "PLAIN-PC"}
    assert client.post("/api/ingest", json=[plain_hb], headers=KEY).status_code == 200
    # 같은 PC 의 이벤트가 평문(수집기 등)으로 와도 TLS 기록은 그대로
    assert client.post("/api/ingest", json=[_win("TLS-PC", 4624, {})], headers=KEY).status_code == 200
    # 화면 포트(8000)로 온 평문 = 0.4 이전 묶음 — TLS 를 켜면 끊기므로 따로 표시
    web_hb = {**hb, "agent_host": "WEB-PORT-PC"}
    assert client.post("http://testserver:8000/api/ingest", json=[web_hb], headers=KEY).status_code == 200
    r = client.get("/api/agents", params={"since": "1h"}, headers=CSRF).json()
    by_host = {a["host"]: a["last_transport"] for a in r["items"]}
    assert by_host["TLS-PC"] == "tls" and by_host["PLAIN-PC"] == "plain" and by_host["WIN-T"] is None
    assert by_host["WEB-PORT-PC"] == "web"
    assert r["transport"] == {"tls": False, "ingest_plain": True}


def test_nul_bytes_do_not_reject_the_whole_request(client):
    """레코드 하나의 NUL 이 요청 전체(같은 청크의 다른 로그까지)를 거절시키지 않는다 — 에이전트는 거절된 청크를 끝없이 다시 보낸다."""
    ok = {"pri": 38, "host": "NUL-OK", "ident": "sshd", "log_source": "syslog", "message": "fine"}
    records = [ok,
               {**ok, "host": "NUL-\x00SW", "message": "a\x00b", "weird\x00key": "v\x00"},
               _win("NUL-\x00PC", 4625, {"TargetUserName": "ev\x00il", "IpAddress": "10.0.0.\x009"}, channel="Sec\x00urity"),
               {"log": f"{datetime.now(UTC):%Y-%m-%d %H:%M:%S} 10.0.0.10 GET /x - 443 - 203.0.113.5 UA - 200 0 0 1", "file": "a\x00b",
                "agent_host": "NUL-WEB", "log_source": "iis"}]
    r = client.post("/api/ingest", json=records, headers=KEY)
    assert r.status_code == 200 and r.json()["accepted"] == 4, r.text
    stored = {i["host"]: i for i in _items(client, query="host:NUL-OK,NUL-SW,NUL-PC,NUL-WEB")}
    assert set(stored) == {"NUL-OK", "NUL-SW", "NUL-PC", "NUL-WEB"}
    assert (stored["NUL-PC"]["username"], stored["NUL-PC"]["src_ip"], stored["NUL-PC"]["channel"]) == ("evil", "10.0.0.9", "Security")


def test_literal_backslash_u0000_text_is_stored_as_is(client):
    """값에 글자 그대로 든 '\\u0000'(로그온 창에 친 계정 이름 등)을 NUL 로 착각해 지우면 JSON 이 깨져 저장이 실패했다
    (B-40 이후에는 격리 — 공격자가 자기 이벤트를 규칙·검색에서 뺄 수 있었다, 검토에서 재현)."""
    rec = {"pri": 38, "host": "LIT-U0", "ident": "sshd", "log_source": "syslog",
           "message": 'Failed password for ev\\u0000il"x from 203.0.113.70', "note": "a\\u0000\\"}
    r = client.post("/api/ingest", json=[rec], headers=KEY)
    assert r.status_code == 200 and r.json() == {"accepted": 1, "heartbeats": 0}, r.text
    [item] = _items(client, query="host:LIT-U0")
    detail = client.get(f"/api/events/{item['id']}", headers=CSRF).json()
    assert detail["raw"]["note"] == "a\\u0000\\" and detail["message"] == rec["message"]


def test_lone_surrogates_do_not_reject_the_whole_request(client):
    """JSON 의 짝 없는 서로게이트(\\ud800)는 UTF-8 로 보낼 수 없어 요청 전체가 500 이 됐다(B-40, 재현) — U+FFFD 로 바꿔 저장한다."""
    ok = '{"pri": 38, "host": "SUR-OK", "ident": "sshd", "log_source": "syslog", "message": "fine"}'
    bad = ('{"pri": 38, "host": "SUR-\\ud800X", "ident": "sshd", "log_source": "syslog", "message": "a\\udc00b",'
           ' "k\\ud83dey": ["v\\ud800", {"x": "\\udfff"}], "pair": "\\ud83d\\ude00"}')
    r = client.post("/api/ingest", content=f"[{ok}, {bad}]", headers={**KEY, "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["accepted"] == 2, r.text
    stored = {i["host"]: i for i in _items(client, query="host:SUR-OK,SUR-\ufffdX")}
    assert set(stored) == {"SUR-OK", "SUR-\ufffdX"}
    detail = client.get(f"/api/events/{stored['SUR-\ufffdX']['id']}", headers=CSRF).json()
    assert detail["message"] == "a\ufffdb" and detail["raw"]["pair"] == "\U0001f600"   # 짝이 맞는 것은 그대로
    assert detail["raw"]["k\ufffdey"] == ["v\ufffd", {"x": "\ufffd"}]


def _audit_rows(action):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
        return conn.execute("SELECT target, detail FROM audit_log WHERE action = %s ORDER BY id", (action,)).fetchall()


def test_event_view_records_whose_record_was_viewed(client):
    """접속기록에 누구의 기록(정보주체)을 봤는지 — 이벤트의 사용자·IP·분류 (ADR-042)."""
    item = _items(client, user="kim")[0]
    assert client.get(f"/api/events/{item['id']}", headers=CSRF).status_code == 200
    target, detail = _audit_rows("events.view")[-1]
    assert target == str(item["id"])
    assert (detail["username"], detail["src_ip"], detail["category"]) == ("kim", "203.0.113.7", "security")


def test_personal_top_values_are_logged_once_per_ten_minutes(client):
    from app.routers import query

    query._stats_audited.clear()
    before = len(_audit_rows("events.stats"))
    for _ in range(3):   # 대시보드 위젯이 같은 조건으로 되풀이해 불러도 10분에 한 번
        assert client.get("/api/stats/top", params={"since": "1h", "field": "user"}, headers=CSRF).status_code == 200
    assert client.get("/api/stats/top", params={"since": "1h", "field": "host"}, headers=CSRF).status_code == 200  # 개인정보 아님
    assert client.get("/api/stats/top", params={"since": "1h", "field": "ip"}, headers=CSRF).status_code == 200
    assert [r[0] for r in _audit_rows("events.stats")[before:]] == ["user", "ip"]


def test_views_fail_closed_when_the_access_log_cannot_be_written(client, monkeypatch):
    """접속기록을 남기지 못하면 개인정보가 보이는 조회·내려받기는 결과를 내주지 않는다 (503) — 기록 없이 열람되지 않게."""
    from app import db
    from app.routers import query

    event_id = _items(client, user="kim")[0]["id"]
    real_audit = db.audit

    async def broken(*args, required=False, **kwargs):
        if required:
            raise db.AuditError("시험")
        return await real_audit(*args, required=required, **kwargs)

    monkeypatch.setattr(db, "audit", broken)
    query._stats_audited.clear()
    for path, params in (("/api/events", {"since": "1h"}), (f"/api/events/{event_id}", {}),
                         ("/api/stats/top", {"since": "1h", "field": "user"}),
                         ("/api/audit", {"format": "csv", "reason": "시험"}),
                         ("/api/alerts", {"format": "csv", "reason": "시험"})):
        r = client.get(path, params=params, headers=CSRF)
        assert r.status_code == 503 and "접속기록" in r.json()["detail"], (path, r.status_code)
    # 개인정보가 아닌 조회는 그대로
    assert client.get("/api/stats/top", params={"since": "1h", "field": "host"}, headers=CSRF).status_code == 200

