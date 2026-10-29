"""알림 전송기와 엔진 자체 감시 (ADR-045, BACKLOG B-34) — 통합 시험.

회귀: 엔진이 평가 주기 안에서 보내 메일 서버 하나가 멈추면 평가가 늦어졌고, 보내는 중 서버가 멈추면 그 알림은 '전송 중'으로
영영 남았다(아무도 pending 을 다시 보내지 않음). 규칙 쿼리에 시간 상한이 없었고, 상태 띠는 평가가 멈춰도 초록이었다.
전송기는 시험에서 돌지 않는다(conftest) — 시험이 dispatcher.drain() 으로 보낸다.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


class _Receiver(BaseHTTPRequestHandler):
    """경로로 응답을 정한다: /ok → 200, /down → 503, /bad → 400. 받은 것을 남긴다."""

    received: ClassVar[list[tuple[str, dict]]] = []

    def do_POST(self):  # http.server 가 부르는 이름
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Receiver.received.append((self.path, body))
        code = {"/ok": 200, "/down": 503, "/bad": 400}.get(self.path, 200)
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"x")

    def log_message(self, *args):
        pass


def sql(query, params=()):
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

    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            for name, path, extra in (("정상", "ok", {}), ("멈춤", "down", {}), ("거절", "bad", {}),
                                      ("심각만", "ok", {"min_severity": "critical"})):
                r = c.post("/api/settings/channels", json={"name": name, "type": "webhook", **extra,
                                                           "url": f"http://127.0.0.1:{server.server_port}/{path}",
                                                           "config": {"format": "json"}}, headers=CSRF)
                assert r.status_code == 200, r.text
            yield c
    finally:
        server.shutdown()


def _fire(client, notify, severity="error", rule="전송 시험", key="PC-1", fired_at=None):
    from app.alerts.engine import engine
    from app.alerts.message import AlertMessage

    message = AlertMessage(rule=rule, severity=severity, kind="count", group_by="host", group_key=key, event_count=3,
                           threshold=1, window_sec=60, fired_at=fired_at or datetime.now(UTC))
    return client.portal.call(engine.fire, message, tuple(notify))


def _delivery(alert_id, notifier):
    return sql("SELECT status, attempts, last_error, next_attempt_at, claimed_at FROM alert_deliveries"
               " WHERE alert_id = %s AND notifier = %s", (alert_id, notifier))[0]


def _drain(client):
    from app.alerts.dispatcher import dispatcher

    client.portal.call(dispatcher.drain)


def test_fire_only_queues_and_the_dispatcher_sends(client):
    _Receiver.received.clear()
    alert_id = _fire(client, ["정상"])
    status, attempts, _, next_at, claimed = _delivery(alert_id, "정상")
    assert (status, attempts, claimed) == ("pending", 0, None) and next_at <= datetime.now(UTC)
    assert _Receiver.received == []   # 평가(fire)는 네트워크를 쓰지 않는다
    _drain(client)
    assert _delivery(alert_id, "정상")[:2] == ("sent", 1)
    assert [p for p, _ in _Receiver.received] == ["/ok"]


def test_failures_back_off_and_a_down_target_is_tried_once(client):
    _Receiver.received.clear()
    first, second = _fire(client, ["멈춤"], key="A"), _fire(client, ["멈춤"], key="B")
    before = datetime.now(UTC)
    _drain(client)
    # 503 = 받는 곳 자체가 안 됨 → 한 번만 보내고 나머지는 같은 실패로 미룬다 (같은 곳에 30초씩 줄줄이 기다리지 않게)
    assert len([p for p, _ in _Receiver.received if p == "/down"]) == 1
    for alert_id in (first, second):
        status, attempts, error, next_at, _ = _delivery(alert_id, "멈춤")
        assert (status, attempts) == ("failed", 1) and "503" in error
        assert timedelta(seconds=55) < next_at - before < timedelta(seconds=70)   # 1분 뒤
    assert any("이번에는 시도하지 않음" in _delivery(a, "멈춤")[2] for a in (first, second))


def test_a_per_message_rejection_does_not_hold_back_the_others(client):
    _Receiver.received.clear()
    ids = [_fire(client, ["거절"], key=f"K{i}") for i in range(3)]
    _drain(client)
    assert len([p for p, _ in _Receiver.received if p == "/bad"]) == 3   # 400 은 그 알림 하나의 문제
    assert {_delivery(a, "거절")[0] for a in ids} == {"failed"}


def test_fifth_failure_gives_up(client):
    from app import repository
    from app.alerts.dispatcher import dispatcher

    alert_id = _fire(client, ["거절"], key="G")
    sql("UPDATE alert_deliveries SET attempts = 4, status = 'failed' WHERE alert_id = %s", (alert_id,))
    client.portal.call(dispatcher.drain)
    assert _delivery(alert_id, "거절")[:2] == ("gave_up", 5)
    assert client.portal.call(repository.count_gave_up, datetime.now(UTC) - timedelta(hours=1)) >= 1


def test_missing_target_and_minimum_severity(client):
    missing = _fire(client, ["없는곳"], key="M")
    low = _fire(client, ["심각만"], severity="warning", key="L")
    _drain(client)
    assert _delivery(missing, "없는곳")[:3] == ("failed", 1, "알림 대상 '없는곳' 이 설정에 없습니다")
    status, attempts, error, _, _ = _delivery(low, "심각만")
    assert (status, attempts) == ("skipped", 0) and error.startswith("받을 최소 수준(심각 이상)")


def test_send_interrupted_by_a_crash_is_sent_again(client):
    """보내는 도중 서버가 멈추면 행이 '보내는 중'으로 남는다 → 다음에 잠금을 잡을 때 풀어 다시 보낸다."""
    from app import repository
    from app.alerts.dispatcher import RELEASE_ERROR, dispatcher

    alert_id = _fire(client, ["정상"], key="CRASH")
    job = client.portal.call(repository.claim_delivery, "정상", datetime.now(UTC))
    assert job["alert_id"] == alert_id and _delivery(alert_id, "정상")[4] is not None
    _drain(client)
    assert _delivery(alert_id, "정상")[0] == "pending"   # 잡혀 있는 행은 건너뛴다
    assert client.portal.call(repository.release_delivery_claims, datetime.now(UTC), RELEASE_ERROR, 5) == 1
    status, attempts, error, _, claimed = _delivery(alert_id, "정상")
    assert (status, attempts, error, claimed) == ("failed", 1, RELEASE_ERROR, None)
    client.portal.call(dispatcher.drain)
    assert _delivery(alert_id, "정상")[:2] == ("sent", 2)
    # 풀린 뒤 늦게 온 옛 결과는 버린다 (잡은 시각이 다르다)
    assert client.portal.call(repository.finish_delivery, job, "failed", "늦은 결과") is False
    assert _delivery(alert_id, "정상")[0] == "sent"


def test_day_old_queue_rows_expire(client):
    from app import repository
    from app.alerts.dispatcher import EXPIRE_ERROR

    old = _fire(client, ["정상"], key="OLD", fired_at=datetime.now(UTC) - timedelta(hours=25))
    assert client.portal.call(repository.expire_stale_deliveries, datetime.now(UTC) - timedelta(hours=24), EXPIRE_ERROR) == 1
    assert _delivery(old, "정상")[:3] == ("gave_up", 0, EXPIRE_ERROR)


def test_successful_test_send_makes_failed_rows_due_now(client):
    alert_id = _fire(client, ["정상"], key="LATER")
    sql("UPDATE alert_deliveries SET status = 'failed', attempts = 1, next_attempt_at = now() + interval '1 hour'"
        " WHERE alert_id = %s", (alert_id,))
    assert client.post("/api/alerts/test/정상", headers=CSRF).status_code == 200
    assert _delivery(alert_id, "정상")[3] <= datetime.now(UTC)
    _drain(client)
    assert _delivery(alert_id, "정상")[0] == "sent"


def test_rule_query_time_limit_does_not_take_search_slots(client):
    import asyncio

    from app import db

    async def scenario():
        for _ in range(db.SEARCH_SLOTS):   # 화면 검색이 조회 자리를 모두 쓰고 있어도
            await db._search_slots.acquire()
        try:
            with db.background_time_limit(1):
                await db.fetch_one("SELECT pg_sleep(3)")
        finally:
            for _ in range(db.SEARCH_SLOTS):
                db._search_slots.release()

    with pytest.raises(db.QueryTimeout) as caught:
        client.portal.call(scenario)
    assert caught.value.busy is False   # 자리를 기다린 것이 아니라 쿼리가 1초를 넘김

    async def leftover():
        rows = []
        for _ in range(3):
            rows.append(await db.fetch_one("SHOW statement_timeout"))
        return rows

    assert {r["statement_timeout"] for r in client.portal.call(leftover)} == {"0"}   # 풀 연결에 남지 않는다
    del asyncio


def test_slow_or_broken_rule_is_marked_and_the_next_rule_still_runs(client, monkeypatch):
    from app import db, repository
    from app.alerts.engine import engine
    from app.alerts.rules import parse_text

    config = parse_text("""rules:
  - name: 느린 규칙
    match: { event_id: "1" }
    notify: [정상]
  - name: 다음 규칙
    match: { event_id: "4625" }
    group_by: host
    notify: [정상]
""")
    real = repository.alert_candidates

    async def candidates(f, group_by, *args, **kwargs):
        if f.event_ids == [1]:
            await db.fetch_one("SELECT pg_sleep(3)")
        return await real(f, group_by, *args, **kwargs)

    monkeypatch.setattr(repository, "alert_candidates", candidates)
    monkeypatch.setattr(engine, "config", config)
    from dataclasses import replace

    from app.alerts import engine as engine_module

    monkeypatch.setattr(engine_module, "settings", replace(engine_module.settings, alert_rule_timeout_sec=1))
    events = [{"date": datetime.now(UTC).isoformat(), "EventID": 4625, "Channel": "Security", "agent_host": f"T{i}",
               "log_source": "winevtlog"} for i in range(101)]
    assert client.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == 101
    now = datetime.now(UTC)
    for rule in config.rules:
        client.portal.call(engine._run_rule, rule, now)
    slow, nxt = engine.runs["느린 규칙"], engine.runs["다음 규칙"]
    assert (slow.error_kind, slow.errors_in_row) == ("timeout", 1) and "1초" in slow.error
    # 기준을 넘은 묶음 101개 → 100개만 알리고 '일부만'
    assert (nxt.error, nxt.candidates, nxt.truncated, nxt.fired) == (None, 100, True, 100)
    from app.alerts import health

    assert health.rule_state(True, slow.as_dict(), 1, 30, now) == "timeout"
    assert health.rule_state(True, nxt.as_dict(), 1, 30, now) == "truncated"
    # 다음 평가가 늦어 그 사이 로그를 보지 못했다 → 평가 공백
    client.portal.call(engine._run_rule, config.rules[1], now + timedelta(minutes=30))
    gap = engine.runs["다음 규칙"].last_gap
    assert gap and gap["sec"] == 25 * 60


def test_health_shows_in_the_screen_and_the_public_endpoint(client):
    from app.alerts import health

    client.portal.call(lambda: health.current(fresh=True))   # 캐시 없이
    cfg = client.get("/api/alerts/config", headers=CSRF).json()
    codes = {p["code"] for p in cfg["health"]["problems"]}
    assert "dispatcher_off" in codes and cfg["health"]["status"] == "down"   # 시험은 전송기를 끈다
    assert {n["name"]: n["health"]["state"] for n in cfg["notifiers"]}["정상"] in ("ok", "idle")
    r = client.get("/healthz/alerts")   # 로그인 없이
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "down" and "dispatcher_off" in body["problems"]
    assert "정상" not in r.text and "멈춤" not in r.text   # 받는 곳 이름·오류 문구가 새지 않는다
