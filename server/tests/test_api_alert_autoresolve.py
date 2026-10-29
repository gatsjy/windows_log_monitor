"""자동 해결과 해소 통지 (BACKLOG B-35 2단계) — 통합 시험.

회귀: 서비스가 살아나거나 PC 가 다시 들어와도 알림은 사람이 닫을 때까지 '처리 안 됨'으로 남았고, 받은 사람은 끝났는지 알 수 없었다.
규칙은 꺼 두고(백그라운드 평가가 끼지 않게) 시험이 evaluate 를 직접 부른다. 전송은 dispatcher.drain() 으로.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30

rules:
  - name: 오류 다발
    enabled: false
    match: { event_id: "1000" }
    window: 1m
    threshold: 1
    cooldown: 1h
    resolve: auto
    severity: error
    notify: [당직]
  - name: 로그온 실패
    enabled: false
    match: { event_id: "4625" }
    window: 1m
    threshold: 1
    cooldown: 1h
    severity: error
    notify: [당직]
  - name: 서버 끊김
    enabled: false
    kind: agent_silent
    silent_for: 10m
    hosts: [SRV-01]
    severity: error
    notify: [당직]
"""


class _Receiver(BaseHTTPRequestHandler):
    received: ClassVar[list[dict]] = []

    def do_POST(self):  # http.server 가 부르는 이름
        _Receiver.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

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

    from app.alerts.engine import engine
    from app.main import app

    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            assert c.post("/api/settings/channels", json={"name": "당직", "type": "webhook", "config": {"format": "json"},
                                                          "url": f"http://127.0.0.1:{server.server_port}/duty"},
                          headers=CSRF).status_code == 200
            engine.reload(force=True)
            yield c
    finally:
        server.shutdown()
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _event(host, event_id=1000):
    return {"date": datetime.now(UTC).isoformat(), "EventID": event_id, "Channel": "Application", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": "응용 프로그램 오류"}


def _ingest(client, *events):
    assert client.post("/api/ingest", json=list(events), headers=KEY).json()["accepted"] == len(events)


def _alive(host, at):
    """PC 가 at 까지 하트비트를 보내고 있다 (조용한 PC 의 건수 0 은 회복으로 치지 않는다)."""
    sql("UPDATE agents SET last_seen = %s WHERE host = %s", (at, host))


def _evaluate(client, name, now=None):
    from app.alerts.engine import engine

    rule = next(r for r in engine.config.rules if r.name == name)
    return client.portal.call(engine.evaluate, rule, now or datetime.now(UTC))


def _drain(client):
    from app.alerts.dispatcher import dispatcher

    client.portal.call(dispatcher.drain)


def _deliveries(alert_id):
    return sorted((a, s, e) for a, s, e in sql(
        "SELECT action, status, last_error FROM alert_deliveries WHERE alert_id = %s", (alert_id,)))


def _alert(alert_id):
    [row] = sql("SELECT status, auto_resolved, resolved_by FROM alerts WHERE id = %s", (alert_id,))
    return row


def _bodies(host):
    return [b for b in _Receiver.received if b["alert"]["group_key"] == host]


def _fire(client, host):
    """알림 하나를 내고 보낸다 → (알림 번호, 평가 시각)."""
    _ingest(client, _event(host))
    now = datetime.now(UTC)
    [alert_id] = _evaluate(client, "오류 다발", now)
    _drain(client)
    return alert_id, now


def _quiet(client, host, now, minutes=6):
    """집계 기간이 지나도록 조용했다 (PC 는 살아 있음) → 자동 해결을 볼 때."""
    later = now + timedelta(minutes=minutes)
    _alive(host, later)
    _evaluate(client, "오류 다발", later)
    return later


def test_quiet_target_is_resolved_and_receivers_hear_it(client):
    alert_id, now = _fire(client, "WEB-01")
    # 집계 기간(1분)이 지나도 AUTO_RESOLVE_HOLD(5분) 전에는 보지 않는다 — 경계에서 알림·해소가 번갈아 나지 않게
    _quiet(client, "WEB-01", now, minutes=2)
    assert _alert(alert_id)[0] == "open"
    # 예전에 받았지만 지금은 규칙의 받는 곳이 아닌 곳(빼거나 지운 곳)에는 해소를 보내지 않는다
    sql("INSERT INTO alert_deliveries (alert_id, notifier, status) VALUES (%s, '옛 받는 곳', 'sent')", (alert_id,))
    _quiet(client, "WEB-01", now)
    assert _alert(alert_id) == ("resolved", True, "system")
    [(author, action, text)] = sql("SELECT author, action, text FROM alert_notes WHERE alert_id = %s", (alert_id,))
    assert (author, action) == ("system", "auto_resolve") and "기준 1건 아래로 내려가 자동으로 해결" in text
    assert _deliveries(alert_id) == [("resolve", "pending", None), ("trigger", "sent", None), ("trigger", "sent", None)]
    assert sql("SELECT notifier FROM alert_deliveries WHERE alert_id = %s AND action = 'resolve'", (alert_id,)) == [("당직",)]
    _drain(client)
    trigger, resolved = _bodies("WEB-01")
    assert (trigger["event_action"], resolved["event_action"]) == ("trigger", "resolve")
    assert trigger["dedup_key"] == resolved["dedup_key"] and resolved["title"].startswith("[해소] [오류] 오류 다발")
    detail = client.get(f"/api/alerts/{alert_id}", headers=CSRF).json()
    assert detail["auto_resolved"] is True
    assert [(d["notifier"], d["action"], d["status"]) for d in detail["deliveries"]] == [
        ("당직", "trigger", "sent"), ("당직", "resolve", "sent"), ("옛 받는 곳", "trigger", "sent")]


def test_target_that_keeps_failing_stays_open(client):
    _ingest(client, _event("WEB-02"))
    [alert_id] = _evaluate(client, "오류 다발")
    sql("UPDATE alerts SET fired_at = fired_at - interval '20 minutes' WHERE id = %s", (alert_id,))
    _ingest(client, _event("WEB-02"))   # 지금도 계속된다
    assert _evaluate(client, "오류 다발") == []   # 재알림 간격 안
    assert _alert(alert_id)[0] == "open"


def test_dark_pc_is_not_called_recovered(client):
    """PC 가 꺼져 오류도 멎었다 — 건수 0 은 '모름'이지 회복이 아니다 (검토에서 재현)."""
    alert_id, now = _fire(client, "WEB-07")
    _evaluate(client, "오류 다발", now + timedelta(minutes=6))   # 하트비트 없음
    assert _alert(alert_id)[0] == "open"


def test_silenced_target_is_resolved_without_a_notice(client):
    alert_id, now = _fire(client, "WEB-03")
    r = client.post("/api/alerts/silences", json={"rule": "오류 다발", "group_key": "WEB-03", "duration_sec": 3600,
                                                  "reason": "서버 점검"}, headers=CSRF)
    assert r.status_code == 200, r.text
    _quiet(client, "WEB-03", now)
    assert _alert(alert_id)[0] == "resolved"
    assert _deliveries(alert_id) == [("trigger", "sent", None)]   # 점검 중에는 해소도 잡음


def test_unsent_alert_is_not_sent_after_it_resolved(client):
    _ingest(client, _event("WEB-04"))
    now = datetime.now(UTC)
    [alert_id] = _evaluate(client, "오류 다발", now)   # 보내기 전에 (받는 곳이 멈춘 동안 등)
    _quiet(client, "WEB-04", now)
    assert _deliveries(alert_id) == [("trigger", "skipped", "보내기 전에 조건이 풀려 자동으로 해결됨")]
    _drain(client)
    assert _bodies("WEB-04") == []


def test_alert_that_failed_in_flight_gets_no_resolve(client):
    """자동 해결 때 '보내는 중'이던 알림은 해소 대상에 들지만, 결국 실패하면 해소도 보내지 않는다 (검토에서 재현)."""
    _ingest(client, _event("WEB-08"))
    now = datetime.now(UTC)
    [alert_id] = _evaluate(client, "오류 다발", now)
    sql("UPDATE alert_deliveries SET claimed_at = now() WHERE alert_id = %s", (alert_id,))   # 전송기가 보내는 중
    _quiet(client, "WEB-08", now)
    assert ("resolve", "pending", None) in _deliveries(alert_id)
    sql("UPDATE alert_deliveries SET claimed_at = NULL, status = 'failed', attempts = 1, next_attempt_at = now()"
        " WHERE alert_id = %s AND action = 'trigger'", (alert_id,))   # 보내기 실패
    _drain(client)
    assert _deliveries(alert_id) == [("resolve", "skipped", "이 곳으로 알림이 전해지지 않아 해소 통지도 보내지 않습니다"),
                                     ("trigger", "skipped", "보내기 전에 조건이 풀려 자동으로 해결됨")]
    assert _bodies("WEB-08") == []


def test_late_resolve_does_not_close_the_newer_alert(client):
    """해소가 재시도를 기다리는 사이 같은 문제가 다시 나면 지난 해소를 보내지 않는다 — 같은 dedup_key 라 받는 쪽이
    지금 열린 사고를 닫는다 (검토에서 재현)."""
    first, now = _fire(client, "WEB-09")
    _quiet(client, "WEB-09", now)
    sql("UPDATE alert_deliveries SET status = 'failed', attempts = 1 WHERE alert_id = %s AND action = 'resolve'", (first,))
    _ingest(client, _event("WEB-09"))
    [second] = _evaluate(client, "오류 다발")   # 해결 뒤 재발
    _drain(client)
    assert ("resolve", "skipped", "같은 대상에 새 알림이 있어 지난 알림의 해소 통지를 보내지 않습니다 (새 알림을 닫지 않게)") \
        in _deliveries(first)
    assert [b["event_action"] for b in _bodies("WEB-09")] == ["trigger", "trigger"] and _alert(second)[0] == "open"


def test_reopen_is_respected(client):
    alert_id, now = _fire(client, "WEB-05")
    _quiet(client, "WEB-05", now)
    r = client.post("/api/alerts/handle", json={"ids": [alert_id], "action": "reopen", "note": "아직 불안정합니다"},
                    headers=CSRF)
    assert r.status_code == 200, r.text
    assert _alert(alert_id) == ("open", False, None)
    _drain(client)
    assert ("resolve", "skipped", "해소 통지를 보내기 전에 알림이 다시 열렸습니다") in _deliveries(alert_id)
    assert [b["event_action"] for b in _bodies("WEB-05")] == ["trigger"]
    # 다음 주기에 엔진이 도로 닫지 않는다 — 다시 연 알림은 사람이 해결한다 (검토에서 재현)
    _quiet(client, "WEB-05", now, minutes=8)
    assert _alert(alert_id) == ("open", False, None)
    # 사람이 해결해도 자동 해소 통지는 나가지 않는다
    assert client.post("/api/alerts/handle", json={"ids": [alert_id], "action": "resolve", "note": "재시작"},
                       headers=CSRF).status_code == 200
    _drain(client)
    assert [b["event_action"] for b in _bodies("WEB-05")] == ["trigger"]


def test_old_alerts_resolve_without_a_notice(client):
    """이 기능을 켜고 처음 돌 때 몇 달 묵은 알림이 '해소'로 쏟아지지 않게."""
    alert_id, now = _fire(client, "WEB-10")
    sql("UPDATE alerts SET fired_at = fired_at - interval '8 days' WHERE id = %s", (alert_id,))
    _quiet(client, "WEB-10", now)
    assert _alert(alert_id)[0] == "resolved" and _deliveries(alert_id) == [("trigger", "sent", None)]
    [(text,)] = sql("SELECT text FROM alert_notes WHERE alert_id = %s", (alert_id,))
    assert text.endswith("(오래된 알림이라 해소 통지는 보내지 않음)")


def test_security_rules_wait_for_a_person(client):
    _ingest(client, _event("WEB-06", 4625))
    now = datetime.now(UTC)
    [alert_id] = _evaluate(client, "로그온 실패", now)
    _alive("WEB-06", now + timedelta(hours=2))
    _evaluate(client, "로그온 실패", now + timedelta(hours=2))
    assert _alert(alert_id)[0] == "open"


def test_silent_pc_that_comes_back_is_resolved(client):
    now = datetime.now(UTC)
    sql("INSERT INTO agents (host, last_seen) VALUES ('SRV-01', %s)", (now - timedelta(minutes=30),))
    [alert_id] = _evaluate(client, "서버 끊김", now)
    _drain(client)
    assert _evaluate(client, "서버 끊김", now) == []   # 끊긴 동안에는 한 번만, 아직 해결하지 않는다
    assert _alert(alert_id)[0] == "open"
    back = now + timedelta(minutes=1)
    _alive("SRV-01", back)
    assert _evaluate(client, "서버 끊김", back) == []
    assert _alert(alert_id) == ("resolved", True, "system")
    _drain(client)
    assert "로그/하트비트가 다시 들어옵니다" in _bodies("SRV-01")[-1]["text"]
    # 돌아온 뒤 다시 끊기면 새 알림
    assert len(_evaluate(client, "서버 끊김", back + timedelta(minutes=11))) == 1


def test_report_separates_automatic_resolutions(client):
    from app.reports import builder

    now = datetime.now(UTC)
    payload = client.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    auto = sql("SELECT count(*) FROM alerts WHERE auto_resolved AND resolved_at >= now() - interval '1 hour'")[0][0]
    assert payload["alerts"]["auto_resolved_in_period"] == auto >= 6
    # 해결까지 걸린 시간은 사람이 해결한 것만 — WEB-05 하나 (자동 해결이 섞이면 조건이 풀린 시각이 대응 시간이 된다)
    assert payload["alerts"]["median_resolve_min"] is not None
