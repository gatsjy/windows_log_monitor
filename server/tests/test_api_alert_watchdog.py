"""알림 기능 감시 (ADR-045 2단계, BACKLOG B-34) — 통합 시험.

회귀: 상태 띠·/healthz/alerts·보고서는 문제를 보여 줄 뿐, 아무도 보고 있지 않으면 메일 서버가 멈추거나 평가가 멈춘 채 하루가 갔다.
감시 작업은 시험에서 돌지 않는다(전송기와 함께 꺼짐) — 시험이 watchdog.check(now) 를 직접 부른다.
"""

from __future__ import annotations

import asyncio
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
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30
  fallback_notify: [당직, 메일]

rules:
  - name: 로그온 실패
    enabled: false
    match: { event_id: "4625" }
    notify: [메일]
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
            for name, path in (("당직", "duty"), ("메일", "mail")):
                assert c.post("/api/settings/channels", json={"name": name, "type": "webhook", "config": {"format": "json"},
                                                              "url": f"http://127.0.0.1:{server.server_port}/{path}"},
                              headers=CSRF).status_code == 200
            engine.reload(force=True)
            yield c
    finally:
        server.shutdown()
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _check(client, now=None):
    from app.alerts.watchdog import watchdog

    client.portal.call(watchdog.check, now or datetime.now(UTC))


def _system_alerts(rule):
    return sql("SELECT id, group_key, severity, payload FROM alerts WHERE rule = %s ORDER BY id", (rule,))


def _sent_to(client, alert_id):
    from app.alerts.dispatcher import dispatcher

    client.portal.call(dispatcher.drain)
    return sorted(n for (n, s) in sql("SELECT notifier, status FROM alert_deliveries WHERE alert_id = %s", (alert_id,))
                  if s == "sent")


def _audit(action):
    return sql("SELECT target, detail FROM audit_log WHERE action = %s ORDER BY id", (action,))


def test_failing_target_is_reported_through_the_other_targets(client):
    from app.alerts.dispatcher import dispatcher

    health = dispatcher.health("메일")
    health.fail(datetime.now(UTC) - timedelta(minutes=20), "메일 전송 실패 (smtp.local:587): 연결 거부")
    _check(client)
    [(alert_id, key, severity, payload)] = _system_alerts("알림 전송 실패")
    assert (key, severity) == ("메일", "error") and payload["kind"] == "system"
    assert payload["description"].startswith("'메일'(으)로 20분째 알림을 보내지 못하고 있습니다")
    assert _sent_to(client, alert_id) == ["당직"]   # 실패하는 그 곳은 뺀다
    assert [t for t, _ in _audit("alerts.health.target_down")] == ["메일"]
    _check(client)   # 같은 문제는 한 시간에 한 번
    assert len(_system_alerts("알림 전송 실패")) == 1
    health.ok(datetime.now(UTC))
    _check(client)
    assert [t for t, _ in _audit("alerts.health.target_recovered")] == ["메일"]


def test_broken_rule_is_reported(client):
    from app.alerts.engine import RuleRun, engine

    engine.runs["무거운 규칙"] = RuleRun(last_run_at=datetime.now(UTC), errors_in_row=3, error="쿼리가 20초를 넘겼습니다",
                                    error_kind="timeout")
    _check(client)
    [(alert_id, key, _, payload)] = _system_alerts("알림 규칙 동작 안 함")
    assert key == "무거운 규칙" and "미리보기로 확인하세요" in payload["description"]
    assert _sent_to(client, alert_id) == ["당직", "메일"]
    engine.runs["무거운 규칙"].errors_in_row = 0
    _check(client)
    assert [t for t, _ in _audit("alerts.health.rule_recovered")] == ["무거운 규칙"]
    del engine.runs["무거운 규칙"]


def test_stalled_evaluation_is_restarted_and_reported(client):
    from app.alerts.engine import engine
    from app.alerts.watchdog import watchdog

    started = []

    def factory():
        started.append(1)
        return asyncio.get_running_loop().create_task(asyncio.sleep(3600))

    watchdog.start(factory, None)
    real_task, real_progress = engine.task, engine.progress_at
    engine.progress_at = datetime.now(UTC) - timedelta(minutes=10)
    try:
        _check(client)
        assert started == [1]   # 멈춘 평가 작업을 다시 시작
        [(_, _, severity, payload)] = _system_alerts("알림 엔진 멈춤")
        assert severity == "critical" and "평가 작업을 다시 시작했습니다" in payload["description"]
        assert _audit("alerts.health.engine_stall")
        engine.progress_at = datetime.now(UTC)   # 다시 나아간다
        _check(client)
        [(_, resume)] = _audit("alerts.health.engine_resume")
        assert resume["sec"] >= 600
    finally:
        if engine.task is not real_task and engine.task is not None:
            engine.task.cancel()
        engine.task, engine.progress_at = real_task, real_progress
        watchdog.start(None, None)


def test_system_alerts_can_be_silenced_but_not_config_alerts(client):
    ok = client.post("/api/alerts/silences", json={"rule": "알림 전송 실패", "duration_sec": 3600, "reason": "메일 서버 점검"},
                     headers=CSRF)
    assert ok.status_code == 200, ok.text
    no = client.post("/api/alerts/silences", json={"rule": "알림 설정 변경", "duration_sec": 3600, "reason": "x"}, headers=CSRF)
    assert no.status_code == 422


def test_fallback_defaults_to_report_recipients_and_warns_when_none(client):
    from app.alerts import health
    from app.alerts.watchdog import watchdog

    assert client.portal.call(watchdog.recipients) == ["당직", "메일"]
    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES.replace("  fallback_notify: [당직, 메일]\n", ""), encoding="utf-8")
    from app.alerts.engine import engine

    engine.reload(force=True)
    assert client.portal.call(watchdog.recipients) == []
    state = client.portal.call(lambda: health.current(fresh=True))
    assert "no_fallback" in {p["code"] for p in state["problems"]}
    r = client.put("/api/settings/report", json={"targets": ["당직"]}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert client.portal.call(watchdog.recipients) == ["당직"]


def test_unknown_fallback_target_is_refused(client):
    r = client.put("/api/alerts/config", content=RULES.replace("[당직, 메일]", "[없는곳]").encode(),
                   headers={**CSRF, "Content-Type": "text/plain"})
    assert r.status_code == 422 and "없는곳" in r.text


# ------------------------------------------------------------------ 정기 시험 전송·Oracle 생존 신호 (B-34 남은 것)

def test_weekly_test_send_reaches_each_target_once(client, monkeypatch):
    from dataclasses import replace

    from app.alerts import health
    from app.alerts import watchdog as watchdog_module
    from app.alerts.dispatcher import dispatcher
    from app.alerts.watchdog import watchdog

    monkeypatch.setattr(watchdog_module, "settings",
                        replace(watchdog_module.settings, alert_test_weekday=1, alert_test_time="00:00"))
    monkeypatch.setattr(watchdog_module, "RETEST_AFTER_SEC", 0)
    assert client.post("/api/settings/channels", json={"name": "끊긴곳", "type": "webhook", "config": {"format": "json"},
                                                       "url": "http://127.0.0.1:9/gone"}, headers=CSRF).status_code == 200

    async def recipients(exclude=None):
        return [n for n in ("당직", "메일", "끊긴곳") if n != exclude]

    monkeypatch.setattr(watchdog, "recipients", recipients)
    before = len(_Receiver.received)
    results = client.portal.call(watchdog.scheduled_tests, datetime.now(UTC))
    assert {(r["target"], r["ok"]) for r in results} == {("당직", True), ("메일", True), ("끊긴곳", False)}
    sent = _Receiver.received[before:]
    assert len(sent) == 2 and {b["alert"]["rule"] for b in sent} == {"정기 시험 알림"}
    assert {t: d["ok"] for t, d in _audit("alerts.test.scheduled")} == {"당직": True, "메일": True, "끊긴곳": False}
    # 실패한 곳은 '보내지 못하는 중' — 15분이 지나도 고쳐지지 않으면 '알림 전송 실패'가 다른 곳으로 나간다
    assert dispatcher.health("끊긴곳").failing_since is not None
    assert client.portal.call(watchdog.scheduled_tests, datetime.now(UTC)) == []   # 같은 주에는 한 번
    # 다시 시작해 메모리 상태가 사라져도 상태 띠·보고서에 남는다 (감사로그)
    dispatcher.targets.pop("끊긴곳")
    state = client.portal.call(lambda: health.current(fresh=True))
    assert "test_failed" in {p["code"] for p in state["problems"]}
    # 고친 뒤 화면의 '테스트 발송'이 성공하면 사라진다 — 여기서는 받는 곳을 지운 것으로
    channel_id = next(c["id"] for c in client.get("/api/settings/channels", headers=CSRF).json()["items"] if c["name"] == "끊긴곳")
    assert client.delete(f"/api/settings/channels/{channel_id}", headers=CSRF).status_code == 200


def test_oracle_heartbeat_state_changes_are_audited(client, monkeypatch):
    from app.alerts import health, targets
    from app.alerts.notifiers import NotifierError
    from app.alerts.watchdog import watchdog

    class Writer:
        heartbeat_sql = "UPDATE H SET A = :at"
        fail = True
        calls: ClassVar[list[dict]] = []

        async def heartbeat(self, values):
            Writer.calls.append(values)
            if Writer.fail:
                raise NotifierError("ORA-12541: TNS:no listener", target_down=True)

    async def load():
        return {"사내DB": Writer(), "당직": object()}, {}

    monkeypatch.setattr(targets, "load_notifiers", load)
    now = datetime.now(UTC)
    client.portal.call(watchdog.heartbeat, now)
    client.portal.call(watchdog.heartbeat, now + timedelta(minutes=6))
    assert [t for t, _ in _audit("alerts.health.heartbeat_fail")] == ["사내DB"]   # 바뀔 때만 (1분마다 쌓이지 않게)
    state = client.portal.call(lambda: health.current(now + timedelta(minutes=6), fresh=True))
    assert "heartbeat_failing" in {p["code"] for p in state["problems"]}
    Writer.fail = False
    client.portal.call(watchdog.heartbeat, now + timedelta(minutes=7))
    [(_, ok)] = _audit("alerts.health.heartbeat_ok")
    assert ok["sec"] == 420 and watchdog.heartbeats["사내DB"]["failing_since"] is None
    assert set(Writer.calls[0]) == {"at", "status", "version", "problems"} and Writer.calls[0]["at"].tzinfo is None
    watchdog.heartbeats.clear()
    monkeypatch.setattr(health, "_cache", None)   # 앞으로 당긴 시각의 상태를 다음 시험 모듈에 남기지 않는다


def test_only_tests_that_run_the_alert_path_count(client):
    """Oracle '연결 시험'은 접속만 본다 — 알림 SQL 을 실행한 시험(SQL 시험 실행·테스트 발송)만 받는 곳의 시험으로 센다 (검토)."""
    from app import repository

    since = datetime.now(UTC) - timedelta(minutes=1)
    sql("INSERT INTO audit_log (actor, action, target, detail) VALUES ('admin', 'settings.channel.test', '사내DB',"
        " '{\"type\": \"oracle\", \"ok\": true}')")
    assert client.portal.call(repository.latest_target_tests, ["사내DB"], since) == {}
    sql("INSERT INTO audit_log (actor, action, target, detail) VALUES ('admin', 'settings.oracle.dry_run', '사내DB',"
        " '{\"commit\": false, \"ok\": false, \"error\": \"ORA-00942\"}')")
    tests = client.portal.call(repository.latest_target_tests, ["사내DB"], since)
    assert tests["사내DB"]["ok"] is False and tests["사내DB"]["error"] == "ORA-00942"
