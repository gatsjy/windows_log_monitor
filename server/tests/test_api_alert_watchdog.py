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
