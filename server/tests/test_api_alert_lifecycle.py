"""알림 수명주기 1단계: 해결 뒤 재발·지난 알림 이후 건수·지연 수신 (BACKLOG B-35) — 통합 시험.

회귀: 재알림 간격은 마지막 fired_at 만 봐서, 담당자가 '해결'한 서비스가 다시 죽어도 간격(5분~2시간) 동안 알림이 나지 않았다.
건너뛴 동안 몇 건이 더 왔는지 남지 않았고, 장애 뒤 몰아 받은 몇 시간치 이벤트가 '10분에 n건'처럼 보였다.
규칙은 꺼 두고(백그라운드 평가가 끼지 않게) 시험이 evaluate 를 직접 부른다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패
    enabled: false
    match: { event_id: "4625" }
    window: 10m
    threshold: 1
    cooldown: 1h
    severity: error
    notify: [없는대상]
"""


def _event(host, ago=timedelta(0)):
    return {"date": (datetime.now(UTC) - ago).isoformat(), "EventID": 4625, "Channel": "Security", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": "로그온 실패"}


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

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"},
                   headers=CSRF)
            engine.reload(force=True)
            yield c
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _ingest(client, *events):
    assert client.post("/api/ingest", json=list(events), headers=KEY).json()["accepted"] == len(events)


def _evaluate(client):
    from app.alerts.engine import engine

    return client.portal.call(engine.evaluate, engine.config.rules[0], datetime.now(UTC))


def _payload(client, alert_id):
    return client.get(f"/api/alerts/{alert_id}", headers=CSRF).json()


def test_first_alert_has_no_history(client):
    _ingest(client, _event("H1"), _event("H1"))
    [first] = _evaluate(client)
    detail = _payload(client, first)
    assert "previous_id" not in detail["payload"] and detail["followup"] == {"n": 0, "last_at": None}


def test_events_skipped_by_cooldown_are_counted(client):
    _ingest(client, *[_event("H1")] * 3)
    assert _evaluate(client) == []   # 재알림 간격
    first = client.get("/api/alerts", params={"since": "1h"}, headers=CSRF).json()["items"][0]
    followup = _payload(client, first["id"])["followup"]
    assert followup["n"] == 3 and followup["last_at"] is not None


def test_resolved_alert_recurs_only_with_new_events(client):
    first = client.get("/api/alerts", params={"since": "1h"}, headers=CSRF).json()["items"][0]
    r = client.post("/api/alerts/handle", json={"ids": [first["id"]], "action": "resolve", "note": "서비스 재시작"},
                    headers=CSRF)
    assert r.status_code == 200, r.text
    # 해결 직후 창 안에 남은 같은 이벤트로는 울리지 않는다
    assert _evaluate(client) == []
    _ingest(client, _event("H1"))
    [again] = _evaluate(client)
    payload = _payload(client, again)["payload"]
    assert payload["recurred"] is True and payload["previous_id"] == first["id"]
    assert payload["since_previous"] == 4   # 앞 알림 뒤 3건 + 해결 뒤 1건
    from app.alerts.message import AlertMessage

    assert f"해결된 알림(#{first['id']}) 뒤 새로 발생" in AlertMessage.from_dict(payload).text()
    # 앞 알림은 더 이상 가장 최근이 아니다 — 뒤 이벤트 수는 새 알림이 센다
    assert _payload(client, first["id"])["followup"] is None


def test_acknowledged_alert_keeps_the_cooldown(client):
    latest = client.get("/api/alerts", params={"since": "1h"}, headers=CSRF).json()["items"][0]
    assert client.post("/api/alerts/handle", json={"ids": [latest["id"]], "action": "ack"}, headers=CSRF).status_code == 200
    _ingest(client, _event("H1"))
    assert _evaluate(client) == []


def test_delayed_events_are_marked(client):
    """장애 뒤 에이전트가 몇 시간치를 몰아 보내면 수신 기준 창 안에 오래전 이벤트가 섞인다 — 받는 사람이 알게."""
    from app.alerts.message import AlertMessage

    _ingest(client, _event("H2", ago=timedelta(hours=5)), _event("H2", ago=timedelta(hours=4)))
    [alert_id] = [a for a in _evaluate(client)]
    message = AlertMessage.from_dict(_payload(client, alert_id)["payload"])
    assert message.delayed_line().startswith("지연 수신분 포함 — 발생 시각")
    assert "지연 수신분 포함" in message.text() and "지연 수신분 포함" in message.html()
    on_time = AlertMessage.from_dict({**message.to_dict(), "first_event_at": message.fired_at.isoformat()})
    assert on_time.delayed_line() == ""
