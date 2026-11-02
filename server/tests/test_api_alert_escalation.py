"""에스컬레이션 대기열 넣기 (BACKLOG B-43) — 통합 시험: 기한·상태·무음·관찰·늦은 기한·중복·처리 기록·저장 검증."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30

rules:
  - name: 보안 감사 로그 삭제
    enabled: false
    match: { event_id: "1102" }
    severity: critical
    notify: [운영팀]
    mode: observe
escalations:
  - name: 심각 미확인
    severity: [critical]
    ack_timeout: 2h
    steps:
      - after: 15m
        notify: [운영팀]
      - after: 1h
        unless: resolved
        notify: [운영팀]
"""


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _alert(minutes_ago, severity="critical", status="open", payload="{}", rule="원격 데스크톱 무차별 대입"):
    return sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload, status)"
               " VALUES (now() - make_interval(mins => %s), %s, %s, 'DC-01', 1, %s::jsonb, %s) RETURNING id",
               (minutes_ago, rule, severity, payload, status))[0][0]


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
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            yield c
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _escalate(client):
    from app.alerts.engine import engine

    return client.portal.call(engine._escalate, datetime.now(UTC))


def _rows(alert_id):
    return sql("SELECT action, status FROM alert_deliveries WHERE alert_id = %s ORDER BY action", (alert_id,))


def test_due_steps_are_queued_once_with_a_note(client):
    fresh = _alert(5)                                   # 아직 15분 전
    unacked = _alert(20)                                # 15분 미확인
    acked = _alert(70, status="acked")                 # 확인함 — 미확인 단계는 아님, 1시간 미해결 단계는 넣음
    warning = _alert(20, severity="warning")            # 정책 밖 심각도
    old = _alert(10 * 60)                               # 기한이 지난 지 6시간 넘음 — 정책을 새로 켜도 쏟아지지 않게
    silenced = _alert(20)
    sql("INSERT INTO alert_silences (id, ends_at, reason, created_by) VALUES (900, now(), '점검', 't')")
    sql("UPDATE alerts SET silence_id = 900 WHERE id = %s", (silenced,))
    observed = _alert(20, payload='{"observe": true}')
    builtin = _alert(20, rule="알림 설정 변경")
    assert _escalate(client) == 2
    assert _rows(unacked) == [("escalate:900:acked", "pending")]
    assert _rows(acked) == [("escalate:3600:resolved", "pending")]
    for quiet in (fresh, warning, old, silenced, observed, builtin):
        assert _rows(quiet) == [], quiet
    [(text,)] = sql("SELECT text FROM alert_notes WHERE alert_id = %s AND action = 'escalate'", (unacked,))
    assert text == "15분 동안 아무도 확인하지 않음 (심각 미확인) → 운영팀 에 다시 알림"
    assert _escalate(client) == 0                       # 같은 단계는 한 번만 (기본 키)


def test_unknown_escalation_target_is_rejected_on_save(client):
    text = RULES.replace("        notify: [운영팀]\n      - after: 1h", "        notify: [없는팀]\n      - after: 1h")
    r = client.put("/api/alerts/config", content=text.encode(), headers={**CSRF, "Content-Type": "text/plain"})
    assert r.status_code == 422 and "없는팀" in r.text
    body = client.get("/api/alerts/config").json()
    assert body["escalations"] == [{"name": "심각 미확인", "severities": ["critical"], "rules": [], "steps": [
        {"after_sec": 900, "unless": "acked", "notify": ["운영팀"]}, {"after_sec": 3600, "unless": "resolved", "notify": ["운영팀"]}],
        "ack_timeout_sec": 7200}]


def test_long_step_is_measured_from_queue_time(client):
    """'하루 미해결' 같은 단계는 알림 발생 24시간 뒤에 들어간다 — 발생 시각으로 재면 넣자마자 '하루가 지나' 버려졌다 (검토에서 재현)."""
    from datetime import timedelta

    from app import repository

    alert_id = _alert(25 * 60)
    assert client.portal.call(repository.queue_escalation, alert_id, ("운영팀",), "escalate:86400:resolved", "하루 미해결") == ["운영팀"]
    client.portal.call(repository.expire_stale_deliveries, datetime.now(UTC) - timedelta(hours=24), "하루가 지나 보내지 않았습니다")
    assert _rows(alert_id) == [("escalate:86400:resolved", "pending")]


def test_alert_csv_with_escalation_note(client):
    """다시 알림 처리 기록이 있어도 알림 이력 CSV 가 만들어진다 — 예전에는 KeyError 로 500 (검토에서 재현)."""
    r = client.get("/api/alerts", params={"since": "2d", "format": "csv", "reason": "월간 점검"}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert "[다시 알림]" in r.text and "운영팀 다시 알림:pending" in r.text


def test_ack_timeout_reopens_and_renotifies_each_round(client):
    """확인 시간 초과 (B-43 2단계): 확인만 하고 2시간 안에 해결하지 않으면 처리 안 됨으로 되돌리고 첫 단계 받는 곳에 다시 알린다.
    다시 확인했다가 또 넘기면 회차가 늘어 한 번 더. 아직 시간 안·해결됨·무음·내장 알림은 그대로."""
    from app.alerts.dispatcher import _stale
    from app.alerts.engine import engine
    from app.alerts.notifiers import Notifier

    def acked(acked_minutes_ago, **kw):
        aid = _alert(300, status="acked", **kw)
        sql("UPDATE alerts SET acked_by = 'kim', acked_at = now() - make_interval(mins => %s) WHERE id = %s",
            (acked_minutes_ago, aid))
        return aid
    late, recent, builtin = acked(150), acked(30), acked(150, rule="알림 설정 변경")
    resolved = _alert(300, status="resolved")
    run = lambda: client.portal.call(engine._ack_timeouts, datetime.now(UTC))
    assert run() == 1
    assert sql("SELECT status, acked_by, acked_at FROM alerts WHERE id = %s", (late,)) == [("open", None, None)]
    assert ("acktimeout:7200:1", "pending") in _rows(late)
    [(text,)] = sql("SELECT text FROM alert_notes WHERE alert_id = %s AND action = 'ack_timeout'", (late,))
    assert text == "kim 이(가) 확인한 뒤 2시간 동안 해결되지 않음 (심각 미확인) — 처리 안 됨으로 다시 엶 → 운영팀 에 다시 알림"
    for quiet in (recent, builtin, resolved):
        assert not [r for r in _rows(quiet) if r[0].startswith("acktimeout:")], quiet
    assert run() == 0                                      # 다시 열었으니 더 할 일이 없다
    sql("UPDATE alerts SET status = 'acked', acked_by = 'lee', acked_at = now() - interval '3 hours' WHERE id = %s", (late,))
    assert run() == 1 and ("acktimeout:7200:2", "pending") in _rows(late)   # 회차 2
    # 보낼 때 다시 본다 — 그 사이 다시 확인했으면 보내지 않는다
    job = {"action": "acktimeout:7200:2", "alert_status": "acked"}
    assert _stale(job, Notifier("x")) == "다시 알리기 전에 확인됨"
    assert _stale({**job, "alert_status": "open"}, Notifier("x")) is None
    detail = client.get(f"/api/alerts/{late}").json()
    assert [n["action"] for n in detail["notes"]].count("ack_timeout") == 2


def test_reopen_does_not_fire_steps_that_were_already_acked(client):
    """다시 연 알림에 '15분 동안 아무도 확인하지 않음'을 늦게 보내지 않는다 — 그 기한에는 확인돼 있었다 (검토에서 재현: 틀린 처리 기록·겹친 알림)."""
    from app.alerts.engine import engine

    aid = _alert(130, status="acked")
    sql("UPDATE alerts SET acked_by = 'kim', acked_at = fired_at + interval '5 minutes' WHERE id = %s", (aid,))
    now = datetime.now(UTC)
    assert client.portal.call(engine._ack_timeouts, now) >= 1
    client.portal.call(engine._escalate, now)
    actions = [a for a, _ in _rows(aid)]
    assert "acktimeout:7200:1" in actions and "escalate:900:acked" not in actions
    assert not sql("SELECT 1 FROM alert_notes WHERE alert_id = %s AND action = 'escalate' AND text LIKE '15분%%'", (aid,))


def test_old_acked_alerts_are_not_reopened_in_bulk(client):
    """기한이 지난 지 6시간 넘은 확인 알림은 다시 열지 않는다 — 정책을 새로 켜거나 줄였을 때 몇 달 묵은 알림이 쏟아지지 않게 (검토에서 재현)."""
    from app.alerts.engine import engine

    def acked(hours_ago):
        aid = _alert(hours_ago * 60 + 10, status="acked")
        sql("UPDATE alerts SET acked_by = 'kim', acked_at = now() - make_interval(hours => %s) WHERE id = %s", (hours_ago, aid))
        return aid
    ancient, stale, recent = acked(24 * 200), acked(10), acked(7)     # 기한(확인 + 2시간)이 4800일·8시간·5시간 전
    client.portal.call(engine._ack_timeouts, datetime.now(UTC))
    status = dict(sql("SELECT id, status FROM alerts WHERE id = ANY(%s)", ([ancient, stale, recent],)))
    assert (status[ancient], status[stale], status[recent]) == ("acked", "acked", "open")
