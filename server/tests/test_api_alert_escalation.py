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
        {"after_sec": 900, "unless": "acked", "notify": ["운영팀"]}, {"after_sec": 3600, "unless": "resolved", "notify": ["운영팀"]}]}]
