"""조사 플레이북 API (BACKLOG B-66) — 통합 시험: 알림 값으로 채운 질문의 건수·상위 값·최근 로그, 조회 범위, 빠진 값, 문장 주입."""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Probe#Pass2026q"
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패 급증
    sid: 1000005
    enabled: false
    match: { event_id: "4625" }
    threshold: 2
    group_by: host
    severity: warning
    notify: [운영팀]
"""
BOOK = """title: 로그온 실패 급증
steps:
  - question: 실패한 계정은?
    why: 여러 계정이면 대입
    query: 'event_id:4625 host:{host}'
    window: 1h
    top: user
  - question: 같은 계정이 성공했나?
    why: 맞혔을 수 있다
    query: 'event_id:4624 user:{user}'
    window: 2h
  - question: 출발지 IP 의 다른 시도?
    why: IP 가 없으면 건너뜀
    query: 'event_id:4625 ip:{ip}'
"""
EVIL = 'kim" -host:none'          # 로그에서 온 사용자 이름이 문장 조건이 되려는 값


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _ev(host, event_id, user, hours_ago=0):
    return {"date": (datetime.now(UTC) - timedelta(hours=hours_ago)).isoformat(), "EventID": event_id, "Channel": "Security", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": f"{event_id}", "EventData": {"TargetUserName": user}}


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.alerts import playbook
    from app.alerts.engine import engine
    from app.main import app

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    books = playbook.directory()
    books.mkdir(exist_ok=True)
    (books / "1000005.yaml").write_text(BOOK, encoding="utf-8")
    try:
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            # 알림의 최근 이벤트(표본 첫 줄)가 EVIL 이 되게 lee 를 먼저 — 플레이북의 {user} 는 그 이벤트의 사용자
            events = ([_ev("PC-1", 4625, "lee")] + [_ev("PC-1", 4625, EVIL) for _ in range(2)]
                      + [_ev("PC-1", 4624, EVIL), _ev("PC-2", 4624, "kim")])
            assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == len(events)
            rule = engine.config.rules[0]
            admin.portal.call(engine.evaluate, rule, datetime.now(UTC))
            [(alert_id,)] = sql("SELECT id FROM alerts WHERE group_key = 'PC-1'")
            temp = admin.post("/api/users", json={"username": "medic", "role": "viewer"}, headers=CSRF).json()
            assert admin.post("/api/user-groups", json={"name": "의료", "scope_hosts": ["MED-*"],
                                                        "member_ids": [temp["user"]["id"]]}, headers=CSRF).status_code == 200
            medic = TestClient(app)
            medic.post("/api/auth/login", json={"username": "medic", "password": temp["temp_password"]}, headers=CSRF)
            medic.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD},
                       headers=CSRF)
            yield {"admin": admin, "medic": medic, "alert_id": alert_id}
    finally:
        shutil.rmtree(books, ignore_errors=True)
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def test_steps_are_filled_counted_and_escaped(ctx):
    r = ctx["admin"].get(f"/api/alerts/{ctx['alert_id']}/playbook")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] and body["title"] == "로그온 실패 급증"
    first, success, by_ip = body["steps"]
    assert first["query"] == "event_id:4625 host:PC-1" and first["count"] == 3
    assert {t["value"]: t["n"] for t in first["top"]} == {EVIL: 2, "lee": 1}
    # 로그에서 온 사용자 이름은 한 값으로만 — '-host:none' 이 조건이 되지 않는다 (PC-2 의 kim 성공은 세지 않음)
    assert success["query"] == 'event_id:4624 user:"kim"" -host:none"' and success["count"] == 1
    assert success["events"][0]["host"] == "PC-1"
    assert by_ip["missing"] == ["ip"] and "count" not in by_ip      # 값이 없으면 넓게 찾지 않고 건너뜀
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'alerts.playbook'")
    assert detail["rule"] == "로그온 실패 급증" and detail["steps"] == 3


def test_scope_and_missing_playbook(ctx):
    assert ctx["medic"].get(f"/api/alerts/{ctx['alert_id']}/playbook").status_code == 404     # 범위 밖 알림
    assert ctx["admin"].get("/api/alerts/999999/playbook").status_code == 404
    from app.alerts import playbook

    (playbook.directory() / "1000005.yaml").write_text("steps: [", encoding="utf-8")
    assert "플레이북 파일 오류" in ctx["admin"].get(f"/api/alerts/{ctx['alert_id']}/playbook").json()["error"]
    (playbook.directory() / "1000005.yaml").unlink()
    assert ctx["admin"].get(f"/api/alerts/{ctx['alert_id']}/playbook").json() == {"available": False}


def _alert_for(client, host):
    from app.alerts.engine import engine

    client.portal.call(engine.evaluate, engine.config.rules[0], datetime.now(UTC))
    return sql("SELECT id FROM alerts WHERE group_key = %s ORDER BY id DESC LIMIT 1", (host,))[0][0]


def test_control_character_in_value_skips_only_that_step(ctx):
    """로그에서 온 값(syslog 호스트 이름 등)에 제어 문자가 있으면 검색 문장을 만들 수 없다 — 그 질문만 건너뛰고 500 이 아니다 (검토에서 재현)."""
    from app.alerts import playbook

    (playbook.directory() / "1000005.yaml").write_text(BOOK, encoding="utf-8")
    host = "BAD\x07HOST"
    admin = ctx["admin"]
    assert admin.post("/api/ingest", json=[_ev(host, 4625, "x"), _ev(host, 4625, "y")], headers=KEY).json()["accepted"] == 2
    r = admin.get(f"/api/alerts/{_alert_for(admin, host)}/playbook")
    assert r.status_code == 200, r.text
    first = r.json()["steps"][0]
    assert "error" in first and "count" not in first


def test_window_follows_event_time_not_alert_time(ctx):
    """밀려 들어온 로그(발생 시각이 몇 시간 전)도 질문의 구간에 든다 — 알림 시각 기준이면 0건이었다 (검토에서 재현)."""
    from app.alerts import playbook

    (playbook.directory() / "1000005.yaml").write_text(BOOK, encoding="utf-8")
    admin = ctx["admin"]
    assert admin.post("/api/ingest", json=[_ev("LATE-1", 4625, "kim", hours_ago=6) for _ in range(2)],
                      headers=KEY).json()["accepted"] == 2
    first = admin.get(f"/api/alerts/{_alert_for(admin, 'LATE-1')}/playbook").json()["steps"][0]
    assert first["query"] == "event_id:4625 host:LATE-1" and first["count"] == 2
