"""규칙 시험기·관찰 모드 (BACKLOG B-52) — 통합 시험.

규칙 미리보기는 24시간 건수만 보여 줘 특정 이벤트가 왜 안 걸렸는지(경로 틀림·제외 조건·값 형식) 알 수 없었고,
새 규칙을 켜면 바로 메일이 나갔다. 시험기는 조건마다 기대·실제를, 관찰 모드는 기록만 하고 보내지 않는다.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Reader#Pass2026q"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl"
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패
    match: { query: "event_id:4625 -user:svc_backup" }
    window: 10m
    threshold: 1
    group_by: host
    cooldown: 1h
    severity: warning
    notify: [운영팀]
  - name: PC 끊김
    kind: agent_silent
    silent_for: 1h
    notify: [운영팀]
"""


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _event(host, user):
    return {"date": datetime.now(UTC).isoformat(), "EventID": 4625, "Channel": "Security", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": "로그온 실패", "EventData": {"TargetUserName": user}}


def _agent_4625():
    """실제 에이전트(Fluent Bit 4.0) 모양 — EventData 없이 StringInserts 만 (ADR-038)."""
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record.get("EventID") == 4625:
            return {**record, "log_source": "winevtlog", "agent_host": "WIN-CI"}
    raise AssertionError("고정 자료에 4625 가 없음")


@pytest.fixture(scope="module")
def ctx():
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
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            events = [_event("PC-01", "kim"), _event("PC-02", "svc_backup")]
            assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == 2
            ids = {h: i for i, h in sql("SELECT id, host FROM events")}
            temp = admin.post("/api/users", json={"username": "viewer", "role": "viewer"}, headers=CSRF).json()
            viewer = TestClient(app)
            viewer.post("/api/auth/login", json={"username": "viewer", "password": temp["temp_password"]}, headers=CSRF)
            viewer.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD},
                        headers=CSRF)
            yield {"admin": admin, "viewer": viewer, "ids": ids}
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _test(client, **body):
    return client.post("/api/alerts/rules/test", json=body, headers=CSRF)


def test_saved_rule_against_stored_events(ctx):
    admin, ids = ctx["admin"], ctx["ids"]
    r = _test(admin, name="로그온 실패", event_id=ids["PC-01"])
    assert r.status_code == 200, r.text
    assert r.json()["matched"] is True and r.json()["event"]["username"] == "kim"
    r = _test(admin, name="로그온 실패", event_id=ids["PC-02"]).json()
    assert r["matched"] is False
    [failed] = [c for c in r["checks"] if not c["ok"]]
    assert failed == {"key": "user", "op": "not_in", "expected": ["svc_backup"], "actual": "svc_backup", "ok": False,
                      "exception": None}
    # 상세 보기와 같은 접속기록 (실제 사용자·IP 를 돌려준다)
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'events.view' AND target = %s", (str(ids["PC-02"]),))
    assert detail["rule_test"] == "로그온 실패" and detail["username"] == "svc_backup"


def test_exception_is_named(ctx):
    admin, ids = ctx["admin"], ctx["ids"]
    assert admin.post("/api/alerts/exceptions", json={"rule": "로그온 실패", "term": "user:kim", "reason": "시험 계정"},
                      headers=CSRF).status_code == 200
    r = _test(admin, name="로그온 실패", event_id=ids["PC-01"]).json()
    assert r["matched"] is False
    assert [c["exception"] for c in r["checks"] if not c["ok"]] == ["user:kim"]


def test_editing_rule_with_pasted_agent_record(ctx):
    """편집 중인 규칙 + 붙여 넣은 원본 → 수집과 같은 정규화(EventData 이름 붙이기 포함)로 판단."""
    admin = ctx["admin"]
    sample = _agent_4625()
    rule = {"name": "원격 로그온 실패", "match": {"query": "event_id:4625 f.EventData.LogonType:10"}, "window_sec": 600,
            "threshold": 1, "severity": "warning"}
    r = _test(admin, rule=rule, sample=sample).json()
    by = {c["key"]: c for c in r["checks"]}
    assert by["event_id"]["ok"] and by["f.EventData.LogonType"]["actual"] == "2" and not by["f.EventData.LogonType"]["ok"]
    assert r["event"]["host"] == "WIN-CI" and r["event"]["id"] is None and r["ingest_error"] is None
    rule["match"] = {"query": "event_id:4625 f.EventData.LogonType:2"}
    assert _test(admin, rule=rule, sample=sample).json()["matched"] is True
    assert sql("SELECT count(*) FROM events WHERE host = 'WIN-CI'")[0][0] == 0      # 시험한 원본은 저장하지 않는다


def test_refusals(ctx):
    admin, viewer, ids = ctx["admin"], ctx["viewer"], ctx["ids"]
    assert _test(viewer, name="로그온 실패", event_id=ids["PC-01"]).status_code == 403
    assert _test(admin, name="없는 규칙", event_id=ids["PC-01"]).status_code == 404
    assert _test(admin, name="PC 끊김", event_id=ids["PC-01"]).status_code == 400
    assert _test(admin, name="로그온 실패").status_code == 400                                 # 이벤트 없음
    assert _test(admin, name="로그온 실패", event_id=ids["PC-01"], sample={"a": 1}).status_code == 400   # 둘 다
    assert _test(admin, name="로그온 실패", event_id=999_999_999).status_code == 404
    heartbeat = {"type": "heartbeat", "host": "PC-01"}
    assert _test(admin, name="로그온 실패", sample=heartbeat).status_code == 400
    assert _test(admin, name="로그온 실패", sample={"x": "a" * 70_000}).status_code == 413


def _fire(client):
    from app.alerts.engine import engine

    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute("DELETE FROM alert_notes WHERE alert_id IN (SELECT id FROM alerts WHERE rule = '로그온 실패')")
        conn.execute("DELETE FROM alert_deliveries WHERE alert_id IN (SELECT id FROM alerts WHERE rule = '로그온 실패')")
        conn.execute("DELETE FROM alerts WHERE rule = '로그온 실패'")
    sql("UPDATE rule_exceptions SET ended_at = now(), ended_by = 'test' WHERE ended_at IS NULL")
    rule = next(r for r in engine.config.rules if r.name == "로그온 실패")
    return client.portal.call(engine.evaluate, rule, datetime.now(UTC))


def test_observe_mode_records_without_sending_and_promotes(ctx):
    admin = ctx["admin"]
    r = admin.post("/api/alerts/rules/mode", json={"names": ["로그온 실패"], "mode": "observe"}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert "    mode: observe" in Path(os.environ["WLM_ALERTS_FILE"]).read_text(encoding="utf-8")
    [(weakened, changes)] = sql("SELECT weakened, changes FROM alert_config_versions ORDER BY id DESC LIMIT 1")
    assert weakened and [c["change"] for c in changes] == ["observe"]        # 탐지 약화 — 다른 관리자에게
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'alerts.rule.mode'")
    assert detail["mode"] == "observe" and detail["rules"] == ["로그온 실패"]
    rules = {x["name"]: x for x in admin.get("/api/alerts/config").json()["rules"]}
    assert rules["로그온 실패"]["mode"] == "observe"

    [alert_id] = _fire(admin)
    assert sql("SELECT status, last_error FROM alert_deliveries WHERE alert_id = %s", (alert_id,)) == [
        ("skipped", "관찰 모드 — 규칙을 켜기 전 시험 중이라 보내지 않음")]
    item = next(a for a in admin.get("/api/alerts", params={"since": "1h"}).json()["items"] if a["id"] == alert_id)
    assert item["observed"] is True
    assert admin.post("/api/alerts/rules/mode", json={"names": ["PC 끊김"], "mode": "observe"},
                      headers=CSRF).status_code == 400                       # 끊김 규칙은 관찰 모드 없음

    # 승격: 다음 알림부터 보낸다
    assert admin.post("/api/alerts/rules/mode", json={"names": ["로그온 실패"], "mode": "active"},
                      headers=CSRF).status_code == 200
    assert "mode:" not in Path(os.environ["WLM_ALERTS_FILE"]).read_text(encoding="utf-8")
    [alert_id] = _fire(admin)
    assert sql("SELECT status FROM alert_deliveries WHERE alert_id = %s", (alert_id,)) == [("pending",)]
    item = next(a for a in admin.get("/api/alerts", params={"since": "1h"}).json()["items"] if a["id"] == alert_id)
    assert item["observed"] is False


def test_rule_editor_keeps_observe_mode(ctx):
    admin = ctx["admin"]
    rule = {"name": "새 규칙", "match": {"event_id": "4740"}, "window_sec": 300, "threshold": 1, "severity": "warning",
            "notify": ["운영팀"], "mode": "observe"}
    assert admin.put("/api/alerts/rules", json={"rule": rule}, headers=CSRF).status_code == 200
    rules = {x["name"]: x for x in admin.get("/api/alerts/config").json()["rules"]}
    assert rules["새 규칙"]["mode"] == "observe"
    bad = {**rule, "name": "틀린 모드", "mode": "maybe"}
    assert admin.put("/api/alerts/rules", json={"rule": bad}, headers=CSRF).status_code == 200   # 화면 값이 아니면 기본(active)
    assert {x["name"]: x for x in admin.get("/api/alerts/config").json()["rules"]}["틀린 모드"]["mode"] == "active"


def test_pasted_sample_leaves_no_process_state():
    """붙여 넣은 MSSQL 'Error:' 머리줄이 머리줄 기억에 남으면 그 PC·파일의 다음 실제 본문 줄이 시험한 번호로 저장된다."""
    from app.normalizers import normalize_safely, normalize_sample

    now = datetime.now(UTC)
    stamp = f"{now:%Y-%m-%d %H:%M:%S}.10"

    def line(text):
        return {"log": f"{stamp} Logon       {text}", "file": "ERRORLOG", "agent_host": "SQL-T", "log_source": "mssql"}

    head = normalize_sample(line("Error: 18456, Severity: 14, State: 8."), now)
    assert head.raw["mssql"]["header"] is True
    assert normalize_safely(line("본문 줄"), now).event_id is None        # 시험한 머리줄과 짝지어지지 않음
    normalize_safely(line("Error: 18456, Severity: 14, State: 8."), now)
    assert normalize_sample(line("본문 줄"), now).event_id == 18456       # 시험도 실제 기억은 읽되
    assert normalize_safely(line("본문 줄"), now).event_id == 18456       # 꺼내 쓰지 않는다
