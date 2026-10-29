"""알림 처리(확인·해결·다시 열기·메모)와 무음 통합 테스트 — BACKLOG B-02, B-03, ADR-029.

알림은 엔진(engine.evaluate / fire)으로 실제로 발생시킨다. 앱의 이벤트 루프에서 돌려야 해서 TestClient.portal 을 쓴다.
규칙은 enabled: false 로 써서 백그라운드 평가가 끼어들지 않게 하고, 테스트가 evaluate 를 직접 부른다.
이 모듈의 테스트는 위에서 아래로 이어지는 하나의 시나리오다(앞 테스트의 알림·재알림 간격을 뒤 테스트가 전제로 쓴다).
대상(PC)은 시나리오마다 다르게 써서 서로의 재알림 간격에 걸리지 않게 한다.
"""

from __future__ import annotations

import csv
import io
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Handle#Member2026"
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
  - name: 서버 응답 없음
    kind: agent_silent
    enabled: false
    silent_for: 10m
    hosts: [AGENT-Z]
    severity: error
    notify: [없는대상]
"""
EMPTY_RULES = "settings:\n  interval_sec: 30\n\nrules:\n"


def _logon_failure(host):
    now = datetime.now(UTC).isoformat()
    return {"date": now, "EventID": 4625, "Channel": "Security", "Computer": host, "agent_host": host,
            "log_source": "winevtlog", "Message": "로그온 실패"}


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    from fastapi.testclient import TestClient

    from app.alerts.engine import engine
    from app.main import app

    try:
        yield from _scenario(TestClient, app, engine)
    finally:
        # 준비 중에 실패해도 되돌린다 — 다음 모듈(규칙 관리 테스트)이 없는 알림 대상을 참조하는 규칙 때문에 저장을 거부당하지 않게
        Path(os.environ["WLM_ALERTS_FILE"]).write_text(EMPTY_RULES, encoding="utf-8")
        engine.reload(force=True)


def _scenario(TestClient, app, engine):
    with TestClient(app) as admin:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        events = [_logon_failure("PC-A"), _logon_failure("PC-B"), _logon_failure("MED-01")]
        assert admin.post("/api/ingest", json=events, headers={"X-API-Key": "test-key"}).json()["accepted"] == 3

        clients, ids = {}, {}
        for name in ("viewer", "handler", "med-handler"):
            temp = admin.post("/api/users", json={"username": name, "role": "viewer"}, headers=CSRF).json()
            ids[name] = temp["user"]["id"]
            c = TestClient(app)
            c.post("/api/auth/login", json={"username": name, "password": temp["temp_password"]}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD},
                   headers=CSRF)
            clients[name] = c
        for group, body in (("당직", {"permissions": ["alerts.handle"], "member_ids": [ids["handler"]]}),
                            ("의료정보과", {"permissions": ["alerts.handle"], "scope_hosts": ["MED-*"],
                                         "member_ids": [ids["med-handler"]]})):
            assert admin.post("/api/user-groups", json={"name": group, **body}, headers=CSRF).status_code == 200

        engine.reload(force=True)

        def evaluate(at=None, rule=0):
            """rule: 0 = 로그온 실패(건수), 1 = 서버 응답 없음(agent_silent). 평가한 뒤 전송기로 보낸다 (ADR-045 — 시험에서는
            전송기가 돌지 않는다)."""
            from app.alerts.dispatcher import dispatcher

            fired = admin.portal.call(engine.evaluate, engine.config.rules[rule], at or datetime.now(UTC))
            admin.portal.call(dispatcher.drain)
            return fired

        yield {"admin": admin, **clients, "evaluate": evaluate}


def _alerts(client, **params):
    r = client.get("/api/alerts", params={"since": "1h", **params}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()


def _handle(client, ids, action, note="", with_related=False):
    return client.post("/api/alerts/handle", json={"ids": ids, "action": action, "note": note,
                                                   "with_related": with_related}, headers=CSRF)


def _ingest(client, *hosts):
    r = client.post("/api/ingest", json=[_logon_failure(h) for h in hosts], headers={"X-API-Key": "test-key"})
    assert r.status_code == 200 and r.json()["accepted"] == len(hosts), r.text


def _open_count(client):
    return client.get("/api/stats/summary", headers=CSRF).json()["alerts_open"]


def test_alert_lifecycle(ctx):
    admin, viewer, handler = ctx["admin"], ctx["viewer"], ctx["handler"]
    fired = ctx["evaluate"]()
    assert len(fired) == 3
    by_host = {a["group_key"]: a for a in _alerts(admin)["items"]}
    pc_a = by_host["PC-A"]["id"]
    assert by_host["PC-A"]["status"] == "open"
    assert _open_count(admin) == 3
    # 사이드바 숫자·상태별 수도 조회 범위를 따른다 (MED-* 사용자에게는 MED-01 하나)
    assert _open_count(ctx["med-handler"]) == 1
    assert _alerts(ctx["med-handler"])["counts"] == {"open": 1, "acked": 0, "resolved": 0}

    # 확인: 알림을 볼 수 있으면 누구나 (권한 없는 조회자도). 확인하면 사이드바 숫자에서 빠진다
    r = _handle(viewer, [pc_a], "ack", "보는 중")
    assert r.status_code == 200 and r.json()["changed"] == [pc_a]
    assert _handle(viewer, [pc_a], "ack").json() == {"ok": True, "changed": [], "unchanged": [pc_a], "missing": []}
    assert _open_count(admin) == 2

    # 해결·다시 열기: alerts.handle 권한
    assert _handle(viewer, [pc_a], "resolve").status_code == 403
    assert _handle(handler, [pc_a], "resolve", "계정 잠금 확인, 사용자 비밀번호 초기화").json()["changed"] == [pc_a]
    detail = admin.get(f"/api/alerts/{pc_a}", headers=CSRF).json()
    assert (detail["status"], detail["acked_by"], detail["resolved_by"]) == ("resolved", "viewer", "handler")
    assert [(n["action"], n["author"]) for n in detail["notes"]] == [("ack", "viewer"), ("resolve", "handler")]
    # 해결된 알림을 '확인'으로 되살릴 수 없고(권한 없는 다시 열기 우회 방지), 처리 안 된 알림은 다시 열 것이 없다
    assert _handle(viewer, [pc_a], "ack").json()["unchanged"] == [pc_a]
    assert admin.get(f"/api/alerts/{pc_a}", headers=CSRF).json()["status"] == "resolved"
    pc_b = by_host["PC-B"]["id"]
    assert _handle(handler, [pc_b], "reopen").json()["unchanged"] == [pc_b]

    assert _handle(handler, [pc_a], "reopen", "재발").json()["changed"] == [pc_a]
    detail = admin.get(f"/api/alerts/{pc_a}", headers=CSRF).json()
    assert (detail["status"], detail["acked_by"], detail["resolved_at"]) == ("open", None, None)
    assert [n["action"] for n in detail["notes"]] == ["ack", "resolve", "reopen"]  # 이전 기록은 남는다

    # 누구나 하는 '확인'으로 대기열에서 치운 알림은 담당자가 처리 안 됨으로 되돌릴 수 있다
    assert _handle(viewer, [pc_a], "ack").json()["changed"] == [pc_a]
    assert _handle(handler, [pc_a], "reopen", "아직 조치 전").json()["changed"] == [pc_a]
    detail = admin.get(f"/api/alerts/{pc_a}", headers=CSRF).json()
    assert (detail["status"], detail["acked_by"]) == ("open", None)
    assert [n["action"] for n in detail["notes"]] == ["ack", "resolve", "reopen", "ack", "reopen"]

    # 메모: 누구나, 빈 메모는 거부
    assert viewer.post(f"/api/alerts/{pc_a}/notes", json={"text": "  "}, headers=CSRF).status_code == 422
    note = viewer.post(f"/api/alerts/{pc_a}/notes", json={"text": "사용자에게 전화함"}, headers=CSRF)
    assert note.status_code == 200 and note.json()["author"] == "viewer"
    assert admin.get(f"/api/alerts/{pc_a}", headers=CSRF).json()["note_count"] == 1

    # 상태 필터와 상태별 수
    data = _alerts(admin, status="open")
    assert {a["status"] for a in data["items"]} == {"open"}
    assert data["counts"] == {"open": 3, "acked": 0, "resolved": 0}


def test_bulk_resolve_and_scope(ctx):
    admin, handler, med = ctx["admin"], ctx["handler"], ctx["med-handler"]
    items = _alerts(admin, status="unresolved")["items"]
    all_ids = [a["id"] for a in items]
    med_id = next(a["id"] for a in items if a["group_key"] == "MED-01")

    # 조회 범위(MED-*) 밖의 알림은 보이지도, 처리되지도 않는다
    assert [a["group_key"] for a in _alerts(med)["items"]] == ["MED-01"]
    others = [i for i in all_ids if i != med_id]
    assert med.get(f"/api/alerts/{others[0]}", headers=CSRF).status_code == 404
    assert _handle(med, others, "ack").status_code == 404
    r = _handle(med, all_ids, "ack")
    assert r.json()["changed"] == [med_id] and sorted(r.json()["missing"]) == sorted(others)

    assert med.post(f"/api/alerts/{others[0]}/notes", json={"text": "범위 밖"}, headers=CSRF).status_code == 404

    r = _handle(handler, [*all_ids, 999999], "resolve", "점검 후 일괄 종료")
    assert sorted(r.json()["changed"]) == sorted(all_ids) and r.json()["missing"] == [999999]
    assert _open_count(admin) == 0
    # 확인 없이 바로 해결해도 확인한 사람·시각이 남는다 (인지 시각 증적)
    pc_b = admin.get(f"/api/alerts/{next(a['id'] for a in items if a['group_key'] == 'PC-B')}", headers=CSRF).json()
    assert pc_b["acked_by"] == "handler" and pc_b["acked_at"] is not None


def test_notes_are_append_only(ctx):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        alert_id = conn.execute(
            "INSERT INTO alerts (rule, severity, payload) VALUES ('기록 시험', 'info', '{}') RETURNING id").fetchone()[0]
        conn.execute("INSERT INTO alert_notes (alert_id, author, action, text) VALUES (%s, 'tester', 'note', '원문')",
                     (alert_id,))
        for statement in ("UPDATE alert_notes SET text = '조작'", "DELETE FROM alert_notes",
                          "TRUNCATE alert_notes", "TRUNCATE alerts CASCADE"):
            with pytest.raises(psycopg.errors.RaiseException, match="수정하거나 삭제할 수 없습니다"):
                conn.execute(statement)
        # 알림째 지우면(보관기간 만료와 같은 경로) 처리 기록도 함께 지워진다
        conn.execute("DELETE FROM alerts WHERE id = %s", (alert_id,))
        assert conn.execute("SELECT count(*) FROM alert_notes WHERE alert_id = %s", (alert_id,)).fetchone()[0] == 0


def test_csv_export_has_handling_columns(ctx, monkeypatch):
    r = ctx["admin"].get("/api/alerts", params={"since": "1h", "format": "csv", "reason": "사고 조사"}, headers=CSRF)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
    assert rows[0][6:11] == ["처리 상태", "확인한 사람", "확인 시각", "해결한 사람", "해결 시각"]
    pc_a = next(row for row in rows[1:] if row[4] == "PC-A")
    assert pc_a[6] == "해결됨" and pc_a[9] == "handler"
    assert "[다시 열기] 재발" in pc_a[13] and "[메모] 사용자에게 전화함" in pc_a[13]
    audit = ctx["admin"].get("/api/audit", params={"since": "1h", "action": "alerts."}, headers=CSRF).json()["items"]
    assert {"alerts.ack", "alerts.resolve", "alerts.reopen", "alerts.note", "alerts.export"} <= {a["action"] for a in audit}

    # 조회 범위가 있는 사용자의 CSV 에는 범위 안의 알림만
    med = ctx["med-handler"].get("/api/alerts", params={"since": "1h", "format": "csv", "reason": "사고 조사"}, headers=CSRF)
    assert {row[4] for row in list(csv.reader(io.StringIO(med.text.lstrip("\ufeff"))))[1:]} == {"MED-01"}

    # 상한에서 잘리면 파일 끝·응답 머리글·감사로그에 남긴다 (증적이 몰래 빠지지 않게)
    from app.routers import alerts as alerts_router

    monkeypatch.setattr(alerts_router, "CSV_LIMIT", 1)
    r = ctx["admin"].get("/api/alerts", params={"since": "1h", "format": "csv", "reason": "사고 조사"}, headers=CSRF)
    rows = list(csv.reader(io.StringIO(r.text.lstrip("\ufeff"))))
    assert r.headers.get("X-WLM-Truncated") == "1" and len(rows) == 3 and rows[-1][0].startswith("(최근 1건까지만")
    last = ctx["admin"].get("/api/audit", params={"since": "1h", "action": "alerts.export"}, headers=CSRF).json()["items"][0]
    assert last["detail"]["truncated"] is True and last["detail"]["rows"] == 1 and last["detail"]["reason"] == "사고 조사"
    assert ctx["admin"].get("/api/alerts", params={"since": "1h", "format": "csv"}, headers=CSRF).status_code == 400


def test_silence_validation(ctx):
    admin, viewer, med = ctx["admin"], ctx["viewer"], ctx["med-handler"]

    def create(client, **body):
        return client.post("/api/alerts/silences", json={"reason": "점검", **body}, headers=CSRF)

    assert create(viewer, duration_sec=3600).status_code == 403          # alerts.handle 없음
    assert create(admin).status_code == 422                              # 기간 없음
    assert create(admin, duration_sec=3600, reason=" ").status_code == 422
    assert create(admin, rule="없는 규칙", duration_sec=3600).status_code == 422
    assert create(admin, duration_sec=31 * 86400).status_code == 422     # 30일 초과
    soon = datetime.now(UTC)
    # 끝 시각은 '지금부터 30일 안' — 미래 시작 무음을 이어 붙여 늘리거나, 끝 시각을 직접 멀리 잡아도 안 된다
    assert create(admin, ends_at=(soon + timedelta(days=31)).isoformat()).status_code == 422
    assert create(admin, starts_at=(soon + timedelta(days=29)).isoformat(), duration_sec=2 * 86400).status_code == 422
    assert create(admin, starts_at=(soon + timedelta(days=31)).isoformat(), duration_sec=3600).status_code == 422
    assert create(admin, starts_at="9999-12-31T23:59:30+00:00", duration_sec=60).status_code == 422  # 500 아님
    assert create(admin, ends_at="2026-01-01T00:00:00").status_code == 422  # 시간대 없음
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    assert create(admin, ends_at=past).status_code == 422
    # 조회 범위가 있는 담당자는 볼 수 있는 규칙·대상 한 개에만
    assert create(med, duration_sec=3600).status_code == 403
    assert create(med, rule="로그온 실패", group_key="PC-A", duration_sec=3600).status_code == 403
    r = create(med, rule="로그온 실패", group_key="MED-01", duration_sec=3600)
    assert r.status_code == 200, r.text
    assert admin.delete(f"/api/alerts/silences/{r.json()['id']}", headers=CSRF).status_code == 200
    assert admin.delete(f"/api/alerts/silences/{r.json()['id']}", headers=CSRF).status_code == 409
    # 예정 무음 취소: 한 번만 되고(두 번째 409, 해제한 사람 유지), 목록에서는 끝난 것
    later = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    upcoming = create(admin, rule="로그온 실패", group_key="PC-U", starts_at=later, duration_sec=3600).json()["id"]
    assert med.delete(f"/api/alerts/silences/{upcoming}", headers=CSRF).status_code == 404  # 범위 밖이라 보이지도 않음
    assert admin.delete(f"/api/alerts/silences/{upcoming}", headers=CSRF).status_code == 200
    assert admin.delete(f"/api/alerts/silences/{upcoming}", headers=CSRF).status_code == 409
    listed = {s["id"]: s for s in admin.get("/api/alerts/silences", headers=CSRF).json()["items"]}
    assert listed[upcoming]["state"] == "ended"

    # 범위가 있는 사용자에게 보이는 무음: 모든 규칙·모든 대상 / 내 PC 를 대상으로 한 것만 (범위 밖 PC 이름·사유는 안 보임)
    broad = {name: create(admin, duration_sec=3600, **body).json()["id"] for name, body in
             (("global", {}), ("dc", {"group_key": "DC-01"}), ("med", {"group_key": "MED-02"}))}
    seen = {s["id"]: s for s in med.get("/api/alerts/silences", headers=CSRF).json()["items"]}
    assert broad["global"] in seen and broad["med"] in seen and broad["dc"] not in seen
    assert seen[broad["global"]]["suppressed"] is None  # 범위 밖 알림까지 센 숫자는 감춘다
    assert med.delete(f"/api/alerts/silences/{broad['global']}", headers=CSRF).status_code == 403  # 남의 알림까지 풀 수 없다
    for silence_id in broad.values():
        assert admin.delete(f"/api/alerts/silences/{silence_id}", headers=CSRF).status_code == 200


def test_silence_suppresses_delivery_then_realerts_when_over(ctx):
    admin, handler, evaluate = ctx["admin"], ctx["handler"], ctx["evaluate"]
    # 앞 테스트의 알림이 재알림 간격(1시간) 안에 있으므로, 새 대상으로 시험한다
    assert admin.post("/api/ingest", json=[_logon_failure("PC-S")], headers={"X-API-Key": "test-key"}).status_code == 200
    r = handler.post("/api/alerts/silences", json={"rule": "로그온 실패", "group_key": "PC-S", "duration_sec": 3600,
                                                   "reason": "PC-S 패치 작업"}, headers=CSRF)
    assert r.status_code == 200, r.text
    silence_id = r.json()["id"]

    fired = evaluate()
    assert len(fired) == 1
    alert = admin.get(f"/api/alerts/{fired[0]}", headers=CSRF).json()
    assert alert["silence_id"] == silence_id and alert["silence"]["reason"] == "PC-S 패치 작업"
    assert [(d["status"], d["last_error"]) for d in alert["deliveries"]] == [("skipped", f"무음 #{silence_id}: PC-S 패치 작업")]

    assert evaluate() == []  # 무음 중에는 재알림 간격대로 (알림 행이 쌓이지 않음)
    _ingest(admin, "PC-S")     # 무음 중에 들어온 이벤트 = 점검 잡음
    assert evaluate() == []
    listed = {s["id"]: s for s in admin.get("/api/alerts/silences", headers=CSRF).json()["items"]}
    assert listed[silence_id]["state"] == "active" and listed[silence_id]["suppressed"] == 1
    assert admin.get("/api/alerts/config", headers=CSRF).json()["silences_active"] == 1

    # 무음을 풀어도 무음 중에 쌓인 이벤트만으로는 다시 울리지 않는다 (점검 잡음)
    assert handler.delete(f"/api/alerts/silences/{silence_id}", headers=CSRF).status_code == 200
    assert evaluate(datetime.now(UTC) + timedelta(seconds=1)) == []
    # 무음이 끝난 뒤 이벤트가 새로 들어오면(문제가 계속되면) 재알림 간격을 기다리지 않고 바로 다시 알린다
    assert admin.post("/api/ingest", json=[_logon_failure("PC-S")], headers={"X-API-Key": "test-key"}).status_code == 200
    again = evaluate(datetime.now(UTC) + timedelta(seconds=1))
    assert len(again) == 1
    alert = admin.get(f"/api/alerts/{again[0]}", headers=CSRF).json()
    assert alert["silence_id"] is None and alert["deliveries"][0]["status"] == "failed"  # 대상이 없어 실패 = 전송 시도함
    assert alert["related_unresolved"] == 1
    assert evaluate(datetime.now(UTC) + timedelta(seconds=2)) == []  # 이제는 보통 재알림 간격
    # 상세의 '같은 규칙·대상 함께 해결' — 개수와 상관없이 서버가 한 번에
    r = _handle(handler, [again[0]], "resolve", "패치 후 정상", with_related=True)
    assert sorted(r.json()["changed"]) == sorted([fired[0], again[0]])

    audit = admin.get("/api/audit", params={"since": "1h", "action": "alerts.silence."}, headers=CSRF).json()["items"]
    assert {"alerts.silence.create", "alerts.silence.end"} <= {a["action"] for a in audit}


def test_broad_and_upcoming_silences_in_engine(ctx):
    admin, handler, evaluate = ctx["admin"], ctx["handler"], ctx["evaluate"]

    def silence(**body):
        r = handler.post("/api/alerts/silences", json={"reason": "점검", **body}, headers=CSRF)
        assert r.status_code == 200, r.text
        return r.json()["id"]

    def delivery_of(alert_id):
        alert = admin.get(f"/api/alerts/{alert_id}", headers=CSRF).json()
        return alert["silence_id"], alert["deliveries"][0]["status"]

    # 모든 규칙·모든 대상
    everything = silence(duration_sec=3600)
    _ingest(admin, "PC-G")
    fired = evaluate()
    assert len(fired) == 1 and delivery_of(fired[0]) == (everything, "skipped")
    assert handler.delete(f"/api/alerts/silences/{everything}", headers=CSRF).status_code == 200

    # 규칙만 정함(모든 대상)
    rule_wide = silence(rule="로그온 실패", duration_sec=3600)
    _ingest(admin, "PC-R")
    fired = evaluate()
    assert len(fired) == 1 and delivery_of(fired[0]) == (rule_wide, "skipped")
    assert handler.delete(f"/api/alerts/silences/{rule_wide}", headers=CSRF).status_code == 200

    # 예정 무음은 시작 전에는 막지 않는다
    later = silence(rule="로그온 실패", group_key="PC-H", duration_sec=3600,
                    starts_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat())
    _ingest(admin, "PC-H")
    fired = evaluate()
    assert len(fired) == 1 and delivery_of(fired[0]) == (None, "failed")  # 대상이 없어 실패 = 전송을 시도함
    assert handler.delete(f"/api/alerts/silences/{later}", headers=CSRF).status_code == 200


def test_agent_silent_realerts_after_silence(ctx):
    admin, handler, evaluate = ctx["admin"], ctx["handler"], ctx["evaluate"]
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("INSERT INTO agents (host, last_seen) VALUES ('AGENT-Z', now() - interval '1 hour')")
    r = handler.post("/api/alerts/silences", json={"rule": "서버 응답 없음", "group_key": "AGENT-Z", "duration_sec": 3600,
                                                   "reason": "서버 교체"}, headers=CSRF)
    silence_id = r.json()["id"]

    fired = evaluate(rule=1)
    assert len(fired) == 1
    assert admin.get(f"/api/alerts/{fired[0]}", headers=CSRF).json()["deliveries"][0]["status"] == "skipped"
    assert evaluate(rule=1) == []  # 끊긴 동안 한 번만
    # 무음이 끝났는데도 여전히 끊겨 있으면 다시 알린다 (무음 때문에 아무도 모르는 일이 없게)
    assert handler.delete(f"/api/alerts/silences/{silence_id}", headers=CSRF).status_code == 200
    again = evaluate(datetime.now(UTC) + timedelta(seconds=1), rule=1)
    assert len(again) == 1
    assert admin.get(f"/api/alerts/{again[0]}", headers=CSRF).json()["deliveries"][0]["status"] == "failed"
    assert evaluate(datetime.now(UTC) + timedelta(seconds=2), rule=1) == []


def test_scoped_list_is_not_cut_by_newer_out_of_scope_alerts(ctx):
    # 지금 가장 최근 알림들은 모두 범위 밖(PC-*, AGENT-Z)이다. LIMIT 를 범위로 거르기 전에 걸면 MED-01 이 목록에서 사라진다
    assert [a["group_key"] for a in _alerts(ctx["med-handler"], limit=1)["items"]] == ["MED-01"]


def test_purge_removes_notes_with_alerts(ctx):
    from app import repository

    deleted, silences = ctx["admin"].portal.call(repository.purge_alerts, datetime.now(UTC) + timedelta(days=1))
    assert deleted >= 5 and silences >= 1
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
        assert conn.execute("SELECT count(*) FROM alert_notes").fetchone()[0] == 0
