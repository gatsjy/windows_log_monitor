"""접속기록 점검 결과서 (BACKLOG B-72 3단계, ISMS 2.9.5, ADR-060) — 통합 시험: 근거 스냅샷·결과·2단계 결재·고칠 수 없음·CSV·권한·준비도·보고서."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _login(app, username, temp, password):
    from fastapi.testclient import TestClient

    c = TestClient(app)
    c.post("/api/auth/login", json={"username": username, "password": temp}, headers=CSRF)
    assert c.post("/api/auth/password", json={"current_password": temp, "new_password": password}, headers=CSRF).status_code == 200
    return c


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as admin:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        clients = {}
        for name, group in (("auditor", {"permissions": ["reports.view"]}),
                            ("medic", {"permissions": ["reports.view"], "scope_hosts": ["MED-*"]}), ("plain", None)):
            temp = admin.post("/api/users", json={"username": name, "role": "viewer"}, headers=CSRF).json()
            if group:
                assert admin.post("/api/user-groups", json={"name": f"{name}-g", **group, "member_ids": [temp["user"]["id"]]},
                                  headers=CSRF).status_code == 200
            clients[name] = _login(app, name, temp["temp_password"], "Vault#Insp2026qq")
        # 근거에 잡히게: 사유가 짧은 내려받기 하나
        assert admin.get("/api/alerts", params={"since": "1d", "format": "csv", "reason": "확인"}).status_code == 200
        yield {"admin": admin, **clients}


def _entry(client, iid, **body):
    return client.post(f"/api/inspections/{iid}/entries", json=body, headers=CSRF)


def test_permissions(ctx):
    assert ctx["plain"].get("/api/inspections").status_code == 403
    assert ctx["medic"].get("/api/inspections").status_code == 403   # 조회 범위가 있으면 전체 점검을 볼 수 없다
    assert ctx["auditor"].get("/api/inspections").status_code == 200


def test_flow_with_evidence_and_two_step_approval(ctx, monkeypatch):
    from app import inspection

    monkeypatch.setattr(inspection, "WORK_HOURS", (0, 0))   # 모든 로그인을 업무시간 외로 — 시각과 상관없이 근거를 본다
    auditor, admin = ctx["auditor"], ctx["admin"]
    now = datetime.now(UTC)
    r = auditor.post("/api/inspections", json={"title": "시험 점검", "period_start": (now - timedelta(days=2)).isoformat(),
                                               "period_end": (now + timedelta(minutes=1)).isoformat()}, headers=CSRF)
    assert r.status_code == 200, r.text
    iid = r.json()["id"]
    d = auditor.get(f"/api/inspections/{iid}").json()
    items = {i["key"]: i for i in d["items"]}
    assert list(items) == list(inspection.ITEM_KEYS) and d["status"] == "open"
    assert items["downloads"]["evidence"]["total"] >= 1 and "사유가 짧은 것 1건" in items["downloads"]["summary"]
    assert {r["actor"] for r in items["accounts"]["evidence"]["logins"]} >= {"admin", "auditor", "medic", "plain"}
    assert "업무시간" in items["off_hours"]["summary"] and items["off_hours"]["evidence"]["logins"]
    assert items["privilege"]["evidence"]["actions"].get("user.create") >= 3   # 처음 관리자도 센다

    assert _entry(auditor, iid, kind="sign").status_code == 422                         # 다 정하기 전에는 서명 못 함
    assert _entry(auditor, iid, kind="result", item="downloads", result="issue").status_code == 422   # 부적정은 조치 필수
    assert _entry(auditor, iid, kind="result", item="nope", result="ok").status_code == 422
    for key in inspection.ITEM_KEYS:
        body = {"result": "issue", "note": "사유 '확인' — 담당자에게 다시 받음"} if key == "downloads" else {"result": "ok"}
        assert _entry(auditor, iid, kind="result", item=key, **body).status_code == 200
    assert _entry(auditor, iid, kind="sign", note="이상 없음(1건 조치)").status_code == 200
    assert _entry(auditor, iid, kind="result", item="retention", result="na").status_code == 409   # 서명 뒤 잠김
    assert _entry(auditor, iid, kind="approve").status_code == 403                   # 서명한 사람은 승인 못 함
    assert _entry(admin, iid, kind="reject").status_code == 422
    assert _entry(admin, iid, kind="reject", note="계정 항목 근거 보강").status_code == 200
    assert _entry(auditor, iid, kind="sign").status_code == 200
    assert _entry(admin, iid, kind="approve", note="승인").status_code == 200
    d = auditor.get(f"/api/inspections/{iid}").json()
    assert d["status"] == "approved" and d["issues"] == ["downloads"] and d["approved"]["author"] == "admin"
    listed = auditor.get("/api/inspections").json()["items"][0]
    assert (listed["status"], listed["done"], listed["items"], listed["issues"]) == ("approved", 8, 8, 1)
    actions = [a for (a,) in sql("SELECT action FROM audit_log WHERE action LIKE 'inspection.%%' ORDER BY id")]
    assert actions[0] == "inspection.start" and actions.count("inspection.result") == 8 and "inspection.reject" in actions

    # 결과서 CSV — 사유 필수·개인정보 내려받기
    assert auditor.get(f"/api/inspections/{iid}/csv").status_code == 400
    r = auditor.get(f"/api/inspections/{iid}/csv", params={"reason": "ISMS 심사 증적"})
    text = r.content.decode("utf-8-sig")
    assert r.status_code == 200 and "개인정보 내려받기와 사유" in text and "부적정" in text and "(승인)" in text


def test_records_cannot_be_changed(ctx):
    for query in ("UPDATE inspection_entries SET note = 'x'", "DELETE FROM inspection_entries", "UPDATE inspections SET title = 'x'",
                  "DELETE FROM inspections", "TRUNCATE inspection_entries", "TRUNCATE inspections CASCADE"):
        with pytest.raises(psycopg.Error, match="접속기록 점검 결재 증적"):
            sql(query)


def test_overdue_in_readiness_and_report(ctx):
    from app import inspection, readiness
    from app.reports import builder

    now = datetime.now(UTC)
    o = ctx["admin"].portal.call(inspection.overview, now, 31)
    assert not o["overdue"] and o["last_title"] == "시험 점검"
    assert not ctx["admin"].portal.call(inspection.overview, now + timedelta(days=40), 31)["overdue"]   # 한 주기 + 여유 14일
    assert ctx["admin"].portal.call(inspection.overview, now + timedelta(days=46), 31)["overdue"]
    items = {i.key: i for i in readiness.judge(ctx["admin"].portal.call(readiness.collect, now))}
    assert items["access_log_inspection"].status == "ok"
    later = {**ctx["admin"].portal.call(readiness.collect, now),
             "access_log_inspection": ctx["admin"].portal.call(inspection.overview, now + timedelta(days=46), 31)}
    assert {i.key: i for i in readiness.judge(later)}["access_log_inspection"].status == "warn"
    payload = ctx["admin"].portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    assert payload["access_log_inspection"]["last_title"] == "시험 점검"
    old = {k: v for k, v in payload.items() if k != "access_log_inspection"}
    assert builder._attention(old) is not None   # B-72 3단계 이전 보고서도


def test_period_checks_and_duplicates(ctx):
    """기간: 시작·끝 함께, 하루 이상, 끝은 지금까지. 시간대 없는 값은 표시 시간대(전에는 500). 같은 기간을 겹쳐 시작하면 409 — 지울 수 없어
    영영 '진행 중'으로 남는다."""
    auditor, now = ctx["auditor"], datetime.now(UTC)

    def start(**period):
        return auditor.post("/api/inspections", json={"title": "기간 시험", **period}, headers=CSRF)

    iso = lambda d: d.isoformat()
    assert start(period_start=iso(now - timedelta(days=3))).status_code == 422
    assert start(period_start=iso(now - timedelta(hours=2)), period_end=iso(now - timedelta(hours=1))).status_code == 422
    assert start(period_start=iso(now - timedelta(days=3)), period_end=iso(now + timedelta(days=1))).status_code == 422
    assert start(period_start="9999-12-31T23:00:00Z", period_end="2026-01-01T00:00:00Z").status_code == 422   # 넘침 → 500 이었다
    # 1년: UTC 로 기원전이 되어 저장은 되는데 읽을 때마다 실패 → 점검 목록·준비도·보고서가 영영 깨졌다 (행은 지울 수 없음, 검토에서 재현)
    assert start(period_start="0001-01-01T00:00:00+14:00", period_end=iso(now - timedelta(hours=1))).status_code == 422
    assert start(period_start="0001-01-01T00:00:00", period_end="0001-01-03T00:00:00").status_code == 422
    naive = {"period_start": "2026-01-01T00:00:00", "period_end": "2026-02-01T00:00:00"}
    r = start(**naive)
    assert r.status_code == 200, r.text
    d = auditor.get(f"/api/inspections/{r.json()['id']}").json()
    assert datetime.fromisoformat(d["period_start"]) == datetime(2025, 12, 31, 15, tzinfo=UTC)   # 한국 시간 1월 1일 0시
    dup = start(**naive)
    assert dup.status_code == 409 and f"#{r.json()['id']}" in dup.json()["detail"]
    assert auditor.get("/api/inspections").json()["default_period"]["title"].endswith("월 접속기록 점검")


def test_detail_view_is_access_logged(ctx):
    """근거에 계정 이름·내려받기 사유가 든다 — 열람도 접속기록(ADR-042). 대량 조회 점검도 센다."""
    from app import accesslog, repository

    accesslog.forget()
    iid = ctx["auditor"].get("/api/inspections").json()["items"][0]["id"]
    before = sql("SELECT count(*) FROM audit_log WHERE action = 'inspection.view'")[0][0]
    assert ctx["auditor"].get(f"/api/inspections/{iid}").status_code == 200
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'inspection.view'")[0][0] == before + 1
    assert {"inspection.view", "audit.list", "report.view", "report.print"} <= set(repository.PERSONAL_VIEW_ACTIONS)


def test_integrity_evidence_covers_failures_inside_the_period(ctx):
    """기간 안에 검증이 실패했다가 다시 통과해도 근거에 남는다 (지금 상태만 보면 '정상'). 이 모듈의 마지막 시험 — 실패 기록을 남긴다."""
    from app import db

    admin, now = ctx["admin"], datetime.now(UTC)
    admin.portal.call(db.audit, "system", "integrity.verify", "audit_log", {"ok": False, "problems": ["#3 해시 다름"]})
    admin.portal.call(db.audit, "system", "integrity.verify", "audit_log", {"ok": True, "problems": []})
    r = ctx["auditor"].post("/api/inspections", json={"title": "위변조 시험", "period_start": (now - timedelta(days=1, hours=1)).isoformat(),
                                                      "period_end": (datetime.now(UTC) + timedelta(minutes=1)).isoformat()}, headers=CSRF)
    assert r.status_code == 200, r.text
    item = next(i for i in ctx["auditor"].get(f"/api/inspections/{r.json()['id']}").json()["items"] if i["key"] == "integrity")
    assert item["summary"].startswith("기간 중 문제") and "위·변조 검증 실패: #3 해시 다름" in item["summary"]
    assert item["evidence"]["runs"]["integrity.verify"] == 1 and item["evidence"]["problem_count"] >= 1
