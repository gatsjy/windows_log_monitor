"""분기 권한 검토 (BACKLOG B-72 2단계, ISMS 2.5.6, ADR-058) — 통합 시험: 스냅샷·결정·2단계 결재·고칠 수 없음·CSV·준비도·보고서.

회귀 대상이 아니라 새 기능: 계정·권한이 아직 필요한지 분기마다 보는 증적(누가 언제 무엇을 보고 유지·회수했나)이 없었다.
"""

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
        ids = {}
        temps = {}
        for name, role in (("boss", "admin"), ("kim", "viewer"), ("old", "viewer")):
            r = admin.post("/api/users", json={"username": name, "role": role}, headers=CSRF).json()
            ids[name], temps[name] = r["user"]["id"], r["temp_password"]
        assert admin.post("/api/user-groups", json={"name": "의료정보과", "permissions": ["alerts.handle"], "scope_hosts": ["MED-*"],
                                                    "member_ids": [ids["kim"]]}, headers=CSRF).status_code == 200
        assert admin.patch(f"/api/users/{ids['old']}", json={"is_active": False}, headers=CSRF).status_code == 200
        boss = _login(app, "boss", temps["boss"], "Gate#Review2026q")
        kim = _login(app, "kim", temps["kim"], "Lake#Review2026qq")
        yield {"admin": admin, "boss": boss, "kim": kim, "ids": ids, "admin_id": sql("SELECT id FROM users WHERE username = 'admin'")[0][0]}


def _entry(client, review_id, **body):
    return client.post(f"/api/access-reviews/{review_id}/entries", json=body, headers=CSRF)


def test_viewer_cannot_see_reviews(ctx):
    assert ctx["kim"].get("/api/access-reviews").status_code == 403


def test_review_flow_with_two_step_approval(ctx):
    admin, boss, ids = ctx["admin"], ctx["boss"], ctx["ids"]
    rid = admin.post("/api/access-reviews", json={"title": "2026년 4분기 권한 검토"}, headers=CSRF).json()["id"]
    r = admin.get(f"/api/access-reviews/{rid}").json()
    by = {u["username"]: u for u in r["users"]}
    assert set(by) == {"admin", "boss", "kim", "old"} and r["status"] == "open" and r["active"] == 3
    assert by["kim"]["groups"] == ["의료정보과"] and by["kim"]["permissions"] == ["alerts.handle"] and by["kim"]["scoped"]
    assert not by["old"]["is_active"] and by["admin"]["permissions"] == ["(관리자 — 모든 기능)"]

    assert _entry(admin, rid, kind="sign").status_code == 422                     # 다 정하기 전에는 서명 못 함
    assert _entry(admin, rid, kind="decision", user_id=ids["kim"], decision="revoke").status_code == 422   # 회수는 사유 필수
    assert _entry(admin, rid, kind="decision", user_id=ids["old"], decision="keep").status_code == 422     # 꺼진 계정
    assert _entry(admin, rid, kind="decision", user_id=99999, decision="keep").status_code == 422
    assert _entry(admin, rid, kind="decision", user_id=ids["kim"], decision="maybe").status_code == 422
    for uid, decision, note in ((ctx["admin_id"], "keep", ""), (ids["boss"], "keep", ""), (ids["kim"], "revoke", "부서 이동")):
        assert _entry(admin, rid, kind="decision", user_id=uid, decision=decision, note=note).status_code == 200
    assert _entry(admin, rid, kind="sign", note="이상 없음").status_code == 200
    assert _entry(admin, rid, kind="decision", user_id=ids["kim"], decision="keep").status_code == 409   # 서명 뒤 잠김
    assert _entry(admin, rid, kind="approve").status_code == 403                  # 서명한 사람은 승인 못 함
    assert _entry(boss, rid, kind="reject").status_code == 422                    # 반려는 사유 필수
    assert _entry(boss, rid, kind="reject", note="kim 은 겸직 — 조정으로").status_code == 200
    assert _entry(admin, rid, kind="decision", user_id=ids["kim"], decision="change", note="alerts.handle 회수").status_code == 200
    assert _entry(admin, rid, kind="decision", user_id=ids["kim"], decision="revoke", note="부서 이동 확인").status_code == 200
    assert _entry(admin, rid, kind="sign").status_code == 200
    assert _entry(boss, rid, kind="approve", note="승인").status_code == 200
    assert _entry(boss, rid, kind="approve").status_code == 409
    r = admin.get(f"/api/access-reviews/{rid}").json()
    assert r["status"] == "approved" and r["approved"]["author"] == "boss" and r["follow_up"] == ["kim"]
    assert [e["kind"] for e in r["entries"]].count("decision") == 5
    actions = [a for (a,) in sql("SELECT action FROM audit_log WHERE action LIKE 'access_review.%%' ORDER BY id")]
    assert actions[0] == "access_review.start" and actions.count("access_review.approve") == 1 and "access_review.reject" in actions
    listed = admin.get("/api/access-reviews").json()["items"][0]
    assert (listed["status"], listed["decided"], listed["active"], listed["revokes"], listed["approved_by"]) == ("approved", 3, 3, 1, "boss")


def test_records_cannot_be_changed(ctx):
    for query in ("UPDATE access_review_entries SET note = 'x'", "DELETE FROM access_review_entries",
                  "UPDATE access_reviews SET title = 'x'", "DELETE FROM access_reviews", "TRUNCATE access_review_entries",
                  "TRUNCATE access_reviews CASCADE"):
        with pytest.raises(psycopg.Error, match="권한 검토 결재 증적"):
            sql(query)


def test_follow_up_overdue_in_readiness_and_report(ctx):
    from app import readiness
    from app.auth import review
    from app.reports import builder

    admin, kim_id = ctx["admin"], ctx["ids"]["kim"]
    now = datetime.now(UTC)
    o = admin.portal.call(review.overview, now, 92)
    assert o["follow_up"] == ["kim"] and not o["overdue"] and o["age_days"] == 0
    assert admin.portal.call(review.overview, now + timedelta(days=93), 92)["overdue"]
    assert not admin.portal.call(review.overview, now + timedelta(days=93), 0)["overdue"]   # 0 = 알리지 않음
    items = {i.key: i for i in readiness.judge(admin.portal.call(readiness.collect, now))}
    assert items["access_review"].status == "bad" and "kim" in items["access_review"].detail
    payload = admin.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    assert any("회수로 정했는데 아직 켜진 계정 1개: kim" in a["text"] for a in payload["attention"])
    old = {k: v for k, v in payload.items() if k != "access_review"}
    assert builder._attention(old) is not None            # B-72 2단계 이전 보고서도 판단한다
    assert admin.patch(f"/api/users/{kim_id}", json={"is_active": False}, headers=CSRF).status_code == 200
    items = {i.key: i for i in readiness.judge(admin.portal.call(readiness.collect, now))}
    assert items["access_review"].status == "ok"
    # 진행 중인 새 검토가 있으면 함께 보인다
    admin.post("/api/access-reviews", json={"title": "임시 검토"}, headers=CSRF)
    items = {i.key: i for i in readiness.judge(admin.portal.call(readiness.collect, now))}
    assert "진행 중: 임시 검토" in items["access_review"].detail


def test_csv_needs_reason_and_is_audited(ctx):
    admin = ctx["admin"]
    rid = next(r["id"] for r in admin.get("/api/access-reviews").json()["items"] if r["status"] == "approved")
    assert admin.get(f"/api/access-reviews/{rid}/csv").status_code == 400
    r = admin.get(f"/api/access-reviews/{rid}/csv", params={"reason": "ISMS 심사 증적"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    text = r.content.decode("utf-8-sig")
    assert "kim" in text and "회수" in text and "(승인)" in text and "부서 이동 확인" in text
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'access_review.export'")
    assert detail["reason"] == "ISMS 심사 증적" and detail["rows"] == 4
