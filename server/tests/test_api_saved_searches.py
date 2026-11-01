"""저장한 검색 (BACKLOG B-64) — 통합 시험.

정기 점검의 반복 검색을 이름 붙여 저장·공유하고, 알림 규칙이 match.saved 로 같은 검색을 쓴다.
규칙이 쓰는 검색은 탐지 조건이므로 만든 사람이라도 알림 규칙을 고칠 수 없으면 고치지 못하고, 고치면 관리 작업 알림이 간다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Reader#Pass2026q"
EMPTY = "settings:\n  interval_sec: 30\n\nrules:\n"
RULE = {"name": "실패 급증 (저장한 검색)", "match": {"saved": "로그온 실패 kim"}, "window_sec": 600, "threshold": 3,
        "group_by": "host", "cooldown_sec": 3600, "severity": "warning", "notify": ["운영팀"]}


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _event(host, user):
    return {"date": datetime.now(UTC).isoformat(), "EventID": 4625, "Channel": "Security", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": "로그온 실패", "EventData": {"TargetUserName": user}}


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

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(EMPTY, encoding="utf-8")
    try:
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            events = [_event("PC-01", "kim") for _ in range(3)] + [_event("PC-02", "lee") for _ in range(4)]
            assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == len(events)
            temp = admin.post("/api/users", json={"username": "viewer", "role": "viewer"}, headers=CSRF).json()
            viewer = TestClient(app)
            viewer.post("/api/auth/login", json={"username": "viewer", "password": temp["temp_password"]}, headers=CSRF)
            viewer.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD},
                        headers=CSRF)
            yield {"admin": admin, "viewer": viewer}
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text(EMPTY, encoding="utf-8")
        engine.reload(force=True)


def _save(client, name, query, **extra):
    return client.post("/api/searches", json={"name": name, "query": query, **extra}, headers=CSRF)


def _by_name(client):
    return {s["name"]: s for s in client.get("/api/searches").json()["items"]}


def test_save_validates_and_stores_canonical_sentence(ctx):
    viewer = ctx["viewer"]
    r = _save(viewer, "내 검색", "  event_id:4625   user:kim ")
    assert r.status_code == 200, r.text
    assert r.json()["query"] == "event_id:4625 user:kim" and r.json()["owner"] == "viewer" and r.json()["can_edit"]
    assert _save(viewer, "내 검색", "event_id:4624").status_code == 409            # 이름은 하나
    assert _save(viewer, "빈 검색", "   ").status_code == 400
    assert _save(viewer, "틀린 검색", "event_id:").status_code == 400
    assert _save(viewer, "보호 시도", "event_id:4625", protected=True).status_code == 403   # 보호는 관리자만
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'search.save'")
    assert detail == {"query": "event_id:4625 user:kim", "shared": False, "protected": False}


def test_sharing_ownership_and_protection(ctx):
    admin, viewer = ctx["admin"], ctx["viewer"]
    assert _save(admin, "관리자 비공개", "level:1").status_code == 200
    assert _save(admin, "점검 — 로그온 실패", "event_id:4625", shared=True, protected=True).json()["protected"]
    seen = _by_name(viewer)
    assert "관리자 비공개" not in seen and seen["점검 — 로그온 실패"]["can_edit"] is False
    assert {"내 검색", "관리자 비공개", "점검 — 로그온 실패"} <= set(_by_name(admin))     # 관리자는 전부
    protected = seen["점검 — 로그온 실패"]["id"]
    body = {"name": "점검 — 로그온 실패", "query": "event_id:4624", "shared": True, "protected": False}
    assert viewer.put(f"/api/searches/{protected}", json=body, headers=CSRF).status_code == 403
    assert viewer.delete(f"/api/searches/{protected}", headers=CSRF).status_code == 403
    hidden = _by_name(admin)["관리자 비공개"]["id"]
    assert viewer.delete(f"/api/searches/{hidden}", headers=CSRF).status_code == 404     # 남의 비공개는 없는 것처럼
    mine = seen["내 검색"]["id"]
    r = viewer.put(f"/api/searches/{mine}", json={"name": "내 검색 (kim)", "query": "user:kim event_id:4625",
                                                   "shared": True}, headers=CSRF)
    assert r.status_code == 200 and r.json()["shared"] and r.json()["name"] == "내 검색 (kim)"
    assert viewer.put(f"/api/searches/{mine}", json={"name": "점검 — 로그온 실패", "query": "user:kim"},
                      headers=CSRF).status_code == 409                                    # 이름 겹침
    assert admin.delete(f"/api/searches/{hidden}", headers=CSRF).status_code == 200
    assert {a for (a,) in sql("SELECT action FROM audit_log WHERE action LIKE 'search.%%'")} == {
        "search.save", "search.update", "search.delete"}


def test_rule_uses_saved_search(ctx):
    from app.alerts.engine import engine

    admin, viewer = ctx["admin"], ctx["viewer"]
    # 없는 검색을 가리키는 규칙은 저장하지 않는다
    r = admin.put("/api/alerts/rules", json={"rule": RULE}, headers=CSRF)
    assert r.status_code == 422 and "없는 저장한 검색" in r.text
    assert _save(viewer, "로그온 실패 kim", "event_id:4625 user:kim", shared=True).status_code == 200
    assert admin.put("/api/alerts/rules", json={"rule": RULE}, headers=CSRF).status_code == 200, r.text
    preview = admin.post("/api/alerts/rules/preview", json={"rule": RULE, "hours": 1}, headers=CSRF)
    assert preview.status_code == 200 and preview.json()["matched"] == 3, preview.text
    assert _fired_hosts(admin) == ["PC-01"]

    # 규칙이 쓰는 검색: 만든 사람(알림 규칙 권한 없음)은 고치지 못하고, 지우거나 이름을 바꿀 수 없다
    item = _by_name(viewer)["로그온 실패 kim"]
    assert item["used_by"] == [RULE["name"]] and item["can_edit"] is False
    body = {"name": "로그온 실패 kim", "query": "event_id:4625 user:nobody", "shared": True}
    assert viewer.put(f"/api/searches/{item['id']}", json=body, headers=CSRF).status_code == 403
    assert admin.delete(f"/api/searches/{item['id']}", headers=CSRF).status_code == 409
    assert admin.put(f"/api/searches/{item['id']}", json={**body, "name": "새 이름"}, headers=CSRF).status_code == 409

    # 관리자가 문장을 바꾸면 다음 평가부터 규칙에 반영되고, 관리 작업 알림이 간다
    r = admin.put(f"/api/searches/{item['id']}", json={**body, "query": "event_id:4625 user:lee"}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert sql("SELECT count(*) FROM alerts WHERE rule = '관리 작업 알림'")[0][0] == 1
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'search.update' ORDER BY id DESC LIMIT 1")
    assert detail["old_query"] == "event_id:4625 user:kim" and detail["used_by"] == [RULE["name"]]
    assert _fired_hosts(admin) == ["PC-02"]

    # 검색이 사라지면(DB 에서 직접) 그 규칙만 오류 — 조용히 '모든 이벤트'가 되지 않는다
    sql("DELETE FROM saved_searches WHERE name = '로그온 실패 kim'")
    rule = next(x for x in engine.config.rules if x.name == RULE["name"])
    admin.portal.call(engine._run_rule, rule, datetime.now(UTC))
    assert "로그온 실패 kim" in engine.runs[RULE["name"]].error
    assert admin.post("/api/alerts/rules/preview", json={"rule": RULE, "hours": 1}, headers=CSRF).status_code == 400


def test_rule_match_saved_combines_with_query():
    """규칙 문장과 저장한 검색은 AND, 예외는 그 뒤에 제외 항으로 (engine.rule_filter 가 이름을 문장으로 바꿔 넘긴다)."""
    from app.alerts.rules import parse

    rule = parse({"rules": [{"name": "r", "match": {"saved": "s", "query": "host:PC-01"}, "notify": ["x"]}]}).rules[0]
    assert rule.match["saved"] == "s" and rule.categories == ()
    f = rule.event_filter(["user:svc"], saved="event_id:4625 category:security")
    assert f.event_ids == [4625] and f.hosts == ["PC-01"] and f.categories == ["security"]
    assert f.excludes == {"user": ["svc"]}
    assert rule.event_filter().event_ids == []                    # 문장을 모르면 저장한 검색 조건은 없다 (엔진이 막는다)


def test_recent_searches_come_from_access_log(ctx):
    viewer = ctx["viewer"]
    for query in ("user:kim", "event_id:4625", "user:kim"):
        assert viewer.get("/api/events", params={"query": query, "since": "24h"}).status_code == 200
    items = viewer.get("/api/searches/recent").json()["items"]
    assert [i["query"] for i in items] == ["user:kim", "event_id:4625"]          # 같은 문장은 한 번, 마지막에 쓴 순
    assert ctx["admin"].get("/api/searches/recent").json()["items"] == []         # 남의 검색은 안 보인다


def _fired_hosts(client):
    from app.alerts.engine import engine

    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute("DELETE FROM alert_notes WHERE alert_id IN (SELECT id FROM alerts WHERE rule = %s)", (RULE["name"],))
        conn.execute("DELETE FROM alert_deliveries WHERE alert_id IN (SELECT id FROM alerts WHERE rule = %s)", (RULE["name"],))
        conn.execute("DELETE FROM alerts WHERE rule = %s", (RULE["name"],))
    rule = next(x for x in engine.config.rules if x.name == RULE["name"])
    client.portal.call(engine.evaluate, rule, datetime.now(UTC))
    return sorted(r[0] for r in sql("SELECT group_key FROM alerts WHERE rule = %s", (RULE["name"],)))
