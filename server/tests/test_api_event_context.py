"""앞뒤 로그 (BACKLOG B-61) — 통합 시험.

이벤트 하나를 찾은 뒤 같은 PC 에서 그 전후에 무슨 일이 있었는지 보려면 검색을 다시 짜야 했다.
같은 시각 여러 건(번호로 나눔)·경계·조회 범위·이어 보기·접속기록을 본다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
T0 = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=30)
PASSWORD = "Viewer#Pass2026"


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _insert(host, source, category, seconds, message):
    [(event_id,)] = sql("INSERT INTO events (ts, host, source, category, level, message, raw, username)"
                        " VALUES (%s, %s, %s, %s, 4, %s, '{}', 'kim') RETURNING id",
                        (T0 + timedelta(seconds=seconds), host, source, category, message))
    return event_id


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
        # CTX-PC: 10초 간격 + 같은 시각(40초) 세 건 + 다른 소스·분류, 다른 PC 는 끼지 않아야 한다
        for n, sec in enumerate((0, 10, 20, 30)):
            ids[f"s{n}"] = _insert("CTX-PC", "winevtlog", "security", sec, f"보안 {n}")
        for n in range(3):
            ids[f"tie{n}"] = _insert("CTX-PC", "winevtlog", "security", 40, f"같은 시각 {n}")
        ids["sys"] = _insert("CTX-PC", "winevtlog", "system", 45, "시스템")
        ids["iis"] = _insert("CTX-PC", "iis", "web", 50, "웹")
        ids["late"] = _insert("CTX-PC", "winevtlog", "security", 60, "보안 끝")
        ids["other"] = _insert("OTHER-PC", "winevtlog", "security", 41, "다른 PC")
        temp = admin.post("/api/users", json={"username": "scoped", "role": "viewer"}, headers=CSRF).json()
        assert admin.post("/api/user-groups", json={"name": "보안팀", "scope_categories": ["security"],
                                                    "member_ids": [temp["user"]["id"]]}, headers=CSRF).status_code == 200
        scoped = TestClient(app)
        scoped.post("/api/auth/login", json={"username": "scoped", "password": temp["temp_password"]}, headers=CSRF)
        scoped.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD}, headers=CSRF)
        yield {"admin": admin, "scoped": scoped, "ids": ids}


def _context(client, event_id, **params):
    r = client.get(f"/api/events/{event_id}/context", params=params, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()


def _messages(res):
    return [i["message"] for i in res["items"]]


def test_before_and_after_on_the_same_pc_with_ties(ctx):
    ids = ctx["ids"]
    base = ids["tie1"]   # 같은 시각 세 건 중 가운데 — 번호로 앞뒤가 나뉜다
    before = _context(ctx["admin"], base, direction="before", limit=3)
    after = _context(ctx["admin"], base, direction="after", limit=3)
    assert _messages(before) == ["같은 시각 0", "보안 3", "보안 2"]          # 가까운 것부터
    assert _messages(after) == ["같은 시각 2", "시스템", "웹"]
    assert before["next_cursor"] and after["next_cursor"]
    assert "다른 PC" not in _messages(before) + _messages(after)


def test_paging_to_the_edges(ctx):
    ids = ctx["ids"]
    page = _context(ctx["admin"], ids["tie1"], direction="before", limit=3)
    rest = _context(ctx["admin"], ids["tie1"], direction="before", limit=3, cursor=page["next_cursor"])
    assert _messages(rest) == ["보안 1", "보안 0"] and rest["next_cursor"] is None    # 처음까지
    end = _context(ctx["admin"], ids["late"], direction="after")
    assert end["items"] == [] and end["next_cursor"] is None                          # 마지막 뒤는 없음
    assert ctx["admin"].get(f"/api/events/{ids['late']}/context", params={"cursor": "x"}, headers=CSRF).status_code == 400


def test_same_source_narrows(ctx):
    after = _context(ctx["admin"], ctx["ids"]["tie2"], direction="after", same="source")
    assert _messages(after) == ["시스템", "보안 끝"]    # 웹(iis)은 빠진다


def test_scope_applies_to_neighbours_and_base(ctx):
    """조회 범위(보안 분류만)인 사용자에게는 범위 밖 이웃이 빠지고, 범위 밖 로그는 기준으로도 못 쓴다."""
    after = _context(ctx["scoped"], ctx["ids"]["tie2"], direction="after")
    assert _messages(after) == ["보안 끝"]
    assert ctx["scoped"].get(f"/api/events/{ctx['ids']['sys']}/context", headers=CSRF).status_code == 404


def test_context_is_access_logged_once_per_ten_minutes(ctx, monkeypatch):
    from app import accesslog, db

    accesslog.forget()
    before = sql("SELECT count(*) FROM audit_log WHERE action = 'events.context'")[0][0]
    base = ctx["ids"]["s2"]
    for direction in ("before", "after", "after"):
        _context(ctx["admin"], base, direction=direction)
    rows = sql("SELECT target, detail FROM audit_log WHERE action = 'events.context' ORDER BY id")[before:]
    assert len(rows) == 1 and rows[0][0] == str(base) and rows[0][1]["host"] == "CTX-PC"

    real = db.audit

    async def broken(*args, required=False, **kwargs):
        if required:
            raise db.AuditError("시험")
        return await real(*args, required=required, **kwargs)

    monkeypatch.setattr(db, "audit", broken)
    accesslog.forget()
    assert ctx["admin"].get(f"/api/events/{base}/context", headers=CSRF).status_code == 503   # 기록을 못 하면 보여 주지 않는다
