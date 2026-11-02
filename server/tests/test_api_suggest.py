"""검색 문장 값 자동완성 (BACKLOG B-65) — 통합 시험: 앞 글자(대소문자 무시)·많은 순·LIKE 글자·조회 범위·접속기록."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _ev(host, user):
    return {"date": datetime.now(UTC).isoformat(), "EventID": 4625, "Channel": "Security", "Computer": host, "agent_host": host,
            "log_source": "winevtlog", "Message": "x", "EventData": {"TargetUserName": user}}


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
        events = ([_ev("PC-1", "Kim.Minsu")] * 3 + [_ev("PC-1", "kim.jiwoo")] + [_ev("MED-01", "kimura")] * 2
                  + [_ev("PC-2", "a_b"), _ev("PC-2", "axb")])
        assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == len(events)
        temp = admin.post("/api/users", json={"username": "medic", "role": "viewer"}, headers=CSRF).json()
        assert admin.post("/api/user-groups", json={"name": "의료", "scope_hosts": ["MED-*"], "member_ids": [temp["user"]["id"]]},
                          headers=CSRF).status_code == 200
        medic = TestClient(app)
        medic.post("/api/auth/login", json={"username": "medic", "password": temp["temp_password"]}, headers=CSRF)
        medic.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": "Ward#Pass2026q"},
                   headers=CSRF)
        yield {"admin": admin, "medic": medic}


def _values(client, **params):
    r = client.get("/api/suggest", params=params)
    assert r.status_code == 200, r.text
    return [(i["value"], i["n"]) for i in r.json()["items"]]


def test_prefix_is_case_insensitive_and_most_frequent_first(ctx):
    assert _values(ctx["admin"], key="user", prefix="KIM") == [("Kim.Minsu", 3), ("kimura", 2), ("kim.jiwoo", 1)]
    assert _values(ctx["admin"], key="host", prefix="") == [("PC-1", 4), ("MED-01", 2), ("PC-2", 2)]


def test_like_wildcards_are_literal(ctx):
    assert _values(ctx["admin"], key="user", prefix="a_") == [("a_b", 1)]          # _ 가 아무 글자가 아니다
    assert _values(ctx["admin"], key="user", prefix="%") == []


def test_scope_and_access_log(ctx):
    assert _values(ctx["medic"], key="user", prefix="kim") == [("kimura", 2)]      # 범위 밖 PC 의 사용자 이름은 보이지 않는다
    assert ctx["admin"].get("/api/suggest", params={"key": "message"}).status_code == 400
    targets = {t for (t,) in sql("SELECT target FROM audit_log WHERE action = 'events.stats'")}
    assert "suggest:user" in targets and "suggest:host" not in targets


def test_time_cap_even_when_search_limit_is_off(ctx, monkeypatch):
    """WLM_SEARCH_TIMEOUT_SEC=0(상한 없음)이어도 입력마다 부르는 자동완성은 3초 — min(0, 3) 이면 상한·조회 자리 없이 돌았다 (검토에서 재현)."""
    from dataclasses import replace

    from app import db
    from app.routers import query

    seen = []
    real = db.limit_statement_time
    monkeypatch.setattr(query, "settings", replace(query.settings, search_timeout_sec=0))
    monkeypatch.setattr(db, "limit_statement_time", lambda sec: (seen.append(sec), real(sec))[1])
    assert ctx["admin"].get("/api/suggest", params={"key": "host"}).status_code == 200
    assert seen[-1] == query.SUGGEST_TIMEOUT_SEC


def test_custom_range_is_respected(ctx):
    """고른 구간 밖의 값은 제안하지 않는다 — 고르면 0건이었다 (검토에서 재현)."""
    from datetime import timedelta

    old = {**_ev("PC-9", "old.user"), "date": (datetime.now(UTC) - timedelta(days=20)).isoformat()}
    assert ctx["admin"].post("/api/ingest", json=[old], headers=KEY).json()["accepted"] == 1
    since = (datetime.now(UTC) - timedelta(days=25)).isoformat()
    until = (datetime.now(UTC) - timedelta(days=15)).isoformat()
    assert _values(ctx["admin"], key="user", prefix="", since=since, until=until) == [("old.user", 1)]
