"""검색 '통계' 탭과 이벤트 CSV (BACKLOG B-62) — 통합 시험.

top(필드 하나·건수만)과 timeseries 뿐이라 '계정별 로그온한 PC 수와 처음/마지막 시각', 'IP 별 실패 횟수와 시도한 계정 수' 같은
점검 질문을 표로 만들 수 없었고, 이벤트 CSV 도 없었다.
"""

from __future__ import annotations

import csv
import io
import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
T0 = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=50)
PASSWORD = "Scope#Team2026x"


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _insert(host, user, ip, minute, event_id=4624, category="security", message="m"):
    sql("INSERT INTO events (ts, host, source, category, event_id, level, message, raw, username, src_ip)"
        " VALUES (%s, %s, 'winevtlog', %s, %s, 4, %s, %s::jsonb, %s, %s)",
        (T0 + timedelta(minutes=minute), host, category, event_id, message,
         '{"EventData": {"LogonType": "%s"}}' % (10 if user == "kim" else 3), user, ip))


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
        for host, minute in (("PC-A", 1), ("PC-A", 5), ("PC-B", 9), ("PC-B", 12), ("PC-C", 20)):
            _insert(host, "kim", "10.0.0.5", minute)
        _insert("PC-A", "lee", "10.0.0.6", 3)
        for n, user in enumerate(("admin", "root", "test")):        # 한 IP 에서 여러 계정으로 실패
            _insert("DC-01", user, "203.0.113.9", 30 + n, event_id=4625)
        _insert("=cmd|' /C calc'!A0", "kim", None, 40, event_id=7036, category="system", message="=HYPERLINK(\"x\")")  # 로그에서 온 수식
        temp = admin.post("/api/users", json={"username": "viewer", "role": "viewer"}, headers=CSRF).json()
        assert admin.post("/api/user-groups", json={"name": "시스템팀", "scope_categories": ["system"],
                                                    "member_ids": [temp["user"]["id"]]}, headers=CSRF).status_code == 200
        viewer = TestClient(app)
        viewer.post("/api/auth/login", json={"username": "viewer", "password": temp["temp_password"]}, headers=CSRF)
        viewer.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD}, headers=CSRF)
        yield {"admin": admin, "viewer": viewer}


def _group(client, **params):
    r = client.get("/api/stats/group", params={"since": "2h", **params}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()


def test_accounts_by_pc_count_with_first_and_last(ctx):
    """'계정별 로그온한 PC 수와 처음/마지막 시각'."""
    res = _group(ctx["admin"], by="user", distinct="host", query="event_id:4624")
    rows = {i["keys"][0]: i for i in res["items"]}
    assert rows["kim"]["n"] == 5 and rows["kim"]["distinct"] == [3]
    assert rows["kim"]["first_ts"].startswith((T0 + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M"))
    assert rows["lee"]["n"] == 1 and rows["lee"]["distinct"] == [1]
    assert res["items"][0]["keys"] == ["kim"] and res["truncated"] is False   # 건수 많은 순


def test_failures_by_ip_with_accounts_tried_and_two_keys(ctx):
    res = _group(ctx["admin"], by="ip", distinct="user", query="event_id:4625")
    assert [(i["keys"], i["n"], i["distinct"]) for i in res["items"]] == [(["203.0.113.9"], 3, [3])]
    pairs = _group(ctx["admin"], by="user,host", query="user:kim event_id:4624")
    assert {tuple(i["keys"]): i["n"] for i in pairs["items"]} == {("kim", "PC-A"): 2, ("kim", "PC-B"): 2, ("kim", "PC-C"): 1}
    raw = _group(ctx["admin"], by="f.EventData.LogonType", query="event_id:4624")   # 원본 필드로도 묶는다
    assert {i["keys"][0]: i["n"] for i in raw["items"]} == {"10": 5, "3": 1}


def test_limits_and_bad_fields(ctx):
    res = _group(ctx["admin"], by="host", limit=2)
    assert len(res["items"]) == 2 and res["truncated"] is True
    for params in ({"by": "nope"}, {"by": "host,user,ip,category"}, {"by": "host,host"}, {"by": ""},
                   {"by": "host", "distinct": "user,ip,host"}):
        assert ctx["admin"].get("/api/stats/group", params={"since": "2h", **params}, headers=CSRF).status_code == 400, params


def test_scope_applies(ctx):
    res = _group(ctx["viewer"], by="host")
    assert [i["keys"][0] for i in res["items"]] == ["=cmd|' /C calc'!A0"]   # 시스템 분류만 보인다


def test_personal_grouping_is_access_logged(ctx):
    from app import accesslog

    accesslog.forget()
    before = sql("SELECT count(*) FROM audit_log WHERE action = 'events.stats'")[0][0]
    _group(ctx["admin"], by="host")                       # 개인정보 아님
    _group(ctx["admin"], by="host", distinct="user")      # 서로 다른 사용자 수도 사용자를 다룬다
    _group(ctx["admin"], by="host", distinct="user")      # 같은 조건은 10분에 한 번
    rows = sql("SELECT target FROM audit_log WHERE action = 'events.stats' ORDER BY id")[before:]
    assert rows == [("host",)]


def test_csv_needs_a_reason_is_logged_and_neutralizes_formulas(ctx):
    admin = ctx["admin"]
    assert admin.get("/api/stats/group", params={"since": "2h", "by": "host", "format": "csv"}, headers=CSRF).status_code == 400
    assert admin.get("/api/events", params={"since": "2h", "format": "csv"}, headers=CSRF).status_code == 400
    r = admin.get("/api/stats/group", params={"since": "2h", "by": "host", "distinct": "user", "format": "csv", "reason": "월간 점검"},
                  headers=CSRF)
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    table = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert table[0] == ["PC", "건수", "서로 다른 사용자 수", "처음(UTC)", "마지막(UTC)"]
    assert any(row[0] == "'=cmd|' /C calc'!A0" for row in table[1:])       # 수식으로 실행되지 않게
    r = admin.get("/api/events", params={"since": "2h", "format": "csv", "reason": "사고 조사"}, headers=CSRF)
    table = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert table[0][0] == "발생 시각(UTC)" and len(table) == 1 + 10
    assert any(row[12] == "'=HYPERLINK(\"x\")" for row in table[1:])
    exports = sql("SELECT target, detail FROM audit_log WHERE action = 'events.export' ORDER BY id")
    assert [(t, d["reason"], d["rows"]) for t, d in exports] == [("stats.group", "월간 점검", 5), ("events", "사고 조사", 10)]


def test_exports_fail_closed(ctx, monkeypatch):
    from app import db

    real = db.audit

    async def broken(*args, required=False, **kwargs):
        if required:
            raise db.AuditError("시험")
        return await real(*args, required=required, **kwargs)

    monkeypatch.setattr(db, "audit", broken)
    for path, params in (("/api/stats/group", {"by": "host"}), ("/api/events", {})):
        r = ctx["admin"].get(path, params={"since": "2h", "format": "csv", "reason": "월간 점검", **params}, headers=CSRF)
        assert r.status_code == 503, path
