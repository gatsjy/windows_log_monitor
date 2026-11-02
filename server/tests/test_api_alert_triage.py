"""알림 묶어 보기·종료 분류·규칙별 오탐률 (BACKLOG B-44) — 통합 시험.

장애 때 같은 규칙이 수십 PC 에서 터지면 다른 심각 알림이 묻히고, 닫을 때 정탐·오탐을 남기지 않아 어떤 규칙을 고칠지 정할 수 없었다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Triage#Pass2026q"
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패
    enabled: false
    match: { event_id: "4625" }
    severity: warning
    notify: [운영팀]
  - name: 서비스 중지
    enabled: false
    match: { event_id: "7034" }
    severity: critical
    notify: [운영팀]
"""


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _alert(rule, key, severity, minutes_ago):
    return sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload)"
               " VALUES (now() - make_interval(mins => %s), %s, %s, %s, 1, '{}') RETURNING id",
               (minutes_ago, rule, severity, key))[0][0]


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
            clients = {}
            for name, group in (("handler", {"permissions": ["alerts.handle"]}),
                                ("medic", {"permissions": ["alerts.handle"], "scope_hosts": ["MED-*"]})):
                temp = admin.post("/api/users", json={"username": name, "role": "viewer"}, headers=CSRF).json()
                assert admin.post("/api/user-groups", json={"name": f"{name}-g", **group, "member_ids": [temp["user"]["id"]]},
                                  headers=CSRF).status_code == 200
                c = TestClient(app)
                c.post("/api/auth/login", json={"username": name, "password": temp["temp_password"]}, headers=CSRF)
                c.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD},
                       headers=CSRF)
                clients[name] = c
            ids = {
                "PC-A": [_alert("로그온 실패", "PC-A", "warning", m) for m in (30, 20, 10)],
                "PC-B": [_alert("로그온 실패", "PC-B", "warning", 5)],
                "SRV-1": [_alert("서비스 중지", "SRV-1", "critical", 50)],
                "MED-01": [_alert("로그온 실패", "MED-01", "warning", m) for m in (60, 40)],
            }
            yield {"admin": admin, **clients, "ids": ids}
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _handle(client, ids, action, **extra):
    return client.post("/api/alerts/handle", json={"ids": ids, "action": action, **extra}, headers=CSRF)


def test_groups_put_unresolved_and_severe_first_and_scope_before_limit(ctx):
    admin, medic = ctx["admin"], ctx["medic"]
    body = admin.get("/api/alerts/groups", params={"since": "1d"}).json()
    order = [(g["rule"], g["group_key"]) for g in body["items"]]
    assert order[0] == ("서비스 중지", "SRV-1")               # 심각한 묶음이 위로 (마지막 발생은 가장 오래됐어도)
    pc_a = next(g for g in body["items"] if g["group_key"] == "PC-A")
    assert (pc_a["n"], pc_a["open"], pc_a["resolved"], pc_a["last_id"]) == (3, 3, 0, max(ctx["ids"]["PC-A"]))
    # 조회 범위는 GROUP BY·LIMIT 전에 — 한 줄만 달라고 해도 범위 안 묶음이 나온다
    assert [g["group_key"] for g in medic.get("/api/alerts/groups", params={"since": "1d", "limit": 1}).json()["items"]] == ["MED-01"]


def test_resolve_requires_classification_and_records_it(ctx):
    handler, ids = ctx["handler"], ctx["ids"]
    assert _handle(handler, ids["PC-A"][:1], "resolve").status_code == 422
    assert _handle(handler, ids["PC-A"][:1], "resolve", resolution="auto").status_code == 422     # 자동 해소는 엔진만
    # 묶음 처리 = 가장 최근 알림 + with_related — 같은 규칙·대상 전부
    r = _handle(handler, [ids["PC-A"][-1]], "resolve", resolution="fp_rule", note="임계값이 낮음", with_related=True)
    assert sorted(r.json()["changed"]) == sorted(ids["PC-A"])
    assert {row[0] for row in sql("SELECT resolution FROM alerts WHERE id = ANY(%s)", (ids["PC-A"],))} == {"fp_rule"}
    assert {row[0] for row in sql("SELECT resolution FROM alert_notes WHERE alert_id = ANY(%s) AND action = 'resolve'",
                                  (ids["PC-A"],))} == {"fp_rule"}
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'alerts.resolve'")
    assert detail["resolution"] == "fp_rule" and detail["targets"] == 1 and len(detail["ids"]) == 3
    item = next(a for a in ctx["admin"].get("/api/alerts", params={"since": "1d"}).json()["items"] if a["id"] == ids["PC-A"][0])
    assert item["resolution"] == "fp_rule"
    # 다시 열면 분류는 비운다 (처리 기록의 처음 판단은 남음)
    assert _handle(handler, ids["PC-A"][:1], "reopen").json()["changed"] == ids["PC-A"][:1]
    assert sql("SELECT resolution FROM alerts WHERE id = %s", (ids["PC-A"][0],)) == [(None,)]
    assert _handle(handler, ids["PC-A"][:1], "resolve", resolution="fp_rule").status_code == 200


def test_auto_resolve_is_classified_auto(ctx):
    from app import repository

    now = datetime.now(UTC)
    changed, _ = ctx["admin"].portal.call(repository.auto_resolve, "로그온 실패", "PC-B", "조건이 풀림", (), now,
                                          now - timedelta(days=7))
    assert changed == ctx["ids"]["PC-B"]
    assert sql("SELECT resolution FROM alerts WHERE id = %s", (changed[0],)) == [("auto",)]
    assert sql("SELECT resolution FROM alert_notes WHERE alert_id = %s AND action = 'auto_resolve'", (changed[0],)) == [("auto",)]


def test_rule_quality_and_report(ctx):
    admin, handler, medic, ids = ctx["admin"], ctx["handler"], ctx["medic"], ctx["ids"]
    assert _handle(handler, ids["MED-01"], "resolve", resolution="tp_malicious").status_code == 200
    q = {r["name"]: r["quality"] for r in admin.get("/api/alerts/config").json()["rules"]}["로그온 실패"]
    # 정탐 2 · 오탐 3 (자동 해소 1 은 오탐률에 넣지 않음) → 오탐률 3/5
    assert (q["n"], q["tp"], q["fp"], q["auto"], q["fp_rate"]) == (6, 2, 3, 1, 0.6) and q["mttr_sec"] >= 0
    assert all(r["quality"] is None for r in medic.get("/api/alerts/config").json()["rules"])   # 범위 사용자는 전체 숫자를 못 봄

    from app.reports import builder, render

    now = datetime.now(UTC)
    payload = admin.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    al = payload["alerts"]
    assert al["resolutions"] == {"fp_rule": 3, "tp_malicious": 2, "auto": 1}
    assert al["false_positive_rules"] == [{"rule": "로그온 실패", "n": 3}]
    page = render.html(payload, 1)
    assert "해결한 알림의 종료 분류" in page and "오탐 — 규칙 문제" in page and "오탐이 많은 규칙" in page
    old = {**payload, "alerts": {k: v for k, v in al.items() if k not in ("resolutions", "false_positive_rules")}}
    assert "종료 분류" not in render.html(old, 1)        # B-44 이전 보고서도 그린다
