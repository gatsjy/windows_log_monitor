"""알림의 개체·관련 알림·개체 페이지 (BACKLOG B-67, ADR-064) — 통합 시험.

- wlm_alert_entities(마이그레이션 046): 새 알림과 옛 알림을 같은 규칙으로 채우는 SQL 함수 — 표로 고정
- 엔진: 조건에 맞은 로그의 PC·계정(표기 통일)·IP 를 알림에 붙이고, 10개를 넘는 종류는 넣지 않는다
- 관련 알림: 앞뒤 1시간·같은 개체·조회 범위, 개체 페이지: 계정 표기 통일·조회 범위·접속기록
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

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
    enabled: false
    match: { event_id: "4625" }
    threshold: 2
    group_by: host
    severity: warning
    notify: [운영팀]
  - name: 계정 대입
    enabled: false
    match: { event_id: "4625" }
    threshold: 2
    group_by: user
    severity: error
    notify: [운영팀]
  - name: IP 대입
    enabled: false
    match: { event_id: "4771" }
    threshold: 2
    group_by: ip
    severity: error
    notify: [운영팀]
  - name: 새 서비스
    enabled: false
    match: { event_id: "7045" }
    threshold: 1
    group_by: host
    severity: warning
    notify: [운영팀]
  - name: 새 출발지
    kind: new_terms
    enabled: false
    match: { event_id: "4624" }
    fields: [account, ip]
    severity: warning
    notify: [운영팀]
"""


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _ev(host, event_id, user, ip=None):
    data = {"TargetUserName": user, **({"IpAddress": ip} if ip else {})}
    return {"date": datetime.now(UTC).isoformat(), "EventID": event_id, "Channel": "Security", "Computer": host,
            "agent_host": host, "log_source": "winevtlog", "Message": f"{event_id}", "EventData": data}


def _rule(name):
    from app.alerts.engine import engine

    return next(r for r in engine.config.rules if r.name == name)


def _fire(client, name):
    from app.alerts.engine import engine

    client.portal.call(engine.evaluate, _rule(name), datetime.now(UTC))


def _alert(rule, key):
    rows = sql("SELECT id, entity_hosts, entity_accounts, entity_ips FROM alerts WHERE rule = %s AND group_key = %s"
               " ORDER BY id DESC LIMIT 1", (rule, key))
    assert rows, (rule, key)
    return rows[0]


def _viewer(admin, app, username, group):
    from fastapi.testclient import TestClient

    temp = admin.post("/api/users", json={"username": username, "role": "viewer"}, headers=CSRF).json()
    assert admin.post("/api/user-groups", json={**group, "member_ids": [temp["user"]["id"]]}, headers=CSRF).status_code == 200
    client = TestClient(app)
    client.post("/api/auth/login", json={"username": username, "password": temp["temp_password"]}, headers=CSRF)
    client.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD}, headers=CSRF)
    return client


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app import accesslog
    from app.alerts.engine import engine
    from app.main import app

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    try:
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            medic = _viewer(admin, app, "medic", {"name": "의료", "scope_hosts": ["MED-*"]})
            dba = _viewer(admin, app, "dba", {"name": "DB", "scope_categories": ["mssql"]})
            accesslog.forget()
            yield {"admin": admin, "medic": medic, "dba": dba}
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


# ------------------------------------------------------------------ 채우는 규칙 (SQL 함수)

LONG = "x" * 257
CASES = [
    # (payload, 종류, observed, 기대)
    ({"kind": "count", "group_by": "host", "group_key": "PC-1"}, "host", None, ["PC-1"]),
    ({"kind": "count", "group_by": "host", "group_key": "PC-1"}, "account", None, []),
    # 사용자로 묶은 대상은 표기 통일 열쇠로, 표본 로그의 PC 도 (세지 못했을 때 — 옛 알림)
    ({"kind": "count", "group_by": "user", "group_key": "HOSP\\Kim", "samples": [{"host": "PC-2"}, {"host": "PC-1"}]},
     "account", None, ["kim"]),
    ({"kind": "count", "group_by": "user", "group_key": "HOSP\\Kim", "samples": [{"host": "PC-2"}, {"host": "PC-1"}]},
     "host", None, ["PC-1", "PC-2"]),
    ({"kind": "count", "group_by": "account", "group_key": "kim"}, "account", None, ["kim"]),
    ({"kind": "count", "group_by": "ip", "group_key": "10.0.0.5"}, "ip", None, ["10.0.0.5"]),
    # 센 값이 있으면 표본은 보지 않는다. 대상 값이 앞, 나머지는 글자 순
    ({"kind": "count", "group_by": "ip", "group_key": "10.0.0.5", "samples": [{"host": "PC-1"}]}, "host", ["PC-9", "PC-3"],
     ["PC-3", "PC-9"]),
    ({"kind": "count", "group_by": "host", "group_key": "PC-5"}, "host", ["PC-1", "PC-5"], ["PC-5", "PC-1"]),
    # 10개를 넘으면 그 종류의 센 값은 넣지 않는다 — 대상 값은 남는다
    ({"kind": "count", "group_by": "host", "group_key": "PC-1"}, "host", [f"H{i:02}" for i in range(11)], ["PC-1"]),
    ({"kind": "count", "group_by": "host", "group_key": "PC-1"}, "host", [f"H{i:02}" for i in range(10)],
     ["PC-1", *[f"H{i:02}" for i in range(10)]]),
    # 다른 묶음 기준(분류 등)은 대상 이름이 개체가 아니다
    ({"kind": "count", "group_by": "category", "group_key": "security"}, "host", None, []),
    ({"kind": "count", "group_by": "f.EventData.TargetUserName", "group_key": "kim"}, "account", None, []),
    # 끊김 규칙
    ({"kind": "agent_silent", "group_by": "host", "group_key": "PC-7"}, "host", None, ["PC-7"]),
    ({"kind": "stream_silent", "group_key": "PC-8 · Security", "stream": {"host": "PC-8"}}, "host", None, ["PC-8"]),
    # 처음 보는 값: 알림의 PC·조합의 값, 몰려온 묶음의 값(10개까지)
    ({"kind": "new_terms", "group_key": "x", "terms": {"fields": ["user", "ip"], "values": ["kim@hosp.local", "1.2.3.4"],
                                                      "host": "PC-3"}}, "account", None, ["kim"]),
    ({"kind": "new_terms", "group_key": "x", "terms": {"fields": ["user", "ip"], "values": ["kim@hosp.local", "1.2.3.4"],
                                                      "host": "PC-3"}}, "ip", None, ["1.2.3.4"]),
    ({"kind": "new_terms", "group_key": "x", "terms": {"fields": ["user", "ip"], "values": ["kim", "1.2.3.4"],
                                                      "host": "PC-3"}}, "host", None, ["PC-3"]),
    ({"kind": "new_terms", "terms": {"fields": ["user"], "items": [{"values": ["A"]}, {"values": ["b"]}, {"values": 5}]}},
     "account", None, ["a", "b"]),
    ({"kind": "new_terms", "terms": {"fields": ["user"], "items": [{"values": [f"u{i}"]} for i in range(11)]}},
     "account", None, []),
    # 빈 값·긴 값(GIN 색인 한 줄 상한)·깨진 모양은 넘긴다
    ({"kind": "count", "group_by": "host", "group_key": ""}, "host", None, []),
    ({"kind": "count", "group_by": "host", "group_key": LONG}, "host", None, []),
    ({"kind": "count", "group_by": "host", "group_key": "PC-1"}, "host", ["", LONG], ["PC-1"]),
    ({"terms": "bad", "samples": "bad", "stream": [1]}, "host", None, []),
    ({"terms": {"fields": "user", "values": "kim", "items": {"a": 1}}, "samples": [1, "x", None]}, "account", None, []),
    ({"kind": "config", "group_key": "admin", "samples": []}, "host", None, []),
]


@pytest.mark.parametrize(("payload", "kind", "observed", "expected"), CASES)
def test_entity_function_table(ctx, payload, kind, observed, expected):
    from app.repository import _json

    [(got,)] = sql("SELECT wlm_alert_entities(%s::jsonb, %s, %s::text[])", (_json(payload), kind, observed))
    assert got == expected


def test_entity_limit_matches_repository(ctx):
    """서버가 세는 상한(ENTITY_MAX + 1 개까지 가져옴)과 SQL 함수의 상한이 같다."""
    from app.repository import ENTITY_MAX

    payload = '{"kind": "count", "group_by": "none", "group_key": ""}'
    ok = [f"H{i}" for i in range(ENTITY_MAX)]
    assert sql("SELECT wlm_alert_entities(%s::jsonb, 'host', %s)", (payload, ok))[0][0] == sorted(ok)
    assert sql("SELECT wlm_alert_entities(%s::jsonb, 'host', %s)", (payload, [*ok, "H99"]))[0][0] == []


# ------------------------------------------------------------------ 엔진이 채운다

def test_engine_attaches_entities_from_matching_logs(ctx):
    admin = ctx["admin"]
    events = [_ev("PC-1", 4625, "HOSP\\Kim", "10.0.0.5"), _ev("PC-1", 4625, "kim@hosp.local", "10.0.0.5"),
              _ev("PC-2", 4625, "HOSP\\Kim", "10.0.0.6")]
    assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == 3
    _fire(admin, "로그온 실패 급증")
    _, hosts, accounts, ips = _alert("로그온 실패 급증", "PC-1")
    assert (hosts, accounts, ips) == (["PC-1"], ["kim"], ["10.0.0.5"])
    _fire(admin, "계정 대입")
    _, hosts, accounts, ips = _alert("계정 대입", "HOSP\\Kim")
    # 묶음 기준이 표기 그대로(user:)라 kim@hosp.local 은 다른 대상이지만 계정 열쇠는 같다
    assert (hosts, accounts, ips) == (["PC-1", "PC-2"], ["kim"], ["10.0.0.5", "10.0.0.6"])


def test_too_many_hosts_are_not_attached(ctx):
    """한 IP 가 PC 11대를 두드렸다 — PC 는 넣지 않는다(모든 PC 의 관련 알림이 되지 않게), IP 는 대상이라 남는다."""
    admin = ctx["admin"]
    events = [_ev(f"SPRAY-{i:02}", 4771, f"u{i}", "10.9.9.9") for i in range(11)]
    assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == 11
    _fire(admin, "IP 대입")
    _, hosts, accounts, ips = _alert("IP 대입", "10.9.9.9")
    assert (hosts, accounts, ips) == ([], [], ["10.9.9.9"])


def test_timeout_falls_back_to_sample_hosts(ctx, monkeypatch):
    """개체를 세다 시간이 넘으면 알림은 그대로 내고 표본 로그의 PC 만 붙인다."""
    from app import db, repository

    async def slow(f):
        raise db.QueryTimeout("시간 초과")

    monkeypatch.setattr(repository, "alert_entities", slow)
    admin = ctx["admin"]
    assert admin.post("/api/ingest", json=[_ev("SLOW-1", 4625, "lee", "10.1.1.1")] * 2, headers=KEY).json()["accepted"] == 2
    _fire(admin, "로그온 실패 급증")
    _, hosts, accounts, ips = _alert("로그온 실패 급증", "SLOW-1")
    assert (hosts, accounts, ips) == (["SLOW-1"], [], [])


# ------------------------------------------------------------------ 관련 알림

def _shift(alert_id, delta):
    sql("UPDATE alerts SET fired_at = fired_at + %s WHERE id = %s", (delta, alert_id))


def test_related_alerts_share_entity_within_an_hour(ctx):
    admin = ctx["admin"]
    host_alert = _alert("로그온 실패 급증", "PC-1")[0]
    user_alert = _alert("계정 대입", "HOSP\\Kim")[0]
    spray = _alert("IP 대입", "10.9.9.9")[0]
    r = admin.get(f"/api/alerts/{host_alert}/related")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["entities"] == {"host": ["PC-1"], "account": ["kim"], "ip": ["10.0.0.5"]} and body["window_sec"] == 3600
    items = {i["id"]: i for i in body["items"]}
    assert user_alert in items and spray not in items and host_alert not in items
    assert (items[user_alert]["shared_host"], items[user_alert]["shared_account"], items[user_alert]["shared_ip"]) == \
        (["PC-1"], ["kim"], ["10.0.0.5"])
    # 경계: 59분 앞은 관련, 61분 앞은 아니다
    _shift(user_alert, -timedelta(minutes=59))
    assert user_alert in {i["id"] for i in admin.get(f"/api/alerts/{host_alert}/related").json()["items"]}
    _shift(user_alert, -timedelta(minutes=2))
    assert user_alert not in {i["id"] for i in admin.get(f"/api/alerts/{host_alert}/related").json()["items"]}
    _shift(user_alert, timedelta(minutes=61))
    assert admin.get("/api/alerts/999999/related").status_code == 404


def test_alert_without_entities_has_no_related(ctx):
    admin = ctx["admin"]
    [(alert_id,)] = sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload)"
                        " VALUES (now(), '로그온 실패 급증', 'warning', '', 1, '{}') RETURNING id")
    body = admin.get(f"/api/alerts/{alert_id}/related").json()
    assert body["entities"] == {"host": [], "account": [], "ip": []} and body["items"] == []


def test_related_alerts_follow_scope(ctx):
    """조회 범위(MED-*)의 사용자: 범위 밖 알림의 관련 알림은 404, 범위 안 알림의 관련 알림에 범위 밖 PC 의 알림이 섞이지 않는다."""
    admin, medic = ctx["admin"], ctx["medic"]
    events = [_ev("MED-1", 4625, "kim", "10.0.0.5")] * 2
    assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == 2
    _fire(admin, "로그온 실패 급증")
    med = _alert("로그온 실패 급증", "MED-1")[0]
    pc1 = _alert("로그온 실패 급증", "PC-1")[0]
    assert pc1 in {i["id"] for i in admin.get(f"/api/alerts/{med}/related").json()["items"]}   # 같은 계정·IP
    r = medic.get(f"/api/alerts/{med}/related")
    assert r.status_code == 200, r.text
    assert pc1 not in {i["id"] for i in r.json()["items"]}
    assert medic.get(f"/api/alerts/{pc1}/related").status_code == 404


# ------------------------------------------------------------------ 개체 페이지

def test_entity_page_unifies_account_spelling(ctx):
    from app import accesslog

    accesslog.forget()
    admin = ctx["admin"]
    r = admin.get(f"/api/entities/user/{quote('HOSP\\KIM', safe='')}", params={"since": "1d"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value"] == "kim" and body["query"] == "account:kim" and body["agent"] is None
    rules = {a["rule"] for a in body["alerts"]}
    assert {"로그온 실패 급증", "계정 대입"} <= rules and "IP 대입" not in rules
    [(target, detail)] = sql("SELECT target, detail FROM audit_log WHERE action = 'entity.view'")
    assert target == "user:kim" and detail["since"] == "1d"


def test_entity_page_host_and_ip(ctx):
    admin = ctx["admin"]
    body = admin.get("/api/entities/host/PC-1").json()
    assert body["query"] == "host:PC-1" and body["agent"]["host"] == "PC-1" and body["agent"]["status"] == "online"
    assert {a["group_key"] for a in body["alerts"]} >= {"PC-1", "HOSP\\Kim"}
    body = admin.get("/api/entities/ip/10.9.9.9").json()
    assert [a["rule"] for a in body["alerts"]] == ["IP 대입"]
    # 값에 따옴표가 필요하면 검색 문장에서 한 값으로
    assert admin.get(f"/api/entities/host/{quote('A B*', safe='')}").json()["query"] == 'host:"A B*"'


def test_entity_page_rejects_bad_input(ctx):
    admin = ctx["admin"]
    assert admin.get("/api/entities/pc/PC-1").status_code == 404
    assert admin.get(f"/api/entities/host/{'x' * 257}").status_code == 400
    assert admin.get(f"/api/entities/host/{quote(chr(7) + 'BAD', safe='')}").status_code == 400
    assert admin.get("/api/entities/host/PC-1", params={"since": "어제"}).status_code == 400


def test_entity_page_follows_scope(ctx):
    medic = ctx["medic"]
    body = medic.get("/api/entities/user/kim").json()
    assert {a["group_key"] for a in body["alerts"]} == {"MED-1"}       # 범위 밖 PC 의 kim 알림은 안 보인다
    assert medic.get("/api/entities/host/PC-1").json()["agent"] is None   # 범위 밖 PC 의 수신 정보도
    assert medic.get("/api/entities/host/MED-1").json()["agent"]["host"] == "MED-1"


# ------------------------------------------------------------------ 검토 보완 (1차)

def _terms_alert(client, values, host, sightings):
    """처음 보는 값 알림 하나 — 엔진처럼 본 PC(sightings)를 넘긴다."""
    from app.alerts.engine import engine
    from app.alerts.message import AlertMessage

    now = datetime.now(UTC)
    message = AlertMessage(rule="새 출발지", severity="warning", kind="new_terms", group_by="none", group_key=" · ".join(values),
                           event_count=1, threshold=1, window_sec=0, fired_at=now,
                           terms={"fields": ["account", "ip"], "values": values, "host": host, "history_days": 30})
    return client.portal.call(engine.fire_rule, _rule("새 출발지"), message, None, [(h, now) for h in sightings])


def test_scoped_user_does_not_see_other_pcs_of_a_new_terms_alert(ctx):
    """처음 보는 값 알림은 본 PC 를 모두 개체로 둔다 — MED-* 사용자에게는 MED 의 것만, 범위 밖 PC 로 찾거나 잇지 않는다 (검토에서 재현)."""
    admin, medic = ctx["admin"], ctx["medic"]
    base = _terms_alert(admin, ["roam", "10.50.0.1"], "MED-1", ["MED-1", "HR-DB-01"])
    other = _terms_alert(admin, ["other", "10.50.0.2"], "MED-2", ["MED-2", "HR-DB-01"])   # 범위 밖 PC 로만 이어짐
    assert sql("SELECT entity_hosts FROM alerts WHERE id = %s", (base,))[0][0] == ["MED-1", "HR-DB-01"]
    assert admin.get(f"/api/alerts/{base}").json()["entity_hosts"] == ["MED-1", "HR-DB-01"]
    assert other in {i["id"] for i in admin.get(f"/api/alerts/{base}/related").json()["items"]}
    assert medic.get(f"/api/alerts/{base}").json()["entity_hosts"] == ["MED-1"]
    rows = {a["id"]: a for a in medic.get("/api/alerts").json()["items"]}
    assert rows[base]["entity_hosts"] == ["MED-1"] and rows[other]["entity_hosts"] == ["MED-2"]
    related = medic.get(f"/api/alerts/{base}/related").json()
    assert related["entities"]["host"] == ["MED-1"] and other not in {i["id"] for i in related["items"]}
    assert medic.get("/api/entities/host/HR-DB-01").json()["alerts"] == []
    assert {a["id"] for a in medic.get("/api/entities/host/MED-1").json()["alerts"]} >= {base}


def test_category_scope_does_not_reveal_pc_status(ctx):
    """분류로만 정한 범위(mssql)는 모든 PC 이름에 맞는다 — 그 분류의 로그가 없는 PC 의 수신 정보는 주지 않는다(수집 PC 목록과 같게, 검토에서 재현)."""
    admin, dba = ctx["admin"], ctx["dba"]
    sqlev = {"date": datetime.now(UTC).isoformat(), "EventID": 18456, "Channel": "Application", "ProviderName": "MSSQLSERVER",
             "Computer": "SQL-01", "agent_host": "SQL-01", "log_source": "winevtlog", "Message": "Login failed"}
    assert admin.post("/api/ingest", json=[sqlev], headers=KEY).json()["accepted"] == 1
    assert dba.get("/api/entities/host/PC-1").json()["agent"] is None            # 보안 로그만 있는 PC
    assert admin.get("/api/entities/host/PC-1").json()["agent"]["host"] == "PC-1"
    assert dba.get("/api/entities/host/SQL-01").json()["agent"]["host"] == "SQL-01"
    assert dba.get("/api/entities/host/NO-SUCH").json()["agent"] is None


def test_machine_accounts_do_not_link_alerts(ctx):
    """업데이트가 여러 PC 에 서비스를 깔면 7045 계정이 모두 LocalSystem — 계정으로 서로 잇지 않는다 (검토에서 재현)."""
    admin = ctx["admin"]
    events = [{"date": datetime.now(UTC).isoformat(), "EventID": 7045, "Channel": "System", "Computer": h, "agent_host": h,
               "log_source": "winevtlog", "Message": "service", "EventData": {"ServiceName": "Upd", "AccountName": "LocalSystem"}}
              for h in ("SVC-1", "SVC-2")]
    assert admin.post("/api/ingest", json=events, headers=KEY).json()["accepted"] == 2
    assert sql("SELECT DISTINCT username FROM events WHERE host = 'SVC-1'") == [("LocalSystem",)]
    _fire(admin, "새 서비스")
    one, hosts, accounts, _ = _alert("새 서비스", "SVC-1")
    assert (hosts, accounts) == (["SVC-1"], [])
    # 옛 알림·대상 이름에서 온 기본 계정(NT AUTHORITY\SYSTEM 으로 묶음)도 잇지 않는다
    ids = [sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload, entity_accounts)"
               " VALUES (now(), '계정 대입', 'error', %s, 1, '{}', '{system}') RETURNING id", (f"NT AUTHORITY\\SYSTEM {i}",))[0][0]
           for i in range(2)]
    body = admin.get(f"/api/alerts/{ids[0]}/related").json()
    assert body["entities"]["account"] == [] and ids[1] not in {i["id"] for i in body["items"]}
    assert one not in {i["id"] for i in admin.get(f"/api/alerts/{_alert('새 서비스', 'SVC-2')[0]}/related").json()["items"]}
