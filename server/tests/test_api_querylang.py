"""검색 문장 통합 시험 (B-01, ADR-033): 케이스 표의 고정 이벤트를 실제 DB 에 넣고 SQL 결과가 표·매처와 같은지,
API(검색·해석·오류 위치·조회 범위)·대시보드 검증·알림 규칙(match.query)까지.

SQL ≡ Python 매처 ≡ (표) ≡ JS 매처(node 시험)의 고리를 여기서 닫는다: NULL 제외, ILIKE 대소문자, raw #>> 글자 표현.
"""

from __future__ import annotations

import json
import os
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
CASES = json.loads((Path(__file__).resolve().parent / "querylang_cases.json").read_text(encoding="utf-8"))
T0 = datetime(2001, 1, 1, tzinfo=UTC)          # 다른 시험의 기간과 섞이지 않게 아주 옛 시각
T1 = T0 + timedelta(hours=1)
PASSWORD = "Query#Member2026"


class Params(dict):
    def getlist(self, key):
        value = self.get(key)
        return [] if value is None else [value]

    def multi_items(self):
        return list(self.items())


def _login(app, name, temp):
    from fastapi.testclient import TestClient

    c = TestClient(app)
    c.post("/api/auth/login", json={"username": name, "password": temp}, headers=CSRF)
    c.post("/api/auth/password", json={"current_password": temp, "new_password": PASSWORD}, headers=CSRF)
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

    from app import repository
    from app.alerts.engine import engine
    from app.config import settings
    from app.main import app
    from app.normalizers.base import Event

    # 이 모듈이 저장하는 알림 규칙은 끝나면 되돌린다 (규칙 파일은 시험 세션 전체가 같이 쓴다)
    rules_file = Path(settings.alerts_file)
    saved_rules = rules_file.read_text(encoding="utf-8") if rules_file.exists() else None
    with TestClient(app) as admin:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        events = [Event(ts=T0 + timedelta(seconds=fx["id"]), host=fx["host"], source=fx["source"], level=fx["level"],
                        message=fx["message"], raw={**fx["raw"], "_fx": fx["id"]}, channel=fx["channel"],
                        provider=fx["provider"], event_id=fx["event_id"], category=fx["category"],
                        username=fx["username"], src_ip=fx["src_ip"])
                  for fx in CASES["fixtures"]]
        admin.portal.call(repository.insert_batch, events, [], None)
        users = {}
        for name in ("viewer", "scoped"):
            temp = admin.post("/api/users", json={"username": name, "role": "viewer"}, headers=CSRF).json()
            users[name] = (_login(app, name, temp["temp_password"]), temp["user"]["id"])
        group = {"name": "보안관제", "scope_categories": ["security"], "member_ids": [users["scoped"][1]]}
        assert admin.post("/api/user-groups", json=group, headers=CSRF).status_code == 200
        with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
            fx_of = dict(conn.execute("SELECT id, (raw->>'_fx')::int FROM events WHERE raw ? '_fx'").fetchall())
        try:
            yield {"admin": admin, "viewer": users["viewer"][0], "scoped": users["scoped"][0], "fx_of": fx_of}
        finally:
            if saved_rules is None:
                rules_file.unlink(missing_ok=True)
            else:
                rules_file.write_text(saved_rules, encoding="utf-8")
            engine.reload()


def _sql_ids(ctx, params: dict) -> list[int]:
    from app import repository
    from app.filters import EventFilter

    f = replace(EventFilter.from_params(Params(params), default_since=None), since=T0, until=T1)
    where, args = repository.where_clause(f)
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
        query = psycopg.sql.SQL("SELECT (raw->>'_fx')::int FROM events WHERE {} AND raw ? '_fx' ORDER BY 1").format(where)
        return [r[0] for r in conn.execute(query, args).fetchall()]


def _matcher_ids(params: dict) -> list[int]:
    from app.filters import EventFilter

    f = EventFilter.from_params(Params(params), default_since=None)
    return [fx["id"] for fx in CASES["fixtures"] if f.matches(fx)]


@pytest.mark.parametrize("case", CASES["match"], ids=[c["name"] for c in CASES["match"]])
def test_sql_gives_the_table_result(ctx, case):
    assert _sql_ids(ctx, case["params"]) == case["ids"]


def _random_sentences(n: int) -> list[str]:
    """고정 이벤트의 값 어휘로 만든 문장들 (포함·제외·여러 값·따옴표·대소문자 변형 섞음)."""
    from app.querylang import Term, format_query

    fx = CASES["fixtures"]
    pick = random.Random(1)
    columns = {"host": "host", "channel": "channel", "provider": "provider", "source": "source", "user": "username",
               "ip": "src_ip"}
    vocab = {key: sorted({f[col] for f in fx if f[col] is not None} | {"NOPE"}) for key, col in columns.items()}
    vocab["user"] += ["SVC_BACKUP", "Svc_Backup"]
    vocab["category"] = sorted({f["category"] for f in fx})
    vocab["level"] = [1, 2, 3, 4, 5]
    vocab["event_id"] = sorted({f["event_id"] for f in fx if f["event_id"] is not None} | {9999})
    words = sorted({w for f in fx if f["message"] for w in f["message"].split()
                    if not any(c in w for c in '"“”*|()\'!') and w not in ("-", "/")})
    words += ["TIMEOUT", "İSTANBUL", "οδοσ", "50%", "_off", "\\\\srv"]
    paths = {("EventID",): ["4625", "4624", "4740", "2"], ("Flag",): ["true", "false"], ("StringInserts", "5"): ["user77", "e"],
             ("EventData", "LogonType"): ["10", "3"], ("EventData", "TargetUserName"): ["svc_backup", "Svc_Backup"],
             ("Arr",): ['["x", "y"]', "x"], ("N",): ["null"], ("log",): ["GET /"], ("StringInserts", "11"): ["sa"]}
    out = []
    for _ in range(n):
        terms = []
        for _ in range(pick.randint(1, 4)):
            neg = pick.random() < 0.35
            kind = pick.random()
            if kind < 0.35:
                count = 1 if pick.random() < 0.7 else pick.randint(2, 3)
                terms.append(Term("msg", tuple(pick.sample(words, count)), neg))
            elif kind < 0.5:
                path = pick.choice(sorted(paths))
                terms.append(Term("f", tuple(pick.sample(paths[path], min(len(paths[path]), pick.randint(1, 2)))), neg, path))
            else:
                key = pick.choice(sorted(vocab))
                terms.append(Term(key, tuple(pick.sample(vocab[key], min(len(vocab[key]), pick.randint(1, 3)))), neg))
        out.append(format_query(terms))
    return out


def test_random_sentences_sql_equals_matcher(ctx):
    for text in _random_sentences(300):
        assert _sql_ids(ctx, {"query": text}) == _matcher_ids({"query": text}), text


def test_search_api_same_result_as_legacy_params(ctx):
    """URL 공유: 같은 문장·같은 (고정) 구간이면 누가 열어도 같은 결과. 옛 파라미터와도 같다."""
    window = {"since": T0.isoformat(), "until": T1.isoformat(), "limit": 100}

    def ids(client, params):
        r = client.get("/api/events", params={**window, **params})
        assert r.status_code == 200, r.text
        return sorted(ctx["fx_of"][e["id"]] for e in r.json()["items"])

    for client in (ctx["admin"], ctx["viewer"]):
        assert ids(client, {"query": "host:DC-01 event_id:4625"}) == ids(client, {"host": "DC-01", "event_id": "4625"}) == [1, 2]
        assert ids(client, {"query": 'msg:"Failed password","Invalid user"'}) == ids(client, {"q": "Failed password|Invalid user"})
        assert ids(client, {"query": "-user:svc_backup", "category": "security"}) == [2, 10, 15, 16]
    count = ctx["admin"].get("/api/stats/count", params={**window, "query": "level:오류,심각"}).json()
    assert count["current"] == 4
    top = ctx["admin"].get("/api/stats/top", params={**window, "field": "host", "query": "-host:DC-01 category:security"}).json()
    assert [r["value"] for r in top["items"]] == ["DC-02", "WIN-CI", "WIN-CI2"]
    # 접속기록: 검색 문장 원문이 그대로 남는다 (ISMS 2.9.4)
    audit = ctx["admin"].get("/api/audit", params={"since": "1h", "action": "events.search"}, headers=CSRF).json()["items"]
    assert any(a["detail"]["query"].get("query") == "-user:svc_backup" for a in audit)


def test_bad_sentence_is_400_with_position(ctx):
    r = ctx["admin"].get("/api/events", params={"query": "event_id:4625 hots:DC-01"})
    assert r.status_code == 400
    body = r.json()
    assert body["detail"].startswith("검색 문장 15번째 글자 'hots':")
    assert body["query_error"] == {"param": "query", "code": "unknown_key", "start": 14, "end": 18,
                                   "message": "알 수 없는 조건 'hots' 입니다. 'host' 를 찾으셨나요? 글자 그대로 찾으려면 따옴표로 감싸세요."}
    # 같은 이름을 두 번(빈 값 포함) 보내면 거절 — 실행한 문장과 접속기록이 어긋나지 않게
    twice = ctx["admin"].get("/api/events?query=user%3Aadmin&query=&limit=5")
    assert twice.status_code == 400 and "한 번만" in twice.json()["detail"]
    # 옛 파라미터 오류는 지금처럼 문자열만
    old = ctx["admin"].get("/api/events", params={"level": "x"})
    assert old.status_code == 400 and "query_error" not in old.json()
    assert ctx["admin"].get("/api/live", params={"query": "host:"}).status_code == 400


def test_parse_endpoint(ctx):
    ok = ctx["viewer"].get("/api/search/parse", params={"query": "Host:A  level:1,Error -\"잘못된 암호\""}).json()
    assert ok["ok"] and ok["canonical"] == 'host:A level:심각,오류 -"잘못된 암호"' and not ok["never"]
    assert [t["key"] for t in ok["terms"]] == ["host", "level", "msg"]
    assert ctx["viewer"].get("/api/search/parse", params={"query": "host:A host:B"}).json()["never"] is True
    bad = ctx["viewer"].get("/api/search/parse", params={"query": "level:7"})
    assert bad.status_code == 400 and bad.json()["query_error"]["code"] == "bad_level"
    assert ctx["viewer"].get("/api/search/parse").json()["terms"] == []
    # 경로가 비는 f. 파라미터(f..)는 한도에 세지 않는다 — 검색 API 와 같은 셈 (예전에는 여기서만 500)
    ten = " ".join(f"f.k{i}:1" for i in range(10))
    assert ctx["viewer"].get("/api/search/parse", params={"f..": "x", "query": ten}).status_code == 200
    over = ctx["viewer"].get("/api/search/parse", params={"f.a": "x", "query": ten})
    assert over.status_code == 400 and over.json()["query_error"]["code"] == "too_many_fields"


def test_scoped_user_cannot_widen_with_a_sentence(ctx):
    window = {"since": T0.isoformat(), "until": T1.isoformat()}
    scoped = ctx["scoped"]
    assert scoped.get("/api/stats/count", params={**window, "query": "-category:security"}).json()["current"] == 0
    assert scoped.get("/api/stats/count", params={**window, "query": "category:system"}).json()["current"] == 0
    assert scoped.get("/api/stats/count", params={**window, "query": "-user:svc_backup"}).json()["current"] == 4   # 2, 10, 15, 16


def test_dashboard_widget_sentence_is_checked(ctx):
    doc = {"title": "문장 시험", "widgets": [{"type": "stat", "title": "x", "query": {"level": "1", "query": "hots:x"}}]}
    r = ctx["admin"].put("/api/dashboards/querylang-test", json=doc, headers=CSRF)
    assert r.status_code == 422 and r.json()["detail"].startswith("widgets[0].query.query: 검색 문장 1번째 글자 'hots'")
    doc["widgets"][0]["query"]["query"] = '-user:svc_backup "잘못된 암호"'
    assert ctx["admin"].put("/api/dashboards/querylang-test", json=doc, headers=CSRF).status_code == 200
    doc["widgets"][0]["query"] = {"q": "a|b", "f.x": "1"}            # 옛 키는 그대로 저장
    assert ctx["admin"].put("/api/dashboards/querylang-test", json=doc, headers=CSRF).status_code == 200


def test_alert_rule_with_sentence(ctx):
    admin = ctx["admin"]
    rule = {"name": "문장 규칙", "kind": "count", "severity": "warning", "notify": ["운영팀"], "group_by": "host",
            "window_sec": 300, "threshold": 1, "cooldown_sec": 1800,
            "match": {"category": "security", "query": '-user:svc_backup "로그온" C:\\x\\y 한글'}}
    bad = admin.put("/api/alerts/rules", json={"rule": {**rule, "match": {"query": "level:>3"}}}, headers=CSRF)
    assert bad.status_code == 422 and "검색 문장 7번째 글자 '>'" in bad.json()["detail"]
    assert admin.put("/api/alerts/rules", json={"rule": rule}, headers=CSRF).status_code == 200
    saved = next(r for r in admin.get("/api/alerts/config", headers=CSRF).json()["rules"] if r["name"] == "문장 규칙")
    assert saved["match"]["query"] == '-user:svc_backup "로그온" C:\\x\\y 한글'   # 따옴표·역슬래시·한글이 YAML 왕복에 그대로
    from app.alerts.engine import engine

    engine.reload()
    loaded = next(r for r in engine.config.rules if r.name == "문장 규칙")
    assert loaded.categories == ("security",)
    # 미리보기도 같은 조건 (제외 포함). 고정 이벤트는 방금 받은 것(received_at)이라 '최근 1시간'에 든다
    def matched(query, client=admin):
        r = client.post("/api/alerts/rules/preview", json={"rule": {**rule, "match": {"query": query}}, "hours": 1},
                        headers=CSRF)
        assert r.status_code == 200, r.text
        return r.json()["matched"]

    assert matched("category:security") == 6 and matched("category:security -user:svc_backup") == 4


def test_rule_preview_respects_scope_and_sentence_categories_are_visible(ctx):
    """규칙 미리보기도 조회 범위 안의 이벤트만 센다. 분류가 match.query 에만 있는 규칙의 알림도 그 분류 범위 사용자에게 보인다."""
    from fastapi.testclient import TestClient

    from app.alerts.engine import engine
    from app.main import app

    admin = ctx["admin"]
    temp = admin.post("/api/users", json={"username": "sysman", "role": "viewer"}, headers=CSRF).json()
    group = {"name": "시스템관리", "permissions": ["alerts.manage"], "scope_categories": ["system"],
             "member_ids": [temp["user"]["id"]]}
    assert admin.post("/api/user-groups", json=group, headers=CSRF).status_code == 200
    sysman = _login(app, "sysman", temp["temp_password"])
    rule = {"name": "분류 문장 규칙", "kind": "count", "severity": "warning", "notify": ["운영팀"], "group_by": "host",
            "window_sec": 300, "threshold": 1, "cooldown_sec": 1800, "match": {"query": "category:security"}}
    preview = sysman.post("/api/alerts/rules/preview", json={"rule": rule, "hours": 1}, headers=CSRF)
    assert preview.status_code == 200 and preview.json()["matched"] == 0      # 보안 이벤트는 범위 밖
    assert admin.put("/api/alerts/rules", json={"rule": rule}, headers=CSRF).status_code == 200
    engine.reload()
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("INSERT INTO alerts (rule, severity, payload, group_key) VALUES ('분류 문장 규칙', 'warning', '{}', 'X')")

    def rules_seen(client: TestClient) -> set[str]:
        r = client.get("/api/alerts", params={"since": "1h"}, headers=CSRF)
        assert r.status_code == 200, r.text
        return {a["rule"] for a in r.json()["items"]}

    assert "분류 문장 규칙" in rules_seen(ctx["scoped"])       # 보안 범위 사용자
    assert "분류 문장 규칙" not in rules_seen(sysman)          # 시스템 범위 사용자


def test_rule_categories_from_sentence_and_list_query_rejected():
    from app.alerts.rules import ConfigError, parse

    base = {"name": "r", "notify": ["x"]}
    cfg = parse({"rules": [{**base, "match": {"query": "category:security,system -host:A"}},
                           {**base, "name": "r2", "match": {"category": "security,iis", "query": "category:iis,mssql"}},
                           {**base, "name": "r3", "match": {"query": "-category:security"}}]})
    assert [r.categories for r in cfg.rules] == [("security", "system"), ("iis",), ()]
    with pytest.raises(ConfigError, match="match.query 는 문자열"):
        parse({"rules": [{**base, "match": {"query": ["host:A", "host:B"]}}]})
    with pytest.raises(ConfigError, match="번째 글자"):
        parse({"rules": [{**base, "match": {"query": "hots:A"}}]})


def test_float_values_match_like_postgresql(ctx):
    """원본 필드의 실수: 검색(SQL #>>)이 0.00001 로 찾는 이벤트를 실시간 매처도 찾는다 (예전에는 1e-05 로 비교해 놓침).
    이 이벤트는 다른 시험의 구간·표시(_fx) 밖에 둔다."""
    from app import repository
    from app.filters import EventFilter
    from app.normalizers.base import Event

    raw = {"_float": 1, "ratio": 0.00001, "big": 1e21, "arr": [2.5e-05, 1], "neg": -0.0}
    at = T1 + timedelta(hours=1)
    ctx["admin"].portal.call(repository.insert_batch, [Event(ts=at, host="FLOAT-PC", source="winevtlog", level=4,
                                                             message="실수", raw=raw)], [], None)
    for query in ("f.ratio:0.00001", "f.big:1000000000000000000000", 'f.arr:"[0.000025, 1]"', "f.neg:0.0"):
        f = replace(EventFilter.from_params(Params({"query": query}), default_since=None), since=at, until=at + timedelta(seconds=1))
        where, args = repository.where_clause(f)
        with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
            sql_n = conn.execute(psycopg.sql.SQL("SELECT count(*) FROM events WHERE {} AND raw ? '_float'").format(where),
                                 args).fetchone()[0]
        assert sql_n == 1, query
        assert f.matches({"raw": raw}), query
