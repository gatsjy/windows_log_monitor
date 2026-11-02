"""계정 표기 통일 (BACKLOG B-54, ADR-062) — DB 시험: SQL wlm_user_key 와 Python account_key 가 같다, 펼쳐져(inline) 색인을 쓴다,
있던 월 파티션의 색인을 뒤에서 만들어 붙인다, 탐지에서 -account: 를 막는다, group_by·상위 값·접속기록."""

from __future__ import annotations

import json
import os
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
CASES = json.loads((Path(__file__).resolve().parent / "querylang_cases.json").read_text(encoding="utf-8"))
T0 = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)


def sql(query, params=None):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


@pytest.fixture(scope="module")
def admin():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app import repository
    from app.main import app
    from app.normalizers.base import Event

    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        events = [Event(ts=T0 + timedelta(seconds=fx["id"]), host=fx["host"], source=fx["source"], level=fx["level"],
                        message=fx["message"], raw={**fx["raw"], "_afx": fx["id"]}, channel=fx["channel"], provider=fx["provider"],
                        event_id=fx["event_id"], category=fx["category"], username=fx["username"], src_ip=fx["src_ip"])
                  for fx in CASES["account_fixtures"]]
        c.portal.call(repository.insert_batch, events, [], None)
        yield c


def _sql_ids(params: dict) -> list[int]:
    from app import repository
    from app.filters import EventFilter

    f = EventFilter.from_params(params, default_since="2h")
    where, args = repository.where_clause(f)
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
        query = psycopg.sql.SQL("SELECT (raw->>'_afx')::int FROM events WHERE {} AND raw ? '_afx' ORDER BY 1").format(where)
        return [r[0] for r in conn.execute(query, args).fetchall()]


@pytest.mark.parametrize("case", CASES["account_match"], ids=[c["name"] for c in CASES["account_match"]])
def test_sql_gives_the_table_result(admin, case):
    assert _sql_ids(case["params"]) == case["ids"]


def test_sql_function_equals_python(admin):
    """SQL·Python·JS 세 곳이 한 글자도 같아야 같은 행을 찾는다 — 표의 표기 + 무작위 3,000개 (서로게이트 쌍·한글·제어 문자 없는 유니코드)."""
    from app.querylang import account_key

    pick = random.Random(62)
    pieces = ["HOSP", "hosp", ".local", "kim", "KIM", "\\", "\\", "@", "@", ".", "PC01", "$", "김", "İ", "Σ", "😀", " ", "x", "Ä", "ß"]
    names = [c["in"] for c in CASES["account_key"]]
    names += ["".join(pick.choice(pieces) for _ in range(pick.randint(0, 8))) for _ in range(3000)]
    rows = sql("SELECT n, wlm_user_key(x) FROM unnest(%s::text[]) WITH ORDINALITY AS t(x, n) ORDER BY n", (names,))
    assert [r[1] for r in rows] == [account_key(n) for n in names]
    assert sql("SELECT wlm_user_key(NULL)") == [(None,)]


def test_function_is_inlined_and_uses_the_index(admin):
    """표현식 하나라 펼쳐지고(줄마다 함수 호출 없음), username IS NOT NULL 을 함께 써서 부분 색인을 쓴다. 정의도 고정 — 뜻을 바꾸려면 새 이름."""
    from app import repository
    from app.filters import EventFilter

    [(volatile, strict, src)] = sql("SELECT provolatile, proisstrict, pg_get_functiondef(oid) FROM pg_proc WHERE proname = 'wlm_user_key'")
    assert (volatile, strict) == ("i", False) and "translate(" in src and "rtrim(u" in src
    where, args = repository.where_clause(EventFilter.from_params({"query": "account:kim"}, default_since="2h"))
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
        conn.execute("ANALYZE events")
        conn.execute("SET enable_seqscan = off")
        conn.execute("SET enable_bitmapscan = on")
        plan = "\n".join(r[0] for r in conn.execute(psycopg.sql.SQL("EXPLAIN (VERBOSE) SELECT id FROM events WHERE {}").format(where),
                                                     args).fetchall())
    assert "Index Scan using events_" in plan and "_ts_idx" in plan and "Seq Scan" not in plan, plan
    assert "wlm_user_key(" not in plan, plan    # 펼쳐짐 — 함수 호출이 아니라 식


def test_builder_attaches_indexes_on_old_partitions(admin):
    """업그레이드: 있던 파티션에는 색인이 없다(부모만 ON ONLY) → 서버가 뒤에서 CONCURRENTLY 로 만들어 붙이면 부모 색인이 유효해진다.
    시험은 부모 색인을 지웠다가 마이그레이션처럼 다시 만들어 '업그레이드 직후'를 만든다."""
    from app import partitions

    sql("DROP INDEX events_account_ts_idx")
    sql("CREATE INDEX events_account_ts_idx ON ONLY events (wlm_user_key(username), ts DESC) WHERE username IS NOT NULL")
    assert sql("SELECT 1 FROM pg_class WHERE relname = 'events_user_ts_idx'") == [(1,)]   # 그 전에는 예전 색인이 user: 를 받친다

    async def status():
        async with await partitions.db.connect_autocommit() as conn:
            return await partitions.account_index_status(conn)

    before = admin.portal.call(status)
    assert before["valid"] is False and before["attached"] == 0 and before["partitions"] >= 3
    from app import readiness

    item = {i.key: i for i in readiness.judge(admin.portal.call(readiness.collect))}["account_index"]
    assert item.status == "warn" and f"0/{before['partitions']}" in item.detail
    assert admin.portal.call(partitions.build_account_indexes) == before["partitions"]
    after = admin.portal.call(status)
    assert after == {"valid": True, "attached": before["partitions"], "partitions": before["partitions"], "missing": []}
    assert "account_index" not in {i.key for i in readiness.judge(admin.portal.call(readiness.collect))}
    assert admin.portal.call(partitions.build_account_indexes) == 0   # 다 붙어 있으면 카탈로그만 보고 끝
    assert _sql_ids({"query": "account:kim"}) == [101, 102, 103, 104, 105]
    # 다 붙으면 예전 username 색인을 지운다 — user: 도 계정 표기 색인으로 찾는다 (색인 둘이면 수집 쓰기가 10% 느렸다)
    assert sql("SELECT 1 FROM pg_class WHERE relname = 'events_user_ts_idx'") == []
    assert _sql_ids({"query": "user:KIM"}) == [102] and _sql_ids({"user": "HOSP\\kim"}) == [103]
    from app import repository
    from app.filters import EventFilter

    where, args = repository.where_clause(EventFilter.from_params({"query": "user:kim"}, default_since="2h"))
    with psycopg.connect(os.environ["WLM_DATABASE_URL"]) as conn:
        conn.execute("SET enable_seqscan = off")
        plan = "\n".join(r[0] for r in conn.execute(psycopg.sql.SQL("EXPLAIN SELECT id FROM events WHERE {}").format(where), args))
    assert "account_ts_idx" in plan and "Seq Scan" not in plan, plan


def test_rules_reject_account_exclusion(admin):
    """공격자가 정하는 이름(IIS cs-username·4625 TargetUserName·sshd)에도 표기 통일이 걸린다 — '-account:svc_backup' 이면 다른 표기로
    로그인을 시도해 규칙을 비켜 간다. 규칙·예외·규칙이 쓰는 저장한 검색 어디서든 막는다. 포함·group_by 는 괜찮다."""
    from app.alerts.rules import ConfigError, parse_text
    from app.filters import FilterError

    rule = "  - name: 계정 시험\n    kind: count\n    severity: warning\n    notify: [운영팀]\n    threshold: 1\n    window_sec: 300\n"
    with pytest.raises(ConfigError, match="-account:"):
        parse_text("rules:\n" + rule + "    match: {query: 'event_id:4625 -account:svc_backup'}\n")
    config = parse_text("rules:\n" + rule + "    group_by: account\n    match: {query: 'account:kim'}\n")
    [r] = config.rules
    assert r.event_filter().accounts == ["kim"]
    with pytest.raises(FilterError, match="-account:"):
        r.event_filter(saved="-account:svc_backup")
    with pytest.raises(FilterError, match="-account:"):
        r.event_filter(exceptions=["account:svc_backup"])


def test_group_by_account_counts_and_links(admin):
    from app.alerts.engine import _link_params, _with_group
    from app.alerts.rules import parse_text
    from app.filters import EventFilter

    [r] = parse_text("rules:\n  - name: 계정 묶음\n    kind: count\n    severity: warning\n    notify: [운영팀]\n    threshold: 1\n"
                     "    window_sec: 300\n    group_by: account\n    match: {query: 'event_id:4624'}\n").rules
    f = _with_group(EventFilter.from_params({"query": "event_id:4624"}, default_since="2h"), "account", "kim")
    assert f.accounts == ["kim"]
    params = _link_params(r, "kim", T0)
    assert params["query"] == "event_id:4624 account:kim" and "account" not in params   # 주소 파라미터가 아니라 문장으로
    assert _sql_ids({"query": params["query"]}) == [101, 102, 103, 104, 105]


def test_top_values_by_account_are_access_logged(admin):
    """계정 열쇠는 사용자 이름에서 만든 개인정보 — 상위 값·자동완성도 접속기록(ADR-042)."""
    from app import accesslog

    accesslog.forget()
    r = admin.get("/api/stats/top", params={"field": "account", "since": "2h", "limit": 5})
    assert r.status_code == 200, r.text
    top = {i["value"]: i["n"] for i in r.json()["items"]}
    assert top["kim"] == 5 and top["administrator"] == 2 and None not in top
    s = admin.get("/api/suggest", params={"key": "account", "prefix": "KI", "since": "2h"})
    assert s.status_code == 200 and [i["value"] for i in s.json()["items"]][:2] == ["kim", "kim@hosp"]
    targets = [t for (t,) in sql("SELECT target FROM audit_log WHERE action = 'events.stats' ORDER BY id")]
    assert "account" in targets and "suggest:account" in targets


def test_exception_on_account_is_refused(admin):
    r = admin.post("/api/alerts/exceptions/preview", json={"rule": "아무 규칙", "term": "account:svc_backup"}, headers=CSRF)
    assert r.status_code in (400, 404)   # 규칙이 없으면 404 가 먼저일 수 있다 — 아래 단위에서 문구를 본다
    from fastapi import HTTPException

    from app.routers.alerts import _exception_term

    with pytest.raises(HTTPException, match="-account:"):
        _exception_term("account:svc_backup")
