"""검색 문장 (B-01, ADR-033) 단위 시험 — 케이스 표 querylang_cases.json 하나로 파서·정규형·매처·SQL 모양을 본다.

같은 표를 web/js/querylang.js 도 (개발 PC 의 node 로) 돌린다: node --test 'server/tests/js/*.test.mjs'
DB 결과(SQL)와의 일치는 test_api_querylang.py.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.filters import EventFilter, FilterError, parse_query
from app.querylang import SYNC, QueryError, Term, format_query, parse_terms, walk_raw
from app.repository import where_clause

CASES = json.loads((Path(__file__).resolve().parent / "querylang_cases.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 10, 3, 5, 0, 0, tzinfo=UTC)


class Params(dict):
    def getlist(self, key):
        value = self.get(key)
        return [] if value is None else [value]

    def multi_items(self):
        return list(self.items())


def _filter(params: dict) -> EventFilter:
    return EventFilter.from_params(Params(params), default_since=None, now=NOW)


def _ids(params: dict) -> list[int]:
    f = _filter(params)
    return [fx["id"] for fx in CASES["fixtures"] if f.matches(fx)]


def _budget(case: dict) -> dict:
    return {"field_budget": case["budget"]} if "budget" in case else {}


def _strip(terms: list[dict]) -> list[dict]:
    return [{k: v for k, v in t.items() if k != "span"} for t in terms]


PARSE = CASES["parse"]


@pytest.mark.parametrize("case", PARSE, ids=[c["text"][:40] or "(빈 문장)" for c in PARSE])
def test_parse(case):
    if "error" in case:
        with pytest.raises(QueryError) as info:
            parse_terms(case["text"], **_budget(case))
        assert info.value.as_dict() == case["error"]
        return
    terms = parse_terms(case["text"], **_budget(case))
    assert [t.to_json() for t in terms] == case["terms"]
    # 정규형과 왕복: format(parse(x)) == canonical, parse(canonical) == parse(x)
    assert format_query(terms) == case["canonical"]
    assert _strip([t.to_json() for t in parse_terms(case["canonical"], **_budget(case))]) == _strip(case["terms"])


def test_table_is_big_enough_and_uses_every_error():
    ok = [c for c in PARSE if "terms" in c]
    errors = [c for c in PARSE if "error" in c]
    assert len(ok) >= 45 and len(errors) >= 40
    codes = set(SYNC["errors"]) - {"hint_suggest"}
    assert codes == {c["error"]["code"] for c in errors}
    assert len(CASES["match"]) >= 30 and len(CASES["same_sql"]) >= 10 and len(CASES["fold"]) >= 12
    assert len(CASES["edits"]) >= 12


@pytest.mark.parametrize("case", CASES["match"], ids=[c["name"] for c in CASES["match"]])
def test_match(case):
    assert _ids(case["params"]) == case["ids"]


@pytest.mark.parametrize("case", CASES["same_sql"], ids=[c["query"] for c in CASES["same_sql"]])
def test_same_meaning_same_sql(case):
    """같은 뜻이면 SQL 이 바이트 단위로 같다 → 같은 실행 계획 (기존 검색보다 느려지지 않음)."""
    assert where_clause(_filter(case["legacy"])) == where_clause(_filter({"query": case["query"]}))


@pytest.mark.parametrize("case", CASES["fold"], ids=[json.dumps(c["params"], ensure_ascii=False) for c in CASES["fold"]])
def test_folded_links_mean_the_same(case):
    """화면이 옛 링크 파라미터를 문장으로 접어도(web/js foldParams) 결과가 같다."""
    if case["same_sql"] is None:
        with pytest.raises(FilterError):
            _filter(case["params"])
        return
    folded = {**case["rest"], **({"query": case["query"]} if case["query"] else {})}
    assert _ids(folded) == _ids(case["params"])
    if case["same_sql"]:
        assert where_clause(_filter(folded)) == where_clause(_filter(case["params"]))


def test_query_error_text():
    with pytest.raises(QueryError) as info:
        parse_terms("event_id:4625 hots:WEB-01")
    assert str(info.value) == ("검색 문장 15번째 글자 'hots': 알 수 없는 조건 'hots' 입니다. 'host' 를 찾으셨나요?"
                               " 글자 그대로 찾으려면 따옴표로 감싸세요.")
    with pytest.raises(QueryError) as info:
        parse_terms("host:")
    assert str(info.value) == "검색 문장 5번째 글자 ':': 'host:' 뒤에 값이 없습니다."
    assert isinstance(info.value, FilterError)   # 기존 except FilterError 경로(400·ConfigError)로 잡힌다


def test_merged_intersection_and_never():
    f = _filter({"host": "A,B,C", "query": "host:C,B,X"})
    assert f.hosts == ["B", "C"] and not f.never   # 기존 순서 유지
    assert _filter({"query": "host:A host:B"}).never
    assert where_clause(_filter({"query": "host:A host:B", "level": "1"})) == where_clause(EventFilter(never=True))
    g = _filter({"query": "-host:A -host:B,A -msg:x -msg:x"})
    assert g.excludes == {"host": ["A", "B"]} and g.msg_not == ["x"]


def test_merged_does_not_touch_the_original():
    base = _filter({"host": "A,B", "f.x": "1"})
    merged = base.merged(parse_terms("host:A f.y:2 -host:C"))
    assert base.hosts == ["A", "B"] and base.fields == [(["x"], "1")] and base.excludes == {}
    assert merged.hosts == ["A"] and merged.fields == [(["x"], "1"), (["y"], "2")]


def test_query_param_rules():
    def repeated(*values):
        return type("P", (Params,), {"getlist": lambda self, k: list(values) if k == "query" else []})()

    with pytest.raises(FilterError, match="한 번만"):
        EventFilter.from_params(repeated("a", "b"), default_since=None)
    # 빈 값을 하나 더 붙여도 거절 — 실행한 문장과 접속기록(마지막 값만 남김)이 어긋나지 않게
    with pytest.raises(FilterError, match="한 번만"):
        EventFilter.from_params(repeated("user:admin", ""), default_since=None)
    # 원본 필드 조건은 URL 의 f. 와 합쳐 10개
    params = {f"f.u{i}": "1" for i in range(8)}
    with pytest.raises(QueryError) as info:
        _filter({**params, "query": "f.a:1 f.b:1 f.c:1"})
    assert info.value.code == "too_many_fields"
    assert parse_query("level:오류").levels == [2]


def test_unicode_digit_path_does_not_crash():
    """'²'.isdigit() 가 True 라서 예전에는 배열 위치로 int('²') 를 하다 터졌다."""
    assert walk_raw({"a": ["x", "y"]}, ["a", "²"]) is None
    f = _filter({"f.a.²": "x"})
    assert not f.matches({"raw": {"a": ["x"]}})


def test_term_equality_ignores_span():
    assert Term("host", ("A",), span=(0, 6)) == Term("host", ("A",), span=(3, 9))


def test_live_filter_matches_with_scope():
    from app.filters import Scope

    f = replace(_filter({"query": "-category:security"}), scopes=(Scope(categories=("security",)),))
    assert not f.matches({"category": "system", "host": "X"})   # 문장으로 범위를 넓힐 수 없다
    assert not f.matches({"category": "security", "host": "X"})


def test_raw_text_is_postgresql_text():
    """#>> 와 같은 글자: 실수는 지수 표기 없이(저장 때 repr 이 jsonb 숫자가 된다), 배열·객체는 ', ' · ': '."""
    from app.querylang import raw_text

    assert [raw_text(v) for v in (1e-05, 2.5e-05, 1e21, 1000.0, 1000, -0.0, True, None, "그대로")] == \
        ["0.00001", "0.000025", "1000000000000000000000", "1000.0", "1000", "0.0", "true", "null", "그대로"]
    assert raw_text([1e-05, "x", {"a": None}]) == '[0.00001, "x", {"a": null}]'
