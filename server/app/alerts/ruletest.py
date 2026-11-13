"""로그 하나가 규칙에 걸리는지 조건마다 — 규칙 시험기(B-52, routers/alerts.test_rule)와 기본 규칙 표본 게이트(B-45,
tests/test_rule_samples.py)가 같이 쓴다. 따로 두면 화면의 '맞음'과 표본 시험의 '맞음'이 다른 뜻이 된다.

건수·기간은 보지 않는다(로그 하나). 대신 엔진이 세지 않는 경우를 조건으로 더한다:
- 묶음 기준 값이 없는(NULL) 로그는 엔진이 세지 않는다(repository.alert_candidates 의 _skip_missing_key).
- 처음 보는 값(B-47)은 볼 값이 빈 로그를 세지 않는다(repository.scan_new_terms 의 '' 제외).
"""

from __future__ import annotations

from typing import Any

from ..filters import EVENT_FIELD, EventFilter
from ..querylang import account_key, raw_field, raw_text
from .rules import Rule


def event_value(event: dict[str, Any], name: str) -> str | None:
    """엔진이 묶거나 보는 값과 같은 글자 (repository._field_expr) — f.<경로>는 원본 글자, account 는 계정 열쇠."""
    if name.startswith("f."):
        current = raw_field(event.get("raw"), [p for p in name[2:].split(".") if p])
        return None if current is None else raw_text(current)
    if name == "account":
        return account_key(event.get("username"))
    value = event.get(EVENT_FIELD.get(name, name))
    return None if value is None else str(value)


def _group_value(event: dict[str, Any], group_by: str) -> Any:
    """묶음 값 — 시험기 화면은 원래 형(정수 이벤트 ID 등)을 보인다."""
    if group_by.startswith("f.") or group_by == "account":
        return event_value(event, group_by)
    return event.get(EVENT_FIELD.get(group_by, group_by))


def checks(rule: Rule, f: EventFilter, event: dict[str, Any]) -> list[dict[str, Any]]:
    """{key, op, expected, actual, ok} — 모두 ok 면 엔진이 이 로그를 센다. f 는 엔진과 같은 조건(engine.rule_filter)."""
    out = f.explain(event)
    if rule.group_by != "none":
        value = _group_value(event, rule.group_by)
        out.append({"key": rule.group_by, "op": "group_key", "expected": [], "actual": value, "ok": value is not None})
    for name in rule.terms_fields:
        value = event_value(event, name)
        out.append({"key": name, "op": "term_field", "expected": [], "actual": value, "ok": value not in (None, "")})
    return out
