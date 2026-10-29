"""알림 기능 상태 판단 (ADR-045, B-34) — DB 없는 단위 시험."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.alerts import health

NOW = datetime(2026, 10, 29, 3, 0, tzinfo=UTC)


def _engine(**kw):
    return {"interval_sec": 30, "rule_timeout_sec": 20, "running": True, "standby": False,
            "progress_at": NOW - timedelta(seconds=5), "cycle_sec": 0.5, "current_rule": None, **kw}


def _dispatcher(**kw):
    return {"enabled": True, "running": True, "standby": False, "progress_at": NOW - timedelta(seconds=3), "targets": {}, **kw}


def _assess(engine=None, dispatcher=None, queue=(), gave_up=0, rules=(), used=frozenset()):
    return health.assess(engine or _engine(), dispatcher or _dispatcher(), list(queue), gave_up,
                         [dict(r) for r in rules], set(used), NOW)


def _codes(result):
    return [(p["level"], p["code"]) for p in result["problems"]]


def test_all_well():
    result = _assess()
    assert (result["status"], result["problems"]) == ("ok", [])


@pytest.mark.parametrize(("engine", "expected"), [
    (_engine(progress_at=NOW - timedelta(minutes=4), current_rule="느린 규칙"), [("bad", "evaluator_down")]),
    (_engine(running=False), [("bad", "evaluator_down")]),
    (_engine(progress_at=NOW - timedelta(hours=2), standby=True), []),   # 다른 서버가 평가 중
    (_engine(cycle_sec=45), [("warn", "evaluator_slow")]),
])
def test_evaluator(engine, expected):
    assert _codes(_assess(engine=engine)) == expected


def test_stall_allows_one_slow_rule():
    # 규칙 하나가 시간 상한(20초)까지 걸릴 수 있다 → 2×20+30 = 70초보다 짧은 120초가 기준
    assert health.engine_stall(30, 20) == timedelta(seconds=120)
    assert health.engine_stall(30, 90) == timedelta(seconds=210)
    assert "느린 규칙" in _assess(engine=_engine(progress_at=NOW - timedelta(minutes=4), current_rule="느린 규칙"))[
        "problems"][0]["text"]


def test_dispatcher_and_queue():
    queue = [{"notifier": "당직", "due": 12, "oldest_due_at": NOW - timedelta(minutes=12), "queued": 12, "sending": 0}]
    assert _codes(_assess(dispatcher=_dispatcher(running=False), queue=queue)) == [("bad", "dispatcher_down"), ("warn", "backlog")]
    assert _codes(_assess(dispatcher=_dispatcher(enabled=False))) == [("bad", "dispatcher_off")]
    assert _codes(_assess(queue=[{**queue[0], "oldest_due_at": NOW - timedelta(minutes=2)}])) == []


def test_failing_targets():
    t = {"당직": {"failing_since": NOW - timedelta(minutes=20), "last_error": "메일 전송 실패: 연결 거부"},
         "웹훅": {"failing_since": None}}
    result = _assess(dispatcher=_dispatcher(targets=t), used={"당직", "웹훅"})
    assert _codes(result) == [("warn", "target_failing")]
    assert "'당직'(으)로 20분째 보내지 못하고" in result["problems"][0]["text"]
    # 규칙이 쓰는 받는 곳이 모두 15분 넘게 실패 → 알림이 아무에게도 가지 않는다
    assert _codes(_assess(dispatcher=_dispatcher(targets=t), used={"당직"})) == [
        ("bad", "targets_all_down"), ("warn", "target_failing")]
    assert _codes(_assess(gave_up=3)) == [("warn", "gave_up")]


@pytest.mark.parametrize(("enabled", "run", "state"), [
    (False, None, "off"),
    (True, None, "never"),
    (True, {"last_run_at": NOW, "error": "쿼리가 20초를 넘겼습니다", "error_kind": "timeout"}, "timeout"),
    (True, {"last_run_at": NOW, "error": "relation does not exist", "error_kind": "error"}, "error"),
    (True, {"last_run_at": NOW, "truncated": True}, "truncated"),
    (True, {"last_run_at": NOW, "duration_ms": 12_000}, "slow"),
    (True, {"last_run_at": NOW - timedelta(minutes=5), "duration_ms": 30}, "stale"),
    (True, {"last_run_at": NOW, "duration_ms": 30}, "ok"),
])
def test_rule_state(enabled, run, state):
    assert health.rule_state(enabled, run, 20, 30, NOW) == state
    assert state in health.RULE_LABELS


def test_rule_problems_name_the_rules():
    rules = [{"name": "A", "enabled": True, "run": {"last_run_at": NOW, "error": "x", "error_kind": "error"}},
             {"name": "B", "enabled": True, "run": {"last_run_at": NOW, "truncated": True}},
             {"name": "C", "enabled": True, "run": {"last_run_at": NOW, "last_gap": {"at": NOW - timedelta(hours=1)}}},
             {"name": "D", "enabled": False, "run": None}]
    result = _assess(rules=rules)
    assert _codes(result) == [("warn", "rule_error"), ("warn", "rule_truncated"), ("warn", "rule_gap")]
    assert "'A'" in result["problems"][0]["text"] and result["status"] == "warn"


def test_public_view_has_no_names_or_messages():
    t = {"당직-비밀": {"failing_since": NOW - timedelta(minutes=20), "last_error": "smtp.secret.local 연결 거부"}}
    result = _assess(dispatcher=_dispatcher(targets=t), used={"당직-비밀"},
                     rules=[{"name": "비밀 규칙", "enabled": True, "run": {"last_run_at": NOW, "error": "x"}}])
    view = health.public_view(result, "0.5.0")
    text = str(view)
    assert view["status"] == "down" and "비밀" not in text and "smtp" not in text
    assert view["problems"] == ["rule_error", "target_failing", "targets_all_down"]
