"""자동 해결·해소 통지·묶음 키 (BACKLOG B-35 2단계) — DB 없는 단위 시험.

회귀: 서비스가 살아나거나 PC 가 다시 들어와도 알림은 사람이 닫을 때까지 '처리 안 됨'으로 남았고, 사내 사고관리·SMS 는
알림으로 연 티켓을 닫을 방법이 없었다(같은 문제인지 가릴 키도 없었다).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.alerts import ruleedit
from app.alerts.dispatcher import _stale
from app.alerts.message import RESOLVED_COLOR, SEVERITY_COLORS, AlertMessage
from app.alerts.messenger import FORMATS
from app.alerts.notifiers import ORACLE_DEFAULT_SQL, OracleNotifier, WebhookNotifier, oracle_binds
from app.alerts.rules import ConfigError, parse
from app.reports import render

NOW = datetime(2026, 10, 30, 1, 0, tzinfo=UTC)


def _rule(**raw):
    return parse({"rules": [{"name": "r", "notify": ["운영팀"], **raw}]}).rules[0]


def _message(**overrides) -> AlertMessage:
    values = {"rule": "서비스 비정상 종료", "severity": "error", "kind": "count", "group_by": "host", "group_key": "WEB-01",
              "event_count": 2, "threshold": 1, "window_sec": 600, "fired_at": NOW - timedelta(minutes=95),
              "first_event_at": NOW - timedelta(minutes=100), "last_event_at": NOW - timedelta(minutes=96), "alert_id": 41,
              "samples": [{"id": 1, "ts": NOW.isoformat(), "host": "WEB-01", "level": 2, "channel": "System",
                           "event_id": 7031, "message": "서비스가 예기치 않게 종료되었습니다"}],
              "link": "http://logmon.local/#/events?host=WEB-01"}
    values.update(overrides)
    return AlertMessage(**values)


def _resolved(**overrides) -> AlertMessage:
    return _message(event_action="resolve", resolved_at=NOW, **overrides)


# ------------------------------------------------------------------ 규칙

def test_resolve_defaults_by_kind():
    assert _rule(match={"event_id": "7031"}).resolve == "manual"
    assert _rule(kind="agent_silent").resolve == "auto"
    assert _rule(kind="agent_silent", resolve="manual").resolve == "manual"
    assert _rule(match={"event_id": "7031"}, resolve="auto").resolve == "auto"


@pytest.mark.parametrize(("raw", "error"), [
    ({"resolve": "sometimes"}, "resolve 는 manual, auto"),
    ({"resolve": "auto", "group_by": "ip", "distinct": {"field": "user", "min": 5}}, "자동 해결할 수 없습니다"),
])
def test_resolve_is_validated(raw, error):
    with pytest.raises(ConfigError, match=error):
        _rule(match={"event_id": "4625"}, **raw)


def test_resolve_is_written_back_by_the_rule_editor():
    text = ruleedit.emit_rule({"name": "r", "match": {"event_id": "7031"}, "resolve": "auto", "severity": "error",
                               "notify": ["운영팀"]})
    assert "    resolve: auto\n    severity: error\n" in text


# ------------------------------------------------------------------ 메시지

def test_trigger_payload_is_unchanged_and_resolve_payload_says_so():
    trigger = _message().to_dict()
    assert "event_action" not in trigger and "resolved_at" not in trigger   # 저장되는 payload 는 예전 그대로
    resolved = _resolved().to_dict()
    assert resolved["event_action"] == "resolve" and resolved["resolved_at"] == NOW.isoformat()
    assert AlertMessage.from_dict(resolved).resolved_at == NOW


def test_dedup_key_is_per_rule_and_target():
    a, b = _message(), _resolved(alert_id=99, event_count=7)
    assert a.dedup_key == b.dedup_key and len(a.dedup_key) == 32
    assert _message(group_key="WEB-02").dedup_key != a.dedup_key
    assert _message(rule="다른 규칙").dedup_key != a.dedup_key
    # 이어 붙이면 같아지는 이름·대상 쌍이 같은 키가 되지 않게 (구분자)
    assert _message(rule="ab", group_key="c").dedup_key != _message(rule="a", group_key="bc").dedup_key


def test_resolve_wording_and_no_samples():
    m = _resolved()
    assert m.title() == "[해소] [오류] 서비스 비정상 종료 · WEB-01"
    assert "기준(1건) 아래로 내려가 자동으로 해결했습니다" in m.summary()
    assert m.detail.startswith("알림 #41 ") and "(1시간 35분)" in m.detail
    assert "최근 이벤트" not in m.text() and "해소 시각" in m.text()
    assert "서비스가 예기치 않게" not in m.html() and RESOLVED_COLOR in m.html()
    silent = _resolved(kind="agent_silent", event_count=0, threshold=0)
    assert "로그/하트비트가 다시 들어옵니다" in silent.summary()


@pytest.mark.parametrize("fmt", sorted(set(FORMATS) - {"json"}))   # json 은 알림 전체 데이터(표본 포함)를 그대로 싣는다
def test_every_format_builds_a_resolve_notice(fmt):
    data = WebhookNotifier("w", "https://h.example.com/x", fmt).payload(_resolved())
    text = str(data)
    assert "[해소]" in text and "서비스가 예기치 않게" not in text and "건수" not in text


def test_json_carries_dedup_key_and_action_and_colors_follow_the_action():
    hook = WebhookNotifier("w", "https://h.example.com/x", "json")
    trigger, resolved = hook.payload(_message()), hook.payload(_resolved())
    assert (trigger["event_action"], resolved["event_action"]) == ("trigger", "resolve")
    assert trigger["dedup_key"] == resolved["dedup_key"]
    slack = WebhookNotifier("w", "https://h.example.com/x", "slack")
    assert slack.payload(_message())["attachments"][0]["color"] == SEVERITY_COLORS["error"]
    assert slack.payload(_resolved())["attachments"][0]["color"] == RESOLVED_COLOR


# ------------------------------------------------------------------ Oracle

def test_oracle_binds_and_who_gets_resolve_notices():
    custom = "INSERT INTO T (K, A, ID) VALUES (:dedup_key, :event_action, :alert_id)"
    assert oracle_binds(custom, _resolved()) == {"dedup_key": _message().dedup_key, "event_action": "resolve", "alert_id": 41}
    conn = object()
    assert OracleNotifier("o", conn, custom).accepts_resolve() is None
    # 예전(기본) SQL 은 알림과 해소를 가리지 못한다 — 같은 알림 번호의 줄이 하나 더 생기지 않게 보내지 않는다
    default = ORACLE_DEFAULT_SQL.format(table="LOGMON_ALERTS")
    assert "event_action" in OracleNotifier("o", conn, default).accepts_resolve()
    # 문자열 안의 ':event_action' 은 바인드가 아니다
    assert OracleNotifier("o", conn, "INSERT INTO T (X) VALUES (':event_action')").accepts_resolve() is not None


# ------------------------------------------------------------------ 전송기

def test_stale_rows_are_skipped_not_sent():
    hook = WebhookNotifier("w", "https://h.example.com/x", "json")
    ok = {"action": "resolve", "alert_status": "resolved", "auto_resolved": True, "newer": False, "delivered": True}
    assert _stale(ok, hook) is None
    assert _stale({**ok, "alert_status": "open"}, hook) == "해소 통지를 보내기 전에 알림이 다시 열렸습니다"
    assert _stale({**ok, "auto_resolved": False}, hook) == "담당자가 해결 처리한 알림이라 자동 해소 통지를 보내지 않습니다"
    assert "새 알림을 닫지 않게" in _stale({**ok, "newer": True}, hook)
    assert _stale({**ok, "delivered": False}, hook) == "이 곳으로 알림이 전해지지 않아 해소 통지도 보내지 않습니다"
    assert _stale({"action": "trigger", "auto_resolved": True}, hook) == "보내기 전에 조건이 풀려 자동으로 해결됨"
    assert _stale({"action": "trigger", "auto_resolved": False, "alert_status": "resolved"}, hook) is None   # 사람이 해결해도 보낸다


def test_resolve_notice_counts_from_the_first_alert_of_the_problem():
    """재알림 간격마다 다시 알렸으면 해소 통지의 '얼마나 갔나'는 마지막 알림이 아니라 처음 알림부터."""
    m = _resolved(started_at=NOW - timedelta(hours=5))
    assert "처음 알림" in m.detail and "(5시간 0분)" in m.detail
    assert AlertMessage.from_dict(m.to_dict()).started_at == NOW - timedelta(hours=5)


# ------------------------------------------------------------------ 보고서

def test_report_counts_auto_resolved_separately_and_renders_old_payloads():
    al = {"resolved_in_period": 9, "auto_resolved_in_period": 4}
    assert render._resolved_note(al) == "기간 안에 해결 9건 (자동 4건, 중앙값은 사람이 해결한 것만)"
    assert render._resolved_note({"resolved_in_period": 3}) == "기간 안에 해결 3건"   # B-35 2단계 이전 보고서
