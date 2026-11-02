"""확인 안 된 알림 에스컬레이션 (BACKLOG B-43) — DB 없는 단위 시험: 정책 형식, 약화 판단, 보낼 때의 건너뜀, 문구."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.alerts import configdiff
from app.alerts.dispatcher import _stale
from app.alerts.message import AlertMessage, escalation_from_action
from app.alerts.rules import ConfigError, parse_text

BASE = """rules:
  - name: 보안 감사 로그 삭제
    match: { event_id: "1102" }
    severity: critical
    notify: [보안팀]
escalations:
  - name: 심각 미확인
    severity: [critical]
    steps:
      - after: 15m
        notify: [당직]
      - after: 1h
        unless: resolved
        notify: [당직, 보안팀장]
"""


def test_policy_parsed_and_targets_counted_as_used():
    cfg = parse_text(BASE)
    [p] = cfg.escalations
    assert [(s.after, s.unless, s.notify) for s in p.steps] == [
        (timedelta(minutes=15), "acked", ("당직",)), (timedelta(hours=1), "resolved", ("당직", "보안팀장"))]
    assert p.matches("아무 규칙", "critical") and not p.matches("아무 규칙", "warning")
    assert [s.action for s in p.steps] == ["escalate:900:acked", "escalate:3600:resolved"]
    assert cfg.used_targets()["보안팀장"] == ["(에스컬레이션 심각 미확인)"]   # 받는 곳을 지우지 못하게


@pytest.mark.parametrize(("old", "new", "error"), [
    ("after: 15m\n        notify: [당직]", "after: 1h\n        unless: resolved\n        notify: [당직]", "겹칩니다"),
    ("after: 15m", "after: 8d", "7일"),
    ("unless: resolved", "unless: read", "unless"),
    ("notify: [당직]\n      - after: 1h", "notify: []\n      - after: 1h", "받는 곳"),
    ("severity: [critical]", "severity: [urgent]", "severity"),
    ("severity: [critical]", "rules: [없는 규칙]", "없는 규칙"),
    ("  - name: 심각 미확인\n", "  - name: 심각 미확인\n    steps: []\n  - name: 심각 미확인\n", "steps"),
])
def test_policy_errors(old, new, error):
    assert old in BASE
    with pytest.raises(ConfigError, match=error):
        parse_text(BASE.replace(old, new, 1))


def _changes(before, after):
    return [(c["change"], c["weakens"]) for c in configdiff.diff(parse_text(before), parse_text(after))]


def test_weakening_escalation_is_flagged():
    assert _changes(BASE, BASE.replace("after: 15m", "after: 2h")) == [("escalation", True)]          # 늦춤
    assert _changes(BASE, BASE.replace("[당직, 보안팀장]", "[당직]")) == [("escalation", True)]          # 받는 곳 뺌
    assert _changes(BASE, BASE.replace("[critical]", "[critical, error]")) == [("escalation", False)]  # 넓힘
    assert _changes(BASE, BASE.replace("after: 15m", "after: 5m")) == [("escalation", False)]          # 당김
    assert _changes(BASE, BASE.replace("unless: resolved", "unless: acked")) == [("escalation", True)]  # 확인만 하면 멈춤 (검토)
    assert _changes(BASE, BASE.replace("        unless: resolved\n", "")) == [("escalation", True)]
    assert _changes(BASE, BASE[:BASE.index("escalations:")]) == [("escalation_removed", True)]
    assert _changes(BASE[:BASE.index("escalations:")], BASE) == [("escalation_added", False)]


class _Reader:
    """메일·메신저처럼 사람이 읽는 받는 곳 — 다시 알림을 늘 받는다."""

    def accepts_escalation(self):
        return None


def test_stale_at_send_time():
    """넣을 때가 아니라 보낼 때 본다 — 그 사이 누가 확인·해결했으면 다시 알리지 않는다."""
    job, reader = {"action": "escalate:900:acked", "alert_status": "open"}, _Reader()
    assert _stale(job, reader) is None
    assert _stale({**job, "alert_status": "acked"}, reader) == "다시 알리기 전에 확인됨"
    assert _stale({**job, "alert_status": "resolved"}, reader) == "다시 알리기 전에 해결됨"
    assert _stale({"action": "escalate:3600:resolved", "alert_status": "acked"}, reader) is None   # 해결 전까지는 보냄


def test_oracle_needs_escalation_bind():
    """기본 INSERT(알림 번호가 기본 키)는 다시 알림을 중복으로 버리고 드라이버는 성공으로 친다 — :escalation 을 받는 SQL 만 (검토에서 재현)."""
    from app.alerts.notifiers import ORACLE_DEFAULT_SQL, OracleNotifier, oracle_binds

    default = OracleNotifier("o", object(), ORACLE_DEFAULT_SQL.format(table="LOGMON_ALERTS"))
    assert "escalation" in _stale({"action": "escalate:900:acked", "alert_status": "open"}, default)
    custom = "INSERT INTO T (ID, K, E) VALUES (:alert_id, :dedup_key, :escalation)"
    assert _stale({"action": "escalate:900:acked", "alert_status": "open"}, OracleNotifier("o", object(), custom)) is None
    m = AlertMessage(rule="r", severity="critical", kind="count", group_by="host", group_key="DC-01", event_count=1,
                     threshold=1, window_sec=300, fired_at=datetime.now(UTC), alert_id=7)
    assert oracle_binds(custom, m)["escalation"] is None
    m.escalation = "15분 동안 아무도 확인하지 않음"
    assert oracle_binds(custom, m)["escalation"] == "15분 동안 아무도 확인하지 않음"


def test_message_says_why_it_comes_again():
    m = AlertMessage(rule="보안 감사 로그 삭제", severity="critical", kind="count", group_by="host", group_key="DC-01",
                     event_count=1, threshold=1, window_sec=300, fired_at=datetime.now(UTC))
    m.escalation = escalation_from_action("escalate:900:acked")
    assert m.title() == "[다시 알림 — 15분 동안 아무도 확인하지 않음] [심각] 보안 감사 로그 삭제 · DC-01"
    assert m.summary().startswith("15분 동안 아무도 확인하지 않음 — 담당자가 확인하세요.")
    m.escalation = ""
    assert "escalation" not in m.to_dict()        # 보통 알림의 본문(웹훅 json·저장 payload)은 예전과 같다
    assert escalation_from_action("trigger") is None and escalation_from_action("escalate:x:acked") is None
