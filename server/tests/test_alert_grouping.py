"""알림 묶음 전송 (BACKLOG B-41, ADR-057) — DB 없는 단위 시험: 묶음 메시지 문구, 설정 검증·심각도별 시간, 설정 변경 약화 판단.

회귀: 대상 키마다 알림 한 통이라 윈도 업데이트 재부팅 물결로 300대에서 서비스 오류가 나면 메일 300통, 두레이는 주소별 1.1초 간격이라
5분 넘게 걸리며 진짜 신호가 묻혔다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.alerts import configdiff
from app.alerts.message import GROUP_LIST_MAX, AlertMessage
from app.alerts.rules import ConfigError, parse_text

NOW = datetime(2026, 11, 2, 1, 0, tzinfo=UTC)


def _msg(i: int, **kw) -> AlertMessage:
    values = {"rule": "서비스 비정상 종료", "severity": "error", "kind": "count", "group_by": "host", "group_key": f"PC-{i:03d}",
              "event_count": i + 1, "threshold": 1, "window_sec": 600, "fired_at": NOW + timedelta(seconds=i), "alert_id": 100 + i,
              "first_event_at": NOW - timedelta(minutes=5), "last_event_at": NOW + timedelta(seconds=i),
              "description": "서비스가 비정상 종료됐습니다",
              "samples": [{"ts": NOW.isoformat(), "host": f"PC-{i:03d}", "level": 2, "message": "stopped"}]}
    values.update(kw)
    return AlertMessage(**values)


def test_group_message_counts_targets_and_lists_them():
    g = AlertMessage.group([_msg(i) for i in range(37)])
    assert g.title() == "[오류] 서비스 비정상 종료 · 37대 (PC-000, PC-001, PC-002 외 34대)"
    assert g.event_count == sum(range(1, 38)) and g.alert_id is None and len(g.samples) == 5
    assert "같은 규칙의 알림 37건" in g.summary()
    lines = g.detail.split("\n")
    assert lines[0].startswith("- PC-000 · 1건 · ") and lines[0].endswith("#100")
    assert lines[GROUP_LIST_MAX] == "… 외 17건 — 전체는 알림 화면에서"
    assert "/#/alerts?since=7d&rule=" in g.link
    assert g.fired_text().count("~") == 1 and "grouped" in g.to_dict()
    assert "grouped" not in _msg(1).to_dict()           # 저장되는 알림 payload 는 예전과 같다


def test_group_message_kinds():
    resolved = AlertMessage.group([_msg(i, event_action="resolve", resolved_at=NOW + timedelta(hours=1)) for i in range(3)])
    assert resolved.title().startswith("[해소] [오류]") and "자동으로 해결됐습니다" in resolved.summary()
    assert "1건" not in resolved.detail                     # 해소 통지에는 건수를 다시 보이지 않는다
    silent = AlertMessage.group([_msg(i, kind="agent_silent", group_by="none", window_sec=900) for i in range(4)])
    assert silent.summary().startswith("4대에서 15분 이상") and "· 4대 (" in silent.title()
    users = AlertMessage.group([_msg(i, group_by="user", group_key=f"user{i}") for i in range(2)])
    assert "· 2건 (user0, user1)" in users.title()
    esc = AlertMessage.group([_msg(i, escalation="15분 동안 아무도 확인하지 않음") for i in range(2)])
    assert esc.title().startswith("[다시 알림 — 15분 동안 아무도 확인하지 않음]") and esc.summary().startswith("15분 동안")
    # 가장 심각한 알림이 바탕 (같은 규칙이어도 내장 알림은 심각도가 다를 수 있다)
    assert AlertMessage.group([_msg(0, severity="warning"), _msg(1, severity="critical")]).severity == "critical"


def test_group_settings_validation_and_timing():
    cfg = parse_text("rules: []\n")
    assert (cfg.group_wait_sec, cfg.group_interval_sec) == (30, 300)
    assert cfg.group_timing("warning") == (30, 300) and cfg.group_timing("critical") == (0, 60)
    off = parse_text("settings:\n  group_interval_sec: 0\nrules: []\n")
    assert off.group_timing("warning") == (0, 0) and off.group_timing("critical") == (0, 0)
    short = parse_text("settings:\n  group_wait_sec: 0\n  group_interval_sec: 30\nrules: []\n")
    assert short.group_timing("critical") == (0, 30)
    for bad in ("group_wait_sec: 301", "group_wait_sec: -1", "group_interval_sec: 3601", "group_interval_sec: true",
                "group_wait_sec: '30'"):
        with pytest.raises(ConfigError, match="group_"):
            parse_text(f"settings:\n  {bad}\nrules: []\n")


@pytest.mark.parametrize(("before", "after", "weakens"), [
    ("", "  group_interval_sec: 600\n", True),        # 간격을 늘리면 알림이 늦게 간다
    ("", "  group_wait_sec: 120\n", True),
    ("", "  group_interval_sec: 0\n", False),         # 묶지 않으면 더 자주 보낼 뿐
    ("  group_interval_sec: 0\n", "", True),          # 다시 묶기 — 늦어진다
    ("", "  group_wait_sec: 10\n", False),
])
def test_grouping_changes_in_config_diff(before, after, weakens):
    old = parse_text(f"settings:\n  interval_sec: 30\n{before}rules: []\n")
    new = parse_text(f"settings:\n  interval_sec: 30\n{after}rules: []\n")
    assert [(c["change"], c["weakens"]) for c in configdiff.diff(old, new)] == [("grouping", weakens)]
