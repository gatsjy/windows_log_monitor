"""규칙 블록 편집: 다른 규칙과 주석을 건드리지 않고, 결과가 다시 검증을 통과하는지."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.alerts import ruleedit
from app.alerts.rules import parse_text

# 저장소(…/config) 또는 컨테이너(/app/config)
SHIPPED = next(p for p in (Path(__file__).resolve().parents[2] / "config" / "alerts.yaml",
                           Path("/app/config/alerts.yaml")) if p.exists())
TEXT = SHIPPED.read_text(encoding="utf-8")
COMMENTS = [line for line in TEXT.split("\n") if line.lstrip().startswith("#")]


def rules_of(text):
    return {r.name: r for r in parse_text(text).rules}


def test_names_and_next_sid():
    names = ruleedit.names(TEXT)
    assert len(names) == len(parse_text(TEXT).rules) and "계정 잠금" in names
    assert ruleedit.next_sid(TEXT) == max(r.sid for r in parse_text(TEXT).rules) + 1


def test_replace_changes_only_that_rule_and_keeps_comments():
    before = rules_of(TEXT)
    new = ruleedit.replace(TEXT, "계정 잠금", {
        "name": "계정 잠금", "sid": before["계정 잠금"].sid, "group": "계정·인증 공격",
        "match": {"event_id": "4740"}, "group_by": "user", "window": "10m", "threshold": 3,
        "cooldown": "1h", "severity": "error", "tags": ["MITRE T1110"], "notify": ["운영팀"]})
    after = rules_of(new)
    assert after["계정 잠금"].threshold == 3 and after["계정 잠금"].severity == "error"
    assert {k: v for k, v in after.items() if k != "계정 잠금"} == {k: v for k, v in before.items() if k != "계정 잠금"}
    assert all(c in new for c in COMMENTS)  # 머리말·구역 제목 주석 그대로


def test_toggle_keeps_inline_comment_inside_block():
    off = ruleedit.set_enabled(TEXT, "서버 응답 없음", False)
    assert rules_of(off)["서버 응답 없음"].enabled is False
    assert "# 서버만" in off
    on = ruleedit.set_enabled(off, "서버 응답 없음", True)
    assert on == TEXT


def test_append_and_delete_round_trip():
    rule = {"name": '새 규칙: "따옴표" #1', "sid": 1009999, "group": "기타",
            "match": {"event_id": "4625", "f.EventData.LogonType": "10", "q": "a|b"},
            "window": "5m", "threshold": 2, "cooldown": "30m", "severity": "info", "notify": ["운영팀"]}
    added = ruleedit.append(TEXT, rule)
    parsed = rules_of(added)['새 규칙: "따옴표" #1']
    assert parsed.match == {"event_id": "4625", "f.EventData.LogonType": "10", "q": "a|b"} and parsed.sid == 1009999
    assert ruleedit.delete(added, rule["name"]) == TEXT


def test_emit_quotes_values_that_would_change_type():
    text = ruleedit.emit_rule({"name": "on", "group": "123", "match": {"level": "1"}, "severity": "warning",
                               "tags": ["yes", "ISMS 2.9.2"], "notify": ["운영팀"]})
    data = yaml.safe_load(text)[0]
    assert data["name"] == "on" and data["group"] == "123" and data["tags"] == ["yes", "ISMS 2.9.2"]


def test_missing_rule_raises():
    with pytest.raises(ruleedit.EditError):
        ruleedit.delete(TEXT, "없는 규칙")
