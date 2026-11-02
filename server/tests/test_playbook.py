"""조사 플레이북 (BACKLOG B-66) — DB 없는 단위 시험: 기본 플레이북 형식, 자리표시자 이스케이프(문장 주입), 오류."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.alerts import playbook
from app.querylang import parse_terms

# 저장소: server/tests → ../../config, 컨테이너: /app/tests → /app/config (test_alerts 와 같은 방식)
ROOT = Path(__file__).resolve().parents[1]
CONFIG = next(p for p in (ROOT / "config", ROOT.parent / "config") if (p / "alerts.yaml").exists())
SHIPPED = sorted((CONFIG / "playbooks").glob("*.yaml"))


def test_shipped_playbooks_are_valid_and_match_rules():
    assert len(SHIPPED) >= 7
    rules = {r["sid"]: r for r in yaml.safe_load((CONFIG / "alerts.yaml").read_text(encoding="utf-8"))["rules"]}
    for path in SHIPPED:
        sid = int(path.stem)
        book = playbook.parse(sid, path.read_text(encoding="utf-8"))   # 틀리면 PlaybookError
        assert sid in rules and rules[sid].get("kind", "count") == "count", path.name
        assert book.title == rules[sid]["name"], path.name                 # 규칙 이름을 바꾸면 여기도
        assert all(s.why for s in book.steps), path.name                   # 당직이 '왜'를 알아야 판단한다


@pytest.mark.parametrize("value", ['kim" -host:*', "a,b", "x:y", "-svc", "OR", "공백 있는 이름", "'따옴표'", "<10"])
def test_slot_values_cannot_inject_conditions(value):
    """로그에서 온 값(사용자 이름 등)이 문장의 다른 조건이 되면 안 된다 — 정규형 따옴표 규칙으로 한 값으로만."""
    filled, missing = playbook.fill("event_id:4624 user:{user} host:{host}", {"user": value, "host": "PC-1"})
    assert not missing
    terms = parse_terms(filled)
    assert [(t.key, t.values, t.neg) for t in terms] == [("event_id", (4624,), False), ("user", (value,), False),
                                                          ("host", ("PC-1",), False)]


def test_missing_values_skip_the_question():
    assert playbook.fill("user:{user} ip:{ip}", {"user": "kim", "ip": None}) == (None, ["ip"])
    assert playbook.values_for({"group_key": "10.0.0.9"}, "ip", {"host": "PC-1", "username": None, "src_ip": "10.0.0.5"}) == {
        "key": "10.0.0.9", "host": "PC-1", "user": None, "ip": "10.0.0.9"}      # 묶음 기준 값이 정본


@pytest.mark.parametrize(("text", "error"), [
    ("steps: []", "steps"),
    ("steps:\n  - question: q\n    query: 'user:{who}'", "자리표시자"),
    ("steps:\n  - question: q\n    query: 'event_id:'", "query"),
    ("steps:\n  - question: q\n    query: 'event_id:1'\n    window: 90d", "30일"),
    ("steps:\n  - question: q\n    query: 'event_id:1'\n    top: message", "top"),
    ("steps:\n" + "".join(f"  - question: q{i}\n    query: 'event_id:1'\n" for i in range(9)), "8개"),
    ("steps: [", "YAML"),
])
def test_bad_playbooks_are_rejected(text, error):
    with pytest.raises(playbook.PlaybookError, match=error):
        playbook.parse(1, text)
