"""알림 설정 차이·'탐지 약화' 판단 (NEW-M2, ADR-043) — DB 없는 단위 시험."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.alerts import configdiff
from app.alerts.message import AlertMessage
from app.alerts.rules import parse_text

BASE = """settings:
  interval_sec: 30
rules:
  - name: 로그온 실패 급증
    sid: 1000001
    match: { event_id: "4625" }
    window: 10m
    threshold: 10
    group_by: ip
    severity: error
    notify: [보안팀]
  - name: 계정 잠금
    sid: 1000002
    match: { event_id: "4740" }
    severity: warning
    notify: [운영팀, 보안팀]
  - name: 꺼진 규칙
    enabled: false
    match: { event_id: "1102" }
    severity: critical
    notify: [보안팀]
  - name: 서버 응답 없음
    kind: agent_silent
    silent_for: 10m
    severity: critical
    notify: [당직]
"""


def _changes(before: str, after: str) -> list[tuple[str, bool]]:
    return [(c["change"], c["weakens"]) for c in configdiff.diff(parse_text(before), parse_text(after))]


@pytest.mark.parametrize(("old", "new", "expected"), [
    ("    threshold: 10\n", "    threshold: 50\n", [("threshold", True)]),
    ("    threshold: 10\n", "    threshold: 5\n", [("threshold", False)]),
    ("    window: 10m\n", "    window: 1m\n", [("window", True)]),
    ("    window: 10m\n", "    window: 1h\n", [("window", False), ("cooldown", True)]),   # 재알림 간격은 window 이상으로 오른다
    ("    severity: error\n", "    severity: info\n", [("severity", True)]),
    ("    severity: warning\n", "    severity: critical\n", [("severity", False)]),
    ("    notify: [운영팀, 보안팀]\n", "    notify: [운영팀]\n", [("notify_removed", True)]),
    ("    notify: [운영팀, 보안팀]\n", "    notify: [운영팀, 보안팀, 당직]\n", [("notify_added", False)]),
    ('    match: { event_id: "4625" }\n', '    match: { event_id: "4625", host: "DC-*" }\n', [("match", True)]),
    ("    group_by: ip\n", "    group_by: user\n", [("group_by", True)]),
    ("    group_by: ip\n", "    group_by: ip\n    distinct: { field: user, min: 5 }\n", [("distinct", True)]),
    ("    silent_for: 10m\n", "    silent_for: 1h\n", [("silent_for", True)]),
    ("  interval_sec: 30\n", "  interval_sec: 300\n", [("interval", True)]),
    ("  interval_sec: 30\n", "  interval_sec: 10\n", [("interval", False)]),
])
def test_each_kind_of_change(old, new, expected):
    assert old in BASE
    assert _changes(BASE, BASE.replace(old, new, 1)) == expected


def test_disable_remove_add_and_rename():
    disabled = BASE.replace("    sid: 1000002\n", "    sid: 1000002\n    enabled: false\n")
    assert _changes(BASE, disabled) == [("disabled", True)]
    assert _changes(disabled, BASE) == [("enabled", False)]
    removed = BASE[:BASE.index("  - name: 계정 잠금")] + BASE[BASE.index("  - name: 꺼진 규칙"):]
    assert _changes(BASE, removed) == [("removed", True)]
    assert _changes(removed, BASE) == [("added", False)]
    # sid 가 같으면 이름이 바뀌어도 같은 규칙 — 이름 바꾸기 자체는 약화가 아니다
    renamed = BASE.replace("name: 계정 잠금", "name: 계정 잠김")
    assert _changes(BASE, renamed) == [("renamed", False)]


def test_changes_to_a_disabled_rule_do_not_weaken():
    # 꺼져 있던 규칙은 지우거나 기준을 바꿔도 지금의 탐지가 약해지지 않는다
    changed = BASE.replace('    match: { event_id: "1102" }\n', '    match: { event_id: "1102", host: "X" }\n')
    assert _changes(BASE, changed) == [("match", False)]
    gone = BASE[:BASE.index("  - name: 꺼진 규칙")] + BASE[BASE.index("  - name: 서버 응답 없음"):]
    assert _changes(BASE, gone) == [("removed", False)]


def test_texts_name_the_rule_and_values():
    texts = [c["text"] for c in configdiff.diff(parse_text(BASE), parse_text(BASE.replace("threshold: 10", "threshold: 50")))]
    assert texts == ["규칙 '로그온 실패 급증'(1000001) 건수 기준 10 → 50"]


def test_unknown_previous_version_counts_as_weakened():
    new = parse_text(BASE)
    changes = configdiff.diff(None, new)
    assert [c["weakens"] for c in changes] == [True]
    # 비교할 수 없으면 새 판본의 켜진 규칙들의 받는 곳으로 (아무에게도 안 가지 않게)
    assert [r.name for r in configdiff.affected(None, new, changes)] == ["로그온 실패 급증", "계정 잠금", "서버 응답 없음"]


def test_recipients_are_the_old_rules_receivers():
    old = parse_text(BASE)
    # 받는 곳을 지우면서 기준도 올림 → 알림은 바뀌기 전 받는 곳(보안팀 포함)으로
    new = parse_text(BASE.replace("    notify: [운영팀, 보안팀]\n", "    notify: [운영팀]\n"))
    changes = configdiff.diff(old, new)
    rules = configdiff.affected(old, new, changes)
    assert [r.name for r in rules] == ["계정 잠금"]
    assert configdiff.recipients(rules) == ("운영팀", "보안팀")
    assert configdiff.severity(rules) == "warning"
    # 규칙 하나로 좁힐 수 없는 변경(평가 주기)은 모든 규칙의 받는 곳, 가장 높은 심각도로
    slower = parse_text(BASE.replace("interval_sec: 30", "interval_sec: 600"))
    every = configdiff.affected(old, slower, configdiff.diff(old, slower))
    # 꺼진 규칙('꺼진 규칙', critical)은 받는 곳·심각도에 넣지 않는다 — 평가하지 않으니 영향이 없다
    assert [r.name for r in every] == ["로그온 실패 급증", "계정 잠금", "서버 응답 없음"]
    assert configdiff.recipients(every) == ("보안팀", "운영팀", "당직")
    assert configdiff.severity(every) == "critical"


def test_config_message_text_has_summary_once():
    m = AlertMessage(rule="알림 설정 변경", severity="warning", kind="config", group_by="none", group_key="화면에서 저장 · kim",
                     event_count=1, threshold=0, window_sec=0, fired_at=datetime(2026, 10, 29, tzinfo=UTC),
                     description="탐지를 약하게 하는 알림 설정 변경 1건\n- 규칙 '<b>x</b>' 끔")
    assert m.summary() == "탐지를 약하게 하는 알림 설정 변경 1건"
    assert m.text().count("탐지를 약하게 하는") == 1 and "- 규칙 '<b>x</b>' 끔" in m.text()
    assert "&lt;b&gt;x&lt;/b&gt;" in m.html() and "<b>x</b>" not in m.html()


def test_rule_cannot_take_a_builtin_name():
    from app.alerts.rules import ConfigError

    with pytest.raises(ConfigError, match="내장 알림 이름"):
        parse_text(BASE.replace("name: 계정 잠금", "name: 알림 설정 변경"))


def test_reenabling_compares_with_the_last_enabled_version():
    """끄고 → (꺼진 채) 기준을 올리고 → 켜면 바로 앞 판본은 꺼진 모양이라 약화가 보이지 않았다(검토에서 재현)."""
    on = parse_text(BASE)
    off_and_weaker = parse_text(BASE.replace("    sid: 1000001\n", "    sid: 1000001\n    enabled: false\n")
                                .replace("threshold: 10", "threshold: 100000").replace("severity: error", "severity: info"))
    back_on = parse_text(BASE.replace("threshold: 10", "threshold: 100000").replace("severity: error", "severity: info"))
    assert configdiff.needs_history(off_and_weaker, back_on) == {"sid:1000001"}
    history = {"sid:1000001": (on.rules[0], 7)}
    changes = configdiff.diff(off_and_weaker, back_on, history)
    assert [(c["change"], c["weakens"]) for c in changes] == [("enabled", False), ("severity", True), ("threshold", True)]
    assert changes[1]["text"] == "규칙 '로그온 실패 급증'(1000001) 다시 켬 — 판본 #7에서 켜져 있던 때와 비교: 심각도 오류 → 정보"
    assert [r.name for r in configdiff.affected(off_and_weaker, back_on, changes, history)] == ["로그온 실패 급증"]
    # 기록이 없어도 켜면서 함께 바꾼 것은 비교한다 (꺼진 규칙이라는 이유로 넘기지 않는다)
    assert [(c["change"], c["weakens"]) for c in configdiff.diff(
        parse_text(BASE.replace("    sid: 1000001\n", "    sid: 1000001\n    enabled: false\n")), back_on)] == [
        ("enabled", False), ("severity", True), ("threshold", True)]


def test_readding_a_removed_rule_compares_with_its_last_enabled_shape():
    gone = parse_text(BASE[:BASE.index("  - name: 로그온 실패 급증")] + BASE[BASE.index("  - name: 계정 잠금"):])
    weaker = parse_text(BASE.replace("threshold: 10", "threshold: 99"))
    changes = configdiff.diff(gone, weaker, {"sid:1000001": (parse_text(BASE).rules[0], 3)})
    assert [(c["change"], c["weakens"]) for c in changes] == [("added", False), ("threshold", True)]


@pytest.mark.parametrize(("hosts", "expected"), [
    ("[B, A]", []),                                  # 순서만 바뀜
    ("[A, B, C]", [("hosts", False)]),               # 더함 — 넓어짐
    ("[A]", [("hosts", True)]),                      # 뺌
    ("[]", [("hosts", False)]),                      # 전체로
])
def test_agent_silent_hosts_are_compared_as_sets(hosts, expected):
    old = BASE.replace("    silent_for: 10m\n", "    silent_for: 10m\n    hosts: [A, B]\n")
    assert _changes(old, old.replace("hosts: [A, B]", f"hosts: {hosts}")) == expected
    assert _changes(BASE, old) == [("hosts", True)]   # 전체 → 목록은 좁힘


def test_a_rule_that_gets_a_sid_is_the_same_rule():
    # 손으로 쓴 규칙(sid 없음)을 화면에서 고치면 번호가 붙는다 — '삭제 + 추가'가 아니라 실제 바뀐 것만
    old = BASE.replace("    sid: 1000002\n", "")
    changes = configdiff.diff(parse_text(old), parse_text(BASE.replace("    sid: 1000002\n", "    sid: 1000002\n    threshold: 5\n")))
    assert [(c["change"], c["weakens"]) for c in changes] == [("sid", False), ("threshold", True)]
    assert changes[0]["text"] == "규칙 '계정 잠금' 규칙 번호 없음 → 1000002"


def test_settings_must_be_an_object():
    from app.alerts.rules import ConfigError

    with pytest.raises(ConfigError, match="settings"):
        parse_text("settings: 30\nrules: []\n")


def test_messenger_shows_changes_not_a_count_threshold():
    from app.alerts import messenger

    m = AlertMessage(rule="알림 설정 변경", severity="warning", kind="config", group_by="none", group_key="서버에서 파일 직접 수정",
                     event_count=2, threshold=0, window_sec=0, fired_at=datetime(2026, 10, 29, tzinfo=UTC),
                     description="탐지를 약하게 하는 알림 설정 변경 2건\n- 규칙 'A' 끔\n- 규칙 'B' 삭제")
    assert ("변경", "2건") in messenger._facts(m) and all(k != "건수" for k, _ in messenger._facts(m))
    assert "- 규칙 'A' 끔" in messenger.build_text(m)["text"]


def test_removing_a_fallback_receiver_weakens():
    old = BASE.replace("  interval_sec: 30\n", "  interval_sec: 30\n  fallback_notify: [당직, 보안팀]\n")
    assert _changes(old, old.replace("[당직, 보안팀]", "[당직]")) == [("fallback", True)]
    assert _changes(old, old.replace("[당직, 보안팀]", "[당직, 보안팀, 운영팀]")) == [("fallback", False)]
