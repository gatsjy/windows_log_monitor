"""받는 곳 경로 (BACKLOG B-26) — DB 없는 단위 시험: 매칭(continue·replace·기본), 호환(경로 없음), 형식, 약화 판단."""

from __future__ import annotations

import pytest

from app.alerts import configdiff
from app.alerts.rules import ConfigError, _sample_host, parse_text

RULES = """rules:
  - name: 로그온 실패 급증
    group: 계정·인증 공격
    match: { event_id: "4625" }
    severity: warning
    tags: [MITRE T1110, ISMS 2.11.3]
    notify: [운영팀]
  - name: 서버 응답 없음
    kind: agent_silent
    severity: critical
    notify: [당직]
  - name: IP 별 대입
    match: { event_id: "4625" }
    group_by: ip
    severity: error
    notify: [운영팀]
"""
ROUTES = """routes:
  - name: 의료 PC
    match: { hosts: ["MED-*"] }
    notify: [의료정보과]
    continue: true
  - name: 보안 태그
    match: { tags: [MITRE T1110] }
    notify: [보안팀]
  - name: 심각은 당직만
    match: { severity: [critical] }
    notify: [당직, 보안팀장]
    replace: true
"""


def _cfg(routes=ROUTES):
    return parse_text(RULES + routes)


def _rule(cfg, name):
    return next(r for r in cfg.rules if r.name == name)


def test_without_routes_rule_notify_is_unchanged():
    cfg = parse_text(RULES)
    assert cfg.targets_for(_rule(cfg, "로그온 실패 급증"), "PC-1") == (("운영팀",), [])


def test_first_match_stops_unless_continue_and_replace_swaps():
    cfg = _cfg()
    logon = _rule(cfg, "로그온 실패 급증")
    assert cfg.targets_for(logon, "PC-1") == (("운영팀", "보안팀"), ["보안 태그"])
    # 의료 PC 경로는 continue — 다음 경로(보안 태그)도 본다
    assert cfg.targets_for(logon, "med-02") == (("운영팀", "의료정보과", "보안팀"), ["의료 PC", "보안 태그"])
    down = _rule(cfg, "서버 응답 없음")
    assert cfg.targets_for(down, "SRV-1") == (("당직", "보안팀장"), ["심각은 당직만"])      # replace — 규칙 notify 대신
    # IP 로 묶는 규칙은 대상 이름이 PC 가 아니다 — PC 패턴 경로는 맞지 않는다
    assert cfg.targets_for(_rule(cfg, "IP 별 대입"), "MED-01") == (("운영팀",), [])


def test_route_targets_are_used_targets():
    assert "(경로 보안 태그)" in _cfg().used_targets()["보안팀"]


@pytest.mark.parametrize(("text", "error"), [
    ("routes:\n  - name: x\n    notify: []\n", "받는 곳"),
    ("routes:\n  - name: x\n    match: { colour: red }\n    notify: [a]\n", "알 수 없는 조건"),
    ("routes:\n  - name: x\n    match: { rules: [없는 규칙] }\n    notify: [a]\n", "없는 규칙"),
    ("routes:\n  - name: x\n    match: { severity: [urgent] }\n    notify: [a]\n", "severity"),
    ("routes:\n  - name: x\n    notify: [a]\n    continue: yes please\n", "true/false"),
    ("routes:\n  - name: x\n    notify: [a]\n  - name: x\n    notify: [b]\n", "중복"),
])
def test_bad_routes(text, error):
    with pytest.raises(ConfigError, match=error):
        parse_text(RULES + text)


def _changes(before, after):
    return [(c["change"], c["weakens"]) for c in configdiff.diff(_cfg(before), _cfg(after))]


def test_route_changes_weakening():
    assert _changes(ROUTES, ROUTES.replace("notify: [보안팀]\n", "notify: [보안팀, 감사팀]\n")) == [("route", True)]
    # 규칙마다 경로로 받던 곳이 빠진 것도 (로그온 실패 급증 → 보안팀·의료정보과, 서버 응답 없음 → 보안팀장)
    assert _changes(ROUTES, "routes: []\n") == [("route_removed", True)] * 3 + [("route_targets", True)] * 2
    # 맨 뒤에 더하기만 하는 경로는 약해지지 않는다, 앞에 넣어 뒤의 기존 경로를 가리면 약해진다
    tail = ROUTES + "  - name: 끝\n    notify: [감사팀]\n    continue: true\n"
    assert _changes(ROUTES, tail) == [("route_added", False)]
    head = "routes:\n  - name: 앞\n    notify: [감사팀]\n" + ROUTES[len("routes:\n"):]
    assert _changes(ROUTES, head) == [("route_added", True), ("route_targets", True), ("route_targets", True)]


def test_repeated_targets_are_listed_once():
    """경로·규칙 notify 에 같은 받는 곳을 두 번 쓰면 전송 대기열 기본 키에 걸려 알림이 통째로 기록되지 않았다 (검토에서 재현)."""
    cfg = parse_text(RULES.replace("notify: [운영팀]\n", "notify: [운영팀, 운영팀]\n", 1)
                     + ROUTES.replace("notify: [보안팀]", "notify: [보안팀, 보안팀]").replace("notify: [당직, 보안팀장]",
                                                                                      "notify: [당직, 보안팀장, 당직]"))
    logon = _rule(cfg, "로그온 실패 급증")
    assert logon.notify == ("운영팀",)
    assert cfg.targets_for(logon, "PC-1") == (("운영팀", "보안팀"), ["보안 태그"])
    assert cfg.targets_for(_rule(cfg, "서버 응답 없음"), "SRV-1")[0] == ("당직", "보안팀장")


def test_sample_host_matches_its_pattern():
    assert [_sample_host(p) for p in ("MED-*", "PC-0?", "[AB]-01", "[!A]x", "*")] == ["med-", "pc-0x", "a-01", "xx", "x"]


def test_reachable_targets_include_routes():
    """시험 전송·상태 판단·운영 준비도·설정 변경 알림의 받는 곳 — 규칙 notify 만 보면 경로로만 받는 곳이 빠졌다 (검토에서 재현)."""
    cfg = _cfg()
    assert cfg.reachable(_rule(cfg, "로그온 실패 급증")) == ("운영팀", "보안팀", "의료정보과")
    assert cfg.reachable(_rule(cfg, "서버 응답 없음")) == ("당직", "보안팀장")   # replace 가 의료 PC 경로로 더한 곳까지 갈아 끼운다
    assert set(cfg.delivery_targets()) == {"운영팀", "보안팀", "의료정보과", "당직", "보안팀장"}
    off = parse_text(RULES.replace("severity: critical\n", "severity: critical\n    enabled: false\n") + ROUTES)
    assert "보안팀장" not in off.delivery_targets()   # 꺼진 규칙만 쓰는 경로의 받는 곳은 빠진다
    # 설정 변경 알림: replace 경로로 실제로 받던 곳(당직·보안팀장)과 규칙 notify(당직)
    assert configdiff.recipients([_rule(cfg, "서버 응답 없음")], cfg) == ("당직", "보안팀장")
    assert configdiff.recipients([_rule(cfg, "로그온 실패 급증")]) == ("운영팀",)   # 설정 없이 부르면 예전과 같다


@pytest.mark.parametrize(("before", "after", "expected"), [
    # 태그를 빼면 보안 태그 경로가 맞지 않아 보안팀이 빠진다
    ("tags: [MITRE T1110, ISMS 2.11.3]", "tags: [ISMS 2.11.3]", [("tags", False), ("route_targets", True)]),
    # 묶음을 바꾸면 묶음 경로가 맞지 않는다
    ("group: 계정·인증 공격", "group: 기타", [("group", False), ("route_targets", True)]),
    # 심각도를 올려 받는 곳을 갈아 끼우는(replace) 경로에 걸리면 운영팀·보안팀이 빠진다 — 심각도만 보면 '강해짐'
    ("severity: warning\n    tags", "severity: critical\n    tags", [("severity", False), ("route_targets", True)]),
])
def test_rule_edits_that_change_routed_targets_weaken(before, after, expected):
    routes = ("routes:\n  - name: 인증 묶음\n    match: { group: [계정·인증 공격] }\n    notify: [인증팀]\n    continue: true\n"
              "  - name: 심각은 당직만\n    match: { severity: [critical] }\n    notify: [당직]\n    replace: true\n"
              "  - name: 보안 태그\n    match: { tags: [MITRE T1110] }\n    notify: [보안팀]\n")
    old, new = parse_text(RULES + routes), parse_text(RULES.replace(before, after, 1) + routes)
    assert [(c["change"], c["weakens"]) for c in configdiff.diff(old, new)] == expected


def test_reordering_routes_while_adding_one_weakens():
    """순서를 바꾸면서 경로 하나를 더하면 '추가'만 보고 순서 변경을 지나쳤다 (검토에서 재현)."""
    two = "routes:\n  - name: A\n    match: { tags: [MITRE T1110] }\n    notify: [보안팀]\n  - name: B\n    notify: [감사팀]\n"
    swapped = ("routes:\n  - name: B\n    notify: [감사팀]\n  - name: A\n    match: { tags: [MITRE T1110] }\n    notify: [보안팀]\n"
               "  - name: C\n    notify: [감사팀]\n    continue: true\n")
    got = _changes(two, swapped)
    assert ("route_order", True) in got and ("route_targets", True) in got


def test_reenable_after_dropping_a_routed_tag_weakens():
    """끄고 → 태그를 빼고 → 켜면 다시 켬 비교가 경로를 보지 않아 보안팀이 조용히 빠졌다 (검토에서 재현). 다시 추가도 같다."""
    on = _cfg()
    off = parse_text(RULES.replace("    severity: warning\n", "    severity: warning\n    enabled: false\n", 1) + ROUTES)
    edited = parse_text(RULES.replace("    severity: warning\n", "    severity: warning\n    enabled: false\n", 1)
                        .replace("tags: [MITRE T1110, ISMS 2.11.3]", "tags: [ISMS 2.11.3]") + ROUTES)
    back = parse_text(RULES.replace("tags: [MITRE T1110, ISMS 2.11.3]", "tags: [ISMS 2.11.3]") + ROUTES)
    key = configdiff.rule_key(_rule(on, "로그온 실패 급증"))
    assert [c["change"] for c in configdiff.diff(on, off)] == ["disabled"]
    assert not any(c["weakens"] for c in configdiff.diff(off, edited))      # 꺼진 채로 고친 것은 지금 약하게 하지 않는다
    changes = configdiff.diff(edited, back, {key: (_rule(on, "로그온 실패 급증"), 1)})
    assert ("route_targets", True) in [(c["change"], c["weakens"]) for c in changes]
    assert any("보안팀" in c["text"] and "다시 켬" in c["text"] for c in changes)
