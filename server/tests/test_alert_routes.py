"""받는 곳 경로 (BACKLOG B-26) — DB 없는 단위 시험: 매칭(continue·replace·기본), 호환(경로 없음), 형식, 약화 판단."""

from __future__ import annotations

import pytest

from app.alerts import configdiff
from app.alerts.rules import ConfigError, parse_text

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
    assert _changes(ROUTES, "routes: []\n") == [("route_removed", True)] * 3
    # 맨 뒤에 더하기만 하는 경로는 약해지지 않는다, 앞에 넣어 뒤의 기존 경로를 가리면 약해진다
    tail = ROUTES + "  - name: 끝\n    notify: [감사팀]\n    continue: true\n"
    assert _changes(ROUTES, tail) == [("route_added", False)]
    head = "routes:\n  - name: 앞\n    notify: [감사팀]\n" + ROUTES[len("routes:\n"):]
    assert _changes(ROUTES, head) == [("route_added", True)]
