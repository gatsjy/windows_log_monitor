"""기본 규칙 표본 게이트 (BACKLOG B-45) — 기본 규칙마다 실제 에이전트 모양의 '맞아야 함·안 맞아야 함' 표본.

test_shipped_config_is_valid 는 형식만 보고, test_rule_fields 는 Windows 이름만 본다. 이벤트 ID·공급자·분류·수준·메시지 글자·
묶음 값(출발지 IP 등)이 실제 PC 의 로그에서 맞는지는 표본이 있어야 안다. 표본은 tests/fixtures/rules/<sid>.yaml(형식: 그 폴더의 README).

판단은 규칙 시험기(B-52)와 같다(app/alerts/ruletest.checks): 수집과 같은 정규화 → 엔진과 같은 조건 + 묶음 값·볼 값이 비지 않았는지.
안 맞음 표본은 '어느 조건으로' 떨어지는지(fails_on)까지 본다 — 다른 조건으로도 떨어지면 그 조건이 빠진 회귀를 잡지 못했다(검토).
수집 → 엔진의 SQL 집계(기준 건수·서로 다른 값 수)로도 같은 결과인지는 test_api_rule_samples.py 가 본다.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import rulesamples as rs

from app.alerts import ruletest
from app.alerts.rules import parse_text

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in (HERE.parent, HERE.parents[1]) if (p / "config" / "alerts.yaml").exists())
RULES = {r.sid: r for r in parse_text((ROOT / "config" / "alerts.yaml").read_text(encoding="utf-8")).rules}
NOW = datetime(2026, 11, 9, 1, 30, tzinfo=UTC)
# 로그 하나로 판단할 수 없는 규칙 종류 — 표본 대신 이유. 엔진 동작은 각자의 통합 시험이 본다
NO_LOG_SAMPLES = {
    "agent_silent": "로그가 아니라 PC 의 수신(하트비트 포함)이 끊긴 것을 본다",
    "stream_silent": "로그가 아니라 늘 오던 채널이 끊긴 것을 본다",
    "correlation": "로그가 아니라 다른 규칙의 알림을 묶는다 — 재료가 되는 규칙들에 표본이 있다",
}
SAMPLES = rs.all_samples()
BAD_FLAGS = {"parse_error", "unparsed", "template_mismatch"}

# 실측 없이 문서로 만든 Windows 표본 (공급자, 이벤트 ID) → 실측할 곳 (윈도 CI 42723626534 로 9개, 42964906651 로 7034 를 실측으로 바꿨다). 실측이 생기면
# 표본 빌더가 '실측으로 바꾸라'며 실패한다 — 바꾸고 여기서 지운다. 업무 프로그램 흉내(EMR…)는 실측 대상이 아니다
SEC, EVENTLOG, SCM, DEFENDER = ("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog", "Service Control Manager",
                                "Microsoft-Windows-Windows Defender")
DOCS_BASED = {
    (SEC, 4771): "도메인 컨트롤러 — 현장 B-28 (듣기 모드)",
    (EVENTLOG, 1100): "이벤트 로그 서비스 종료 — 현장 B-28",
    ("Microsoft-Windows-Kernel-Power", 41): "비정상 재부팅 — 일부러 일으킬 수 없다, 현장 B-28",
    ("Windows Error Reporting", 1001): "윈도 CI 에서 생기지 않았다(FailFast 는 1000 만, CI 42723626534) — 현장 B-28",
    (DEFENDER, 1116): "EICAR — 러너의 Defender 는 꺼져 있을 수 있다, 현장 B-28",
    (DEFENDER, 1117): "현장 B-28",
    (DEFENDER, 1001): "현장 B-28",
    ("MSSQLSERVER", 18454): "SQL Server 가 있는 PC — 현장 B-28",
    ("MSSQL$EMR", 18486): "이름 있는 인스턴스의 잠긴 계정 — 현장 B-28",
    ("MSSQLSERVER", 18456): "SQL Server 가 있는 PC — 현장 B-28",
    ("MSSQLSERVER", 9002): "현장 B-28",
    ("MSSQLSERVER", 3041): "현장 B-28",
    ("EMRService", 104): "업무 프로그램 흉내 (실측 대상 아님)",
    ("EMRService", 1116): "업무 프로그램 흉내 (실측 대상 아님)",
    ("EMRAgent", 104): "업무 프로그램 흉내 (실측 대상 아님)",
    ("EMRService", 18456): "업무 프로그램 흉내 (실측 대상 아님)",
    ("EMRService", 701): "업무 프로그램 흉내 (실측 대상 아님)",
    ("OpenSSH", 4): "Windows 용 OpenSSH 서버 — 현장 B-28",
}
# 규칙의 조건 가운데 안 맞음 표본으로 지키지 않는 것 (규칙 번호, 조건 이름) → 이유. 그 밖의 조건은 그 조건으로 떨어지는 표본이 있어야 한다 —
# 표본이 없는 조건은 지워져도 아무 시험도 실패하지 않는다(검토)
ALWAYS_PRESENT = {"group_key:host": "PC 이름은 늘 있다 (에이전트가 붙인다)"}
UNGUARDED = {
    (1000002, "source"): "7031·7034 를 쓰는 다른 소스의 실제 로그 형식을 찾지 못했다",
    (1000022, "event_id"): "SubStatus 이름은 4625 템플릿에만 있다 — event_id 하나로만 떨어지는 다른 이벤트가 없다",
    (1000008, "group_key:user"): "계정 잠금(4740)에는 늘 잠긴 계정 이름이 있다",
    (1000023, "group_key:user"): "원격 데스크톱 로그온 성공(4624 유형 10)에는 늘 계정이 있다",
    (1000025, "term_field:account"): "원격 데스크톱 로그온 성공(4624 유형 10)에는 늘 계정이 있다",
}
# 형식에 맞지 않는 표본 → 거부 문구. 앞으로도 캡처되지 않을 이벤트(업무 프로그램 흉내 EMR…)로 써서, 고정 자료가 바뀌어도
# 경우마다 그 검사 하나가 막는지 본다(다른 검사로 떨어져 초록이면 그 검사가 빠져도 모른다 — 검토)
DOC = ("    windows: {event: 104, envelope: 7045}\n    ref: r\n"
       "    fields: {ProviderName: EMRService, Channel: Application, Level: 4, Keywords: '0x80000000000000', Version: 0, "
       "Message: m}\n    strings: ['104']\n")
BROKEN = {
    "근거 없음": ("match:\n  - why: x\n    iis: '2026-11-09 01:02:03 10.0.0.10 GET / - 443 - 10.0.0.1 UA - 500 0 0 1'\n",
                 "ref"),
    "실측 없는데 봉투 없음": ("match:\n  - why: x\n    windows: {event: 65000}\n    ref: r\n", "실측 레코드가 없습니다"),
    "판단 값 빠짐": ("match:\n  - why: x\n" + DOC.replace("Level: 4, ", ""), r"fields 에 \['Level'\]"),
    "실측 있는데 봉투": ("match:\n  - why: x\n" + DOC.replace("event: 104", "event: 4625").replace("EMRService", SEC),
                      "실측 레코드가 생겼습니다"),
    "실측의 정체를 바꿈": ("match:\n  - why: x\n    windows: {event: 4625}\n    fields: {ProviderName: EMRService}\n", "바꾸지 않습니다"),
    "fields 로 이벤트 ID": ("match:\n  - why: x\n" + DOC.replace("Message: m}", "Message: m, EventID: 4740}"), "쓰지 않습니다"),
    "봉투에 where": ("match:\n  - why: x\n" + DOC.replace("envelope: 7045}", "envelope: 7045, where: {X: 1}}"), "where·provider"),
    "이유 없음": ("match:\n  - windows: {event: 4625}\n", "why"),
    "종류 둘": ("match:\n  - why: x\n    windows: {event: 4625}\n    iis: line\n    ref: r\n", "하나만"),
    "없는 이름": ("match:\n  - why: x\n    windows: {event: 4625}\n    inserts: {Logontype: 10}\n", "템플릿에 Logontype"),
    "모르는 키": ("match:\n  - why: x\n    windows: {event: 4625}\n    insert: {LogonType: 10}\n", "모르는 키"),
    "안 맞음에 fails_on 없음": ("no_match:\n  - why: x\n    windows: {event: 4624}\n", "fails_on"),
    "맞음에 fails_on": ("match:\n  - why: x\n    windows: {event: 4625}\n    fails_on: [event_id]\n", "no_match 표본에만"),
    "규칙 번호 다름": ("rule: 1000006\n", "파일 이름과 같은"),
}


def judge(sample: rs.Sample, host: str = "SAMPLE-PC") -> tuple[bool, list[dict], dict]:
    """(맞음, 실패한 조건, 이벤트) — 표본의 마지막 레코드를 규칙 시험기처럼 판단한다."""
    rule = RULES[sample.sid]
    events = rs.normalize_all(rs.with_host(sample.records, host), NOW)
    assert events, f"{sample.id}: 저장되는 레코드가 없습니다"
    event = events[-1]
    assert not event.flags & BAD_FLAGS, f"{sample.id}: 표본이 제대로 해석되지 않습니다 ({sorted(event.flags)})"
    live = event.to_live(NOW)
    checks = ruletest.checks(rule, rule.event_filter(), live)
    return all(c["ok"] for c in checks), [c for c in checks if not c["ok"]], live


def test_every_log_rule_has_both_kinds_of_samples():
    missing = []
    for sid, rule in sorted(RULES.items()):
        if rule.kind in NO_LOG_SAMPLES:
            continue
        mine = [s for s in SAMPLES if s.sid == sid]
        if {s.expect for s in mine} != {True, False}:
            missing.append(f"{sid} {rule.name}: " + ("표본 없음" if not mine else "맞음·아님 중 한쪽만"))
    assert not missing, "기본 규칙에 표본이 없습니다 (tests/fixtures/rules/README.md):\n" + "\n".join(missing)


def test_sample_files_belong_to_log_rules():
    sids = {s.sid for s in SAMPLES}
    assert not sorted(sids - set(RULES)), f"없는 규칙 번호의 표본: {sorted(sids - set(RULES))}"
    no_log = sorted(sid for sid in sids & set(RULES) if RULES[sid].kind in NO_LOG_SAMPLES)
    assert not no_log, f"로그로 판단하지 않는 규칙의 표본: {no_log}"
    assert {r.kind for r in RULES.values()} - {"count", "new_terms"} <= set(NO_LOG_SAMPLES)


@pytest.mark.parametrize("sample", SAMPLES, ids=[s.id for s in SAMPLES])
def test_sample(sample: rs.Sample):
    matched, failed, event = judge(sample)
    seen = {k: event.get(k) for k in ("source", "category", "channel", "provider", "event_id", "level", "username", "src_ip")}
    if sample.expect:
        assert matched, (f"{sample.id} '{RULES[sample.sid].name}' 이(가) 이 로그를 세야 합니다 — {sample.why}\n"
                         f"맞지 않은 조건: {failed}\n이벤트: {seen}")
    else:
        got = {rs.label(c) for c in failed}
        assert got == sample.fails_on, (
            f"{sample.id} '{RULES[sample.sid].name}': 이 표본은 {sorted(sample.fails_on)} 로 떨어져야 하는데 "
            f"{sorted(got) or '맞았습니다'} — {sample.why}\n이벤트: {seen}")


@pytest.mark.parametrize(("body", "message"), BROKEN.values(), ids=list(BROKEN))
def test_loader_rejects_incomplete_samples(tmp_path, body, message):
    path = tmp_path / "1000005.yaml"
    path.write_text(body if body.startswith("rule:") else "rule: 1000005\n" + body, encoding="utf-8")
    with pytest.raises(rs.SampleError, match=message):
        rs.load(path)


def test_docs_based_windows_samples_are_listed():
    docs = {(r["ProviderName"], int(r["EventID"])) for s in SAMPLES if not s.real
            for r in s.records[-1:] if r.get("log_source") == "winevtlog"}
    assert docs == set(DOCS_BASED), f"목록에 없음 {sorted(docs - set(DOCS_BASED))}, 목록에만 있음 {sorted(set(DOCS_BASED) - docs)}"


def test_every_rule_condition_is_guarded_by_a_no_match_sample():
    missing, stale = [], []
    for sid, rule in sorted(RULES.items()):
        if rule.kind in NO_LOG_SAMPLES:
            continue
        need = {rs.label(c) for c in ruletest.checks(rule, rule.event_filter(), {})} - set(ALWAYS_PRESENT)
        have = set().union(*(s.fails_on for s in SAMPLES if s.sid == sid and not s.expect))
        missing += [f"{sid} {rule.name}: {name}" for name in sorted(need - have) if (sid, name) not in UNGUARDED]
        stale += [f"{sid} {name}" for s, name in UNGUARDED if s == sid and (name not in need or name in have)]
    assert not missing, "그 조건으로 떨어지는 안 맞음 표본이 없습니다 (표본을 더하거나 UNGUARDED 에 이유를):\n" + "\n".join(missing)
    assert not stale, f"UNGUARDED 에서 지울 것 (조건이 없어졌거나 표본이 생김): {stale}"
