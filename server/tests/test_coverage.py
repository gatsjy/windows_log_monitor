"""규칙별 데이터 유무·채널 끊김 규칙 (BACKLOG B-37 2단계) — DB 없는 단위 시험.

회귀: 규칙 팩은 감사 정책이 켜져 있다고 가정하는데, 어느 PC 에서 규칙이 보는 로그가 한 번도 오지 않는지 볼 곳이 없었다
(규칙은 켜져 있는데 데이터가 없는 상태가 가장 흔하고 조용한 실패). 늘 오던 채널이 끊긴 것도 화면·보고서에만 있고 알림이 없었다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.alerts import configdiff, coverage
from app.alerts.message import AlertMessage
from app.alerts.rules import ConfigError, parse, parse_text

NOW = datetime(2026, 10, 31, 3, 0, tzinfo=UTC)


def _rule(**raw):
    return parse({"rules": [{"name": "r", "notify": ["운영팀"], **raw}]}).rules[0]


# ------------------------------------------------------------------ 규칙이 필요로 하는 데이터

@pytest.mark.parametrize(("raw", "expected"), [
    ({"match": {"event_id": "4625", "channel": "Security"}}, (set(), {"Security"}, {4625})),
    ({"match": {"query": "event_id:4720,4722 channel:Security -host:TEST-01"}}, (set(), {"Security"}, {4720, 4722})),
    ({"match": {"source": "iis", "level": "2"}}, ({"iis"}, set(), set())),
])
def test_need_comes_from_the_rule_conditions(raw, expected):
    n = coverage.need(_rule(**raw))
    assert (set(n.sources), set(n.channels), set(n.event_ids)) == expected


@pytest.mark.parametrize("raw", [
    {"match": {"level": "1"}},                                  # 수준만 — 모든 로그가 후보라 판단하지 않는다
    {"match": {"category": "auth"}},
    {"kind": "agent_silent"},
    {"kind": "stream_silent"},
])
def test_rules_without_a_data_shape_are_not_judged(raw):
    assert coverage.need(_rule(**raw)) is None


ALIVE = {"DC-01", "WS-01", "WS-02", "WS-03", "LNX-01"}
STREAMS = [{"host": h, "source": "winevtlog", "channel": c} for h, c in [
    ("DC-01", "Security"), ("DC-01", "System"), ("WS-01", "Security"), ("WS-01", "System"),
    ("WS-02", "System"),                       # Security 를 보내지 않는 Windows PC — GPO·에이전트 설정 문제
    ("WS-03", "Security"), ("OLD-01", "Security")]] + [{"host": "LNX-01", "source": "syslog", "channel": "sshd"}]
EVENTS = [{"host": "DC-01", "source": "winevtlog", "channel": "Security", "event_id": 4625},
          {"host": "WS-01", "source": "winevtlog", "channel": "Security", "event_id": 4624},
          {"host": "DB-01", "source": "mssql", "channel": "", "event_id": 18456}]


def test_channel_gap_and_rare_event_counts():
    c = coverage.evaluate(coverage.need(_rule(match={"event_id": "4625", "channel": "Security"})), ALIVE, STREAMS, EVENTS)
    # 대상 = 살아 있고 Windows 이벤트를 보내는 PC (Linux·끊긴 PC 는 빼고)
    assert (c["pcs"], c["channel_pcs"], c["event_pcs"]) == (4, 3, 1)
    assert c["missing"] == ["WS-02"] and c["missing_total"] == 1


def test_conditions_match_like_the_rule_does():
    """규칙은 PC·채널을 정확히(대소문자까지) 맞추고 * 는 와일드카드가 아니다 — 다르게 맞추면 영영 맞지 않는 규칙이 '데이터 있음'으로 보였다."""
    c = coverage.evaluate(coverage.need(_rule(match={"channel": "Security", "host": "WS-01,WS-02,WS-03"})), ALIVE, STREAMS, EVENTS)
    assert (c["pcs"], c["channel_pcs"], c["missing"]) == (3, 2, ["WS-02"])
    c = coverage.evaluate(coverage.need(_rule(match={"query": "channel:Security -host:WS-02"})), ALIVE, STREAMS, EVENTS)
    assert c["missing_total"] == 0
    assert coverage.evaluate(coverage.need(_rule(match={"channel": "Security", "host": "WS-*"})), ALIVE, STREAMS, EVENTS)["pcs"] == 0
    wrong_case = coverage.evaluate(coverage.need(_rule(match={"channel": "security"})), ALIVE, STREAMS, EVENTS)
    assert wrong_case["channel_pcs"] == 0 or wrong_case["pcs"] == 0   # 'security' 채널은 아무도 보내지 않는다


def test_channel_is_inferred_from_where_the_event_ids_arrive():
    """기본 팩의 보안 규칙은 이벤트 ID 만 정한다 — 4625 가 실제로 오는 채널(Security)을 보내지 않는 PC 를 짚는다 (검토에서 재현)."""
    c = coverage.evaluate(coverage.need(_rule(match={"event_id": "4625"})), ALIVE, STREAMS, EVENTS)
    assert (c["channels"], c["channels_implied"], c["pcs"], c["channel_pcs"], c["missing"]) == (
        ["Security"], True, 4, 3, ["WS-02"])
    # 어디서도 본 적 없는 이벤트 ID 는 채널을 모른다 — 숫자만 (경고 없음)
    c = coverage.evaluate(coverage.need(_rule(match={"event_id": "4720"})), ALIVE, STREAMS, EVENTS)
    assert (c["channels"], c["missing_total"], c["event_pcs"]) == ([], 0, 0)


def test_source_is_inferred_from_where_the_event_ids_arrive():
    """SQL Server 18456 은 ERRORLOG 에서 온다 — Windows PC 를 대상으로 0/n 을 보이던 것 (검토)."""
    streams = STREAMS + [{"host": "DB-01", "source": "mssql", "channel": ""}]
    c = coverage.evaluate(coverage.need(_rule(match={"category": "mssql", "event_id": "18456"})), ALIVE | {"DB-01"}, streams, EVENTS)
    assert (c["pcs"], c["event_pcs"]) == (1, 1)


def test_gaps_group_rules_by_channel_and_skip_disabled_rules():
    rules = parse_text("""rules:
  - { name: a, match: { event_id: "4625", channel: Security }, notify: [x] }
  - { name: b, match: { event_id: "4720", channel: Security }, notify: [x] }
  - { name: c, enabled: false, match: { channel: System }, notify: [x] }
""").rules
    data = {r.name: coverage.evaluate(coverage.need(r), ALIVE | {"WS-04"}, STREAMS + [
        {"host": "WS-04", "source": "winevtlog", "channel": "Application"}], EVENTS) for r in rules}
    assert coverage.gaps(rules, data) == [{"channel": "Security", "total": 2, "hosts": ["WS-02", "WS-04"], "rules": ["a", "b"]}]
    assert "missing_all" not in coverage.public(data["a"])


def test_gap_total_is_the_union_of_missing_pcs():
    """규칙마다 빠진 PC 가 다르면 수는 합집합 — 큰 쪽 하나만 세면 이름과 수가 어긋났다 (검토)."""
    rules = parse_text("""rules:
  - { name: a, match: { channel: Security, host: "WS-02,WS-01" }, notify: [x] }
  - { name: b, match: { channel: Security, host: "WS-04,WS-01" }, notify: [x] }
""").rules
    alive = ALIVE | {"WS-04"}
    streams = STREAMS + [{"host": "WS-04", "source": "winevtlog", "channel": "System"}]
    data = {r.name: coverage.evaluate(coverage.need(r), alive, streams, EVENTS) for r in rules}
    assert coverage.gaps(rules, data)[0] | {"rules": None} == {"channel": "Security", "total": 2, "hosts": ["WS-02", "WS-04"],
                                                               "rules": None}


# ------------------------------------------------------------------ 채널 끊김 규칙

def test_stream_silent_rule_shape():
    r = _rule(kind="stream_silent", hosts=["DC-01"], channels=["Security"])
    assert (r.kind, r.hosts, r.channels, r.resolve, r.group_by) == ("stream_silent", ("DC-01",), ("Security",), "auto", "host")
    with pytest.raises(ConfigError, match="resolve"):
        _rule(kind="stream_silent", resolve="later")


@pytest.mark.parametrize(("before", "after", "expected"), [
    ("[Security]", "[Security, System]", [("channels", False)]),
    ("[Security, System]", "[Security]", [("channels", True)]),
    ("[]", "[Security]", [("channels", True)]),      # 전부에서 하나로 좁힘
    ("[Security]", "[]", [("channels", False)]),
    ("[Security]", "[security]", []),                # 채널은 대소문자를 가리지 않고 맞춘다
])
def test_narrowing_a_stream_rule_weakens(before, after, expected):
    text = "rules:\n  - { name: s, kind: stream_silent, channels: %s, notify: [x] }\n"
    changes = configdiff.diff(parse_text(text % before), parse_text(text % after))
    assert [(c["change"], c["weakens"]) for c in changes] == expected


def test_stream_silent_wording():
    m = AlertMessage(rule="늘 오던 로그 끊김", severity="warning", kind="stream_silent", group_by="host", group_key="DC-01 · Security",
                     event_count=0, threshold=0, window_sec=6 * 3600, fired_at=NOW, last_event_at=NOW - timedelta(hours=7),
                     stream={"host": "DC-01", "source": "winevtlog", "channel": "Security", "per_day": 5000})
    assert "DC-01 · Security 로그가 6시간 넘게 들어오지 않습니다 — PC 는 살아 있습니다 (평소 하루 5,000건" in m.summary()
    assert m.to_dict()["stream"]["channel"] == "Security"
    resolved = AlertMessage.from_dict({**m.to_dict(), "event_action": "resolve", "resolved_at": NOW.isoformat()})
    assert resolved.summary().startswith("DC-01 · Security 로그가 다시 들어옵니다")
    plain = AlertMessage(rule="x", severity="info", kind="count", group_by="host", group_key="h", event_count=1, threshold=1,
                         window_sec=60, fired_at=NOW)
    assert "stream" not in plain.to_dict()   # 다른 알림의 payload 는 예전과 같다
