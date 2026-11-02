"""수집 품질 지표 (BACKLOG B-56 1단계) — DB 없는 단위 시험: 정규화기가 다는 표시, 수집 집계 칸, 점검 필요 문구."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app import quality, repository
from app.normalizers import normalize, normalize_safely
from app.normalizers.base import Event

NOW = datetime(2026, 11, 2, 5, 0, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl"


def _real_4625() -> dict:
    return next(r for r in map(json.loads, FIXTURE.read_text(encoding="utf-8").splitlines()) if r.get("EventID") == 4625)


def test_windows_template_mismatch_is_flagged():
    record = _real_4625()
    assert normalize(record, NOW).flags == frozenset()                       # 실측 레코드는 템플릿과 같은 길이
    short = {**record, "StringInserts": record["StringInserts"][:15]}       # 이벤트 버전이 바뀌어 필드가 빠졌다
    assert normalize(short, NOW).flags == {"template_mismatch"}
    unknown = {**record, "EventID": 4999, "StringInserts": ["a"]}           # 템플릿이 없는 이벤트는 불일치가 아니다
    assert normalize(unknown, NOW).flags == frozenset()
    with_map = {**short, "EventData": {"TargetUserName": "kim"}}            # 에이전트가 이름 맵을 보내면 템플릿을 쓰지 않는다
    assert normalize(with_map, NOW).flags == frozenset()


def test_older_versions_are_not_template_mismatches():
    """옛 버전은 앞부분이 같다(named 가 뒤 이름만 버린다) — 표시하지 않는다. 실측 버전의 길이가 다르거나 처음 보는 새 버전이 다르면 표시
    (검토에서 재현: Server 2016·2019 의 4697 v0·Server 2012 R2 의 4624 v1 이 매일 '템플릿 불일치'로 남았다)."""
    from app.normalizers.win_templates import SECURITY, mismatch

    assert not mismatch(SECURITY, 4697, ["x"] * 9, 0) and not mismatch(SECURITY, 4624, ["x"] * 21, 1)
    assert mismatch(SECURITY, 4697, ["x"] * 9, 1)          # 실측 버전인데 길이가 다르다
    assert mismatch(SECURITY, 4624, ["x"] * 29, 4)         # 처음 보는 새 버전 — 중간에 끼었을 수 있다
    assert not mismatch(SECURITY, 4624, ["x"] * 28, 3)     # VERSIONED 와 같다
    assert mismatch(SECURITY, 4740, ["x"] * 30, 0) and not mismatch(SECURITY, 4740, ["x"] * 2, 0)   # 실측 안 한 템플릿은 많을 때만


def test_verified_versions_match_the_real_records():
    """VERIFIED 는 윈도 CI 실측 레코드의 버전과 같아야 한다 (기본 이름 = 그 버전, 4624 는 v3 이 VERSIONED)."""
    from app.normalizers import win_templates as wt

    for r in map(json.loads, FIXTURE.read_text(encoding="utf-8").splitlines()):
        key, v = (r.get("ProviderName") or "", r.get("EventID") or 0), int(r.get("Version") or 0)
        if key in wt.TEMPLATES and (*key, v) not in wt.VERSIONED:
            assert wt.VERIFIED.get(key) == v, key


def test_unparsed_iis_and_parse_errors_are_flagged(monkeypatch):
    line = {"log": "garbage line that is not w3c", "file": "W3SVC9\\u_ex1.log", "agent_host": "WEB-Q", "log_source": "iis"}
    assert normalize(line, NOW).flags == {"unparsed"}
    from app import normalizers

    def boom(record, now, ctx=None):
        raise ValueError("깨진 레코드")
    monkeypatch.setattr(normalizers, "normalize", boom)
    event = normalize_safely({"log": "x", "agent_host": "PC-Q", "log_source": "syslog"}, NOW)
    assert event.flags == {"parse_error"} and event.raw["_ingest"]["error"].startswith("ValueError")


def test_stream_counts_carry_quality_columns():
    def ev(host, ts, flags=()):
        return Event(ts=ts, host=host, source="winevtlog", level=4, message="m", raw={}, channel="Security", flags=frozenset(flags))
    events = [ev("PC-1", NOW), ev("PC-1", NOW - timedelta(hours=2), {"template_mismatch"}),
              ev("PC-1", NOW - timedelta(days=3), {"parse_error"}), ev("PC-1", NOW + timedelta(minutes=10)),
              ev("PC-0", NOW + timedelta(minutes=2), {"unparsed"})]
    hosts, sources, channels, n, pe, up, tm, late, future, lag = repository._stream_counts(events, NOW)
    assert hosts == ["PC-0", "PC-1"] and sources == ["winevtlog"] * 2 and channels == ["Security"] * 2
    assert (n, pe, up, tm, late, future) == ([1, 4], [0, 1], [1, 0], [0, 1], [0, 2], [0, 1])   # 2분 미래는 봐준다
    assert lag == [0, 3 * 86400]


def test_attention_lines():
    rows = [{"host": "WEB-1", "source": "iis", "channel": "IIS", "unparsed": 3, "parse_errors": 0, "late_n": 0},
            {"host": "PC-9", "source": "winevtlog", "channel": "Security", "unparsed": 0, "parse_errors": 2, "late_n": 500}]
    total = {"n": 1000, "parse_errors": 2, "unparsed": 3, "template_mismatch": 0, "late_n": 500, "future_n": 0}
    texts = [a["text"] for a in quality.attention({"total": total, "rows": rows})]
    assert len(texts) == 3 and "WEB-1(iis · IIS)" in texts[1] and "PC-9(winevtlog · Security)" in texts[0]
    assert "500건(50%)" in texts[2]
    assert quality.attention({"total": {**total, "late_n": 50, "parse_errors": 0, "unparsed": 0}, "rows": rows}) == []
    assert quality.attention(None) == []
