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
