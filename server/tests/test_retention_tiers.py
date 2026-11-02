"""이벤트 보관 등급 (BACKLOG B-70) — DB 없는 단위 시험: 설정 검증, 등급 고르기(겹치면 긴 쪽), 보관기간(만들 때 기간보다 줄지 않음)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app import retention

GOOD = """
tiers:
  - id: access
    name: 진료정보 시스템 접속기록
    query: 'host:EMR-01'
    keep_days: 730
  - id: web
    name: 웹 요청
    query: 'source:iis'
    keep_days: 120
"""


def test_parse_good_config():
    config = retention.parse(GOOD)
    assert config.error is None and [(t.id, t.keep_days) for t in config.tiers] == [("access", 730), ("web", 120)]
    assert config.tier("web").name == "웹 요청" and config.tier("nope") is None
    assert config.max_keep_days() == 730
    assert retention.parse("").tiers == () and retention.parse("tiers: []").error is None


@pytest.mark.parametrize(("text", "needle"), [
    ("tiers: [", "YAML"),
    ("tiers: x", "tiers"),
    ("tiers:\n  - id: Web\n    query: 'source:iis'\n    keep_days: 30", "id"),
    ("tiers:\n  - id: web.x\n    query: 'source:iis'\n    keep_days: 30", "id"),       # 파일 이름·backup.sh 에 들어간다
    ("tiers:\n  - id: web\n    query: 'source:iis'\n    keep_days: 30\n  - id: web\n    query: 'host:a'\n    keep_days: 9", "겹칩니다"),
    ("tiers:\n  - id: web\n    query: ''\n    keep_days: 30", "query"),
    ("tiers:\n  - id: web\n    query: 'hots:x'\n    keep_days: 30", "query"),
    ("tiers:\n  - id: web\n    query: 'source:iis'\n    keep_days: 0", "keep_days"),
    ("tiers:\n  - id: web\n    query: 'source:iis'\n    keep_days: true", "keep_days"),
    ("tiers:\n  - id: web\n    query: 'source:iis'\n    keep_days: '30'", "keep_days"),
    ("tiers:\n" + "".join(f"  - id: t{i}\n    query: 'host:a'\n    keep_days: 30\n" for i in range(11)), "10개"),
])
def test_parse_rejects(text, needle):
    config = retention.parse(text)
    assert config.error and needle in config.error and config.tiers == ()


def test_classify_takes_the_longest_matching_tier():
    """접속기록이 '웹 요청 120일' 에도 맞아 짧아지지 않게 — 겹치면 긴 쪽."""
    tiers = retention.parse(GOOD).tiers
    assert retention.classify(tiers, {"host": "EMR-01", "source": "iis"}).id == "access"
    assert retention.classify(tiers, {"host": "WEB-01", "source": "iis"}).id == "web"
    assert retention.classify(tiers, {"host": "PC-01", "source": "winevtlog"}) is None
    short_first = retention.parse(GOOD.replace("730", "60")).tiers   # 이제 web(120) 이 더 길다
    assert retention.classify(short_first, {"host": "EMR-01", "source": "iis"}).id == "web"


def test_keep_days_never_shorter_than_when_archived():
    """만료 = 그 달 끝 + max(만들 때 기간, 지금 설정) — 설정을 늘리면 기존 파일도 늘고, 줄여도 약속한 기간보다 일찍 지우지 않는다.
    (WLM_RETENTION_DAYS=365·WLM_DB_RETENTION_DAYS=90 은 conftest)"""
    config = retention.parse(GOOD)
    meta = {"tier": "web", "keep_days": 120, "to": "2026-01-01T00:00:00+00:00"}
    assert retention.keep_days(meta, config) == 120
    assert retention.keep_days(meta, retention.parse(GOOD.replace("120", "400"))) == 400     # 늘림
    assert retention.keep_days(meta, retention.parse(GOOD.replace("120", "30"))) == 120      # 줄여도 그대로
    assert retention.keep_days(meta, retention.Config()) == 120                              # 등급을 지워도
    assert retention.keep_days({"tier": None, "to": meta["to"]}, config) == 365              # 기본 파일은 WLM_RETENTION_DAYS
    assert retention.expires_at(meta, config) == datetime(2026, 5, 1, tzinfo=UTC)


def test_notes_for_short_tiers():
    notes = retention.notes(retention.parse(GOOD.replace("120", "30")))
    assert len(notes) == 1 and "DB 보관기간(90일)보다 짧아" in notes[0]
    notes = retention.notes(retention.parse(GOOD))
    assert len(notes) == 1 and "접속기록(법정 최소 1년)" in notes[0]


def test_shipped_config_and_its_example_are_valid():
    """기본 파일(등급 없음)과 주석의 예시가 그대로 쓸 수 있는 설정이어야 한다 — 예시를 복사해 쓰다 틀리면 보관이 멈춘다."""
    from pathlib import Path

    here = Path(__file__).resolve().parent   # 저장소: server/tests → ../../config, 컨테이너: /app/tests → /app/config
    path = next(p for p in (here.parent / "config" / "retention.yaml", here.parents[1] / "config" / "retention.yaml") if p.exists())
    text = path.read_text(encoding="utf-8")
    shipped = retention.parse(text)
    assert shipped.error is None and shipped.tiers == ()
    after = text.split("# 예:\n", 1)[1].split("\n\n", 1)[0]
    example = "\n".join(line[2:] for line in after.splitlines())
    config = retention.parse(example)
    assert config.error is None and [t.id for t in config.tiers] == ["emr-access", "web"]
    assert retention.classify(config.tiers, {"host": "EMR-WAS-01", "category": "security", "source": "iis"}).id == "emr-access"
