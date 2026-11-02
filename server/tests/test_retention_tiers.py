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
    example = "\n".join(line.replace("  # ", "  ", 1) if line.startswith("  # ") else line for line in text.splitlines())
    config = retention.parse(example)
    assert config.error is None and [t.id for t in config.tiers] == ["emr-access", "web"]
    assert retention.classify(config.tiers, {"host": "EMR-WAS-01", "category": "security", "source": "iis"}).id == "emr-access"


@pytest.mark.parametrize(("text", "needle"), [
    ("tiers: []\ntiers:\n  - id: a\n    query: 'host:x'\n    keep_days: 30", "두 번"),      # 예시 주석을 풀고 'tiers: []' 를 남김
    ("tiers:\n  - id: a\n    query: 'host:x'\n    keep_days: 30\n    keep_days: 9", "두 번"),
    ("tier: []", "알 수 없는 키"),
    ("tiers:\n  - id: a\n    query: 'host:x'\n    keep: 30\n    keep_days: 9", "알 수 없는 키 keep"),
    ("tiers:\n  - id: a\n    query: 'host:x host:y'\n    keep_days: 30", "맞을 수 없는"),
    ("tiers:\n  - id: a\n    name: 2026-02-30\n    query: 'host:x'\n    keep_days: 30", "YAML"),       # 없는 날짜 → ValueError
    ("tiers: " + "[" * 2000 + "]" * 2000, "YAML"),
])
def test_parse_rejects_silent_mistakes(text, needle):
    config = retention.parse(text)
    assert config.error and needle in config.error, config.error


def test_load_survives_a_non_utf8_file(tmp_path, monkeypatch):
    """한글 메모장 ANSI(CP949)로 저장하면 UnicodeDecodeError 로 서버 기동·정리가 멈췄다(검토에서 재현) — 설정 오류로."""
    from dataclasses import replace

    path = tmp_path / "retention.yaml"
    path.write_bytes("# 한글 주석\ntiers: []\n".encode("cp949"))
    monkeypatch.setattr(retention, "settings", replace(retention.settings, retention_config=str(path)))
    assert "UTF-8" in retention.load().error
    path.write_bytes("\ufefftiers: []\n".encode())
    assert retention.load().error is None


def test_sensitive_tier_satisfies_the_two_year_rule(monkeypatch):
    """민감정보 시스템의 접속기록만 730일 등급으로 두는 것이 권장 방법 — 그런 등급이 있으면 2년 미달 경고를 내지 않는다(준비도가 영영 '나쁨'이었다)."""
    from dataclasses import replace

    from app import partitions

    sensitive = replace(partitions.settings, sensitive_access_log=True, retention_days=365)
    monkeypatch.setattr(partitions, "settings", sensitive)
    monkeypatch.setattr(retention, "settings", sensitive)
    monkeypatch.setattr(retention, "load", lambda: retention.parse(GOOD))
    assert not [w for w in partitions.retention_warnings() if "2년" in w]
    assert any("진료정보 시스템 접속기록" in n for n in retention.notes(retention.parse(GOOD)))
    monkeypatch.setattr(retention, "load", lambda: retention.parse(GOOD.replace("730", "400")))
    assert [w for w in partitions.retention_warnings() if "2년" in w]


def test_classify_folds_the_message_once_with_the_same_result():
    tiers = retention.parse(GOOD + "\n  - id: msg\n    query: '\"로그온 실패\"'\n    keep_days: 400\n").tiers
    event = {"host": "PC-01", "source": "winevtlog", "message": "계정 로그온 실패 (0xC000006A)"}
    assert retention.classify(tiers, event).id == "msg"
    assert retention.classify(tiers, {**event, "message": None}) is None
