"""점검 보고서 단위 테스트 (DB 없이): 만들 기간 계산, HTML 이스케이프, 요약·공지, 설정 검증."""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from app.reports import config, render
from app.reports.scheduler import due_periods, latest_period

SEOUL = ZoneInfo("Asia/Seoul")
CFG = {"daily": {"enabled": True, "time": "09:00"}, "weekly": {"enabled": True, "weekday": 1, "time": "09:00"}, "targets": []}


def kst(*args) -> datetime:
    return datetime(*args, tzinfo=SEOUL)


def periods(now, cfg=CFG):
    return {kind: (s.astimezone(SEOUL), e.astimezone(SEOUL)) for kind, s, e in due_periods(now.astimezone(UTC), cfg, SEOUL)}


def test_daily_is_yesterday_after_send_time():
    assert periods(kst(2026, 10, 15, 8, 59)).get("daily") is None          # 아직 09:00 전
    assert periods(kst(2026, 10, 15, 9, 0))["daily"] == (kst(2026, 10, 14), kst(2026, 10, 15))
    assert periods(kst(2026, 10, 15, 23, 59))["daily"] == (kst(2026, 10, 14), kst(2026, 10, 15))
    # 자정 직후(UTC 로는 전날 15시)에도 표시 시간대 기준 날짜로 계산한다
    assert periods(kst(2026, 10, 16, 0, 30)).get("daily") is None


def test_weekly_is_last_monday_to_sunday():
    monday = kst(2026, 10, 12, 9, 0)
    assert periods(monday)["weekly"] == (kst(2026, 10, 5), kst(2026, 10, 12))
    assert periods(kst(2026, 10, 12, 8, 59)).get("weekly") is None
    # 이번 주 내내 같은 기간 (고유 색인이 중복을 막는다)
    assert periods(kst(2026, 10, 18, 23, 0))["weekly"] == (kst(2026, 10, 5), kst(2026, 10, 12))
    # 보내는 요일을 수요일로 바꾸면 화요일에는 아직
    wed = {**CFG, "weekly": {"enabled": True, "weekday": 3, "time": "07:30"}}
    assert periods(kst(2026, 10, 13, 12, 0), wed).get("weekly") is None
    assert periods(kst(2026, 10, 14, 7, 30), wed)["weekly"] == (kst(2026, 10, 5), kst(2026, 10, 12))


def test_disabled_kinds_are_skipped():
    off = {"daily": {"enabled": False, "time": "09:00"}, "weekly": {"enabled": False, "weekday": 1, "time": "09:00"}}
    assert due_periods(kst(2026, 10, 12, 12, 0), off, SEOUL) == []


def test_latest_period_for_manual_reports():
    now = kst(2026, 10, 15, 3, 0)   # 목요일 새벽
    s, e = latest_period("daily", now, SEOUL)
    assert (s.astimezone(SEOUL), e.astimezone(SEOUL)) == (kst(2026, 10, 14), kst(2026, 10, 15))
    s, e = latest_period("weekly", now, SEOUL)
    assert (s.astimezone(SEOUL), e.astimezone(SEOUL)) == (kst(2026, 10, 5), kst(2026, 10, 12))


def payload(**overrides) -> dict:
    p = {
        "version": 1, "kind": "daily", "title": "일간 점검 보고서 · 2026-10-14 (수)",
        "period": {"start": "2026-10-13T15:00:00+00:00", "end": "2026-10-14T15:00:00+00:00", "label": "x", "tz": "Asia/Seoul"},
        "generated_at": "2026-10-15T00:00:00+00:00",
        "events": {"total": 1200, "previous": 1000, "by_level": {"error": 3, "info": 1197},
                   "trend": {"step_sec": 3600, "buckets": ["2026-10-13T15:00:00+00:00", "2026-10-13T16:00:00+00:00"],
                             "total": [700, 500], "errors": [3, 0]},
                   "top_error_hosts": [{"value": "<script>alert(1)</script>", "n": 3}], "by_category": []},
        "security": {"items": [{"key": "log_cleared", "label": "감사·시스템 로그 삭제", "event_ids": [1102, 104], "n": 1,
                                "attention": "bad"}],
                     "logon_failed_users": [{"value": "kim\"><img src=x onerror=alert(2)>", "n": 9}], "logon_failed_ips": []},
        "alerts": {"fired": 2, "by_severity": {"error": 2}, "by_status": {"open": 1, "acked": 0, "resolved": 1},
                   "unresolved_by_severity": {"error": 1},
                   "unresolved_oldest": [{"id": 7, "fired_at": "2026-10-14T01:00:00+00:00", "rule": "R<x>", "severity": "error",
                                          "group_key": "PC'1", "status": "open"}],
                   "resolved_in_period": 1, "median_resolve_min": 12.5},
        "agents": {"total": 3, "online": 2, "stale": 0, "offline": 1,
                   "silent": [{"host": "OLD-PC", "last_seen": "2026-10-10T00:00:00+00:00", "last_ip": None}]},
        "retention": {"db_retention_days": 90, "retention_days": 365, "partitions": 3, "rows_estimate": 100,
                      "oldest_partition": None, "archives": 0, "archives_missing": 0, "last_integrity_check": None},
        "backup": {"problems": [], "last_backup": None, "last_verify": None, "last_verify_ok_at": None},
        "attention": [{"level": "bad", "text": "감사·시스템 로그 삭제 1건"}, {"level": "warn", "text": "연락이 끊긴 PC 1대"}],
    }
    p.update(overrides)
    return p


def test_html_escapes_every_log_derived_value():
    page = render.page(payload(), 5, {"reviewed_at": None})
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "<img src=x" not in page and "onerror=alert(2)&gt;" in page
    assert "R&lt;x&gt;" in page and "PC&#x27;1" in page
    assert "#/reports/5" in page and "점검 필요 2건" in page and "직전 기간 대비 +20%" in page


def test_review_and_no_attention_rendering():
    reviewed = {"reviewed_at": datetime(2026, 10, 15, 1, 0, tzinfo=UTC), "reviewed_by": "kim", "review_note": "<b>조치함</b>"}
    page = render.page(payload(attention=[]), 5, reviewed)
    assert "특이 사항 없음" in page and "점검 확인" in page and "&lt;b&gt;조치함&lt;/b&gt;" in page


def test_summary_and_notice():
    s = render.summary(payload())
    assert s == {"attention": 2, "bad": 1, "severity": "error", "headline": "점검 필요 2건"}
    assert render.summary(payload(attention=[{"level": "warn", "text": "x"}]))["severity"] == "warning"
    assert render.summary(payload(attention=[]))["severity"] == "info"
    n = render.notice(payload(), 9)
    assert n.title.endswith("— 점검 필요 2건") and n.link.endswith("#/reports/9") and n.html and "로그 1,200건" in n.text


def test_config_validation():
    known = {"운영팀", "슬랙"}
    cfg = config.clean({"daily": {"enabled": True, "time": "07:05"}, "weekly": {"weekday": "5"}, "targets": ["슬랙", " 슬랙 "]},
                       known)
    assert cfg == {"daily": {"enabled": True, "time": "07:05"}, "weekly": {"enabled": True, "weekday": 5, "time": "09:00"},
                   "targets": ["슬랙"]}
    for bad in ({"daily": {"time": "9:00"}}, {"daily": {"time": "24:00"}}, {"weekly": {"weekday": 8}},
                {"weekly": {"weekday": "월"}}, {"targets": ["없는곳"]}):
        with pytest.raises(config.ReportConfigError):
            config.clean(bad, known)
