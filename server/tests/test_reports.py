"""점검 보고서 단위 테스트 (DB 없이): 만들 기간 계산, HTML 이스케이프, 요약·공지, 설정 검증."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from app.reports import builder, config, render
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
    assert "점검 필요 2건" in page and "직전 기간 대비 +20%" in page
    # 화면 iframe(sandbox)·인쇄본에는 앱 링크를 넣지 않는다 (누르면 틀 안에서 막힘). 메일에는 넣는다
    assert "#/reports/5" not in page and "#/reports/5" in render.notice(payload(), 5).html


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


def test_integrity_check_from_cli_or_screen_renders():
    """CLI(예전: 개수)·화면(파일 이름 목록) 어느 쪽이 남긴 무결성 확인이어도 보고서를 그린다 — 문제가 있을 때가 바로 보여야 할 때."""
    for detail, n in (({"files": 3, "bad": 2}, 2), ({"files": 3, "bad": ["a.jsonl.gz"]}, 1), ({"files": 3, "bad": 0}, 0)):
        retention = {**payload()["retention"], "last_integrity_check": {"at": "2026-10-14T01:00:00+00:00", "detail": detail}}
        p = payload(retention=retention)
        assert f"문제 {n}건" in render.page(p, 1) and render.notice(p, 1).html
        assert builder.integrity_bad_count(retention["last_integrity_check"]) == n
        bad = [a for a in builder._attention(p) if "무결성" in a["text"]]
        assert bad == ([{"level": "bad", "text": f"마지막 보관 파일 무결성 확인에서 문제 {n}건"}] if n else [])


def test_trend_buckets_follow_wall_clock_on_dst_days():
    berlin = ZoneInfo("Europe/Berlin")
    utc = lambda *a: datetime(*a, tzinfo=berlin).astimezone(UTC)
    # 서머타임 시작 주 (일요일이 23시간): 7칸이고 마지막 칸이 일요일 자정
    week = builder.trend_buckets("weekly", utc(2026, 3, 23), utc(2026, 3, 30), berlin)
    assert len(week) == 7 and week[-1] == utc(2026, 3, 29) and week[0] == utc(2026, 3, 23)
    # 서머타임 끝나는 날 (25시간): 1시간 칸 25개 (하루짜리 칸 하나로 뭉치지 않는다)
    day = builder.trend_buckets("daily", utc(2026, 10, 25), utc(2026, 10, 26), berlin)
    assert len(day) == 25 and day[1] - day[0] == timedelta(hours=1)
    assert len(builder.trend_buckets("weekly", utc(2026, 10, 19), utc(2026, 10, 26), berlin)) == 7
    assert len(builder.trend_buckets("daily", utc(2026, 10, 14), utc(2026, 10, 15), berlin)) == 24
    # 30분만 바뀌는 시간대(로드하우섬)의 23.5시간 하루: 마지막 반 시간도 칸이 있어야 로그가 빠지지 않는다
    lord_howe = ZoneInfo("Australia/Lord_Howe")
    start, end = datetime(2026, 10, 4, tzinfo=lord_howe), datetime(2026, 10, 5, tzinfo=lord_howe)
    assert end.astimezone(UTC) - start.astimezone(UTC) == timedelta(hours=23, minutes=30)  # 같은 시간대끼리 빼면 벽시계 기준이라 UTC 로
    assert len(builder.trend_buckets("daily", start.astimezone(UTC), end.astimezone(UTC), lord_howe)) == 24
    # 서머타임 시작 날 일간 보고서 기간도 23시간
    p = {k: (s.astimezone(berlin), e.astimezone(berlin)) for k, s, e in due_periods(utc(2026, 3, 30, 9, 0), CFG, berlin)}
    assert p["daily"] == (datetime(2026, 3, 29, tzinfo=berlin), datetime(2026, 3, 30, tzinfo=berlin))


def test_daily_compares_with_same_weekday_last_week():
    """일간을 바로 전날과 비교하면 주말·휴일 다음마다 '로그가 줄었다'는 거짓 경고 → 지난주 같은 요일과 비교한다."""
    s, e = builder.previous_window(kst(2026, 10, 18), kst(2026, 10, 19), SEOUL)   # 일요일 보고서
    assert (s.astimezone(SEOUL), e.astimezone(SEOUL)) == (kst(2026, 10, 11), kst(2026, 10, 12))
    berlin = ZoneInfo("Europe/Berlin")
    s, e = builder.previous_window(datetime(2026, 3, 30, tzinfo=berlin), datetime(2026, 3, 31, tzinfo=berlin), berlin)
    assert s == datetime(2026, 3, 23, tzinfo=berlin) and e - s == timedelta(hours=24)
    ev = {**payload()["events"], "total": 100, "previous": 1000, "previous_label": "지난주 같은 요일"}
    p = payload(events=ev, security={**payload()["security"], "items": []})
    assert {"level": "warn", "text": "로그 수가 지난주 같은 요일보다 90% 줄었습니다 — 수집 PC 상태를 확인하세요"} in builder._attention(p)
    assert "지난주 같은 요일 대비 -90%" in render.page(p, 1)


def test_bad_display_tz_falls_back_to_utc(monkeypatch):
    from app import config as app_config

    monkeypatch.setattr(app_config, "settings", replace(app_config.settings, display_tz="Asia/Seol"))
    assert app_config.display_zone().key == "UTC"
    assert builder.period_label("daily", datetime(2026, 10, 14, tzinfo=UTC), datetime(2026, 10, 15, tzinfo=UTC)) == "2026-10-14 (수)"


def test_alerting_problems_are_in_attention():
    """평가·전송이 멈췄으면 그 사이 알림은 오지 않았다 — 아침 보고서가 알린다 (ADR-045). 예전 보고서(alerting 없음)는 그대로."""
    p = payload()
    assert not [a for a in builder._attention(p) if a["text"].startswith("알림 기능")]
    p["alerting"] = {"problems": [{"level": "bad", "code": "evaluator_down", "text": "알림 규칙 평가가 12분째 멈춰 있습니다"},
                                  {"level": "warn", "code": "gave_up", "text": "최근 24시간 동안 보내지 못하고 재시도를 멈춘 알림 2건"}]}
    lines = [a for a in builder._attention(p) if a["text"].startswith("알림 기능")]
    assert lines == [{"level": "bad", "text": "알림 기능: 알림 규칙 평가가 12분째 멈춰 있습니다"},
                     {"level": "warn", "text": "알림 기능: 최근 24시간 동안 보내지 못하고 재시도를 멈춘 알림 2건"}]
