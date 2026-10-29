"""기록 종류별 보관기간 설정과 법정 최소 경고 (ADR-040) — DB 없이."""

from __future__ import annotations

import importlib
from dataclasses import replace

import pytest

from app import partitions


@pytest.mark.parametrize(("change", "fragment"), [
    ({}, None),
    ({"retention_days": 200}, "접속기록 법정 최소 1년"),
    ({"audit_retention_days": 365}, "권한 부여·변경·말소 기록 법정 최소 3년"),
    ({"report_retention_days": 100}, "점검 증적"),
    ({"sensitive_access_log": True}, "민감정보(진료정보) 처리 시스템의 접속기록 법정 최소 2년"),   # 기본 365 < 730
    ({"sensitive_access_log": True, "retention_days": 730}, None),
    ({"sensitive_access_log": True, "retention_days": 200}, "2년"),   # 한 줄만 (1년 미달 문구와 겹치지 않게)
])
def test_retention_warnings(monkeypatch, change, fragment):
    monkeypatch.setattr(partitions, "settings", replace(partitions.settings, **change))
    warnings = partitions.retention_warnings()
    assert (warnings == []) if fragment is None else (len(warnings) == 1 and fragment in warnings[0])


def test_alert_retention_defaults_to_the_log_retention(monkeypatch):
    # compose 는 정하지 않은 변수를 빈 값으로 넘긴다 — 빈 값이면 로그 보관기간을 따른다 (int('') 로 멈추지 않게)
    from app import config

    monkeypatch.setenv("WLM_RETENTION_DAYS", "730")
    monkeypatch.setenv("WLM_ALERT_RETENTION_DAYS", "")
    monkeypatch.delenv("WLM_AUDIT_RETENTION_DAYS", raising=False)
    fresh = importlib.reload(config).Settings()
    try:
        assert (fresh.alert_retention_days, fresh.audit_retention_days, fresh.report_retention_days) == (730, 1095, 1095)
        monkeypatch.setenv("WLM_ALERT_RETENTION_DAYS", "90")
        assert importlib.reload(config).Settings().alert_retention_days == 90
    finally:
        monkeypatch.undo()
        importlib.reload(config)
