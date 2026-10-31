"""알림 대상 정기 시험 전송과 Oracle 생존 신호 (BACKLOG B-34 남은 것) — DB 없는 단위 시험.

회귀: 알림 경로(메일 비밀번호 만료·웹훅 토큰 폐기)가 깨져도 실제 알림이 나기 전까지 몰랐고, 서버 전체가 멈추면 알릴 길 자체가
없었다(폐쇄망 병원에는 외부 감시 도구가 없는 경우가 많다).
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.alerts import health, watchdog
from app.alerts.notifiers import NotifierError, OracleNotifier

NOW = datetime(2026, 10, 29, 3, 0, tzinfo=UTC)   # 목요일 12:00 KST


def _moment(monkeypatch, weekday, at="09:00", now=NOW):
    monkeypatch.setattr(watchdog, "settings", replace(watchdog.settings, alert_test_weekday=weekday, alert_test_time=at))
    return watchdog.test_moment(now)


@pytest.mark.parametrize(("weekday", "at", "expected"), [
    (1, "09:00", datetime(2026, 10, 26, 0, 0, tzinfo=UTC)),    # 이번 주 월요일 09:00 KST
    (4, "09:00", datetime(2026, 10, 29, 0, 0, tzinfo=UTC)),    # 오늘 09:00 (이미 지남)
    (4, "13:00", datetime(2026, 10, 22, 4, 0, tzinfo=UTC)),    # 오늘 13:00 은 아직 — 지난주 목요일
    (7, "23:30", datetime(2026, 10, 25, 14, 30, tzinfo=UTC)),  # 지난 일요일
    (1, "아홉시", datetime(2026, 10, 26, 0, 0, tzinfo=UTC)),    # 잘못 쓴 시각은 09:00
])
def test_weekly_moment_is_the_latest_one_in_the_past(monkeypatch, weekday, at, expected):
    assert _moment(monkeypatch, weekday, at) == expected


def test_weekly_test_can_be_turned_off(monkeypatch):
    assert _moment(monkeypatch, 0) is None
    assert _moment(monkeypatch, 8) is None


# ------------------------------------------------------------------ 상태 판단

def _assess(tests=None, heartbeats=None, targets=None):
    engine = {"interval_sec": 30, "rule_timeout_sec": 20, "running": True, "standby": False,
              "progress_at": NOW - timedelta(seconds=5), "cycle_sec": 0.5, "current_rule": None}
    dispatcher = {"enabled": True, "running": True, "standby": False, "progress_at": NOW, "targets": targets or {}}
    return health.assess(engine, dispatcher, [], 0, [], {"당직"}, NOW, ["당직"], tests, heartbeats)


def test_failed_test_send_is_reported_until_a_later_success():
    failed = {"당직": {"at": NOW - timedelta(hours=3), "ok": False, "error": "웹훅 응답 403: token revoked",
                     "scheduled": True}}
    [problem] = _assess(tests=failed)["problems"]
    assert problem["code"] == "test_failed" and "'당직'(으)로 정기 시험 전송이 실패했습니다 (3시간 0분 전)" in problem["text"]
    assert _assess(tests={"당직": {**failed["당직"], "ok": True}})["problems"] == []
    # 지금 '보내지 못하는 중'으로 보이면 그쪽 줄 하나로 (같은 문제를 두 번 말하지 않는다)
    down = {"당직": {"failing_since": NOW - timedelta(minutes=2), "last_error": "x"}}
    assert [p["code"] for p in _assess(tests=failed, targets=down)["problems"]] == ["target_failing"]


def test_real_delivery_after_a_failed_test_clears_the_warning():
    """시험이 실패했지만 그 뒤 실제 알림이 그 곳으로 나갔으면 고쳐진 것이다 — 다음 주까지 경고를 남기지 않는다 (검토)."""
    failed = {"당직": {"at": NOW - timedelta(hours=3), "ok": False, "error": "x", "scheduled": True}}
    later_ok = {"당직": {"failing_since": None, "last_ok_at": NOW - timedelta(hours=1)}}
    assert _assess(tests=failed, targets=later_ok)["problems"] == []
    earlier_ok = {"당직": {"failing_since": None, "last_ok_at": NOW - timedelta(hours=4)}}
    assert [p["code"] for p in _assess(tests=failed, targets=earlier_ok)["problems"]] == ["test_failed"]


def test_heartbeat_failing_for_five_minutes_is_reported():
    short = {"사내DB": {"failing_since": NOW - timedelta(minutes=2), "error": "ORA-12541"}}
    assert _assess(heartbeats=short)["problems"] == []
    long = {"사내DB": {"failing_since": NOW - timedelta(minutes=7), "error": "ORA-12541: TNS:no listener"}}
    [problem] = _assess(heartbeats=long)["problems"]
    assert problem["code"] == "heartbeat_failing" and "ORA-12541" in problem["text"]
    assert "heartbeat_failing" in health.public_view(_assess(heartbeats=long), "0")["problems"]


# ------------------------------------------------------------------ Oracle 생존 신호 SQL

def test_heartbeat_sql_binds_are_checked_and_only_used_ones_are_passed(monkeypatch):
    with pytest.raises(NotifierError, match="생존 신호 SQL 에 알 수 없는 바인드 변수: rule_name"):
        OracleNotifier("o", object(), "INSERT INTO T VALUES (:alert_id)", "UPDATE H SET A = :at, R = :rule_name")
    writer = OracleNotifier("o", object(), "INSERT INTO T VALUES (:alert_id)", "UPDATE H SET A = :at, S = ':version';")
    assert writer.heartbeat_sql == "UPDATE H SET A = :at, S = ':version'"   # 끝의 ; 는 드라이버가 받지 않는다
    seen = {}
    monkeypatch.setattr(writer, "_execute", lambda binds, commit, sql=None: seen.update(binds=binds, commit=commit, sql=sql))
    asyncio.run(writer.heartbeat({"at": NOW, "status": "ok", "version": "0.5.0", "problems": 0}))
    assert seen == {"binds": {"at": NOW}, "commit": True, "sql": writer.heartbeat_sql}   # 문자열 안의 ':version' 은 바인드가 아니다
    assert OracleNotifier("o", object(), "INSERT INTO T VALUES (:alert_id)").heartbeat_sql == ""


def test_hung_oracle_does_not_pile_up_heartbeat_threads():
    """응답 없는 Oracle 에 1분마다 스레드가 하나씩 쌓여 로그인·메일까지 막히던 것 (검토에서 재현) — 앞의 것이 끝나야 다음."""
    import threading

    from app.alerts import notifiers

    release = threading.Event()
    calls = []
    writer = OracleNotifier("멈춘DB", object(), "INSERT INTO T VALUES (:alert_id)", "UPDATE H SET A = :at")

    def hang(binds, commit, sql=None):
        calls.append(binds)
        release.wait(5)

    writer._execute = hang

    async def scenario():
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(writer.heartbeat({"at": NOW}), 0.2)
        with pytest.raises(NotifierError, match="앞의 생존 신호가 아직 끝나지 않았습니다"):
            await writer.heartbeat({"at": NOW})
        release.set()
        await asyncio.wrap_future(notifiers._HEARTBEAT_INFLIGHT["멈춘DB"])
        await writer.heartbeat({"at": NOW})   # 끝났으면 다시 낸다

    asyncio.run(scenario())
    assert len(calls) == 2

