"""수집 완전성 1단계: 늘 오던 채널이 끊긴 것 (B-37, ADR-046) — 통합 시험.

회귀: GPO 변경 등으로 DC 의 Security 수집만 끊겨도 하트비트·System 로그는 계속 와서 '연락 끊김'은 조용했고,
점검 보고서는 전체 0건·절반 이하만 봤다. 규칙은 켜져 있는데 데이터가 없는 상태가 가장 흔하고 조용한 실패다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
NOW = datetime.now(UTC)


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _history(host, channel, per_day, days, last_at, source="winevtlog"):
    """지난 며칠의 채널별 수신 (어제까지). 마지막 날의 마지막 수신 시각을 정한다."""
    for i in range(days, 0, -1):
        day = (NOW - timedelta(days=i)).date()
        last = last_at if i == 1 else datetime.combine(day, datetime.min.time(), UTC) + timedelta(hours=23)
        sql("INSERT INTO agent_streams (host, source, channel, day, n, first_at, last_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (host, source, channel, day, per_day, datetime.combine(day, datetime.min.time(), UTC), last))


def _win(host, channel, event_id):
    return {"date": NOW.isoformat(), "EventID": event_id, "Channel": channel, "Computer": host, "agent_host": host,
            "log_source": "winevtlog", "Message": "m"}


@pytest.fixture(scope="module")
def client():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        # DC-01: System 로그는 지금도 오는데 Security 는 어제 저녁부터 조용하다
        assert c.post("/api/ingest", json=[_win("DC-01", "System", 7036), _win("WS-02", "System", 7036)],
                      headers=KEY).status_code == 200
        _history("DC-01", "Security", 5000, 6, NOW - timedelta(hours=7))
        _history("DC-01", "Application", 20, 6, NOW - timedelta(hours=7))   # 하루 20건 — 7시간 조용한 것은 평소
        _history("WS-02", "Security", 3000, 3, NOW - timedelta(hours=9))     # 사흘치뿐 — 평소를 말할 수 없다
        _history("OFF-1", "Security", 4000, 6, NOW - timedelta(hours=30))    # PC 자체가 끊김 — '연락 끊김'이 따로 알린다
        sql("INSERT INTO agents (host, last_seen) VALUES ('OFF-1', %s)", (NOW - timedelta(hours=30),))
        # 오래전부터 켜져 있던 PC 들 — 조용한 시간은 PC 가 켜져 있던 동안만 센다 (방금 처음 들어온 PC 는 그때부터)
        sql("UPDATE agents SET up_since = %s WHERE host IN ('DC-01', 'WS-02')", (NOW - timedelta(days=3),))
        yield c


def test_ingest_counts_each_channel_per_day(client):
    assert client.post("/api/ingest", json=[_win("CNT-1", "Security", 4624)] * 3 + [_win("CNT-1", "System", 7036)],
                       headers=KEY).status_code == 200
    assert client.post("/api/ingest", json=[_win("CNT-1", "Security", 4625)], headers=KEY).status_code == 200
    rows = sql("SELECT channel, n FROM agent_streams WHERE host = 'CNT-1' AND day = %s ORDER BY channel", (NOW.date(),))
    assert rows == [("Security", 4), ("System", 1)]


def test_only_the_usual_channel_that_went_quiet_is_flagged(client):
    from app import repository

    rows = client.portal.call(repository.silent_streams, datetime.now(UTC))
    assert [(r["host"], r["channel"]) for r in rows] == [("DC-01", "Security")]
    assert rows[0]["days"] == 6 and rows[0]["quiet_limit"] == timedelta(hours=6)
    items = client.get("/api/agents", params={"since": "24h"}, headers=CSRF).json()["silent_streams"]
    assert [(s["host"], s["channel"], s["quiet_limit_sec"]) for s in items] == [("DC-01", "Security", 6 * 3600)]


def test_scoped_users_see_only_their_pcs(client):
    from fastapi.testclient import TestClient

    from app.main import app

    temp = client.post("/api/users", json={"username": "ward", "role": "viewer"}, headers=CSRF).json()
    assert client.post("/api/user-groups", json={"name": "병동", "scope_hosts": ["WS-*"], "member_ids": [temp["user"]["id"]]},
                       headers=CSRF).status_code == 200
    ward = TestClient(app)
    ward.post("/api/auth/login", json={"username": "ward", "password": temp["temp_password"]}, headers=CSRF)
    ward.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": "Scope#Member2026"},
              headers=CSRF)
    assert ward.get("/api/agents", params={"since": "24h"}, headers=CSRF).json()["silent_streams"] == []


def test_report_points_at_the_quiet_channel(client):
    from app.reports import builder, render

    payload = client.portal.call(builder.build, "daily", NOW - timedelta(days=1), NOW + timedelta(minutes=1))
    assert payload["agents"]["silent_streams_total"] == 1
    assert payload["agents"]["silent_streams"][0] | {"last_at": None} == {
        "host": "DC-01", "source": "winevtlog", "channel": "Security", "last_at": None, "per_day": 5000}
    texts = [a["text"] for a in payload["attention"]]
    assert "늘 오던 로그가 끊긴 채널 1개: DC-01 Security — 감사 정책·에이전트 설정을 확인하세요" in texts
    assert "늘 오던 로그가 끊긴 채널" in render.html(payload)


# ------------------------------------------------------------------ B-37 2단계: 이벤트 ID·규칙별 데이터 유무·채널 끊김 알림

STREAM_RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패 급증
    match: { event_id: "4625", channel: Security }
    notify: [운영팀]
  - name: 늘 오던 로그 끊김
    enabled: false
    kind: stream_silent
    channels: [Security]
    notify: [운영팀]
"""


@pytest.fixture
def stream_rules(client):
    import os
    from pathlib import Path

    from app.alerts import coverage
    from app.alerts.engine import engine

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(STREAM_RULES, encoding="utf-8")
    engine.reload(force=True)
    coverage.forget()
    yield engine
    Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
    engine.reload(force=True)
    coverage.forget()


def test_ingest_remembers_which_event_ids_each_pc_sends(client):
    assert client.post("/api/ingest", json=[_win("EVT-1", "Security", 4624), _win("EVT-1", "Security", 4625)],
                       headers=KEY).status_code == 200
    rows = sql("SELECT event_id, last_at FROM agent_events WHERE host = 'EVT-1' ORDER BY event_id")
    assert [r[0] for r in rows] == [4624, 4625]
    # 한 시간 안에 다시 오면 고치지 않는다 (수집 부담 — 거의 모든 묶음이 쓰기 없이 지나간다)
    assert client.post("/api/ingest", json=[_win("EVT-1", "Security", 4624)], headers=KEY).status_code == 200
    assert sql("SELECT last_at FROM agent_events WHERE host = 'EVT-1' AND event_id = 4624")[0][0] == rows[0][1]


def test_rule_coverage_shows_pcs_that_do_not_send_the_channel(client, stream_rules):
    # SYS-ONLY: Windows 이벤트는 보내는데 Security 는 보내지 않는다 (GPO·에이전트 설정 문제)
    assert client.post("/api/ingest", json=[_win("SYS-ONLY", "System", 7036)], headers=KEY).status_code == 200
    rules = {r["name"]: r for r in client.get("/api/alerts/config", headers=CSRF).json()["rules"]}
    c = rules["로그온 실패 급증"]["coverage"]
    assert "SYS-ONLY" in c["missing"] and c["channel_pcs"] < c["pcs"] and c["event_pcs"] >= 1
    assert rules["늘 오던 로그 끊김"]["coverage"] is None and rules["늘 오던 로그 끊김"]["channels"] == ["Security"]
    from app.reports import builder

    payload = client.portal.call(builder.build, "daily", NOW - timedelta(days=1), NOW + timedelta(minutes=1))
    [gap] = payload["agents"]["coverage_gaps"]
    assert gap["channel"] == "Security" and "SYS-ONLY" in gap["hosts"] and gap["rules"] == ["로그온 실패 급증"]
    assert any("규칙이 보는 채널 Security 을(를) 보내지 않는 PC" in a["text"] for a in payload["attention"])


def test_quiet_channel_alerts_once_and_resolves_when_it_comes_back(client, stream_rules):
    rule = next(r for r in stream_rules.config.rules if r.kind == "stream_silent")
    now = datetime.now(UTC)
    [alert_id] = client.portal.call(stream_rules.evaluate, rule, now)
    [(key, payload)] = sql("SELECT group_key, payload FROM alerts WHERE id = %s", (alert_id,))
    assert key == "DC-01 · Security" and payload["stream"] == {"host": "DC-01", "source": "winevtlog", "channel": "Security",
                                                               "per_day": 5000}
    assert "DC-01 · Security 로그가 6시간 넘게 들어오지 않습니다" in payload["description"] or payload["kind"] == "stream_silent"
    assert client.portal.call(stream_rules.evaluate, rule, now) == []   # 끊긴 동안 한 번만
    assert client.post("/api/ingest", json=[_win("DC-01", "Security", 4624)], headers=KEY).status_code == 200
    assert client.portal.call(stream_rules.evaluate, rule, datetime.now(UTC)) == []
    assert sql("SELECT status, auto_resolved FROM alerts WHERE id = %s", (alert_id,)) == [("resolved", True)]


def test_scoped_users_match_stream_alerts_by_pc(client, stream_rules):
    from app.alerts.visibility import alert_host

    assert alert_host("늘 오던 로그 끊김", "DC-01 · Security") == "DC-01"
    assert alert_host("로그온 실패 급증", "DC-01 · Security") == "DC-01 · Security"   # 다른 종류의 규칙은 이름 그대로
    # 규칙을 지우거나 이름을 바꿔 종류를 몰라도 'PC · 채널' 모양이면 PC 로 — 와일드카드 범위가 채널 글자에 맞지 않게
    assert alert_host("지운 규칙", "DC-01 · Security") == "DC-01"


def test_pc_that_was_switched_off_is_not_called_silent(client):
    """주말 동안 꺼졌다 월요일에 켜진 PC — 채널이 조용한 시간은 켜진 뒤부터 센다 (검토에서 재현)."""
    from app import repository

    _history("WK-1", "Application", 40, 6, NOW - timedelta(hours=40))
    sql("INSERT INTO agents (host, last_seen, up_since) VALUES ('WK-1', %s, %s)", (NOW, NOW - timedelta(hours=1)))
    rows = client.portal.call(repository.silent_streams, datetime.now(UTC))
    assert "WK-1" not in {r["host"] for r in rows}
    sql("UPDATE agents SET up_since = %s WHERE host = 'WK-1'", (NOW - timedelta(days=2),))   # 이틀째 켜져 있는데 조용하다
    rows = client.portal.call(repository.silent_streams, datetime.now(UTC))
    assert ("WK-1", "Application") in {(r["host"], r["channel"]) for r in rows}
    sql("DELETE FROM agents WHERE host = 'WK-1'")
    sql("DELETE FROM agent_streams WHERE host = 'WK-1'")


def test_pc_maintenance_silence_covers_its_channel_alerts(client, stream_rules):
    """'모든 규칙 · DC-01' 무음(PC 점검)이 'DC-01 · Security' 채널 끊김 알림에도 걸린다 (검토)."""
    from app import repository

    assert client.post("/api/alerts/silences", json={"group_key": "DC-01", "duration_sec": 3600, "reason": "DC 점검"},
                       headers=CSRF).status_code == 200
    now = datetime.now(UTC)
    silence = client.portal.call(repository.active_silence, "늘 오던 로그 끊김", "DC-01 · Security", now, "DC-01")
    assert silence is not None and silence["reason"] == "DC 점검"
    assert client.portal.call(repository.active_silence, "늘 오던 로그 끊김", "WS-02 · Security", now, "WS-02") is None


def test_fresh_event_ids_are_not_rewritten(client):
    """한 시간 안에 고친 줄은 고르기에서 빠져 잠그지도 쓰지도 않는다 — xmax 가 그대로 (검토)."""
    assert client.post("/api/ingest", json=[_win("XMAX-1", "Security", 4624)], headers=KEY).status_code == 200
    [(before,)] = sql("SELECT xmax::text FROM agent_events WHERE host = 'XMAX-1'")
    assert client.post("/api/ingest", json=[_win("XMAX-1", "Security", 4624)], headers=KEY).status_code == 200
    assert sql("SELECT xmax::text FROM agent_events WHERE host = 'XMAX-1'") == [(before,)]


def test_old_counts_are_purged(client):
    from app import partitions

    client.portal.call(partitions.purge_agent_streams, NOW + timedelta(days=100))
    assert sql("SELECT count(*) FROM agent_streams") == [(0,)]
    assert sql("SELECT count(*) FROM agent_events") == [(0,)]   # 90일 넘게 보이지 않은 이벤트 ID
