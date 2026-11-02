"""처음 보는 값 탐지 (BACKLOG B-47, ADR-063) 통합 시험 — 거슬러 배우기, 조합마다 한 번, history 뒤 다시, 몰려오면 한 통, 상한, 조건 변경."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30
rules:
  - name: 새 출발지
    sid: 1009001
    kind: new_terms
    match: {{ event_id: "4624" }}
    fields: [account, ip]
    history: 30d
    learn: 1d
    burst: {burst}
    max_terms: {max_terms}
    severity: warning
    notify: [운영팀]
"""


def sql(query, params=None):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _config(burst=20, max_terms=50000):
    from app.alerts.engine import engine

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES.format(burst=burst, max_terms=max_terms), encoding="utf-8")
    engine.reload(force=True)
    return engine.config.rules[0]


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

    rules_file = Path(os.environ["WLM_ALERTS_FILE"])
    saved = rules_file.read_text(encoding="utf-8") if rules_file.exists() else None
    with TestClient(app) as c:
        now = datetime.now(UTC)   # 지난달 파티션 — 거슬러 배우기·만료 시험이 며칠 전 로그를 넣는다 (달 초에 돌아도)
        start = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
        sql(f"CREATE TABLE IF NOT EXISTS events_{start:%Y_%m} PARTITION OF events FOR VALUES FROM ('{start:%Y-%m-%d}')"
            f" TO ('{now:%Y-%m}-01')")
        yield c
    if saved is None:
        rules_file.unlink(missing_ok=True)
    else:
        rules_file.write_text(saved, encoding="utf-8")
    from app.alerts.engine import engine

    engine.reload(force=True)


def logon(user: str, ip: str, ago: timedelta = timedelta(0), event_id: int = 4624):
    """받은 시각을 ago 만큼 앞당긴 로그온 (같은 달 파티션 안에서)."""
    at = datetime.now(UTC) - ago
    sql("INSERT INTO events (received_at, ts, host, source, category, event_id, level, username, src_ip, message, raw)"
        " VALUES (%s, %s, 'DC-01', 'winevtlog', 'security', %s, 4, %s, %s, '로그온', '{}'::jsonb)", (at, at, event_id, user, ip))


def evaluate(client, rule, now=None):
    from app.alerts.engine import RuleRun, engine

    run = RuleRun()
    fired = client.portal.call(engine.evaluate, rule, now or datetime.now(UTC), run)
    return fired, run


def alerts():
    return sql("SELECT group_key, payload->'terms' FROM alerts WHERE rule = '새 출발지' ORDER BY id")


def test_learns_backwards_then_alerts_once(client):
    rule = _config()
    logon("HOSP\\kim", "10.0.0.5", timedelta(hours=5))    # 배우는 기간(1일) 안 — 거슬러 배움
    logon("lee", "10.0.0.6", timedelta(hours=3))
    logon("park", "10.0.0.7", timedelta(days=2))          # 배우는 기간 밖 — 배우지 않음
    fired, run = evaluate(client, rule)
    assert fired == [] and run.terms["terms"] == 2 and not run.terms["backfilling"]
    assert sql("SELECT count(*) FROM seen_terms WHERE state = 'learned'") == [(2,)]
    logon("KIM", "10.0.0.5")                              # 같은 계정(표기만 다름)·같은 IP — 이미 본 값
    logon("kim", "10.0.0.99")                             # 새 출발지
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1
    [(key, terms)] = alerts()
    assert key == "kim · 10.0.0.99" and terms["values"] == ["kim", "10.0.0.99"] and terms["host"] == "DC-01"   # 그 값을 처음 본 PC
    assert evaluate(client, rule)[0] == []               # 겹쳐 본 구간에서도 다시 알리지 않는다
    logon("kim", "10.0.0.99")
    assert evaluate(client, rule)[0] == []


def test_message_text(client):
    [(alert_payload,)] = sql("SELECT payload FROM alerts WHERE rule = '새 출발지' ORDER BY id LIMIT 1")
    from app.alerts.message import AlertMessage

    m = AlertMessage.from_dict(alert_payload)
    assert "처음 보는 값: 사용자 표기 통일" not in m.summary()
    assert "10.0.0.99" in m.summary() and "최근 30일 동안 없던 조합" in m.summary()


def test_new_again_after_history(client):
    rule = _config()
    sql("UPDATE seen_terms SET last_seen = now() - interval '40 days', state = 'learned' WHERE term[1] = 'lee'")
    logon("lee", "10.0.0.6")
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1
    terms = alerts()[-1][1]
    assert terms["values"] == ["lee", "10.0.0.6"] and terms["prev_last_seen"]


def test_burst_becomes_one_summary(client):
    rule = _config(burst=3)
    for i in range(5):
        logon(f"user{i}", "10.1.0.1")
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1
    key, terms = alerts()[-1]
    assert key == "처음 보는 값 5개" and terms["count"] == 5 and len(terms["items"]) == 5
    assert sql("SELECT count(*) FROM seen_terms WHERE state = 'aggregated'") == [(5,)]
    assert evaluate(client, rule)[0] == []


def test_cap_counts_and_errors(client):
    from app.alerts.newterms import CappedError

    held = sql("SELECT terms_n FROM new_terms_state")[0][0]
    rule = _config(max_terms=max(100, held))
    for i in range(102):
        logon(f"cap{i}", "10.2.0.1")
    with pytest.raises(CappedError, match="상한"):
        evaluate(client, rule)
    assert sql("SELECT terms_n <= 100, overflow_n > 0 FROM new_terms_state") == [(True, True)]
    sql("UPDATE new_terms_state SET overflow_n = 0")
    sql("DELETE FROM seen_terms WHERE term[1] LIKE 'cap%%'")
    sql("DELETE FROM events WHERE username LIKE 'cap%%'")   # 다음 시험의 거슬러 배우기에 다시 잡히지 않게
    sql("UPDATE new_terms_state SET terms_n = (SELECT count(*) FROM seen_terms)")


def test_filter_change_relearns_and_holds_alerts(client):
    rule = _config()
    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES.format(burst=20, max_terms=50000).replace(
        'match: { event_id: "4624" }', 'match: { event_id: "4624,4625" }'), encoding="utf-8")
    from app.alerts.engine import engine

    engine.reload(force=True)
    rule = engine.config.rules[0]
    logon("choi", "10.3.0.1", timedelta(hours=2), event_id=4625)   # 새 조건으로 거슬러 배울 것
    before = len(alerts())
    fired, _ = evaluate(client, rule)
    assert fired == [] and len(alerts()) == before
    [(reason,)] = sql("SELECT relearn_reason FROM new_terms_state")
    assert reason == "조건 바뀜"
    logon("choi", "10.3.0.1", event_id=4625)
    assert evaluate(client, rule)[0] == []                        # 배운 값


def test_validation():
    from app.alerts.rules import ConfigError, parse_text

    base = "rules:\n  - name: x\n    kind: new_terms\n    severity: warning\n    notify: [a]\n"
    for extra, needle in (("    fields: [account]\n", "조건이 필요"),
                          ("    match: {event_id: '4624'}\n", "fields"),
                          ("    match: {event_id: '4624'}\n    fields: [a, b, c, d]\n", "fields"),
                          ("    match: {event_id: '4624'}\n    fields: [nope]\n", "fields"),
                          ("    match: {event_id: '4624'}\n    fields: [ip]\n    threshold: 3\n", "threshold"),
                          ("    match: {event_id: '4624'}\n    fields: [ip]\n    learn: 40d\n    history: 30d\n", "learn"),
                          ("    match: {event_id: '4624'}\n    fields: [ip]\n    history: 200d\n", "history"),
                          ("    match: {event_id: '4624'}\n    fields: [ip]\n    max_terms: 10\n", "max_terms"),
                          ("    match: {event_id: '4624'}\n    fields: [ip]\n    resolve: auto\n", "resolve")):
        with pytest.raises(ConfigError, match=needle):
            parse_text(base + extra)
    [r] = parse_text(base + "    match: {event_id: '4624'}\n    fields: [account, f.EventData.IpAddress]\n").rules
    assert r.terms_fields == ("account", "f.EventData.IpAddress") and r.group_by == "none" and r.burst == 20


def test_rule_api_preview_and_accesslog(client):
    """화면 경로: 규칙 저장(_clean_rule) → 설정 응답 → 미리보기(처음 보인 값 목록) — 계정·IP 값이 보이니 접속기록."""
    from app import accesslog

    initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
    client.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
    client.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
    accesslog.forget()
    rule = {"name": "새 출발지 화면", "kind": "new_terms", "severity": "warning", "notify": ["운영팀"], "match": {"event_id": "4624"},
            "fields": ["account", "ip"], "history_sec": 30 * 86400, "learn_sec": 86400, "burst": 5}
    r = client.put("/api/alerts/rules", json={"rule": rule}, headers=CSRF)
    assert r.status_code == 200, r.text
    saved = {x["name"]: x for x in client.get("/api/alerts/config", headers=CSRF).json()["rules"]}["새 출발지 화면"]
    assert (saved["kind"], saved["fields"], saved["history_sec"], saved["learn_sec"], saved["burst"]) == (
        "new_terms", ["account", "ip"], 30 * 86400, 86400, 5)
    assert "burst: 5" in Path(os.environ["WLM_ALERTS_FILE"]).read_text(encoding="utf-8")
    logon("preview-user", "10.9.9.9")
    p = client.post("/api/alerts/rules/preview", json={"rule": rule, "hours": 1}, headers=CSRF).json()
    assert p["kind"] == "new_terms" and p["new"] >= 1 and ["preview-user", "10.9.9.9"] in [i["values"] for i in p["items"]]
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'alerts.preview' AND target = '새 출발지 화면'") == [(1,)]
    bad = client.put("/api/alerts/rules", json={"rule": {**rule, "name": "잘못", "fields": []}}, headers=CSRF)
    assert bad.status_code == 422
