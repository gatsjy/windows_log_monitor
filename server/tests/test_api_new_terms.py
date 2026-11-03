"""처음 보는 값 탐지 (BACKLOG B-47, ADR-063) 통합 시험 — 거슬러 배우기, 조합마다 한 번, history 뒤 다시, 몰려오면 한 통, 상한, 조건 변경."""

from __future__ import annotations

import json
import os
import time
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
    assert key.startswith("처음 보는 값 5개 · ") and terms["count"] == 5 and len(terms["items"]) == 5
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
    # 누구의 정보를 봤는지 — 조건이 기록에 (규칙 이름은 고르는 사람이 정한다)
    assert sql("SELECT detail->'match'->>'event_id' FROM audit_log WHERE action = 'alerts.preview'") == [("4624",)]
    bad = client.put("/api/alerts/rules", json={"rule": {**rule, "name": "잘못", "fields": []}}, headers=CSRF)
    assert bad.status_code == 422


# ---------------------------------------------------------------- 검토 보완 (B-47 1차 검토) — 규칙마다 이벤트 ID 를 따로 써서 서로 섞이지 않게
def own_rule(name, event_id, *, fields="[account, ip]", burst=20, max_terms=50000, learn="1d", extra="", match=None, sid=None):
    from app.alerts.engine import engine

    text = (f"settings:\n  interval_sec: 30\n{extra}rules:\n  - name: {name}\n" + (f"    sid: {sid}\n" if sid else "")
            + f"    kind: new_terms\n    match: {match or '{ event_id: \"' + str(event_id) + '\" }'}\n    fields: {fields}\n"
            f"    history: 30d\n    learn: {learn}\n    burst: {burst}\n    max_terms: {max_terms}\n    severity: warning\n"
            "    notify: [운영팀]\n")
    Path(os.environ["WLM_ALERTS_FILE"]).write_text(text, encoding="utf-8")
    engine.reload(force=True)
    return next(r for r in engine.config.rules if r.name == name)


def ev(user, ip, event_id, host="DC-01", at=None, raw="{}"):
    at = at or datetime.now(UTC)
    sql("INSERT INTO events (received_at, ts, host, source, category, event_id, level, username, src_ip, message, raw)"
        " VALUES (%s, %s, %s, 'winevtlog', 'security', %s, 4, %s, %s, '로그온', %s::jsonb)", (at, at, host, event_id, user, ip, raw))


def state_of(name):
    return sql("SELECT id, backfill_from, backfill_to, chunk_sec, overflow_n, cursor_at, rule_key FROM new_terms_state"
               " WHERE rule_key = %s", (f"name:{name}",))[0]


def rule_alerts(name):
    return sql("SELECT id, group_key, silence_id, payload FROM alerts WHERE rule = %s ORDER BY id", (name,))


def test_backfill_keeps_progress_and_chunk_after_timeout(client, monkeypatch):
    """6시간 구간이 시간 초과면: 그 주기의 진행을 잃지 않고, 다음 주기에 시간 초과 난 크기로 다시 키우지 않는다 (검토에서 재현: 영영 멈춤)."""
    from app import db, repository

    real = repository.scan_new_terms

    async def slow(ns, f, fields, start, end, **kw):
        if kw["learning"] and end - start > timedelta(hours=2):
            raise db.QueryTimeout(20)
        return await real(ns, f, fields, start, end, **kw)

    monkeypatch.setattr(repository, "scan_new_terms", slow)
    rule = own_rule("느린 배움", 4811)
    with pytest.raises(db.QueryTimeout):
        evaluate(client, rule)
    _, frm, to, chunk, *_ = state_of("느린 배움")
    assert to is not None and to < datetime.now(UTC) - timedelta(hours=3) and chunk == 7200   # 진행은 남고 크기는 반
    evaluate(client, rule)                                                                     # 2시간씩 — 다시 4시간으로 키우지 않음
    _, frm, to, chunk, *_ = state_of("느린 배움")
    assert to is None and frm is None and chunk == 7200


def test_overflow_clears_when_max_terms_raised(client):
    from app.alerts.newterms import CappedError

    rule = own_rule("상한 시험", 4812, max_terms=100)
    evaluate(client, rule)
    for i in range(102):
        ev(f"ov{i}", "10.12.0.1", 4812)
    with pytest.raises(CappedError, match="두지 못하고 있습니다"):
        evaluate(client, rule)                              # 둔 100개는 한 통으로 알림
    rule = own_rule("상한 시험", 4812, max_terms=1000)
    fired, run = evaluate(client, rule)                     # 겹쳐 본 2분에서 두지 못한 2개를 두고 알린다 — 오류는 풀린다
    assert len(fired) == 2 and run.terms["overflow"] == 0 and state_of("상한 시험")[4] == 0
    assert [a[1] for a in rule_alerts("상한 시험")][-2:] == ["ov100 · 10.12.0.1", "ov101 · 10.12.0.1"]
    assert evaluate(client, rule)[0] == []


def test_filter_change_keeps_unscanned_values_alertable(client):
    rule = own_rule("조건 바꿈 틈", 4813)
    evaluate(client, rule)
    ev("intruder", "198.51.100.7", 4813)                    # 다음 평가 전에 들어온 새 값
    rule = own_rule("조건 바꿈 틈", 4813, match='{ event_id: "4813,4814" }')
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1 and rule_alerts("조건 바꿈 틈")[-1][1] == "intruder · 198.51.100.7"


def test_late_commit_inside_overlap_stays_pending(client):
    """겹쳐 보다 늦게 커밋된 더 이른 행을 찾아도 배우는 기간 뒤면 알릴 차례 그대로 (검토에서 재현: 배운 값으로 바뀜)."""
    from app import repository
    from app.alerts.engine import rule_filter

    rule = own_rule("늦은 커밋", 4815)
    evaluate(client, rule)
    ns, *_ = state_of("늦은 커밋")
    t1 = datetime.now(UTC)
    learn_until = t1 - timedelta(minutes=1)              # 배우는 기간은 늦은 행(t1-30초)보다 앞에서 끝남
    ev("late", "10.15.0.1", 4815, at=t1)
    base = client.portal.call(rule_filter, rule, t1)

    def scan():
        client.portal.call(lambda: repository.scan_new_terms(ns, base, ["account", "ip"], t1 - timedelta(minutes=5),
                                                             datetime.now(UTC) + timedelta(seconds=1), history=rule.history,
                                                             learning=False, learn_until=learn_until, room=1000, cursor=None))

    scan()
    ev("late", "10.15.0.1", 4815, at=t1 - timedelta(seconds=30))
    scan()
    assert sql("SELECT state, first_seen FROM seen_terms WHERE ns = %s AND term[1] = 'late'", (ns,)) == [
        ("pending", t1 - timedelta(seconds=30))]


def test_purge_waits_for_lagging_cursor(client, monkeypatch):
    from app.alerts import newterms

    rule = own_rule("밀린 정리", 4816)
    evaluate(client, rule)
    ns, *_ = state_of("밀린 정리")
    sql("INSERT INTO seen_terms (ns, term_hash, term, first_seen, last_seen, state) VALUES"
        " (%s, wlm_terms_hash(ARRAY['y','10.16.0.1']), ARRAY['y','10.16.0.1'], now() - interval '40 days',"
        " now() - interval '31 days 12 hours', 'learned')", (ns,))
    sql("UPDATE new_terms_state SET cursor_at = now() - interval '2 days' WHERE id = %s", (ns,))
    monkeypatch.setattr(newterms, "SCAN_BUDGET_SEC", 0)
    newterms._purged.pop(ns, None)
    evaluate(client, rule)
    assert sql("SELECT count(*) FROM seen_terms WHERE ns = %s AND term[1] = 'y'", (ns,)) == [(1,)]


def test_catchup_keeps_unfinished_relearn(client, monkeypatch):
    from app.alerts import newterms

    rule = own_rule("멈춘 뒤 다시", 4817)
    evaluate(client, rule)
    ns, *_ = state_of("멈춘 뒤 다시")
    sql("UPDATE new_terms_state SET cursor_at = now() - interval '4 days', backfill_from = now() - interval '10 days',"
        " backfill_to = now() - interval '5 days' WHERE id = %s", (ns,))
    monkeypatch.setattr(newterms, "SCAN_BUDGET_SEC", 0)
    evaluate(client, rule)
    [(frm, reason)] = sql("SELECT backfill_from, relearn_reason FROM new_terms_state WHERE id = %s", (ns,))
    assert frm < datetime.now(UTC) - timedelta(days=9) and reason == "4일 멈춤"


def test_first_host_is_first_event_and_silence_needs_every_host(client):
    """처음 본 PC 는 첫 로그의 PC(이름 순 최솟값이 아님), 한 PC 의 점검 무음이 다른 PC 에서도 보인 새 값을 가리지 않는다."""
    rule = own_rule("여러 PC", 4818)
    evaluate(client, rule)
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
        " VALUES (NULL, 'AA-MAINT', now() - interval '1 minute', now() + interval '1 hour', 'PC 점검', 'admin')")
    t = datetime.now(UTC)
    ev("roam", "10.18.0.1", 4818, host="WS-77", at=t)
    ev("roam", "10.18.0.1", 4818, host="AA-MAINT", at=t + timedelta(seconds=1))
    fired, _ = evaluate(client, rule)
    [(_, _, silence_id, payload)] = rule_alerts("여러 PC")
    assert len(fired) == 1 and payload["terms"]["host"] == "WS-77" and silence_id is None
    assert {s["host"] for s in payload["samples"]} == {"WS-77"}               # 표본은 그 알림의 PC 것만
    sql("UPDATE alert_silences SET ends_at = now() WHERE group_key = 'AA-MAINT'")


def test_silenced_combo_alerts_again_after_silence(client):
    rule = own_rule("무음 뒤", 4819)
    evaluate(client, rule)
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
        " VALUES ('무음 뒤', NULL, now() - interval '1 minute', now() + interval '1 hour', '점검', 'admin')")
    ev("quiet", "10.19.0.1", 4819)
    evaluate(client, rule)
    assert rule_alerts("무음 뒤")[-1][2] is not None                          # 무음 중 — 기록만
    ns, *_ = state_of("무음 뒤")
    sql("UPDATE alert_silences SET starts_at = now() - interval '3 hours', ends_at = now() - interval '30 minutes' WHERE rule = '무음 뒤'")
    # 두 시간 전에 처음 보였고(무음 중) — 시험에서는 받은 시각을 옮겨 흉내 낸다
    sql("UPDATE seen_terms SET last_seen = now() - interval '2 hours', first_seen = now() - interval '2 hours' WHERE ns = %s", (ns,))
    sql("UPDATE events SET received_at = now() - interval '2 hours' WHERE event_id = 4819")
    ev("quiet", "10.19.0.1", 4819)                                             # 무음이 끝난 뒤에도 계속
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1 and rule_alerts("무음 뒤")[-1][2] is None


def test_exception_added_while_pending_is_respected(client):
    rule = own_rule("미룬 동안 예외", 4820)
    evaluate(client, rule)
    ns, *_ = state_of("미룬 동안 예외")
    ev("scanner", "10.20.0.200", 4820)
    sql("INSERT INTO seen_terms (ns, term_hash, term, first_seen, last_seen, first_host, state) VALUES"
        " (%s, wlm_terms_hash(ARRAY['scanner','10.20.0.200']), ARRAY['scanner','10.20.0.200'], now() - interval '10 seconds',"
        " now(), 'DC-01', 'pending')", (ns,))
    sql("INSERT INTO rule_exceptions (rule, term, reason, created_by) VALUES ('미룬 동안 예외', 'ip:10.20.0.200', '취약점 점검기', 'admin')")
    sql("UPDATE new_terms_state SET cursor_at = now() WHERE id = %s", (ns,))
    assert evaluate(client, rule)[0] == []
    assert sql("SELECT state FROM seen_terms WHERE ns = %s AND term[1] = 'scanner'", (ns,)) == [("learned",)]


def test_long_values_cap_key_and_keep_samples(client):
    rule = own_rule("긴 값", 4821, fields="[host, f.cmd]")
    evaluate(client, rule)
    value = "\U00020000" * 300
    ev("svc", "10.21.0.1", 4821, raw=json.dumps({"cmd": value}))
    fired, _ = evaluate(client, rule)
    [(_, key, _, payload)] = rule_alerts("긴 값")
    assert len(fired) == 1 and key.startswith("DC-01 · " + "\U00020000" * 100 + "… #") and len(payload["samples"]) == 1
    assert "f.cmd" not in payload["link"]


def test_burst_keys_differ_by_time(client):
    rule = own_rule("몰림", 4822, burst=2)
    evaluate(client, rule)
    for i in range(3):
        ev(f"b{i}", "10.22.0.1", 4822)
    evaluate(client, rule)
    time.sleep(1.1)                                      # 다음 묶음은 다른 시각 — 수만 같은 다른 사고
    for i in range(3):
        ev(f"c{i}", "10.22.0.2", 4822)
    evaluate(client, rule)
    keys = [a[1] for a in rule_alerts("몰림")]
    assert len(keys) == 2 and keys[0] != keys[1] and all(k.startswith("처음 보는 값 3개 · ") for k in keys)


def test_scoped_user_sees_and_handles_in_list_paths(client):
    """PC 범위 사용자: 목록·숫자·처리(alert_refs)도 상세처럼 처음 본 PC 로 본다 (검토에서 재현: 상세만 보임)."""
    from app import repository
    from app.alerts.visibility import alert_visible, count_by_status
    from app.auth.service import User
    from app.filters import Scope

    [(alert_id, *_)] = rule_alerts("여러 PC")
    user = User(id=99, username="ws", display_name="ws", role="viewer", must_change_password=False,
                password_changed_at=datetime.now(UTC), scopes=(Scope(hosts=("WS-*",)),))
    groups = client.portal.call(repository.alert_group_counts)
    assert any(alert_visible(user, g) for g in groups if g["rule"] == "여러 PC")
    assert count_by_status(user, [g for g in groups if g["rule"] == "여러 PC"])["open"] == 1
    assert all(alert_visible(user, r) for r in client.portal.call(repository.alert_refs, [alert_id]))


def test_reachable_uses_host_routes_and_compliance_lines():
    from app.alerts.configdiff import diff
    from app.alerts.rules import parse_text
    from app.compliance import _rule_lines

    def config(tags):
        return parse_text(f"""routes:
  - name: DC 서버팀
    match: {{ hosts: [DC-*], tags: [RDP] }}
    notify: [서버팀]
rules:
  - name: 새 출발지
    kind: new_terms
    match: {{ event_id: "4624" }}
    fields: [account, ip]
    tags: [{tags}]
    notify: [운영팀]
""")
    old, new = config("RDP"), config("MITRE T1078")
    assert "서버팀" in old.reachable(old.rules[0]) and "서버팀" in old.delivery_targets()
    assert any("서버팀" in c["text"] for c in diff(old, new) if c["change"] == "route_targets")
    text = _rule_lines(old.rules[0])
    assert "끊김" not in text and "조건: event_id=4624" in text and "account + ip 값 조합이 최근 30일" in text


def test_startup_purge_keeps_enabled_rules_and_rekeys_sid(client):
    from app import partitions
    from app.alerts.engine import engine

    rule = own_rule("번호 붙음", 4823)
    evaluate(client, rule)
    sql("UPDATE new_terms_state SET updated_at = now() - interval '8 days'")
    sql("INSERT INTO new_terms_state (rule_key, fields, filter_sig, cursor_at, learn_until, updated_at)"
        " VALUES ('name:지운 규칙', ARRAY['ip'], 'x', now(), now(), now() - interval '8 days')")
    engine.forget()                      # 기동 중 — 설정을 읽기 전에는 지우지 않는다
    client.portal.call(partitions.purge_new_terms)
    assert sql("SELECT count(*) FROM new_terms_state WHERE rule_key = 'name:지운 규칙'") == [(1,)]
    rule = own_rule("번호 붙음", 4823)
    client.portal.call(partitions.purge_new_terms)
    keys = {k for (k,) in sql("SELECT rule_key FROM new_terms_state")}
    assert "name:번호 붙음" in keys and "name:지운 규칙" not in keys
    rule = own_rule("번호 붙음", 4823, sid=1009999)   # 화면에서 저장해 번호가 붙음 — 처음부터 다시 배우지 않고 옮긴다
    evaluate(client, rule)
    assert sql("SELECT relearn_reason FROM new_terms_state WHERE rule_key = 'sid:1009999'") == [("처음",)]
    assert sql("SELECT count(*) FROM new_terms_state WHERE rule_key = 'name:번호 붙음'") == [(0,)]


def test_stale_terms_cleared_for_other_kinds(client):
    from app.alerts.engine import RuleRun, engine
    from app.alerts.rules import parse_text

    [rule] = parse_text("rules:\n  - name: 건수로 바꿈\n    match: {event_id: '1'}\n    notify: [운영팀]\n").rules
    engine.runs[rule.name] = RuleRun(terms={"terms": 1})
    client.portal.call(engine._run_rule, rule, datetime.now(UTC))
    assert engine.runs[rule.name].terms is None


# ---------------------------------------------------------------- 2차 검토 보완
class SlowClock:
    """이어서 훑기는 예산(8초)을 넘긴 것으로, 거슬러 배우기는 아직(16초 안) — 큰 DB 에서 이어서 훑기가 밀린 경우."""

    def __init__(self):
        self.calls = 0

    def monotonic(self):
        self.calls += 1
        return 0.0 if self.calls == 1 else 10.0


def test_cap_error_lasts_until_room_returns(client):
    """두지 못한 값이 겹쳐 보는 2분을 벗어나도 자리가 다시 생길 때까지 오류 — 평가 간격이 길면 감시가 알리지 못했다(검토에서 재현)."""
    from app.alerts.newterms import CappedError

    rule = own_rule("상한 유지", 4831, max_terms=100)
    evaluate(client, rule)
    for i in range(100):
        ev(f"full{i}", "10.31.0.1", 4831)
    evaluate(client, rule)
    ev("attacker", "203.0.113.31", 4831)
    with pytest.raises(CappedError):
        evaluate(client, rule)
    sql("UPDATE events SET received_at = received_at - interval '10 minutes' WHERE event_id = 4831 AND username = 'attacker'")
    sql("UPDATE new_terms_state SET cursor_at = now() WHERE rule_key = 'name:상한 유지'")
    for _ in range(3):                                   # 겹친 구간 밖 — 그래도 오류 (감시가 세 번째에 알린다)
        with pytest.raises(CappedError):
            evaluate(client, rule)
    rule = own_rule("상한 유지", 4831, max_terms=1000)
    evaluate(client, rule)                               # 상한을 올리면 풀린다
    assert state_of("상한 유지")[4] == 0


def test_filter_change_with_lagging_cursor_does_not_learn_unscanned(client, monkeypatch):
    from app.alerts import newterms

    rule = own_rule("밀린 조건 바꿈", 4832)
    evaluate(client, rule)
    ns, *_ = state_of("밀린 조건 바꿈")
    sql("UPDATE new_terms_state SET cursor_at = now() - interval '6 hours', learn_until = now() - interval '7 hours'"
        " WHERE id = %s", (ns,))
    ev("intruder", "198.51.100.32", 4832, at=datetime.now(UTC) - timedelta(minutes=10))
    rule = own_rule("밀린 조건 바꿈", 4832, match='{ event_id: "4832,4833" }')
    monkeypatch.setattr(newterms, "time", SlowClock())   # 이번 주기는 거슬러 배우기만 돈다
    evaluate(client, rule)
    monkeypatch.undo()
    assert sql("SELECT state FROM seen_terms WHERE ns = %s AND term[1] = 'intruder'", (ns,)) == []
    for _ in range(3):
        evaluate(client, rule)
    assert [a[1] for a in rule_alerts("밀린 조건 바꿈")] == ["intruder · 198.51.100.32"]


def test_filter_change_after_long_stop_learns_the_gap(client):
    rule = own_rule("오래 멈춘 뒤 조건 바꿈", 4834)
    evaluate(client, rule)
    ns, *_ = state_of("오래 멈춘 뒤 조건 바꿈")
    sql("UPDATE new_terms_state SET cursor_at = now() - interval '5 days', learn_until = now() - interval '5 days'"
        " WHERE id = %s", (ns,))
    ev("gapuser", "10.34.0.1", 4834, at=datetime.now(UTC) - timedelta(days=4))
    rule = own_rule("오래 멈춘 뒤 조건 바꿈", 4834, match='{ event_id: "4834,4835" }')
    for _ in range(3):
        evaluate(client, rule)
    assert rule_alerts("오래 멈춘 뒤 조건 바꿈") == []
    assert sql("SELECT state FROM seen_terms WHERE ns = %s AND term[1] = 'gapuser'", (ns,)) == [("learned",)]
    assert sql("SELECT relearn_reason FROM new_terms_state WHERE id = %s", (ns,)) == [("5일 멈춤 · 조건 바뀜",)]


def test_cut_keys_stay_distinct(client):
    """앞 100자가 같은 다른 값: 대상 이름이 달라야 한쪽에 건 무음이 다른 쪽을 가리지 않는다."""
    rule = own_rule("긴 명령", 4836, fields="[f.cmd]")
    evaluate(client, rule)
    prefix = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Enc "
    ev("a", "10.36.0.1", 4836, raw=json.dumps({"cmd": prefix + "BENIGN"}))
    evaluate(client, rule)
    [(_, key_a, _, _)] = rule_alerts("긴 명령")
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
        " VALUES ('긴 명령', %s, now() - interval '1 minute', now() + interval '1 day', '정상 스크립트', 'admin')", (key_a,))
    ev("a", "10.36.0.1", 4836, raw=json.dumps({"cmd": prefix + "MALICIOUS"}))
    evaluate(client, rule)
    (_, _, _, _), (_, key_b, silence_b, _) = rule_alerts("긴 명령")
    assert key_a != key_b and key_a.split(" #")[0] == key_b.split(" #")[0] and silence_b is None


def test_scope_and_with_related_follow_host(client):
    """같은 값 조합이 history 뒤 다른 PC 에서 다시 알림: PC 범위 사용자의 목록·함께 해결이 범위 밖 PC 알림을 섞지 않는다."""
    from app import repository
    from app.auth.service import User
    from app.filters import Scope
    from app.routers.alerts import _visible_targets

    rule = own_rule("같은 이름 다른 PC", 4837, fields="[account]")
    evaluate(client, rule)
    ev("svc_x", "10.37.0.1", 4837, host="SRV-09")
    evaluate(client, rule)
    ns, *_ = state_of("같은 이름 다른 PC")
    sql("UPDATE seen_terms SET last_seen = now() - interval '40 days' WHERE ns = %s", (ns,))
    sql("UPDATE events SET received_at = now() - interval '10 minutes' WHERE event_id = 4837")   # 옛 로그는 겹쳐 보는 2분 밖
    ev("svc_x", "10.37.0.2", 4837, host="WS-09")
    evaluate(client, rule)
    [(srv, *_), (ws, *_)] = rule_alerts("같은 이름 다른 PC")
    user = User(id=98, username="ws", display_name="ws", role="viewer", must_change_password=False,
                password_changed_at=datetime.now(UTC), scopes=(Scope(hosts=("WS-*",)),))
    pairs = _visible_targets(user, client.portal.call(repository.alert_group_counts))
    since = datetime.now(UTC) - timedelta(hours=1)
    ids = [a["id"] for a in client.portal.call(lambda: repository.list_alerts(since, 100, rule="같은 이름 다른 PC", pairs=pairs))]
    assert ids == [ws]
    groups = client.portal.call(lambda: repository.alert_groups(since, 100, rule="같은 이름 다른 PC", pairs=pairs))
    assert [g["n"] for g in groups] == [1]
    assert client.portal.call(repository.get_alert, ws)["related_unresolved"] == 0
    assert client.portal.call(lambda: repository.handle_alerts([ws], "ack", "ws", with_related=True)) == [ws]
    assert sql("SELECT status FROM alerts WHERE id = %s", (srv,)) == [("open",)]
    # 범위가 없는 사람의 묶어 보기도 같은 셋으로 — 한 줄의 '모두 확인'이 다른 PC 의 알림을 남기지 않게(3차 검토에서 재현)
    rows = client.portal.call(lambda: repository.alert_groups(since, 100, rule="같은 이름 다른 PC"))
    assert sorted((g["group_key"], g["terms_host"], g["n"]) for g in rows) == [("svc_x", "SRV-09", 1), ("svc_x", "WS-09", 1)]
    # 사고관리로 보내는 중복 제거 키도 PC 마다 — 같은 키면 받는 쪽이 열린 사고에 합쳤다
    from app.alerts.message import AlertMessage

    [(a,), (b,)] = sql("SELECT payload FROM alerts WHERE id IN (%s, %s) ORDER BY id", (srv, ws))
    assert AlertMessage.from_dict(a).dedup_key != AlertMessage.from_dict(b).dedup_key


def test_silenced_burst_reopens_as_one(client):
    rule = own_rule("무음 묶음", 4838, burst=2)
    evaluate(client, rule)
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
        " VALUES ('무음 묶음', NULL, now() - interval '1 minute', now() + interval '1 hour', '망 변경', 'admin')")
    for i in range(5):
        ev(f"net{i}", "10.38.0.1", 4838)
    evaluate(client, rule)
    assert len(rule_alerts("무음 묶음")) == 1
    ns, *_ = state_of("무음 묶음")
    sql("UPDATE alert_silences SET starts_at = now() - interval '3 hours', ends_at = now() - interval '30 minutes'"
        " WHERE rule = '무음 묶음'")
    sql("UPDATE seen_terms SET last_seen = now() - interval '2 hours' WHERE ns = %s", (ns,))   # 무음 중에만 보였고
    sql("UPDATE seen_terms SET last_seen = now() WHERE ns = %s AND term[1] = 'net0'", (ns,))   # 무음 뒤에는 하나만 이어짐
    evaluate(client, rule)
    alerts_now = rule_alerts("무음 묶음")
    assert len(alerts_now) == 2 and alerts_now[-1][1].startswith("처음 보는 값 5개") and alerts_now[-1][2] is None


def test_value_spreading_later_to_unsilenced_pc_alerts(client):
    from app.alerts import newterms

    rule = own_rule("나중에 번짐", 4839)
    evaluate(client, rule)
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
        " VALUES (NULL, 'MAINT-39', now() - interval '1 minute', now() + interval '3 days', '점검', 'admin')")
    ev("newadm", "10.39.0.1", 4839, host="MAINT-39")
    evaluate(client, rule)
    assert rule_alerts("나중에 번짐")[-1][2] is not None
    ev("newadm", "10.39.0.1", 4839, host="WS-39")                  # 다음 주기에 다른 PC 로
    ns, *_ = state_of("나중에 번짐")
    newterms._spread.pop(ns, None)
    fired, _ = evaluate(client, rule)
    [*_, (_, _, silence_id, payload)] = rule_alerts("나중에 번짐")
    assert len(fired) == 1 and silence_id is None
    # 다시 보낸 알림의 PC 는 번진 PC — 점검 중인 첫 PC 로 두면 그 PC 의 경로·조회 범위로 갔다(3차 검토에서 재현)
    assert payload["terms"]["host"] == "WS-39" and {x["host"] for x in payload["samples"]} == {"WS-39"}
    assert sql("SELECT terms_host FROM alerts WHERE id = %s", (fired[0],)) == [("WS-39",)]
    sql("UPDATE alert_silences SET ends_at = now() WHERE group_key = 'MAINT-39'")


def test_reopen_limit_counts_only_qualifying(client):
    from app import repository

    rule = own_rule("다시 열기 상한", 4840)
    evaluate(client, rule)
    ev("plain", "10.40.0.1", 4840)
    evaluate(client, rule)
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
        " VALUES ('다시 열기 상한', NULL, now() - interval '1 minute', now() + interval '1 hour', '점검', 'admin')")
    ev("hushed", "10.40.0.2", 4840)
    evaluate(client, rule)
    ns, *_ = state_of("다시 열기 상한")
    sql("UPDATE alert_silences SET starts_at = now() - interval '3 hours', ends_at = now() - interval '30 minutes'"
        " WHERE rule = '다시 열기 상한'")
    sql("UPDATE alerts SET fired_at = now() - interval '2 hours' WHERE rule = '다시 열기 상한'")   # 알림은 무음 중에 났고
    sql("UPDATE seen_terms SET last_seen = now() - interval '10 minutes' WHERE ns = %s AND term[1] = 'hushed'", (ns,))
    sql("UPDATE seen_terms SET last_seen = now() WHERE ns = %s AND term[1] = 'plain'", (ns,))
    assert client.portal.call(lambda: repository.reopen_silenced_terms(ns, datetime.now(UTC), limit=1)) == 1
    assert sql("SELECT state FROM seen_terms WHERE ns = %s AND term[1] = 'hushed'", (ns,)) == [("pending",)]


# ---------------------------------------------------------------- 3차 재검토 보완
def silence(rule, key, minutes_left, reason="점검", started_minutes_ago=1):
    return sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by) VALUES"
               " (%s, %s, now() - make_interval(mins => %s), now() + make_interval(mins => %s), %s, 'admin') RETURNING id",
               (rule, key, started_minutes_ago, minutes_left, reason))[0][0]


def test_burst_rechecks_pending_against_current_condition(client, monkeypatch):
    """몰려온 묶음도 알리기 전에 지금 조건으로 다시 본다 — 미뤄 둔 동안 건 예외의 값이 '처음 보는 값 n개'에 들어갔다(재현)."""
    rule = own_rule("묶음 다시 보기", 4851, burst=2)
    evaluate(client, rule)
    ns, *_ = state_of("묶음 다시 보기")
    for i in range(3):
        ev(f"scan{i}", "10.51.0.200", 4851)
        sql("INSERT INTO seen_terms (ns, term_hash, term, first_seen, last_seen, first_host, state) VALUES"
            " (%s, wlm_terms_hash(ARRAY[%s, '10.51.0.200']), ARRAY[%s, '10.51.0.200'], now() - interval '5 seconds', now(),"
            " 'DC-01', 'pending')", (ns, f"scan{i}", f"scan{i}"))
    sql("INSERT INTO rule_exceptions (rule, term, reason, created_by) VALUES ('묶음 다시 보기', 'ip:10.51.0.200', '점검기', 'admin')")
    sql("UPDATE new_terms_state SET cursor_at = now() WHERE id = %s", (ns,))
    assert evaluate(client, rule)[0] == []
    assert sql("SELECT DISTINCT state FROM seen_terms WHERE ns = %s AND term[1] LIKE 'scan%%'", (ns,)) == [("learned",)]


def test_burst_from_silenced_pc_is_silenced(client):
    rule = own_rule("점검 중 몰림", 4852, burst=2)
    evaluate(client, rule)
    silence(None, "MH-52", 60)
    for i in range(3):
        ev(f"msi{i}", "10.52.0.1", 4852, host="MH-52")
    evaluate(client, rule)
    [(_, key, silence_id, _)] = rule_alerts("점검 중 몰림")
    assert key.startswith("처음 보는 값 3개") and silence_id is not None
    sql("UPDATE alert_silences SET ends_at = now() WHERE group_key = 'MH-52'")


def test_silence_judged_at_sighting_time(client):
    """두 PC 모두 점검 중에만 본 값: 한 PC 의 무음이 먼저 끝나도 알리지 않는다(지금으로 판단하면 알림이 됐다, 재현)."""
    from app.alerts import newterms

    rule = own_rule("점검 중에만", 4853)
    evaluate(client, rule)
    silence(None, "MA-53", 3 * 24 * 60)
    mb = silence(None, "MB-53", 60)
    ev("patchsvc", "10.53.0.1", 4853, host="MA-53")
    ev("patchsvc", "10.53.0.1", 4853, host="MB-53")
    evaluate(client, rule)
    assert rule_alerts("점검 중에만")[-1][2] is not None
    sql("UPDATE alert_silences SET ends_at = now() WHERE id = %s", (mb,))
    ns, *_ = state_of("점검 중에만")
    newterms._spread.pop(ns, None)
    assert evaluate(client, rule)[0] == []
    sql("UPDATE alert_silences SET ends_at = now() WHERE group_key IN ('MA-53', 'MB-53')")


def test_spread_check_rotates_through_all_candidates(client, monkeypatch):
    from app.alerts import newterms

    monkeypatch.setattr(newterms, "SPREAD_MAX", 5)
    rule = own_rule("돌아가며", 4854, burst=100)
    evaluate(client, rule)
    silence(None, "MC-54", 3 * 24 * 60)
    ev("early", "10.54.0.1", 4854, host="MC-54")
    evaluate(client, rule)
    for i in range(6):                                   # 오래된 'early' 뒤에 6개 더 — 최근 5개만 보면 영영 차례가 안 온다
        ev(f"later{i}", "10.54.0.2", 4854, host="MC-54")
    evaluate(client, rule)
    assert len(rule_alerts("돌아가며")) == 7
    ev("early", "10.54.0.1", 4854, host="WS-54")
    ns, *_ = state_of("돌아가며")
    fired = []
    for _ in range(2):
        newterms._spread.pop(ns, None)
        fired += evaluate(client, rule)[0]
    assert len(fired) == 1 and rule_alerts("돌아가며")[-1][3]["terms"]["host"] == "WS-54"
    sql("UPDATE alert_silences SET ends_at = now() WHERE group_key = 'MC-54'")


def test_hidden_silence_and_scoped_pc_silence(client):
    """범위 밖 PC 의 무음은 상세에 이름·사유 없이, 범위 안 PC 로 건 처음 보는 값 규칙의 무음은 다룰 수 있다."""
    from app import repository
    from app.alerts.visibility import scrub_silence, silence_target_visible, silence_visible
    from app.auth.service import User
    from app.filters import Scope

    rule = own_rule("두 PC 점검", 4855)
    evaluate(client, rule)
    silence(None, "WS-55", 60)
    silence(None, "SRV-55", 24 * 60, reason="EMR DB 비공개 점검")
    t = datetime.now(UTC)
    ev("svc_patch", "10.55.0.1", 4855, host="WS-55", at=t)
    ev("svc_patch", "10.55.0.1", 4855, host="SRV-55", at=t + timedelta(seconds=1))
    evaluate(client, rule)
    [(alert_id, _, silence_id, payload)] = rule_alerts("두 PC 점검")
    assert silence_id is not None and payload["terms"]["host"] == "WS-55"
    user = User(id=97, username="ws", display_name="ws", role="viewer", must_change_password=False,
                password_changed_at=datetime.now(UTC), scopes=(Scope(hosts=("WS-*",)),))
    row = client.portal.call(repository.get_alert, alert_id)
    shown = scrub_silence(user, row["silence"])
    assert shown["hidden"] and shown["reason"] is None and shown["group_key"] is None
    assert silence_target_visible(user, "두 PC 점검", "WS-55") and not silence_target_visible(user, "두 PC 점검", "SRV-55")
    # 범위가 정해진 사용자가 건 무음(PC 로만)은 보이고, 관리자가 건 처음 보는 값 규칙의 무음은 값 조합으로도 맞아 안 보인다
    assert silence_visible(user, {"rule": "두 PC 점검", "group_key": "WS-55", "host_only": True})
    assert not silence_visible(user, {"rule": "두 PC 점검", "group_key": "WS-55", "host_only": False})
    # 이 알림의 규칙·대상 그대로 건 무음은 '다른 대상'이 아니다
    own = {"id": 9, "rule": "두 PC 점검", "group_key": row["group_key"], "host_only": False, "starts_at": t, "ends_at": t,
           "reason": "알려진 VPN", "created_by": "admin", "suppressed": 1}
    assert scrub_silence(user, own, row)["reason"] == "알려진 VPN"
    assert row["terms_host"] == "WS-55"                    # 목록·CSV 에도 PC
    sql("UPDATE alert_silences SET ends_at = now() WHERE group_key IN ('WS-55', 'SRV-55')")


# ---------------------------------------------------------------- 4차 검토 보완
def pending_row(ns, values, first_seen_sql, host):
    sql("INSERT INTO seen_terms (ns, term_hash, term, first_seen, last_seen, first_host, state) VALUES"
        f" (%s, wlm_terms_hash(%s::text[]), %s::text[], {first_seen_sql}, {first_seen_sql}, %s, 'pending')", (ns, values, values, host))


def test_burst_pc_silence_reads_events_not_first_host(client):
    """몰려온 묶음의 PC 무음은 로그에서 — 첫 PC 만 보면 무음 없는 PC 에서도 본 값이 묶음째 묻혔다(재현)."""
    rule = own_rule("묶음 PC", 4861, burst=2)
    evaluate(client, rule)
    ns, *_ = state_of("묶음 PC")
    silence(None, "MH-61", 60, started_minutes_ago=30)
    at = datetime.now(UTC) - timedelta(minutes=4)
    for i in range(3):
        ev(f"m{i}", "10.61.0.1", 4861, host="MH-61", at=at)
        pending_row(ns, [f"m{i}", "10.61.0.1"], "now() - interval '4 minutes'", "MH-61")
    ev("m0", "10.61.0.1", 4861, host="WS-61", at=at + timedelta(seconds=1))
    sql("UPDATE new_terms_state SET cursor_at = now() WHERE id = %s", (ns,))
    evaluate(client, rule)
    [(_, key, silence_id, _)] = rule_alerts("묶음 PC")
    assert key.startswith("처음 보는 값 3개") and silence_id is None
    sql("UPDATE alert_silences SET ends_at = now() WHERE group_key = 'MH-61'")


def test_alert_silenced_by_ended_silence_reopens_on_new_pc_once(client):
    """이미 끝난 PC 무음 중에 본 값의 알림 — 한 시간 안에 무음 없는 PC 에서 보이면 다시 알리고, 그 뒤 되풀이하지 않는다(재현)."""
    from app.alerts import newterms

    rule = own_rule("끝난 무음", 4862)
    evaluate(client, rule)
    ns, *_ = state_of("끝난 무음")
    silence(None, "MX-62", -5, started_minutes_ago=30)
    ev("patch", "10.62.0.1", 4862, host="MX-62", at=datetime.now(UTC) - timedelta(minutes=20))
    pending_row(ns, ["patch", "10.62.0.1"], "now() - interval '20 minutes'", "MX-62")
    sql("UPDATE new_terms_state SET cursor_at = now() WHERE id = %s", (ns,))
    evaluate(client, rule)
    assert rule_alerts("끝난 무음")[-1][2] is not None             # 본 때는 점검 중
    ev("patch", "10.62.0.1", 4862, host="WS-62")
    newterms._spread.pop(ns, None)
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1 and rule_alerts("끝난 무음")[-1][2] is None and rule_alerts("끝난 무음")[-1][3]["terms"]["host"] == "WS-62"
    newterms._spread.pop(ns, None)
    assert evaluate(client, rule)[0] == []                         # 다시 무음 알림을 되풀이하지 않는다


def test_rule_silence_is_judged_now_not_at_sighting(client):
    rule = own_rule("끝난 규칙 무음", 4863)
    evaluate(client, rule)
    ns, *_ = state_of("끝난 규칙 무음")
    silence("끝난 규칙 무음", None, -5, started_minutes_ago=30)
    ev("svc", "10.63.0.2", 4863, host="DC-63", at=datetime.now(UTC) - timedelta(minutes=10))
    pending_row(ns, ["svc", "10.63.0.2"], "now() - interval '10 minutes'", "DC-63")
    sql("UPDATE new_terms_state SET cursor_at = now() WHERE id = %s", (ns,))
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1 and rule_alerts("끝난 규칙 무음")[-1][2] is None


def test_old_pending_rows_rechecked_in_their_own_window(client):
    """오래 미뤄 둔 조합은 처음 본 때의 한 시간으로 다시 본다 — 예외 걸린 값만 배운 것으로, 나머지는 알린다."""
    rule = own_rule("오래 미룸", 4864, burst=1)
    evaluate(client, rule)
    ns, *_ = state_of("오래 미룸")
    old = datetime.now(UTC) - timedelta(days=3)
    ev("keep", "10.64.0.1", 4864, at=old)
    ev("drop", "10.64.0.200", 4864, at=old)
    pending_row(ns, ["keep", "10.64.0.1"], "now() - interval '3 days'", "DC-01")
    pending_row(ns, ["drop", "10.64.0.200"], "now() - interval '3 days'", "DC-01")
    sql("INSERT INTO rule_exceptions (rule, term, reason, created_by) VALUES ('오래 미룸', 'ip:10.64.0.200', '점검기', 'admin')")
    sql("UPDATE new_terms_state SET cursor_at = now() WHERE id = %s", (ns,))
    evaluate(client, rule)
    assert [a[1] for a in rule_alerts("오래 미룸")] == ["keep · 10.64.0.1"]
    assert sql("SELECT state FROM seen_terms WHERE ns = %s AND term[1] = 'drop'", (ns,)) == [("learned",)]


def test_scoped_users_pc_silence_does_not_match_value_combination(client):
    """범위가 정해진 사용자의 무음(PC 로만)은 같은 글자인 값 조합의 범위 밖 알림을 막지 않는다(재현: 계정 'WS-OPS')."""
    rule = own_rule("값이 PC 모양", 4865, fields="[account]")
    evaluate(client, rule)
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by, host_only)"
        " VALUES ('값이 PC 모양', 'ws-ops', now() - interval '1 minute', now() + interval '1 hour', '내 PC 점검', 'ws', true)")
    ev("WS-OPS", "10.65.0.1", 4865, host="DC-65")
    fired, _ = evaluate(client, rule)
    assert len(fired) == 1 and rule_alerts("값이 PC 모양")[-1][2] is None


# ---------------------------------------------------------------- 5차 검토 보완
def test_scoped_silences_keep_working_for_other_rule_kinds(client):
    """PC 로만 맞추는 무음은 PC 범위 사용자만 — 분류만 정해진 사용자의 IP 묶음 무음·채널 끊김 'PC · 채널' 무음이 아무 데도 안 걸렸다(재현)."""
    from app import repository
    from app.alerts.engine import engine
    from app.alerts.rules import parse_text
    from app.alerts.visibility import silence_target_visible, silence_visible
    from app.auth.service import User
    from app.filters import Scope
    from app.routers.alerts import _silence_host_only

    def user(**scope):
        return User(id=96, username="u", display_name="u", role="viewer", must_change_password=False,
                    password_changed_at=datetime.now(UTC), scopes=(Scope(**scope),))

    dba, ward, dc = user(categories=("security",)), user(hosts=("WS-*",)), user(hosts=("DC-01",))
    assert not _silence_host_only(dba) and _silence_host_only(ward) and _silence_host_only(dc)
    engine.config = parse_text("""rules:
  - name: IP 묶음
    match: { category: security }
    group_by: ip
    notify: [운영팀]
  - name: 채널 끊김
    kind: stream_silent
    notify: [운영팀]
  - name: 새 값
    kind: new_terms
    match: { event_id: "4624" }
    fields: [account]
    notify: [운영팀]
""")
    now = datetime.now(UTC)
    sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by, host_only) VALUES"
        " ('IP 묶음', '10.1.2.3', now() - interval '1 minute', now() + interval '1 hour', '스캐너', 'dba', false),"
        " ('채널 끊김', 'WS-02 · Security', now() - interval '1 minute', now() + interval '1 hour', '점검', 'ward', true),"
        " ('새 값', 'WS-05', now() - interval '1 minute', now() + interval '1 hour', '내 PC 점검', 'ward', true)")
    assert client.portal.call(lambda: repository.active_silence("IP 묶음", "10.1.2.3", now)) is not None
    assert client.portal.call(lambda: repository.active_silence("채널 끊김", "WS-02 · Security", now, "WS-02", "WS-02", True)) is not None
    assert silence_target_visible(dc, "채널 끊김", "DC-01 · Security", True)      # 정확한 PC 범위도 'PC · 채널' 에 무음을 건다
    # 무음 수 표시(active_silence_refs)도 PC 로만 맞추는 무음을 목록과 같게 센다
    refs = client.portal.call(repository.active_silence_refs, now)
    assert {r["group_key"] for r in refs if r["rule"] in ("채널 끊김", "새 값") and silence_visible(ward, r)} == {
        "WS-02 · Security", "WS-05"}
    sql("UPDATE alert_silences SET ends_at = now() WHERE rule IN ('IP 묶음', '채널 끊김', '새 값')")
