"""상관 알림 (BACKLOG B-67 2단계, ADR-065) — 통합 시험: 같은 개체·기간 안 서로 다른 전술 수의 경계, 규칙 하나는 한 전술,
관찰·무음 알림 제외, 재알림·같은 흐름의 다른 개체, 조회 범위, 미리보기, 화면에서 저장."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Probe#Pass2026q"
RULES = """settings:
  interval_sec: 30

rules:
  - name: 공격 흐름
    kind: correlation
    enabled: false
    window: 1h
    min_tactics: 3
    severity: critical
    notify: [운영팀]
  - name: 대입
    enabled: false
    match: { event_id: "4625" }
    severity: warning
    tags: [MITRE T1110]
    notify: [운영팀]
"""
CORR = "공격 흐름"


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def put(now, rule, minutes, tags, hosts=(), accounts=(), ips=(), observe=False, silence=None):
    payload = {"kind": "count", "tags": list(tags), **({"observe": True} if observe else {})}
    key = (list(hosts) or list(accounts) or list(ips) or [""])[0]
    return sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload, silence_id, entity_hosts,"
               " entity_accounts, entity_ips) VALUES (%s, %s, 'warning', %s, 1, %s::jsonb, %s, %s, %s, %s) RETURNING id",
               (now + timedelta(minutes=minutes), rule, key, json.dumps(payload), silence, list(hosts), list(accounts),
                list(ips)))[0][0]


def evaluate(client, now):
    from app.alerts.engine import engine

    rule = next(r for r in engine.config.rules if r.name == CORR)
    return client.portal.call(engine.evaluate, rule, now)


def corr(key):
    return sql("SELECT id, payload, entity_hosts, entity_accounts, entity_ips FROM alerts WHERE rule = %s AND group_key = %s"
               " ORDER BY id", (CORR, key))


def _viewer(admin, app, username, group):
    from fastapi.testclient import TestClient

    temp = admin.post("/api/users", json={"username": username, "role": "viewer"}, headers=CSRF).json()
    assert admin.post("/api/user-groups", json={**group, "member_ids": [temp["user"]["id"]]}, headers=CSRF).status_code == 200
    client = TestClient(app)
    client.post("/api/auth/login", json={"username": username, "password": temp["temp_password"]}, headers=CSRF)
    client.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD}, headers=CSRF)
    return client


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app import accesslog
    from app.alerts.engine import engine
    from app.main import app

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    try:
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            medic = _viewer(admin, app, "medic", {"name": "의료", "scope_hosts": ["MED-*"]})
            manager = _viewer(admin, app, "manager", {"name": "의료 규칙", "scope_hosts": ["MED-*"], "permissions": ["alerts.manage"]})
            desk = _viewer(admin, app, "desk", {"name": "PC 지원", "scope_hosts": ["PC*"]})
            accesslog.forget()
            yield {"admin": admin, "medic": medic, "manager": manager, "desk": desk}
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


@pytest.fixture
def now(ctx):
    """시험마다 앞 시험의 알림을 기간·재알림 간격 밖으로 민다 — 서로 섞이지 않게."""
    sql("UPDATE alerts SET fired_at = fired_at - interval '3 days'")
    return datetime.now(UTC)


def test_three_tactics_fire_once_with_the_chain(ctx, now):
    a = put(now, "대입", -50, ["MITRE T1110"], hosts=["X"], ips=["10.0.0.5"])
    b = put(now, "새 서비스", -30, ["MITRE T1543.003"], hosts=["X"], accounts=["evil"])
    c = put(now, "로그 삭제", -10, ["MITRE T1070.001", "ISMS 2.11.3"], hosts=["X"], accounts=["evil"])
    fired = evaluate(ctx["admin"], now)
    [(alert_id, payload, hosts, accounts, ips)] = corr("PC X")
    assert fired == [alert_id] and (hosts, accounts, ips) == (["X"], [], [])
    chain = payload["correlation"]
    assert [s["name"] for s in chain["tactics"]] == ["자격 증명 접근", "지속", "방어 회피"]   # 일어난 순서
    assert {s["rule"] for s in chain["tactics"]} == {"대입", "새 서비스", "로그 삭제"}
    assert [x["id"] for x in chain["alerts"]] == [a, b, c] and payload["event_count"] == 3 and payload["threshold"] == 3
    assert corr("계정 evil") == []   # 같은 흐름 — 계정(전술 2개)으로도 기준 미달
    from app.alerts.message import AlertMessage

    text = AlertMessage.from_dict(payload).text()
    assert "서로 다른 전술 3개" in text and "묶은 알림:" in text and f"#{c}" in text
    assert evaluate(ctx["admin"], now + timedelta(minutes=5)) == []   # 재알림 간격


def test_window_boundary(ctx, now):
    put(now, "대입", -50, ["MITRE T1110"], hosts=["Y"])
    put(now, "새 서비스", -30, ["MITRE T1543.003"], hosts=["Y"])
    old = put(now, "로그 삭제", -61, ["MITRE T1070.001"], hosts=["Y"])
    assert evaluate(ctx["admin"], now) == [] and corr("PC Y") == []    # 61분 전은 기간 밖 — 전술 2개
    sql("UPDATE alerts SET fired_at = %s WHERE id = %s", (now - timedelta(minutes=59), old))
    assert len(evaluate(ctx["admin"], now)) == 1 and len(corr("PC Y")) == 1


def test_one_rule_is_one_tactic(ctx, now):
    """여러 전술에 속한 기법 하나(T1078 = 초기 접근·지속·권한 상승·방어 회피)는 여러 번 울려도 전술 하나로 센다."""
    for minutes in (-40, -30, -20):
        put(now, "유효한 계정", minutes, ["MITRE T1078"], hosts=["Z"])
    put(now, "대입", -15, ["MITRE T1110"], hosts=["Z"])
    assert evaluate(ctx["admin"], now) == []
    put(now, "로그 삭제", -5, ["MITRE T1070.001"], hosts=["Z"])
    assert len(evaluate(ctx["admin"], now)) == 1
    [(_, payload, *_)] = corr("PC Z")
    assert len(payload["correlation"]["tactics"]) == 3 and payload["event_count"] == 5


def test_observe_mode_and_silenced_alerts_do_not_count(ctx, now):
    [(silence,)] = sql("INSERT INTO alert_silences (rule, group_key, starts_at, ends_at, reason, created_by)"
                       " VALUES (NULL, 'W', now() - interval '1 hour', now() + interval '1 hour', '점검', 'admin') RETURNING id")
    put(now, "대입", -30, ["MITRE T1110"], hosts=["W"])
    put(now, "새 서비스", -20, ["MITRE T1543.003"], hosts=["W"])
    put(now, "로그 삭제", -10, ["MITRE T1070.001"], hosts=["W"], observe=True)
    put(now, "감사 정책", -5, ["MITRE T1562.002"], hosts=["W"], silence=silence)
    assert evaluate(ctx["admin"], now) == [] and corr("PC W") == []


def test_same_flow_once_and_new_spread_alerts_again(ctx, now):
    """같은 알림들이 PC·계정에 모두 걸리면 한 통(강한 개체 하나). 그 계정이 다른 PC 에서 새 단계를 더하면 계정으로 다시."""
    for i, (rule, tag) in enumerate((("대입", "MITRE T1110"), ("새 서비스", "MITRE T1543.003"), ("로그 삭제", "MITRE T1070.001"))):
        put(now, rule, -40 + i * 5, [tag], hosts=["V"], accounts=["k"])
    assert len(evaluate(ctx["admin"], now)) == 1
    assert len(corr("PC V")) == 1 and corr("계정 k") == []
    put(now, "PowerShell", -2, ["MITRE T1059.001"], hosts=["V2"], accounts=["k"])
    assert len(evaluate(ctx["admin"], now)) == 1
    [(_, payload, *_)] = corr("계정 k")
    assert len(payload["correlation"]["tactics"]) == 4


def test_machine_accounts_do_not_chain(ctx, now):
    for i, tag in enumerate(("MITRE T1110", "MITRE T1543.003", "MITRE T1070.001")):
        put(now, f"규칙{i}", -30 + i, [tag], accounts=["system"])
    assert evaluate(ctx["admin"], now) == [] and corr("계정 system") == []


def test_scoped_users_do_not_see_correlation_alerts(ctx, now):
    admin, medic = ctx["admin"], ctx["medic"]
    first = put(now, "대입", -30, ["MITRE T1110"], hosts=["MED-1"])
    for minutes, rule, tag in ((-20, "새 서비스", "MITRE T1543.003"), (-10, "로그 삭제", "MITRE T1070.001")):
        put(now, rule, minutes, [tag], hosts=["MED-1"])
    [alert_id] = evaluate(admin, now)
    assert admin.get(f"/api/alerts/{alert_id}").status_code == 200
    assert medic.get(f"/api/alerts/{alert_id}").status_code == 404
    assert alert_id not in {a["id"] for a in medic.get("/api/alerts").json()["items"]}
    assert alert_id in {a["id"] for a in admin.get(f"/api/alerts/{first}/related").json()["items"]}
    assert alert_id not in {a["id"] for a in medic.get(f"/api/alerts/{first}/related").json()["items"]}


def test_preview(ctx, now):
    for i, tag in enumerate(("MITRE T1110", "MITRE T1543.003", "MITRE T1070.001")):
        put(now, f"단계{i}", -30 + i * 5, [tag], hosts=["P"], ips=["10.9.9.9"])
    rule = {"name": "미리보기", "kind": "correlation", "severity": "critical", "window_sec": 3600, "min_tactics": 3,
            "entities": ["host"], "notify": ["운영팀"]}
    r = ctx["admin"].post("/api/alerts/rules/preview", json={"rule": rule, "hours": 24}, headers=CSRF)
    assert r.status_code == 200, r.text
    body = r.json()
    item = next(i for i in body["items"] if i["key"] == "PC P")
    assert item["tactics"] == ["자격 증명 접근", "지속", "방어 회피"] and item["alerts"] == 3
    assert not any(i["kind"] == "ip" for i in body["items"])        # 볼 개체는 PC 만
    assert all(x["name"] != "대입" for x in body["rules"])          # 전술 목록은 켜진 규칙만 (꺼진 규칙은 알림을 내지 않는다)
    assert ctx["manager"].post("/api/alerts/rules/preview", json={"rule": rule, "hours": 24}, headers=CSRF).status_code == 403


def test_save_from_the_form(ctx):
    from app.alerts.engine import engine

    admin = ctx["admin"]
    rule = {"name": "흐름 2", "kind": "correlation", "severity": "error", "window_sec": 7200, "cooldown_sec": 7200,
            "min_tactics": 4, "entities": ["ip", "host"], "notify": ["운영팀"], "mode": "observe", "resolve": "", "match": {}}
    r = admin.put("/api/alerts/rules", json={"rule": rule}, headers=CSRF)
    assert r.status_code == 200, r.text
    text = Path(os.environ["WLM_ALERTS_FILE"]).read_text(encoding="utf-8")
    block = text[text.index("name: 흐름 2"):]
    assert "kind: correlation" in block and "window: 2h" in block and "min_tactics: 4" in block and "cooldown" not in block
    saved = next(r for r in engine.config.rules if r.name == "흐름 2")
    assert (saved.entities, saved.min_tactics, saved.mode) == (("host", "ip"), 4, "observe")
    view = next(r for r in admin.get("/api/alerts/config").json()["rules"] if r["name"] == "흐름 2")
    assert view["min_tactics"] == 4 and view["entities"] == ["host", "ip"]
    assert next(r for r in admin.get("/api/alerts/config").json()["rules"] if r["name"] == "대입")["tactics"] == ["자격 증명 접근"]
    bad = admin.put("/api/alerts/rules", json={"rule": {**rule, "name": "흐름 3", "window_sec": 3600, "cooldown_sec": 600}}, headers=CSRF)
    assert bad.status_code == 422
    assert admin.post("/api/alerts/rules/test", json={"name": "흐름 2", "event_id": 1}, headers=CSRF).status_code == 400



# ------------------------------------------------------------------ 검토 보완 (1차)

def test_long_chain_is_not_announced_again_on_another_entity(ctx, now):
    """묶은 알림이 30개를 넘어도 다음 주기에 같은 흐름을 계정으로 또 알리지 않는다 — 다시 알리지 않을지는 보이는 30개가 아니라 전부로
    (검토에서 재현). 보이는 목록에는 단계마다 센 알림(새 서비스·로그 삭제)이 들어 있다."""
    for i in range(31):
        put(now, "대입", -55 + i, ["MITRE T1110"], hosts=["RDS-01"], accounts=["adm"], ips=[f"203.0.113.{i}"])
    service = put(now, "새 서비스", -10, ["MITRE T1543.003"], hosts=["RDS-01"], accounts=["adm"])
    clear = put(now, "로그 삭제", -5, ["MITRE T1070.001"], hosts=["RDS-01"], accounts=["adm"])
    assert len(evaluate(ctx["admin"], now)) == 1
    [(_, payload, *_)] = corr("PC RDS-01")
    chain = payload["correlation"]
    assert len(chain["ids"]) == 33 and len(chain["alerts"]) == 30 and {service, clear} <= {a["id"] for a in chain["alerts"]}
    assert evaluate(ctx["admin"], now + timedelta(seconds=30)) == [] and corr("계정 adm") == []


def test_newest_alerts_win_when_over_the_limit(ctx, now):
    """기간 안 알림이 상한을 넘으면 최근 것을 본다 — MITRE 태그 없는 운영 알림은 세지도 않는다 (검토에서 재현)."""
    from app.alerts import correlation

    sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload)"
        " SELECT %s, '시스템 심각 오류', 'error', 'N-' || g, 1, '{\"kind\": \"count\", \"tags\": [\"ISMS 2.9.2\"]}'"
        " FROM generate_series(1, %s) g", (now - timedelta(minutes=55), correlation.SOURCE_MAX + 1))
    sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload, entity_hosts)"
        " SELECT %s, '옛 대입', 'warning', 'O-' || g, 1, '{\"kind\": \"count\", \"tags\": [\"MITRE T1110\"]}', ARRAY['O-' || g]"
        " FROM generate_series(1, %s) g", (now - timedelta(minutes=50), correlation.SOURCE_MAX + 1))
    for minutes, rule, tag in ((-5, "대입", "MITRE T1110"), (-3, "새 서비스", "MITRE T1543.003"), (-1, "로그 삭제", "MITRE T1070.001")):
        put(now, rule, minutes, [tag], hosts=["Q"])
    assert len(evaluate(ctx["admin"], now)) == 1 and len(corr("PC Q")) == 1


def test_deleted_correlation_rule_stays_hidden_from_scoped_users(ctx, now):
    """상관 규칙을 지우거나 이름을 바꿔도 그 알림('PC PC-77')은 PC 패턴 'PC*' 범위의 사용자에게 보이지 않는다 — 알림에 남은 종류로 (검토에서 재현)."""
    from app.alerts.engine import engine

    admin, desk = ctx["admin"], ctx["desk"]
    for minutes, rule, tag in ((-30, "대입", "MITRE T1110"), (-20, "새 서비스", "MITRE T1543.003"), (-10, "로그 삭제", "MITRE T1070.001")):
        put(now, rule, minutes, [tag], hosts=["PC-77"])
    [alert_id] = evaluate(admin, now)
    assert sql("SELECT kind FROM alerts WHERE id = %s", (alert_id,)) == [("correlation",)]
    path = Path(os.environ["WLM_ALERTS_FILE"])
    try:
        path.write_text(RULES.replace("  - name: 공격 흐름\n", "  - name: 공격 흐름 (예전)\n", 1), encoding="utf-8")
        engine.reload(force=True)
        assert desk.get(f"/api/alerts/{alert_id}").status_code == 404
        assert alert_id not in {a["id"] for a in desk.get("/api/alerts", params={"since": "1d"}).json()["items"]}
        assert admin.get(f"/api/alerts/{alert_id}").status_code == 200
    finally:
        path.write_text(RULES, encoding="utf-8")
        engine.reload(force=True)



# ------------------------------------------------------------------ 검토 보완 (2차)

def test_repeat_on_the_announced_pc_is_not_announced_again_but_spread_is(ctx, now):
    """이미 알린 흐름의 PC 에서 이미 센 규칙이 한 번 더 울려도(봇이 IP 를 바꿈) 계정으로 다시 알리지 않는다. 그 계정이 다른 PC 로 번지면 알린다 (검토에서 재현)."""
    admin = ctx["admin"]
    put(now, "대입", -40, ["MITRE T1110"], hosts=["SRV-X"], accounts=["evil"], ips=["198.51.100.1"])
    put(now, "새 서비스", -30, ["MITRE T1543.003"], hosts=["SRV-X"], accounts=["evil"])
    put(now, "로그 삭제", -20, ["MITRE T1070.001"], hosts=["SRV-X"], accounts=["evil"])
    assert len(evaluate(admin, now)) == 1 and len(corr("PC SRV-X")) == 1
    put(now, "대입", -1, ["MITRE T1110"], hosts=["SRV-X"], accounts=["evil"], ips=["198.51.100.2"])
    assert evaluate(admin, now + timedelta(seconds=30)) == [] and corr("계정 evil") == []
    put(now, "대입", 0, ["MITRE T1110"], hosts=["SRV-Y"], accounts=["evil"], ips=["198.51.100.3"])
    assert len(evaluate(admin, now + timedelta(seconds=60))) == 1
    [(_, payload, *_)] = corr("계정 evil")
    assert payload["correlation"]["hosts"] == ["SRV-X", "SRV-Y"]


# ------------------------------------------------------------------ 검토 보완 (3차)

def test_second_server_listed_by_a_shared_alert_still_alerts(ctx, now):
    """여러 서버를 적은 알림 하나(한 계정이 여러 서버에 원격 데스크톱)가 첫 흐름에 섞여도, 둘째 서버의 침해는 그 서버로 알린다 — 새 알림의
    (PC, 단계) 짝으로 판단 (흐름 전체의 PC 집합으로 보면 묻혔다, 검토에서 재현). 같은 PC 에서 같은 단계가 반복되면 여전히 조용하다."""
    admin = ctx["admin"]
    put(now, "여러 서버 원격", -30, ["MITRE T1021.001"], hosts=["SRV-A", "SRV-B", "SRV-C"], accounts=["evil"])
    put(now, "새 서비스", -25, ["MITRE T1543.003"], hosts=["SRV-A"], accounts=["evil"])
    put(now, "로그 삭제", -20, ["MITRE T1070.001"], hosts=["SRV-A"], accounts=["evil"])
    assert len(evaluate(admin, now)) == 1 and len(corr("PC SRV-A")) == 1
    put(now, "새 서비스", 5, ["MITRE T1543.003"], hosts=["SRV-B"], accounts=["evil"])
    put(now, "로그 삭제", 8, ["MITRE T1070.001"], hosts=["SRV-B"], accounts=["evil"])
    assert len(evaluate(admin, now + timedelta(minutes=9))) == 1 and len(corr("PC SRV-B")) == 1
    put(now, "로그 삭제", 10, ["MITRE T1070.001"], hosts=["SRV-B"], accounts=["evil"])   # 같은 PC 에서 같은 단계 반복
    assert evaluate(admin, now + timedelta(minutes=11)) == []
    [(_, payload, *_)] = corr("PC SRV-B")
    assert ["SRV-B", "새 서비스", ["TA0003", "TA0004"]] in payload["correlation"]["host_steps"]



# ------------------------------------------------------------------ 검토 보완 (4차)

def test_multi_tactic_technique_does_not_bury_the_next_server(ctx, now):
    """여러 전술에 속한 기법(T1078 유효한 계정 + T1021.001 — 기본 팩 '원격 데스크톱 새 출발지')의 알림 하나가 둘째 서버의 단계들을
    미리 '알린 것'으로 만들지 않는다 — PC 마다 흐름을 셀 때와 같은 규칙(규칙 하나는 전술 하나)으로 늘었는지 본다 (검토에서 재현)."""
    admin = ctx["admin"]
    put(now, "대입", -40, ["MITRE T1110"], hosts=["SRV-M"], accounts=["evil3"])
    put(now, "새 서비스", -30, ["MITRE T1543.003"], hosts=["SRV-M"], accounts=["evil3"])
    put(now, "새 출발지", -20, ["MITRE T1078", "MITRE T1021.001"], hosts=["SRV-N"], accounts=["evil3"])
    assert len(evaluate(admin, now)) == 1 and len(corr("계정 evil3")) == 1
    put(now, "새 서비스", 5, ["MITRE T1543.003"], hosts=["SRV-N"], accounts=["evil3"])
    put(now, "로그 삭제", 8, ["MITRE T1070.001"], hosts=["SRV-N"], accounts=["evil3"])
    assert len(evaluate(admin, now + timedelta(minutes=9))) == 1 and len(corr("PC SRV-N")) == 1


def test_long_flow_does_not_rotate_through_entity_names(ctx, now):
    """기간보다 오래 이어지는 같은 흐름(같은 PC·계정·IP 에서 같은 규칙들)은 재알림 간격마다 PC 로만 다시 알린다 — 앞 알림의 알림들이
    기간 밖으로 나가도 개체가 같으면 같은 흐름 (계정 → IP 로 이름을 바꿔 가며 왔다, 검토에서 재현)."""
    admin = ctx["admin"]
    cycle = (("대입", "MITRE T1110"), ("새 서비스", "MITRE T1543.003"), ("로그 삭제", "MITRE T1070.001"))
    for step in range(16):
        rule, tag = cycle[step % 3]
        put(now, rule, step * 10, [tag], hosts=["SRV-LONG"], accounts=["evil4"], ips=["203.0.113.9"])
        evaluate(admin, now + timedelta(minutes=step * 10, seconds=30))
    keys = [k for (k,) in sql("SELECT group_key FROM alerts WHERE rule = %s AND fired_at > %s ORDER BY id", (CORR, now - timedelta(minutes=1)))]
    assert set(keys) == {"PC SRV-LONG"} and 2 <= len(keys) <= 3
