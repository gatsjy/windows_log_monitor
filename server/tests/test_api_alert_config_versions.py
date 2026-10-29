"""알림 설정 판본과 탐지 약화 알림 (NEW-M2, ADR-043) — 통합 시험.

회귀: config/alerts.yaml 을 서버에서 직접 고치면 로그 한 줄만 남기고 바로 적용됐다(감사로그·해시·차이 없음).
규칙을 끄거나 기준을 올려도 그 규칙의 알림을 받던 사람은 알 수 없었고, 파일이 깨진 채 다시 시작하면 규칙 0개로 돌았다.
이 모듈의 시험은 위에서 아래로 이어지는 하나의 시나리오다(판본이 쌓인다).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES_FILE = Path(os.environ["WLM_ALERTS_FILE"])
START = datetime.now(UTC) - timedelta(hours=1)
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패 급증
    sid: 1000001
    match: { event_id: "4625" }
    window: 10m
    threshold: 10
    severity: error
    notify: [설정감시]
  - name: 계정 잠금
    sid: 1000002
    match: { event_id: "4740" }
    severity: warning
    notify: [설정감시, 다른곳]
"""
EMPTY_RULES = "settings:\n  interval_sec: 30\n\nrules:\n"


class _Receiver(BaseHTTPRequestHandler):
    received: ClassVar[list[tuple[str, dict]]] = []

    def do_POST(self):  # http.server 가 부르는 이름
        _Receiver.received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        return conn.execute(query, params).fetchall()


def _write(text: str) -> None:
    """서버에서 파일을 직접 고친다 (mtime 을 확실히 바꿔 엔진이 실제로 알아채는 경로로)."""
    RULES_FILE.write_text(text, encoding="utf-8")
    at = datetime.now().timestamp() + len(sql("SELECT 1 FROM alert_config_versions"))   # 같은 초에 두 번 써도 다르게
    os.utime(RULES_FILE, (at, at))


@pytest.fixture(scope="module")
def client():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.alerts.engine import engine
    from app.main import app

    RULES_FILE.write_text(RULES, encoding="utf-8")
    engine.forget()   # 처음 설치한 서버처럼 (앞 모듈이 남긴 기억 없이)
    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            for name in ("설정감시", "다른곳"):
                url = f"http://127.0.0.1:{server.server_port}/{'watch' if name == '설정감시' else 'other'}"
                assert c.post("/api/settings/channels", json={"name": name, "type": "webhook", "url": url,
                                                              "config": {"format": "json"}}, headers=CSRF).status_code == 200
            c.portal.call(engine.record)
            yield c
    finally:
        server.shutdown()
        RULES_FILE.write_text(EMPTY_RULES, encoding="utf-8")
        engine.reload(force=True)


def _versions():
    return sql("SELECT source, actor, weakened, changes FROM alert_config_versions ORDER BY id")


def _config_alerts():
    return sql("SELECT id, group_key, severity, silence_id, payload FROM alerts WHERE rule = '알림 설정 변경' ORDER BY id")


def _deliveries(alert_id):
    return sorted(sql("SELECT notifier, status FROM alert_deliveries WHERE alert_id = %s", (alert_id,)))


def test_first_start_records_a_baseline(client):
    assert [(s, a, w, c) for s, a, w, c in _versions()] == [("startup", "system", False, [])]
    assert _config_alerts() == []


def test_disabling_a_rule_on_screen_notifies_its_receivers(client):
    _Receiver.received.clear()
    r = client.post("/api/alerts/rules/enabled", json={"names": ["계정 잠금"], "enabled": False}, headers=CSRF)
    assert r.status_code == 200, r.text
    source, actor, weakened, changes = _versions()[-1]
    assert (source, actor, weakened) == ("ui", "admin", True)
    assert [c["text"] for c in changes] == ["규칙 '계정 잠금'(1000002) 끔"]
    [(alert_id, key, severity, silence_id, payload)] = _config_alerts()
    assert (key, severity, silence_id) == ("화면에서 저장 · admin", "warning", None)
    assert payload["kind"] == "config" and "판본 #2" in payload["description"]
    assert _deliveries(alert_id) == [("다른곳", "sent"), ("설정감시", "sent")]
    assert sorted(p for p, _ in _Receiver.received) == ["/other", "/watch"]
    audit = sql("SELECT actor, detail FROM audit_log WHERE action = 'alerts.config.apply' ORDER BY id")
    assert [(a, d["source"], d["weakened"]) for a, d in audit] == [("system", "startup", False), ("admin", "ui", True)]


def test_strengthening_does_not_notify(client):
    before = len(_config_alerts())
    assert client.post("/api/alerts/rules/enabled", json={"names": ["계정 잠금"], "enabled": True},
                       headers=CSRF).status_code == 200
    assert _versions()[-1][:3] == ("ui", "admin", False)
    assert len(_config_alerts()) == before


def test_direct_file_edit_is_recorded_and_notified(client):
    from app.alerts.engine import engine

    _write(RULES.replace("threshold: 10", "threshold: 50"))
    client.portal.call(engine.tick)   # 엔진의 다음 주기
    source, actor, weakened, changes = _versions()[-1]
    assert (source, actor, weakened) == ("file", "system", True)
    assert [c["text"] for c in changes] == ["규칙 '로그온 실패 급증'(1000001) 건수 기준 10 → 50"]
    alert_id, key, severity, _, _ = _config_alerts()[-1]
    # 바뀐 규칙의 받는 곳으로만, 그 규칙의 심각도로
    assert (key, severity) == ("서버에서 파일 직접 수정", "error")
    assert _deliveries(alert_id) == [("설정감시", "sent")]


def test_unrecorded_file_edit_is_not_blamed_on_the_screen_user(client):
    from app.alerts.engine import engine

    current = RULES_FILE.read_text(encoding="utf-8")
    _write(current.replace("window: 10m", "window: 5m"))
    engine.reload()   # 화면이 규칙 목록을 읽으며 적용 — 판본은 아직
    rule = {"name": "계정 잠금", "sid": 1000002, "match": {"event_id": "4740"}, "threshold": 3, "window_sec": 300,
            "cooldown_sec": 1800, "severity": "warning", "notify": ["설정감시", "다른곳"]}
    assert client.put("/api/alerts/rules", json={"original": "계정 잠금", "rule": rule}, headers=CSRF).status_code == 200
    file_version, ui_version = _versions()[-2:]
    assert file_version[:3] == ("file", "system", True)
    assert [c["text"] for c in file_version[3]] == ["규칙 '로그온 실패 급증'(1000001) 집계 기간 10분 → 5분"]
    assert ui_version[:3] == ("ui", "admin", True)
    assert [c["text"] for c in ui_version[3]] == ["규칙 '계정 잠금'(1000002) 건수 기준 1 → 3"]


def test_wide_silence_notifies_and_cannot_be_silenced(client):
    before = len(_config_alerts())
    narrow = {"rule": "계정 잠금", "group_key": "PC-1", "duration_sec": 7200, "reason": "패치"}
    assert client.post("/api/alerts/silences", json=narrow, headers=CSRF).status_code == 200
    assert len(_config_alerts()) == before   # 한 규칙·한 대상 2시간은 평소 점검
    wide = {"duration_sec": 3600, "reason": "<script>점검</script>"}
    assert client.post("/api/alerts/silences", json=wide, headers=CSRF).status_code == 200
    alert_id, key, _, silence_id, payload = _config_alerts()[-1]
    # '모든 규칙·모든 대상' 무음이 걸려 있는데도 보낸다 (무음으로 막으면 그 뒤의 변경을 아무도 모른다)
    assert (key, silence_id) == ("무음 · admin", None)
    assert payload["description"].startswith("넓은 무음: 모든 규칙 · 모든 대상")
    assert _deliveries(alert_id) == [("다른곳", "sent"), ("설정감시", "sent")]
    long = {"rule": "로그온 실패 급증", "duration_sec": 3 * 86400, "reason": "오탐 조정"}
    assert client.post("/api/alerts/silences", json=long, headers=CSRF).status_code == 200
    alert_id, *_ = _config_alerts()[-1]
    assert _deliveries(alert_id) == [("설정감시", "sent")]


def test_broken_file_at_startup_keeps_the_last_version(client):
    from app.alerts.engine import engine

    applied = [r.name for r in engine.config.rules]
    before = len(_config_alerts())
    _write("rules: [\n")
    engine.forget()   # 서버 재시작
    engine.reload()
    assert engine.config.rules == ()   # 예전에는 이대로 규칙 0개로 돌았다
    client.portal.call(engine.record)
    assert [r.name for r in engine.config.rules] == applied
    assert "마지막으로 적용한 판본" in engine.config_error
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'alerts.config.invalid'") == [(1,)]
    _, key, _, _, payload = _config_alerts()[-1]
    assert len(_config_alerts()) == before + 1 and payload["description"].startswith("알림 설정 파일 오류")
    assert key == "서버에서 파일 직접 수정"
    client.portal.call(engine.record)   # 같은 깨진 파일은 한 번만 알린다
    assert len(_config_alerts()) == before + 1
    status = client.get("/api/alerts/config", headers=CSRF).json()
    assert "마지막으로 적용한 판본" in status["config_error"] and len(status["rules"]) == len(applied)


def test_fixing_the_file_applies_and_compares_with_the_last_version(client):
    from app.alerts.engine import engine

    _write(RULES[:RULES.index("  - name: 계정 잠금")])
    client.portal.call(engine.tick)
    assert engine.config_error is None and [r.name for r in engine.config.rules] == ["로그온 실패 급증"]
    source, _, weakened, changes = _versions()[-1]
    assert (source, weakened) == ("file", True)
    assert {c["text"] for c in changes} == {"규칙 '계정 잠금'(1000002) 삭제",
                                            "규칙 '로그온 실패 급증'(1000001) 집계 기간 5분 → 10분",
                                            "규칙 '로그온 실패 급증'(1000001) 건수 기준 50 → 10"}


def test_change_made_while_the_server_was_stopped(client):
    from app.alerts.engine import engine

    engine.forget()
    _write(RULES[:RULES.index("  - name: 계정 잠금")].replace("severity: error", "severity: info"))
    engine.reload()
    client.portal.call(engine.record)
    source, actor, weakened, changes = _versions()[-1]
    assert (source, actor, weakened) == ("startup", "system", True)
    assert [c["text"] for c in changes] == ["규칙 '로그온 실패 급증'(1000001) 심각도 오류 → 정보"]
    assert _config_alerts()[-1][1] == "서버 시작 때 발견(꺼져 있는 동안 수정)"


def _reset(client):
    from app.alerts.engine import engine

    _write(RULES)
    client.portal.call(engine.tick)
    assert engine.config_error is None and len(engine.config.rules) == 2


RULE_1 = {"name": "로그온 실패 급증", "sid": 1000001, "match": {"event_id": "4625"}, "window_sec": 600, "threshold": 10,
          "cooldown_sec": 1800, "severity": "error", "notify": ["설정감시"]}


def _toggle(client, name, enabled):
    r = client.post("/api/alerts/rules/enabled", json={"names": [name], "enabled": enabled}, headers=CSRF)
    assert r.status_code == 200, r.text


def test_disable_edit_then_enable_is_compared_with_the_last_enabled_version(client):
    """끄고(알림) → 꺼진 채 기준을 크게 올리고(알림 없음) → 켜면, 바로 앞 판본은 꺼진 모양이라 약화가 보이지 않았다(검토에서 재현)."""
    _reset(client)
    enabled_version = sql("SELECT max(id) FROM alert_config_versions")[0][0]
    _toggle(client, "로그온 실패 급증", False)
    before = len(_config_alerts())
    r = client.put("/api/alerts/rules", json={"original": "로그온 실패 급증",
                                              "rule": {**RULE_1, "enabled": False, "threshold": 99999}}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert _versions()[-1][2] is False and len(_config_alerts()) == before
    _toggle(client, "로그온 실패 급증", True)
    source, _, weakened, changes = _versions()[-1]
    assert (source, weakened) == ("ui", True)
    assert [c["text"] for c in changes if c["weakens"]] == [
        f"규칙 '로그온 실패 급증'(1000001) 다시 켬 — 판본 #{enabled_version}에서 켜져 있던 때와 비교: 건수 기준 10 → 99,999"]
    assert len(_config_alerts()) == before + 1


def test_unusual_broken_files_are_recorded_not_ignored(client):
    """UTF-8 이 아닌 파일·settings 가 숫자인 파일은 예외가 새서 오류도 기록도 없이 옛 설정으로 돌았다(검토에서 재현)."""
    from app.alerts.engine import engine

    _reset(client)
    for content, expected in ((("# 한글 주석 (메모장 ANSI)\n" + RULES).encode("cp949"), "UTF-8"),
                              (b"settings: 30\nrules: []\n", "settings")):
        RULES_FILE.write_bytes(content)
        client.portal.call(engine.tick)
        assert expected in engine.config_error and len(engine.config.rules) == 2   # 이전 설정 유지
        assert expected in sql("SELECT detail->>'error' FROM audit_log WHERE action = 'alerts.config.invalid'"
                               " ORDER BY id DESC LIMIT 1")[0][0]
    # 깨진 동안 규칙 하나만 고치는 저장은 막는다 (빈 틀에 규칙 하나를 더해 쓰면 나머지가 사라진다)
    r = client.put("/api/alerts/rules", json={"original": "로그온 실패 급증", "rule": RULE_1}, headers=CSRF)
    assert r.status_code == 409, r.text
    _reset(client)


def test_edit_that_restores_the_modification_time_is_still_seen(client):
    from app.alerts.engine import engine

    _reset(client)
    before = os.stat(RULES_FILE)
    RULES_FILE.write_text(RULES.replace("threshold: 10", "threshold: 70"), encoding="utf-8")
    os.utime(RULES_FILE, ns=(before.st_atime_ns, before.st_mtime_ns))   # 'touch -r' 처럼 수정 시각을 되돌림
    client.portal.call(engine.tick)
    source, actor, weakened, changes = _versions()[-1]
    assert (source, actor, weakened) == ("file", "system", True)
    assert [c["text"] for c in changes] == ["규칙 '로그온 실패 급증'(1000001) 건수 기준 10 → 70"]


def test_back_to_back_silences_count_as_wide(client):
    _reset(client)
    before = len(_config_alerts())
    first = {"rule": "계정 잠금", "duration_sec": 86400, "reason": "하루씩"}
    r = client.post("/api/alerts/silences", json=first, headers=CSRF)
    assert r.status_code == 200 and len(_config_alerts()) == before   # 24시간 하나는 넓지 않다
    nxt = {**first, "starts_at": r.json()["ends_at"]}
    assert client.post("/api/alerts/silences", json=nxt, headers=CSRF).status_code == 200
    _, key, _, _, payload = _config_alerts()[-1]
    assert len(_config_alerts()) == before + 1 and key == "무음 · admin"
    assert payload["description"].startswith("넓은 무음: 계정 잠금 · 모든 대상")


def test_renaming_onto_a_silenced_name_is_flagged(client):
    from app.alerts.engine import engine

    _reset(client)
    # '계정 잠금'에 무음이 걸려 있다 → 다른 규칙을 그 이름으로 바꾸면 그 무음이 그 규칙에 걸린다
    _write(RULES.replace("name: 계정 잠금", "name: 계정 잠금(옛)").replace("name: 로그온 실패 급증", "name: 계정 잠금"))
    client.portal.call(engine.tick)
    _, _, weakened, changes = _versions()[-1]
    assert weakened is True
    assert [c["text"] for c in changes if c["weakens"]] == [
        ("규칙 '로그온 실패 급증'(1000001) 이름 '로그온 실패 급증' → '계정 잠금' (이전 발생 기록과의 연결이 끊김)"
         " — 이 이름에 걸린 무음이 이 규칙에 적용됩니다")]
    _reset(client)


def test_failed_notification_is_retried_without_a_second_version(client, monkeypatch):
    from app.alerts.engine import engine

    _reset(client)
    versions, alerts = len(_versions()), len(_config_alerts())

    async def down(*args, **kwargs):
        raise RuntimeError("DB 끊김")

    monkeypatch.setattr(engine, "notify_change", down)
    _write(RULES.replace("threshold: 10", "threshold: 80"))
    client.portal.call(engine.tick)   # 판본은 남고 알림은 실패 — 탐지는 계속 (tick 은 예외를 삼킨다)
    assert len(_versions()) == versions + 1 and len(_config_alerts()) == alerts
    monkeypatch.undo()
    client.portal.call(engine.record)
    assert len(_versions()) == versions + 1 and len(_config_alerts()) == alerts + 1
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'alerts.config.apply' AND (detail->>'version')::int = %s",
               (sql("SELECT max(id) FROM alert_config_versions")[0][0],)) == [(1,)]


def test_screen_save_waits_until_a_file_change_is_recorded(client, monkeypatch):
    """서버에서 고친 것을 판본으로 남기지 못한 채 화면 저장이 덮으면 그 변경이 화면 사용자 이름으로 남는다."""
    from app import repository
    from app.alerts.engine import engine

    _reset(client)

    async def down(*args, **kwargs):
        raise RuntimeError("DB 끊김")

    monkeypatch.setattr(repository, "insert_alert_config_version", down)
    direct = RULES.replace("threshold: 10", "threshold: 90")
    _write(direct)
    r = client.post("/api/alerts/rules/enabled", json={"names": ["계정 잠금"], "enabled": False}, headers=CSRF)
    assert r.status_code == 503, r.text
    assert RULES_FILE.read_text(encoding="utf-8") == direct   # 덮어쓰지 않았다
    monkeypatch.undo()
    client.portal.call(engine.tick)
    assert _versions()[-1][:3] == ("file", "system", True)


def test_screen_reload_records_right_away(client):
    _reset(client)
    _write(RULES.replace("threshold: 10", "threshold: 11"))
    client.get("/api/alerts/config", headers=CSRF)   # 엔진의 다음 주기 전에 화면이 읽어도
    assert [c["text"] for c in _versions()[-1][3]] == ["규칙 '로그온 실패 급증'(1000001) 건수 기준 10 → 11"]


def test_missing_file_at_startup_runs_on_the_last_version_and_full_save_recovers(client):
    from app.alerts.engine import engine

    _reset(client)
    RULES_FILE.unlink()
    engine.forget()
    engine.reload()
    client.portal.call(engine.record)
    assert [r.name for r in engine.config.rules] == ["로그온 실패 급증", "계정 잠금"]
    assert engine.fallback_version == sql("SELECT max(id) FROM alert_config_versions")[0][0]
    assert sql("SELECT detail->>'missing' FROM audit_log WHERE action = 'alerts.config.invalid' ORDER BY id DESC LIMIT 1") == [
        ("true",)]
    assert client.put("/api/alerts/rules", json={"original": "로그온 실패 급증", "rule": RULE_1}, headers=CSRF).status_code == 409
    r = client.put("/api/alerts/config", content=RULES.encode(), headers={**CSRF, "Content-Type": "text/plain"})
    assert r.status_code == 200, r.text
    assert engine.config_error is None and engine.fallback_version is None and RULES_FILE.exists()


def test_report_lists_the_changes(client):
    from app.reports import builder, render

    payload = client.portal.call(builder.build, "daily", START, datetime.now(UTC) + timedelta(minutes=1))
    texts = [a["text"] for a in payload["attention"]]
    al = payload["alerts"]
    assert al["config_changes_total"] == len(_versions()) - 1   # 처음 기준 판본은 변경이 아니다
    assert al["config_changes_weakened"] == sum(1 for v in _versions() if v[2])
    assert al["config_changes_direct"] == sum(1 for v in _versions()[1:] if v[0] != "ui")
    wide = sql("SELECT count(*) FROM audit_log WHERE action = 'alerts.silence.create' AND (detail->>'wide')::boolean")[0][0]
    assert al["wide_silences_total"] == wide == 3   # 모든 규칙 1시간 · 한 규칙 3일 · 이어 붙인 하루+하루
    assert any(t.startswith("탐지를 약하게 하는 알림 설정 변경") for t in texts)
    assert any(t.startswith("화면을 거치지 않고 서버에서 고친 알림 설정") for t in texts)
    assert any(t.startswith("넓은 무음 3건") for t in texts)
    page = render.html(payload)
    assert "알림 설정 변경" in page and "&lt;script&gt;점검&lt;/script&gt;" in page and "<script>점검" not in page


def test_scoped_users_do_not_see_config_alerts(client):
    from fastapi.testclient import TestClient

    from app.main import app

    temp = client.post("/api/users", json={"username": "ward", "role": "viewer"}, headers=CSRF).json()
    # 모든 PC 를 볼 수 있는 범위라도 범위가 정해진 사용자에게 이 시스템의 설정 변경(규칙·사람 이름)은 보이지 않는다
    assert client.post("/api/user-groups", json={"name": "병동", "scope_hosts": ["*"], "member_ids": [temp["user"]["id"]]},
                       headers=CSRF).status_code == 200
    ward = TestClient(app)   # with 를 쓰면 나갈 때 앱 수명(연결 풀)이 닫힌다
    ward.post("/api/auth/login", json={"username": "ward", "password": temp["temp_password"]}, headers=CSRF)
    r = ward.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": "Scope#Member2026"},
                  headers=CSRF)
    assert r.status_code == 200, r.text
    r = ward.get("/api/alerts", params={"since": "1d"}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert "알림 설정 변경" not in {a["rule"] for a in r.json()["items"]}
    alert_id = _config_alerts()[-1][0]
    assert ward.get(f"/api/alerts/{alert_id}", headers=CSRF).status_code == 404
    assert "알림 설정 변경" in {a["rule"] for a in client.get("/api/alerts", params={"since": "1d"}, headers=CSRF).json()["items"]}


def test_versions_are_append_only_and_purge_keeps_the_last(client):
    from app import repository

    with pytest.raises(psycopg.errors.RaiseException):
        sql("UPDATE alert_config_versions SET actor = 'x'")
    with pytest.raises(psycopg.errors.RaiseException):
        sql("DELETE FROM alert_config_versions")
    last = sql("SELECT max(id) FROM alert_config_versions")[0][0]
    client.portal.call(repository.purge_audit, datetime.now(UTC) + timedelta(days=1))
    assert sql("SELECT id FROM alert_config_versions") == [(last,)]
