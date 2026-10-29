"""관리 작업 알림 (BACKLOG B-36 2단계) — 통합 시험.

회귀: 받는 곳 쪽에서도 탐지를 끌 수 있었다 — 수신 그룹에서 사람을 빼거나, 연동을 끄거나, '받을 최소 수준'을 올리면 규칙은 그대로인데
알림이 아무에게도 가지 않는다. 관리자 계정 만들기·관리 권한 부여·보관 파일 복원도 감사로그에만 남아 다른 사람은 몰랐다.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30
  fallback_notify: [당직]

rules:
  - name: 로그온 실패
    enabled: true
    match: { event_id: "4625" }
    notify: [보안팀, 당직]
"""


class _Receiver(BaseHTTPRequestHandler):
    received: ClassVar[list[dict]] = []

    def do_POST(self):  # http.server 가 부르는 이름
        _Receiver.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.alerts.engine import engine
    from app.main import app

    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            group_id = c.post("/api/settings/groups", json={"name": "보안팀"}, headers=CSRF).json()["id"]
            contacts = [c.post("/api/settings/contacts", json={"name": n, "email": f"{n}@example.com", "group_ids": [group_id]},
                               headers=CSRF).json()["id"] for n in ("kim", "lee")]
            channel_id = c.post("/api/settings/channels", json={"name": "당직", "type": "webhook", "config": {"format": "json"},
                                                                "url": f"http://127.0.0.1:{server.server_port}/duty"},
                                headers=CSRF).json()["id"]
            Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
            engine.reload(force=True)
            yield {"c": c, "group": group_id, "contacts": contacts, "channel": channel_id, "port": server.server_port}
    finally:
        server.shutdown()
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def _admin_alerts():
    return sql("SELECT id, group_key, payload FROM alerts WHERE rule = '관리 작업 알림' ORDER BY id")


def _notifiers(alert_id):
    return sorted(n for (n,) in sql("SELECT notifier FROM alert_deliveries WHERE alert_id = %s", (alert_id,)))


def test_removing_a_receiver_from_a_used_group_is_reported_elsewhere(ctx):
    c = ctx["c"]
    r = c.put(f"/api/settings/groups/{ctx['group']}", json={"name": "보안팀", "member_ids": [ctx["contacts"][0]]}, headers=CSRF)
    assert r.status_code == 200, r.text
    [(alert_id, key, payload)] = _admin_alerts()
    assert key == "관리 작업 · admin" and payload["kind"] == "config"
    assert "'보안팀' 에서 받는 사람 1명이 빠졌습니다 (남은 1명)" in payload["description"]
    assert _notifiers(alert_id) == ["당직"]   # 약해진 그 곳은 빼고


def test_unchanged_save_says_nothing(ctx):
    before = len(_admin_alerts())
    ctx["c"].put(f"/api/settings/groups/{ctx['group']}", json={"name": "보안팀", "member_ids": [ctx["contacts"][0]]},
                 headers=CSRF)
    assert len(_admin_alerts()) == before


def test_channel_turned_off_or_quieter_is_reported(ctx):
    c, url = ctx["c"], f"/api/settings/channels/{ctx['channel']}"
    body = {"name": "당직", "type": "webhook", "config": {"format": "json"}}
    assert c.put(url, json={**body, "min_severity": "critical"}, headers=CSRF).status_code == 200
    alert_id, _, payload = _admin_alerts()[-1]
    assert "'당직' 받을 최소 수준 info → critical" in payload["description"] and _notifiers(alert_id) == ["보안팀"]
    assert c.put(url, json={**body, "is_active": False}, headers=CSRF).status_code == 200
    off = _admin_alerts()[-1][2]["description"]
    assert "'당직'(으)로 이제 보낼 수 없습니다: 사용 안 함" in off
    count = len(_admin_alerts())
    assert c.put(url, json={**body, "is_active": True}, headers=CSRF).status_code == 200   # 되살리는 것은 약화가 아니다
    assert len(_admin_alerts()) == count


def test_admin_grants_are_reported(ctx):
    c = ctx["c"]
    before = len(_admin_alerts())
    temp = c.post("/api/users", json={"username": "boss", "role": "admin"}, headers=CSRF).json()
    assert "관리자 계정 'boss' 을(를) 만들었습니다" in _admin_alerts()[-1][2]["description"]
    viewer = c.post("/api/users", json={"username": "watcher", "role": "viewer"}, headers=CSRF).json()["user"]
    assert len(_admin_alerts()) == before + 1   # 조회자는 알리지 않는다
    assert c.patch(f"/api/users/{viewer['id']}", json={"role": "admin"}, headers=CSRF).status_code == 200
    assert "'watcher' 을(를) 관리자로 바꿨습니다" in _admin_alerts()[-1][2]["description"]
    r = c.post("/api/user-groups", json={"name": "운영", "permissions": ["settings.manage"], "member_ids": [temp["user"]["id"]]},
               headers=CSRF)
    assert r.status_code == 200, r.text
    assert "그룹 '운영' 에 관리 권한 settings.manage 을(를) 주었습니다" in _admin_alerts()[-1][2]["description"]
    count = len(_admin_alerts())
    assert c.post("/api/user-groups", json={"name": "보기만", "permissions": [], "member_ids": [viewer["id"]]},
                  headers=CSRF).status_code == 200
    assert len(_admin_alerts()) == count   # 관리 권한이 없는 그룹


def test_archive_restore_is_reported(ctx, monkeypatch):
    from app import archive

    async def restored(partition, hold_days, actor):
        return 1234

    monkeypatch.setattr(archive, "restore", restored)
    r = ctx["c"].post("/api/settings/retention/restore", json={"partition": "events_2025_01", "hold_days": 7}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert "보관 파일 events_2025_01 을(를) 다시 검색할 수 있게 했습니다 (1,234건, 7일 동안)" in _admin_alerts()[-1][2]["description"]


def test_admin_alerts_cannot_be_silenced(ctx):
    r = ctx["c"].post("/api/alerts/silences", json={"rule": "관리 작업 알림", "duration_sec": 3600, "reason": "x"}, headers=CSRF)
    assert r.status_code == 422


def test_report_summarises_admin_actions(ctx):
    from datetime import UTC, datetime, timedelta

    from app.reports import builder, render

    now = datetime.now(UTC)
    payload = ctx["c"].portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    groups = {g["label"]: g["n"] for g in payload["admin"]["groups"]}
    assert groups["권한·계정"] >= 4 and groups["알림 받는 곳"] >= 4 and groups["보관·복원"] == 0   # 복원은 대체 함수였다
    assert payload["admin"]["alerts"] == len(_admin_alerts())
    assert "관리 작업 요약" in render.html(payload)
