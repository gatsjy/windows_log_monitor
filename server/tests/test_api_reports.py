"""점검 보고서 통합 테스트 (BACKLOG B-05, ADR-032): 실제 로그·알림으로 만들기 → 저장(고칠 수 없음) → 보기·확인 → 정기 실행·보내기.

이 모듈의 테스트는 위에서 아래로 이어지는 시나리오다 (앞에서 만든 보고서를 뒤에서 쓴다).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar
from zoneinfo import ZoneInfo

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Report#Member2026"
NOW = datetime.now(UTC).replace(microsecond=0)
START, END = NOW - timedelta(hours=2), NOW + timedelta(hours=1)


def _event(host, event_id, level=4, minutes_ago=30, **data):
    at = (NOW - timedelta(minutes=minutes_ago)).isoformat()
    return {"date": at, "EventID": event_id, "Level": level, "Channel": "Security", "Computer": host, "agent_host": host,
            "ProviderName": data.pop("provider", "Microsoft-Windows-Security-Auditing"), "log_source": "winevtlog",
            "Message": data.pop("message", "m"), "EventData": data}


class _Receiver(BaseHTTPRequestHandler):
    received: ClassVar[list[dict]] = []

    def do_POST(self):  # http.server 가 부르는 이름
        _Receiver.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"},
                       headers=CSRF)
            events = [
                _event("DC-01", 4625, 3, TargetUserName="kim", IpAddress="203.0.113.9"),
                _event("DC-01", 4625, 3, TargetUserName="kim", IpAddress="203.0.113.9"),
                _event("DC-01", 1102, 4, provider="Microsoft-Windows-Eventlog"),   # 감사 로그 삭제 → 점검 필요(bad)
                _event("<b>WEB</b>", 1000, 2, message="응용 프로그램 오류"),          # 로그에서 온 PC 이름 (이스케이프 확인)
                _event("DB-01", 4624, 4, minutes_ago=60 * 30),                       # 기간 밖 (30시간 전)
            ]
            assert admin.post("/api/ingest", json=events, headers={"X-API-Key": "test-key"}).json()["accepted"] == 5
            users = {}
            for name in ("viewer", "reviewer", "scoped"):
                temp = admin.post("/api/users", json={"username": name, "role": "viewer"}, headers=CSRF).json()
                c = TestClient(app)
                c.post("/api/auth/login", json={"username": name, "password": temp["temp_password"]}, headers=CSRF)
                c.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": PASSWORD},
                       headers=CSRF)
                users[name] = (c, temp["user"]["id"])
            for group, body in (("점검담당", {"permissions": ["reports.view"], "member_ids": [users["reviewer"][1]]}),
                                ("의료정보과", {"permissions": ["reports.view"], "scope_hosts": ["MED-*"],
                                             "member_ids": [users["scoped"][1]]})):
                assert admin.post("/api/user-groups", json={"name": group, **body}, headers=CSRF).status_code == 200
            receiver = f"http://127.0.0.1:{server.server_port}/hook"
            assert admin.post("/api/settings/channels", json={"name": "보고서수신", "type": "webhook", "url": receiver,
                                                              "config": {"format": "json"}}, headers=CSRF).status_code == 200
            yield {"admin": admin, **{k: v[0] for k, v in users.items()}}
    finally:
        server.shutdown()


def _generate(ctx, kind="daily", start=START, end=END, scheduled=False, send_to=()):
    from app.reports import scheduler

    return ctx["admin"].portal.call(lambda: scheduler.generate(kind, start, end, scheduled=scheduled, actor="tester",
                                                               send_to=list(send_to), now=NOW))


def test_report_content_from_real_data(ctx):
    report_id = _generate(ctx)
    r = ctx["admin"].get(f"/api/reports/{report_id}", headers=CSRF).json()
    p = r["payload"]
    assert p["events"]["total"] == 4                       # 기간 밖 1건은 빠진다
    assert p["events"]["by_level"] == {"error": 1, "warning": 2, "info": 1}
    assert sum(p["events"]["trend"]["total"]) == 4 and len(p["events"]["trend"]["buckets"]) == 3
    assert p["events"]["top_error_hosts"] == [{"value": "<b>WEB</b>", "n": 1}]
    items = {i["key"]: i for i in p["security"]["items"]}
    assert items["logon_failed"]["n"] == 2 and items["log_cleared"]["n"] == 1 and items["log_cleared"]["attention"] == "bad"
    assert p["security"]["logon_failed_users"] == [{"value": "kim", "n": 2}]
    assert p["security"]["logon_failed_ips"] == [{"value": "203.0.113.9", "n": 2}]
    assert {"level": "bad", "text": "감사·시스템 로그 삭제 1건"} in p["attention"]
    assert r["summary"]["severity"] == "error" and r["attention"] == len(p["attention"]) and len(r["sha256"]) == 64
    assert any(a["text"].startswith("백업:") for a in p["attention"])   # 백업 기록이 없으면 그것도 점검 필요


def test_list_html_and_permissions(ctx):
    admin = ctx["admin"]
    listing = admin.get("/api/reports", headers=CSRF).json()
    assert listing["items"][0]["created_by"] == "tester" and "payload" not in listing["items"][0]
    assert listing["unreviewed_30d"] == 1 and listing["schedule"]["daily"]["time"] == "09:00"
    report_id = listing["items"][0]["id"]
    page = admin.get(f"/api/reports/{report_id}/html", headers=CSRF)
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "default-src 'none'" in page.headers["content-security-policy"] and page.headers["x-frame-options"] == "SAMEORIGIN"
    assert "<b>WEB</b>" not in page.text and "&lt;b&gt;WEB&lt;/b&gt;" in page.text
    # 권한: reports.view 가 없으면 안 됨, 있어도 조회 범위가 정해져 있으면 안 됨 (모든 PC·분류를 담은 보고서)
    assert ctx["viewer"].get("/api/reports", headers=CSRF).status_code == 403
    assert ctx["scoped"].get(f"/api/reports/{report_id}", headers=CSRF).status_code == 403
    assert ctx["reviewer"].get(f"/api/reports/{report_id}/html", headers=CSRF).status_code == 200


def test_review_once_and_content_is_immutable(ctx):
    reviewer = ctx["reviewer"]
    report_id = reviewer.get("/api/reports", headers=CSRF).json()["items"][0]["id"]
    r = reviewer.post(f"/api/reports/{report_id}/review", json={"note": "로그 삭제는 정기 점검 작업(변경 CR-77)으로 확인"},
                      headers=CSRF)
    assert r.status_code == 200, r.text
    again = ctx["admin"].post(f"/api/reports/{report_id}/review", json={"note": "덮어쓰기"}, headers=CSRF)
    assert again.status_code == 409
    row = reviewer.get(f"/api/reports/{report_id}", headers=CSRF).json()
    assert (row["reviewed_by"], row["review_note"]) == ("reviewer", "로그 삭제는 정기 점검 작업(변경 CR-77)으로 확인")
    assert "점검 확인" in reviewer.get(f"/api/reports/{report_id}/html", headers=CSRF).text
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        for statement in ("UPDATE reports SET payload = '{}'::jsonb", "UPDATE reports SET review_note = '고침'",
                          "DELETE FROM reports", "TRUNCATE reports"):
            with pytest.raises(psycopg.errors.RaiseException):
                conn.execute(statement)
    audit = ctx["admin"].get("/api/audit", params={"since": "1h", "action": "report."}, headers=CSRF).json()["items"]
    assert {"report.create", "report.review"} <= {a["action"] for a in audit}


def test_manual_report_via_api(ctx):
    r = ctx["reviewer"].post("/api/reports", json={"kind": "weekly"}, headers=CSRF)
    assert r.status_code == 200 and r.json()["id"]
    row = ctx["reviewer"].get(f"/api/reports/{r.json()['id']}", headers=CSRF).json()
    assert row["kind"] == "weekly" and row["scheduled"] is False and row["deliveries"] == []   # 지금 만들기는 보내지 않는다
    start = datetime.fromisoformat(row["payload"]["period"]["start"]).astimezone(ZoneInfo("Asia/Seoul"))
    assert start.weekday() == 0 and (start.hour, start.minute) == (0, 0)


def test_settings_validation(ctx):
    admin = ctx["admin"]
    data = admin.get("/api/settings/report", headers=CSRF).json()
    assert "보고서수신" in data["targets"] and "운영팀" in data["targets"]
    for bad in ({"daily": {"time": "9시"}}, {"weekly": {"weekday": 0}}, {"targets": ["없는곳"]}):
        assert admin.put("/api/settings/report", json=bad, headers=CSRF).status_code == 422
    assert ctx["reviewer"].put("/api/settings/report", json={}, headers=CSRF).status_code == 403
    ok = admin.put("/api/settings/report", json={"daily": {"enabled": True, "time": "07:00"},
                                                  "weekly": {"enabled": False}, "targets": ["보고서수신"]}, headers=CSRF)
    assert ok.status_code == 200 and ok.json()["config"]["targets"] == ["보고서수신"]


def test_scheduler_creates_once_and_sends(ctx):
    from app.reports.scheduler import scheduler

    seoul = ZoneInfo("Asia/Seoul")
    now = datetime.combine((NOW.astimezone(seoul) + timedelta(days=1)).date(), datetime.min.time(), tzinfo=seoul)
    now = now.replace(hour=7, minute=1)   # 다음 날 07:01 (설정: 매일 07:00)
    _Receiver.received.clear()
    made = ctx["admin"].portal.call(scheduler.tick, now)
    assert len(made) == 1
    assert ctx["admin"].portal.call(scheduler.tick, now + timedelta(minutes=5)) == []   # 같은 기간은 한 번만
    row = ctx["admin"].get(f"/api/reports/{made[0]}", headers=CSRF).json()
    assert row["scheduled"] and row["kind"] == "daily" and row["created_by"] == "system"
    assert [(d["target"], d["status"]) for d in row["deliveries"]] == [("보고서수신", "sent")]
    sent = _Receiver.received[0]
    assert sent["type"] == "notice" and sent["title"].startswith("일간 점검 보고서") and sent["link"].endswith(f"#/reports/{made[0]}")
    # 다시 보내기 (설정·관리 권한)
    assert ctx["reviewer"].post(f"/api/reports/{made[0]}/send", headers=CSRF).status_code == 403
    again = ctx["admin"].post(f"/api/reports/{made[0]}/send", headers=CSRF)
    assert again.status_code == 200 and again.json()["ok"] and len(_Receiver.received) == 2


def test_purge_after_retention(ctx):
    from app import repository

    deleted = ctx["admin"].portal.call(repository.purge_reports, NOW + timedelta(days=1))
    assert deleted >= 3
    assert ctx["admin"].get("/api/reports", headers=CSRF).json()["items"] == []
