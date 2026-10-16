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


def test_settings_validation(ctx):
    admin = ctx["admin"]
    data = admin.get("/api/settings/report", headers=CSRF).json()
    assert "보고서수신" in data["targets"] and "운영팀" in data["targets"]
    for bad in ({"daily": {"time": "9시"}}, {"weekly": {"weekday": 0}}, {"targets": ["없는곳"]}):
        assert admin.put("/api/settings/report", json=bad, headers=CSRF).status_code == 422
    assert ctx["reviewer"].put("/api/settings/report", json={}, headers=CSRF).status_code == 403
    ok = admin.put("/api/settings/report", json={"daily": {"enabled": True, "time": "07:00"},
                                                  "weekly": {"enabled": False}, "targets": ["보고서수신", "운영팀"]},
                   headers=CSRF)
    assert ok.status_code == 200 and ok.json()["config"]["targets"] == ["보고서수신", "운영팀"]


def test_manual_report_via_api(ctx):
    """지금 만들기는 받는 곳이 설정되어 있어도 보내지 않는다 (받는 곳은 앞 테스트에서 설정). 만든 사람의 IP 도 감사로그에."""
    before = len(_Receiver.received)
    r = ctx["reviewer"].post("/api/reports", json={"kind": "weekly"}, headers=CSRF)
    assert r.status_code == 200 and r.json()["id"]
    row = ctx["reviewer"].get(f"/api/reports/{r.json()['id']}", headers=CSRF).json()
    assert row["kind"] == "weekly" and row["scheduled"] is False and row["deliveries"] == []
    assert len(_Receiver.received) == before
    start = datetime.fromisoformat(row["payload"]["period"]["start"]).astimezone(ZoneInfo("Asia/Seoul"))
    assert start.weekday() == 0 and (start.hour, start.minute) == (0, 0)
    created = [a for a in ctx["admin"].get("/api/audit", params={"since": "1h", "action": "report.create"}, headers=CSRF)
               .json()["items"] if a["actor"] == "reviewer"]
    assert created and created[0]["actor_ip"]


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
    # 운영팀은 메일 서버가 없어 실패 — 사유와 함께 남는다
    assert [(d["target"], d["status"]) for d in row["deliveries"]] == [("보고서수신", "sent"), ("운영팀", "failed")]
    assert row["deliveries"][1]["error"]
    sent = _Receiver.received[0]
    assert sent["type"] == "notice" and sent["title"].startswith("일간 점검 보고서") and sent["link"].endswith(f"#/reports/{made[0]}")
    audit = ctx["admin"].get("/api/audit", params={"since": "1h", "action": "report.deliver"}, headers=CSRF).json()["items"]
    assert audit[0]["actor"] == "system" and [r["status"] for r in audit[0]["detail"]["results"]] == ["sent", "failed"]
    # 다시 보내기 (설정·관리 권한): 기본은 못 받은 곳(운영팀)만 — 이미 받은 웹훅에 또 보내지 않는다
    assert ctx["reviewer"].post(f"/api/reports/{made[0]}/send", headers=CSRF).status_code == 403
    again = ctx["admin"].post(f"/api/reports/{made[0]}/send", headers=CSRF)
    assert again.status_code == 200 and not again.json()["ok"] and [d["target"] for d in again.json()["deliveries"]] == ["운영팀"]
    assert len(_Receiver.received) == 1
    # 기록은 덮어쓰지 않고 덧붙는다 (정기 발송의 결과가 남는다)
    row = ctx["admin"].get(f"/api/reports/{made[0]}", headers=CSRF).json()
    assert [(d["target"], d["status"]) for d in row["deliveries"]] == [("보고서수신", "sent"), ("운영팀", "failed"),
                                                                     ("운영팀", "failed")]
    everyone = ctx["admin"].post(f"/api/reports/{made[0]}/send", json={"all": True}, headers=CSRF)
    assert everyone.status_code == 200 and len(_Receiver.received) == 2
    # 모두 받은 보고서는 기본 보내기가 거절된다
    only_hook = ctx["admin"].put("/api/settings/report", json={"daily": {"enabled": True, "time": "07:00"},
                                                               "weekly": {"enabled": False}, "targets": ["보고서수신"]},
                                 headers=CSRF)
    assert only_hook.status_code == 200
    assert ctx["admin"].post(f"/api/reports/{made[0]}/send", headers=CSRF).status_code == 409


def test_delivery_failure_before_sending_is_recorded(ctx, monkeypatch):
    """받는 곳을 불러오다(비밀값 키 변경 등) 실패해도 보고서마다 '실패'와 사유가 남는다 — '보내지 않음'으로 보이지 않게."""
    from app.reports import scheduler

    async def broken():
        raise RuntimeError("암호화 키가 바뀌어 저장된 비밀값을 풀 수 없습니다")

    monkeypatch.setattr(scheduler.targets, "load_notifiers", broken)
    report_id = _generate(ctx, send_to=["보고서수신"])
    row = ctx["admin"].get(f"/api/reports/{report_id}", headers=CSRF).json()
    assert [(d["target"], d["status"]) for d in row["deliveries"]] == [("보고서수신", "failed")]
    assert "암호화 키가 바뀌어" in row["deliveries"][0]["error"]


def test_interrupted_delivery_resumes_on_next_tick(ctx):
    """보내다가 서버가 멈추면 '보내는 중'이 남고, 다음 주기에 그곳만 이어서 보낸다. 하루가 지나면 실패로 바꾼다."""
    from app import repository
    from app.reports import builder
    from app.reports.scheduler import scheduler

    def insert():   # generate() 가 저장까지만 하고 멈춘 상태
        async def go():
            payload = await builder.build("daily", START, END, NOW)
            return await repository.insert_report("daily", False, START, END, payload, 0, "system",
                                                  [{"target": "보고서수신", "status": "pending", "error": None, "at": None}])
        return ctx["admin"].portal.call(go)

    # 정기 보고서는 꺼서 이 테스트에서는 '이어서 보내기'만 일어나게
    off = {"daily": {"enabled": False}, "weekly": {"enabled": False}, "targets": ["보고서수신"]}
    assert ctx["admin"].put("/api/settings/report", json=off, headers=CSRF).status_code == 200
    report_id = insert()
    assert ctx["admin"].get(f"/api/reports/{report_id}", headers=CSRF).json()["deliveries"][0]["status"] == "pending"
    before = len(_Receiver.received)
    ctx["admin"].portal.call(scheduler.tick, datetime.now(UTC))
    row = ctx["admin"].get(f"/api/reports/{report_id}", headers=CSRF).json()
    assert [(d["target"], d["status"]) for d in row["deliveries"]] == [("보고서수신", "sent")]
    assert len(_Receiver.received) == before + 1
    ctx["admin"].portal.call(scheduler.tick, datetime.now(UTC))   # 다시 보내지 않는다
    assert len(_Receiver.received) == before + 1
    stale = insert()
    ctx["admin"].portal.call(scheduler.tick, datetime.now(UTC) + timedelta(days=2))
    row = ctx["admin"].get(f"/api/reports/{stale}", headers=CSRF).json()
    assert row["deliveries"][0]["status"] == "failed" and "하루가 지나" in row["deliveries"][0]["error"]


def test_report_targets_cannot_be_renamed_or_deleted(ctx):
    admin = ctx["admin"]
    hook = next(c for c in admin.get("/api/settings/channels", headers=CSRF).json()["items"] if c["name"] == "보고서수신")
    assert hook["report_target"] is True and hook["used_by"] == []
    r = admin.delete(f"/api/settings/channels/{hook['id']}", headers=CSRF)
    assert r.status_code == 400 and "점검 보고서" in r.json()["detail"]
    r = admin.put(f"/api/settings/channels/{hook['id']}", json={"name": "새이름", "type": "webhook",
                                                               "url": "http://127.0.0.1:1/hook", "config": {"format": "json"}},
                  headers=CSRF)
    assert r.status_code == 400 and "점검 보고서" in r.json()["detail"]


def test_cli_integrity_result_and_weekly_trend(ctx):
    """CLI 가 남긴 무결성 확인(문제 수만)도 보고서·메일로 그려진다. 주간 추이(하루 칸)의 합은 전체와 같다."""
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("INSERT INTO audit_log (actor, action, detail) VALUES ('cli', 'retention.verify_archives', %s)",
                     (json.dumps({"files": 3, "bad": 2}),))
    seoul = ZoneInfo("Asia/Seoul")
    end = datetime.combine((NOW.astimezone(seoul) + timedelta(days=1)).date(), datetime.min.time(), tzinfo=seoul)
    report_id = _generate(ctx, kind="weekly", start=(end - timedelta(days=7)).astimezone(UTC), end=end.astimezone(UTC))
    row = ctx["admin"].get(f"/api/reports/{report_id}", headers=CSRF).json()
    assert {"level": "bad", "text": "마지막 보관 파일 무결성 확인에서 문제 2건"} in row["payload"]["attention"]
    trend = row["payload"]["events"]["trend"]
    assert len(trend["buckets"]) == 7 and sum(trend["total"]) == row["payload"]["events"]["total"] == 5  # 30시간 전 1건 포함
    page = ctx["admin"].get(f"/api/reports/{report_id}/html", headers=CSRF)
    assert page.status_code == 200 and "문제 2건" in page.text
    sent = ctx["admin"].post(f"/api/reports/{report_id}/send", headers=CSRF)
    assert sent.status_code == 200 and sent.json()["ok"]


def test_purge_after_retention(ctx):
    from app import repository

    deleted = ctx["admin"].portal.call(repository.purge_reports, NOW + timedelta(days=1))
    assert deleted >= 3
    assert ctx["admin"].get("/api/reports", headers=CSRF).json()["items"] == []
