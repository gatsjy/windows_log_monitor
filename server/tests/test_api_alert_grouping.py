"""알림 묶음 전송 (BACKLOG B-41, ADR-057) — 통합 시험: 실제 전송기(drain)와 받는 웹훅으로.

회귀: 대상 키마다 알림 한 통이라 300대에서 같은 오류가 나면 메일·메신저가 300통이었다(두레이는 주소별 1.1초 간격이라 5분 넘게).
모으는 시간·묶음 간격은 DB 의 시각을 앞당겨 흉내 낸다(전송기는 실제 시각과 queued_at·sent_at 을 비교한다).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
BASE = "settings:\n  interval_sec: 30\n{extra}\nrules: []\n"


class _Receiver(BaseHTTPRequestHandler):
    received: ClassVar[list[tuple[str, dict]]] = []

    def do_POST(self):  # http.server 가 부르는 이름
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Receiver.received.append((self.path, body))
        # /picky: 본문에 POISON 이 든 통만 거절하는 받는 쪽 (DLP 프록시·메일 554 처럼 알림 하나의 내용 때문에)
        picky = self.path == "/picky" and "POISON" in json.dumps(body, ensure_ascii=False)
        self.send_response(503 if self.path == "/down" else 400 if picky else 200)
        self.end_headers()
        self.wfile.write(b"x")

    def log_message(self, *args):
        pass


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _config(client, extra=""):
    from app.alerts.engine import engine

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(BASE.format(extra=extra), encoding="utf-8")
    engine.reload(force=True)


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

    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            for name, path, fmt in (("묶음", "ok", "text"), ("기계", "machine", "json"), ("고장", "down", "text"),
                                    ("까다로움", "picky", "text")):
                r = c.post("/api/settings/channels", json={"name": name, "type": "webhook", "config": {"format": fmt},
                                                           "url": f"http://127.0.0.1:{server.server_port}/{path}"}, headers=CSRF)
                assert r.status_code == 200, r.text
            _config(c)
            yield c
    finally:
        server.shutdown()
        _config(None)


@pytest.fixture(autouse=True)
def _clean():
    _Receiver.received.clear()
    yield


def fire(client, rule, keys, notify=("묶음",), severity="error", kind="count", description="시험"):
    from app import repository
    from app.alerts.message import AlertMessage

    ids = []
    for key in keys:
        m = AlertMessage(rule=rule, severity=severity, kind=kind, group_by="host", group_key=key, event_count=3, threshold=1,
                         window_sec=600, fired_at=datetime.now(UTC), description=description.format(key=key))
        ids.append(client.portal.call(repository.insert_alert, m.to_dict(), notify))
    return ids


def drain(client):
    from app.alerts.dispatcher import dispatcher

    client.portal.call(dispatcher.drain)


def passed(rule, seconds):
    """그 규칙의 대기열 시각을 seconds 만큼 앞당긴다 (들어온 시각·보낸 시각·보낼 시각)."""
    sql("UPDATE alert_deliveries d SET queued_at = d.queued_at - make_interval(secs => %s),"
        " sent_at = d.sent_at - make_interval(secs => %s), next_attempt_at = d.next_attempt_at - make_interval(secs => %s)"
        " FROM alerts a WHERE a.id = d.alert_id AND a.rule = %s", (seconds, seconds, seconds, rule))


def posts(path="/ok"):
    return [b for p, b in _Receiver.received if p == path]


def test_storm_of_300_is_two_messages(client):
    """300대 폭주 → 모으는 30초 뒤 한 통, 그 뒤 5분 안에 생긴 것은 '추가' 한 통. 알림마다 증적(보냄·묶음 크기)은 그대로."""
    ids = fire(client, "서비스 비정상 종료", [f"PC-{i:03d}" for i in range(300)])
    drain(client)
    assert posts() == []                                        # 같은 규칙 알림을 모으는 중
    [(held,)] = sql("SELECT count(*) FROM alert_deliveries WHERE alert_id = ANY(%s) AND status = 'pending'"
                    " AND next_attempt_at > now() + interval '20 seconds'", (ids,))
    assert held == 300
    passed("서비스 비정상 종료", 31)
    drain(client)
    [first] = posts()
    assert first["text"].startswith("[오류] 서비스 비정상 종료 · 300대 (PC-000, PC-001, PC-002 외 297대)")
    assert sql("SELECT status, batch_size, count(*) FROM alert_deliveries WHERE alert_id = ANY(%s) GROUP BY 1, 2",
               (ids,)) == [("sent", 300, 300)]
    detail = client.get(f"/api/alerts/{ids[0]}").json()
    assert detail["deliveries"][0]["batch_size"] == 300

    more = fire(client, "서비스 비정상 종료", ["PC-300", "PC-301"])
    passed("서비스 비정상 종료", 31)                              # 모으는 시간은 지났지만 묶음 간격(5분) 안
    drain(client)
    assert len(posts()) == 1
    passed("서비스 비정상 종료", 300)
    drain(client)
    assert len(posts()) == 2 and posts()[1]["text"].startswith("[오류] 서비스 비정상 종료 · 2대 (PC-300, PC-301)")
    assert {r[0] for r in sql("SELECT batch_size FROM alert_deliveries WHERE alert_id = ANY(%s)", (more,))} == {2}


def test_critical_goes_now_and_then_every_minute(client):
    fire(client, "관리자 그룹 구성원 추가", ["DC-01"], severity="critical")
    drain(client)
    assert len(posts()) == 1 and posts()[0]["text"].startswith("[심각] 관리자 그룹 구성원 추가 · DC-01")   # 혼자면 예전 모양
    fire(client, "관리자 그룹 구성원 추가", ["DC-02", "DC-03"], severity="critical")
    drain(client)
    assert len(posts()) == 1                                    # 심각도 간격(1분) 안
    passed("관리자 그룹 구성원 추가", 61)
    drain(client)
    assert len(posts()) == 2 and "· 2대 (DC-02, DC-03)" in posts()[1]["text"]


def test_machine_formats_stay_per_alert(client):
    """json 웹훅은 알림마다 dedup_key 로 사고를 여닫는다 — 묶지도 기다리지도 않는다."""
    ids = fire(client, "계정 잠김", ["kim", "lee", "park"], notify=("기계",))
    drain(client)
    assert sorted(b["alert"]["alert_id"] for b in posts("/machine")) == ids
    assert {r[0] for r in sql("SELECT batch_size FROM alert_deliveries WHERE alert_id = ANY(%s)", (ids,))} == {1}


def test_stale_rows_are_skipped_inside_a_group(client):
    """보낼 때 다시 본다(dispatcher._stale) — 모으는 사이 자동 해결된 알림은 묶음에서 빠진다."""
    ids = fire(client, "디스크 부족", ["SRV-1", "SRV-2", "SRV-3"])
    sql("UPDATE alerts SET status = 'resolved', auto_resolved = true, resolution = 'auto' WHERE id = %s", (ids[1],))
    passed("디스크 부족", 31)
    drain(client)
    [msg] = posts()
    assert "· 2대 (SRV-1, SRV-3)" in msg["text"]
    rows = dict(sql("SELECT alert_id, status || ':' || coalesce(batch_size::text, '-') FROM alert_deliveries"
                    " WHERE alert_id = ANY(%s)", (ids,)))
    assert rows == {ids[0]: "sent:2", ids[1]: "skipped:-", ids[2]: "sent:2"}


def test_failed_group_retries_together(client):
    ids = fire(client, "백업 실패", ["NAS-1", "NAS-2", "NAS-3"], notify=("고장",))
    passed("백업 실패", 31)
    drain(client)
    assert len(posts("/down")) == 1
    rows = sql("SELECT status, attempts, next_attempt_at FROM alert_deliveries WHERE alert_id = ANY(%s)", (ids,))
    assert {(r[0], r[1]) for r in rows} == {("failed", 1)} and len({r[2] for r in rows}) == 1


def test_grouping_off_sends_each_alert(client):
    _config(client, "  group_interval_sec: 0")
    try:
        assert client.get("/api/alerts/config").json()["grouping"] == {"wait_sec": 30, "interval_sec": 0}
        fire(client, "로그온 실패", ["PC-A", "PC-B"])
        drain(client)
        assert sorted(b["text"].split(" · ")[1].split("\n")[0] for b in posts()) == ["PC-A", "PC-B"]
    finally:
        _config(client)


def test_one_rejected_alert_does_not_sink_the_group(client):
    """받는 쪽이 알림 하나의 내용 때문에 묶음을 거절하면 반씩 나눠 다시 보낸다 — 거절된 알림만 시도를 쓴다
    (검토에서 재현: 예전에는 넷 모두 다섯 번 실패해 gave_up)."""
    ids = fire(client, "거절 시험", ["PC-1", "PC-2", "POISON-3", "PC-4"], notify=("까다로움",))
    passed("거절 시험", 31)
    drain(client)
    rows = dict(sql("SELECT a.group_key, d.status || ':' || d.attempts || ':' || coalesce(d.batch_size::text, '-')"
                    " FROM alert_deliveries d JOIN alerts a ON a.id = d.alert_id WHERE d.alert_id = ANY(%s)", (ids,)))
    assert rows == {"PC-1": "sent:1:2", "PC-2": "sent:1:2", "POISON-3": "failed:1:-", "PC-4": "sent:1:1"}   # 보낸 것도 시도 한 번
    sent = [b["text"] for b in posts("/picky") if "POISON" not in b["text"]]
    assert len(sent) == 2 and "· 2대 (PC-1, PC-2)" in sent[0]


def test_builtin_alerts_are_never_grouped(client):
    """내장 알림(설정 변경·관리 작업·감시)은 알림마다 내용(무엇이 바뀌었나)이 본문이라 묶지 않고 기다리지도 않는다 (검토에서 재현)."""
    from app.alerts.builtin import ADMIN_RULE, CONFIG_RULE

    fire(client, CONFIG_RULE, ["화면 · admin", "화면 · boss"], severity="warning", kind="config",
         description="탐지를 약하게 하는 변경\n- {key} 이(가) 규칙 끔")
    fire(client, ADMIN_RULE, ["관리 작업 · admin"], severity="warning", kind="config", description="관리 권한 부여\n- 관리자 계정 x")
    drain(client)
    texts = [b["text"] for b in posts()]
    assert len(texts) == 3 and all("묶어" not in t for t in texts)
    assert any("화면 · boss" in t for t in texts) and any("관리 작업 알림" in t for t in texts)
