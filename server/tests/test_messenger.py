"""웹훅 보내는 형식(메신저 프리셋, BACKLOG B-04): 형식별 본문 스냅샷, 서비스 제한, 서식 문자 무력화, 실제 요청 헤더.

스냅샷은 tests/snapshots/webhook_<형식>.json. 형식을 일부러 바꿨다면 다시 만든다:
  docker compose exec -e WLM_UPDATE_SNAPSHOTS=1 api python -m pytest tests/test_messenger.py
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import pairwise
from pathlib import Path
from typing import ClassVar

import pytest

from app.alerts.message import SEVERITY_COLORS, AlertMessage
from app.alerts.messenger import FORMATS, JANDI_SHOWN_MAX, LINK_TITLE
from app.alerts.notifiers import NotifierError, WebhookNotifier

NOW = datetime(2026, 10, 3, 5, 0, 0, tzinfo=UTC)
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"


def message(**overrides) -> AlertMessage:
    values = {
        "rule": "로그온 실패 급증", "severity": "warning", "kind": "count", "group_by": "host",
        "group_key": "DC-01", "event_count": 27, "threshold": 20, "window_sec": 600, "fired_at": NOW,
        "first_event_at": NOW - timedelta(minutes=9), "last_event_at": NOW, "alert_id": 7,
        "description": "짧은 시간에 로그온 실패가 몰렸습니다", "tags": ["MITRE T1110", "ISMS 2.11.3"],
        "link": "http://logmon.local:8080/#/events?since=2026-10-03T04%3A50%3A00%2B00%3A00&event_id=4625&host=DC-01",
        "samples": [
            {"id": 1, "ts": NOW.isoformat(), "host": "DC-01", "level": 3, "channel": "Security", "event_id": 4625,
             "message": "계정을 로그온하지 못했습니다.\r\n계정 이름: admin"},
            {"id": 2, "ts": (NOW - timedelta(minutes=1)).isoformat(), "host": "DC-01", "level": 3, "channel": "Security",
             "event_id": 4625, "message": "계정을 로그온하지 못했습니다. 원본 주소: 203.0.113.9"},
        ],
    }
    values.update(overrides)
    return AlertMessage(**values)


def body(fmt: str, m: AlertMessage | None = None) -> dict:
    return WebhookNotifier("w", "https://h.example.com/x", fmt).payload(m or message())


# ------------------------------------------------------------------ 스냅샷

@pytest.mark.parametrize("fmt", sorted(set(FORMATS) - {"json"}))
def test_snapshot(fmt):
    """받는 서비스가 보는 본문 그대로. 바뀌면 의도한 변경인지 확인하고 스냅샷을 다시 만든다."""
    actual = json.dumps(body(fmt), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path = SNAPSHOTS / f"webhook_{fmt}.json"
    if os.environ.get("WLM_UPDATE_SNAPSHOTS") == "1":
        SNAPSHOTS.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8")
    # 스냅샷이 없으면 만들고 통과하지 않는다 — 저장소에서 빠진 것을 조용히 넘기지 않게
    assert path.exists(), f"스냅샷 없음: {path.name} — WLM_UPDATE_SNAPSHOTS=1 로 만들고 내용을 확인한 뒤 커밋하세요"
    assert actual == path.read_text(encoding="utf-8")


def test_json_format_keeps_full_alert():
    data = body("json")
    assert data["alert"]["event_count"] == 27 and data["title"].startswith("[경고]")


# --------------------------------------------------------- 서비스 제한·색

def test_slack_respects_block_kit_limits_and_color():
    long = message(rule="가" * 400, description="<&>" * 3000, tags=[f"T{i}" for i in range(400)])
    data = body("slack", long)
    header = data["blocks"][0]
    assert header["type"] == "header" and len(header["text"]["text"]) <= 150
    attachment = data["attachments"][0]
    assert attachment["color"] == SEVERITY_COLORS["warning"] and attachment["fallback"]
    blocks = attachment["blocks"]
    texts = [b["text"]["text"] for b in blocks if "text" in b] + [e["text"] for b in blocks for e in b.get("elements", [])]
    assert texts and all(0 < len(t) <= 3000 for t in texts)
    assert all(not t.endswith(("&", "&a", "&am", "&amp", "&l", "&lt", "&g", "&gt")) for t in texts)  # 엔티티가 잘리지 않음
    fields = next(b["fields"] for b in blocks if "fields" in b)
    assert len(fields) <= 10 and all(len(f["text"]) <= 2000 for f in fields)
    assert len(data["blocks"]) + len(blocks) <= 50 and 0 < len(data["text"]) <= 3000


def test_slack_neutralizes_markup_from_logs():
    """로그 메시지의 <!channel>·<링크|이름>·& 가 멘션·링크로 바뀌지 않는다."""
    evil = message(samples=[{"ts": NOW.isoformat(), "host": "PC", "level": 1, "message": "<!channel> <http://evil|클릭> & 끝"}],
                   description="<!here> 확인")
    text = json.dumps(body("slack", evil), ensure_ascii=False)
    assert "<!channel>" not in text and "<!here>" not in text and "<http://evil" not in text
    assert "&lt;!channel&gt;" in text and "&amp; 끝" in text
    # 대상 이름(로그에서 온 값)이 들어가는 제목도 — 맨 위 text 는 mrkdwn 으로 해석된다
    titled = body("slack", message(group_key="<!channel>"))
    assert "<!channel>" not in titled["text"] and "&lt;!channel&gt;" in titled["text"]


def test_markdown_links_from_logs_are_broken_in_teams_and_jandi():
    evil = message(samples=[{"ts": NOW.isoformat(), "host": "PC", "level": 1, "message": "[로그인](http://evil.example)"}])
    for fmt in ("teams", "jandi"):
        assert "](http://evil" not in json.dumps(body(fmt, evil), ensure_ascii=False)


@pytest.mark.parametrize("severity", ["info", "warning", "error", "critical"])
def test_every_format_builds_for_every_severity(severity):
    for fmt in FORMATS:
        data = body(fmt, message(severity=severity))
        assert len(json.dumps(data, ensure_ascii=False).encode()) < 28_000  # Teams 워크플로 상한 (가장 작음)


def test_test_message_and_silent_alert_build():
    test_msg = message(test=True, rule="테스트 알림", severity="info", samples=[], tags=[], description="")
    silent = message(kind="agent_silent", event_count=0, threshold=0, samples=[])
    for fmt in FORMATS:
        assert body(fmt, test_msg) and body(fmt, silent)
    assert "건수" not in json.dumps(body("jandi", silent), ensure_ascii=False)  # 끊김 알림에는 건수 항목이 없다


def test_link_rendering_and_absence():
    m = message()
    slack = json.dumps(body("slack", m), ensure_ascii=False)
    assert f"|{LINK_TITLE}>" in slack and '"actions"' not in slack  # 버튼 대신 글자 링크 (상호작용 설정 없이도 동작)
    assert "event_id=4625&amp;host=DC-01|" in slack  # 링크 주소의 & 도 제어 문자 규칙대로
    assert body("dooray", m)["attachments"][0]["titleLink"] == m.link
    assert body("jandi", m)["body"].endswith(f"[{LINK_TITLE}]({m.link})")
    assert body("teams", m)["attachments"][0]["content"]["actions"][0]["url"] == m.link
    m = message(link="")
    assert "actions" not in body("teams", m)["attachments"][0]["content"]
    assert LINK_TITLE not in json.dumps(body("slack", m), ensure_ascii=False)
    assert "titleLink" not in body("dooray", m)["attachments"][0]
    assert body("jandi", m)["body"] == m.title()


def test_jandi_color_and_display_limit():
    data = body("jandi", message(description="설명" * 4000, severity="critical"))
    assert data["connectColor"] == SEVERITY_COLORS["critical"].upper()
    shown = len(data["body"]) + sum(len(i["title"]) + len(i["description"]) for i in data["connectInfo"])
    assert shown <= JANDI_SHOWN_MAX + 20 * len(data["connectInfo"])  # 항목마다 최소 20자는 남긴다


# ------------------------------------------------------------- 실제 요청

class _Receiver(BaseHTTPRequestHandler):
    received: ClassVar[list[tuple[dict, dict, float]]] = []
    status = 200

    def do_POST(self):  # http.server 가 부르는 이름
        length = int(self.headers["Content-Length"])
        _Receiver.received.append((dict(self.headers), json.loads(self.rfile.read(length)), time.monotonic()))
        self.send_response(_Receiver.status)
        self.end_headers()
        # 두레이처럼 오류 본문에 요청 경로(토큰 포함)를 그대로 돌려준다
        self.wfile.write(b"ok" if _Receiver.status == 200 else json.dumps({"path": self.path}).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def receiver():
    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Receiver.received, _Receiver.status = [], 200
    yield f"http://127.0.0.1:{server.server_port}/services/1234567890/9876543210/SeCrEtToKeN0123456789"
    server.shutdown()


def test_jandi_sends_required_accept_header(receiver):
    asyncio.run(WebhookNotifier("잔디", receiver, "jandi").send(message()))
    headers, data, _ = _Receiver.received[0]
    assert headers["Accept"] == "application/vnd.tosslab.jandi-v2+json"
    assert headers["Content-Type"].startswith("application/json")
    assert data["connectColor"] == SEVERITY_COLORS["warning"].upper()


def test_user_headers_override_format_headers(receiver):
    hook = WebhookNotifier("잔디", receiver, "jandi", headers={"Accept": "application/json", "X-Token": "t"})
    asyncio.run(hook.send(message()))
    headers, _, _ = _Receiver.received[0]
    assert headers["Accept"] == "application/json" and headers["X-Token"] == "t"


def test_unknown_format_falls_back_to_json():
    assert WebhookNotifier("w", "https://h.example.com/x", "kakao").format == "json"


def test_http_error_message_is_reported(receiver):
    with pytest.raises(NotifierError, match="웹훅 연결 실패"):
        asyncio.run(WebhookNotifier("w", "http://127.0.0.1:9/none", "slack", timeout_sec=1).send(message()))


def test_error_body_does_not_leak_url_token(receiver):
    _Receiver.status = 400
    with pytest.raises(NotifierError) as err:
        asyncio.run(WebhookNotifier("두레이", receiver, "dooray").send(message()))
    assert "웹훅 응답 400" in str(err.value) and "SeCrEtToKeN0123456789" not in str(err.value)
    assert "9876543210" not in str(err.value)


@pytest.mark.parametrize("fmt", ["slack", "teams", "dooray", "jandi"])
def test_cloud_messengers_require_https(fmt):
    with pytest.raises(NotifierError, match="https"):
        WebhookNotifier("w", "http://hook.example.com/services/1/2/token", fmt)
    WebhookNotifier("w", "http://127.0.0.1:8080/relay", fmt)  # 같은 서버 안 중계는 허용
    WebhookNotifier("w", "http://intranet.local/hook", "json")  # 사내 시스템 연동(json·text)은 http 도


def test_same_url_is_spaced_by_format_interval(receiver, monkeypatch):
    """두레이처럼 1초에 1건을 넘으면 버리는 서비스: 같은 주소로는 간격을 두고 차례로 보낸다."""
    monkeypatch.setitem(FORMATS, "dooray", replace(FORMATS["dooray"], min_interval_sec=0.3))
    hook = WebhookNotifier("두레이", receiver, "dooray")

    async def burst():
        await asyncio.gather(*(hook.send(message(alert_id=i)) for i in range(3)))

    asyncio.run(burst())
    times = [t for _, _, t in _Receiver.received]
    assert len(times) == 3 and all(b - a >= 0.28 for a, b in pairwise(times))
