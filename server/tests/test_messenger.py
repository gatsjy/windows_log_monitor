"""웹훅 보내는 형식(메신저 프리셋, BACKLOG B-04): 형식별 본문 스냅샷, 서비스 제한, 서식 문자 무력화, 실제 요청 헤더.

스냅샷은 tests/snapshots/webhook_<형식>.json. 형식을 일부러 바꿨다면 다시 만든다:
  docker compose exec -e WLM_UPDATE_SNAPSHOTS=1 api python -m pytest tests/test_messenger.py
"""

from __future__ import annotations

import asyncio
import json
import os
import re
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
    # 'x' 를 앞에 붙여 잘리는 위치가 엔티티 경계와 맞지 않게 한다 (맞으면 잘못된 구현도 통과한다)
    long = message(rule="가" * 400, description="x" + "<&>" * 3000, tags=[f"T{i}" for i in range(400)])
    data = body("slack", long)
    header = data["blocks"][0]
    assert header["type"] == "header" and len(header["text"]["text"]) <= 150
    attachment = data["attachments"][0]
    assert attachment["color"] == SEVERITY_COLORS["warning"] and attachment["fallback"]
    blocks = attachment["blocks"]
    texts = [b["text"]["text"] for b in blocks if "text" in b] + [e["text"] for b in blocks for e in b.get("elements", [])]
    assert texts and all(0 < len(t) <= 3000 for t in texts)
    broken = [t for t in texts if re.search(r"&(?!amp;|lt;|gt;)", t)]
    assert not broken, broken[0][-40:]  # 엔티티가 중간에 잘리지 않음 (&amp…, &l… 없음)
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
    # 대상 이름(로그에서 온 값)은 맨 위 text·대체 문구·요약·항목에 모두 들어간다 — 어디서도 멘션이 되면 안 된다
    titled = body("slack", message(group_key="<!channel>"))
    attachment = titled["attachments"][0]
    mrkdwn = [titled["text"], attachment["fallback"]]
    for block in attachment["blocks"]:
        mrkdwn += [block["text"]["text"]] if "text" in block else []
        mrkdwn += [f["text"] for f in block.get("fields", [])] + [e["text"] for e in block.get("elements", [])]
    carriers = [t for t in mrkdwn if "!channel" in t]
    assert len(carriers) >= 4 and all("<!channel>" not in t and "&lt;!channel&gt;" in t for t in carriers)


EVIL_LINK = "[로그인](http://evil.example)"


@pytest.mark.parametrize("where", ["group_key", "description", "samples"])
@pytest.mark.parametrize("fmt", ["teams", "jandi", "dooray"])
def test_markdown_links_from_logs_are_broken(fmt, where):
    """로그에서 온 [이름](주소) 가 알림 안에서 누를 수 있는 링크(피싱)가 되지 않는다 — 어느 칸으로 들어와도."""
    values = {"samples": [{"ts": NOW.isoformat(), "host": "PC", "level": 1, "message": EVIL_LINK}]} if where == "samples" \
        else {where: EVIL_LINK}
    text = json.dumps(body(fmt, message(**values)), ensure_ascii=False)
    assert "로그인" in text and "](http://evil" not in text


@pytest.mark.parametrize("severity", ["info", "warning", "error", "critical"])
def test_every_format_builds_for_every_severity(severity):
    for fmt in FORMATS:
        data = body(fmt, message(severity=severity))
        assert len(json.dumps(data, ensure_ascii=False).encode()) < 28_000  # Teams 워크플로 상한 (가장 작음)


def test_huge_group_key_stays_within_service_limits():
    """group_by: f.<경로> 로 수천 자짜리 값(명령줄 등)이 대상이 되어도 서비스 제한 안에 든다."""
    huge = "A" * 10_000
    m = message(group_key=huge, description="설명" * 3000, link="http://logmon.local:8080/#/events?host=" + huge)
    for fmt in ("text", "slack", "teams", "dooray", "jandi"):
        # 모든 칸에 상한이 있으면 입력이 아무리 길어도 수 KB 다 (한 칸이라도 빠지면 10KB 를 넘는다)
        assert len(json.dumps(body(fmt, m), ensure_ascii=False).encode()) < 9_000, fmt
    jandi = body("jandi", m)
    assert 0 <= jandi["body"].find(f"[{LINK_TITLE}](") < 5000  # 링크는 잔디가 보여 주는 앞 5,000자 안
    # 너무 긴 검색 링크는 자르지 않고(깨지므로) 알림 화면으로 바꾼다
    assert body("teams", m)["attachments"][0]["content"]["actions"][0]["url"] == "http://logmon.local:8080/#/alerts"


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

    pad = 0          # 오류 본문에서 경로 앞에 넣을 글자 수 (토큰이 300바이트 경계에 걸치게)
    location = ""    # 30x 로 넘길 주소

    def do_POST(self):  # http.server 가 부르는 이름
        length = int(self.headers["Content-Length"])
        _Receiver.received.append((dict(self.headers), json.loads(self.rfile.read(length)), time.monotonic()))
        self.send_response(_Receiver.status)
        if _Receiver.location:
            self.send_header("Location", _Receiver.location)
        self.end_headers()
        # 두레이처럼 오류 본문에 요청 경로(토큰 포함)를 그대로 돌려준다 (Spring JSON: message 다음에 path)
        error = {"message": "x" * _Receiver.pad, "path": self.path}
        self.wfile.write(b"ok" if _Receiver.status == 200 else json.dumps(error).encode())

    def do_GET(self):  # 넘김을 따라오면 여기로 온다 — 따라오면 안 된다
        _Receiver.received.append((dict(self.headers), None, time.monotonic()))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def receiver():
    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Receiver.received, _Receiver.status, _Receiver.pad, _Receiver.location = [], 200, 0, ""
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


@pytest.mark.parametrize("pad", [240, 250, 260, 270, 280])
def test_token_cut_at_error_body_limit_is_still_hidden(receiver, pad):
    """오류 본문을 자른 뒤 가리면 경계에 걸친 토큰 앞부분이 남는다 — 가린 뒤에 자른다."""
    _Receiver.status, _Receiver.pad = 400, pad
    with pytest.raises(NotifierError) as err:
        asyncio.run(WebhookNotifier("두레이", receiver, "dooray").send(message()))
    # 경로 값에는 가림 표시(…)와 / 말고 아무것도 남지 않아야 한다 ('SeC'·'12345' 같은 토큰 앞부분도)
    shown = re.search(r'"path": "([^"]*)', str(err.value))
    assert shown is None or re.fullmatch(r"[/…]*", shown.group(1)), str(err.value)[-80:]


def test_redirect_is_not_followed(receiver):
    """넘김(302)을 따라가면 본문 없는 GET 이 '성공'으로 기록되고 인증 헤더가 다른 곳으로 간다 → 오류로."""
    _Receiver.status, _Receiver.location = 302, "http://127.0.0.1:9/login"
    hook = WebhookNotifier("사내", receiver, "json", headers={"Authorization": "Bearer secret"})
    with pytest.raises(NotifierError, match="302 — 다른 주소로 넘기려 합니다"):
        asyncio.run(hook.send(message()))
    assert [data is not None for _, data, _ in _Receiver.received] == [True]  # POST 한 번, 따라간 GET 없음


def test_url_with_whitespace_is_rejected_without_echoing_token():
    with pytest.raises(NotifierError, match="공백이나 줄바꿈") as err:
        WebhookNotifier("w", "https://hook.dooray.com/services/1/2/SeCrEt Token0123", "dooray")
    assert "SeCrEt" not in str(err.value)


def test_unexpected_errors_are_redacted(monkeypatch):
    """http.client.InvalidURL·ValueError 처럼 urllib 이 감싸지 않는 오류도 주소를 가린다."""
    from app.alerts import notifiers

    url = "https://user:Pa55word@hooks.example.com/services/1234567890/SeCrEtToKeN0123456789"

    def boom(*args, **kwargs):
        raise ValueError(f"bad url {url} /services/1234567890/SeCrEtToKeN0123456789 Pa55word")

    monkeypatch.setattr(notifiers._OPENER, "open", boom)
    with pytest.raises(NotifierError) as err:
        asyncio.run(WebhookNotifier("w", url, "json").send(message()))
    assert not re.search(r"SeCrEt|1234567890|Pa55word", str(err.value)), str(err.value)


def test_known_messenger_host_needs_https_whatever_the_format():
    """형식을 json·text 로 바꿔 http 메신저 주소를 저장하는 우회를 막는다."""
    for fmt in ("json", "text"):
        with pytest.raises(NotifierError, match="https"):
            WebhookNotifier("w", "http://hook.dooray.com/services/1/2/token", fmt)
        with pytest.raises(NotifierError, match="https"):
            WebhookNotifier("w", "http://team.hooks.slack.com/services/T/B/x", fmt)  # 하위 도메인도
    WebhookNotifier("w", "https://hook.dooray.com/services/1/2/token", "text")
    WebhookNotifier("w", "http://hook.dooray.com.intranet.local/relay", "text")  # 이름만 비슷한 사내 호스트는 그대로


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


def test_spacing_is_per_url_across_notifier_instances(receiver, monkeypatch):
    """엔진은 매 주기 전송기를 새로 만들고, 연동 두 개가 같은 대화방 주소일 수 있다 → 간격은 주소 단위로."""
    monkeypatch.setitem(FORMATS, "dooray", replace(FORMATS["dooray"], min_interval_sec=0.3))
    same = [WebhookNotifier(f"두레이{i}", receiver, "dooray") for i in range(3)]
    other = WebhookNotifier("다른 방", receiver.replace("/services/", "/services/0/"), "dooray")

    async def burst():
        await asyncio.gather(*(h.send(message(alert_id=i)) for i, h in enumerate([*same, other])))

    asyncio.run(burst())
    times = sorted(t for _, _, t in _Receiver.received)
    assert len(times) == 4
    # 같은 주소 3건은 0.3초씩 벌어지고, 다른 주소 1건은 기다리지 않으므로 처음 두 건은 거의 같이 도착한다
    assert times[1] - times[0] < 0.2 and times[-1] - times[0] >= 0.55
