"""전송 실패의 '받는 곳 자체가 안 됨' 구분 (ADR-045) — DB 없는 단위 시험.

전송기는 target_down 이면 그 곳의 다른 대기 알림도 이번에는 시도하지 않는다(같은 곳에 30초씩 줄줄이 기다리지 않게).
알림 하나의 문제(4xx·바인드 오류)를 받는 곳 문제로 보면 다른 알림까지 한 단계씩 늦어진다.
"""

from __future__ import annotations

import io
import smtplib
import urllib.error

import pytest

from app import oracle
from app.alerts import notifiers
from app.alerts.notifiers import EmailNotifier, NotifierError, OracleNotifier, SmtpConfig, WebhookNotifier


def _http_error(code):
    return urllib.error.HTTPError("http://x/hook", code, "x", {}, io.BytesIO(b"body"))


@pytest.mark.parametrize(("raised", "down"), [
    (_http_error(503), True),
    (_http_error(500), True),
    (_http_error(429), True),     # 보내는 속도 제한 — 그 곳에 더 보내도 같다
    (_http_error(400), False),    # 이 알림의 본문 문제
    (_http_error(404), False),
    (urllib.error.URLError("connection refused"), True),
    (OSError("timed out"), True),
])
def test_webhook(monkeypatch, raised, down):
    def fail(*args, **kwargs):
        raise raised

    monkeypatch.setattr(notifiers._OPENER, "open", fail)
    with pytest.raises(NotifierError) as caught:
        WebhookNotifier("훅", "http://127.0.0.1:9/hook")._post(b"{}")
    assert caught.value.target_down is down


def test_email(monkeypatch):
    class Broken:
        def __init__(self, *args, **kwargs):
            raise smtplib.SMTPConnectError(421, "busy")

    monkeypatch.setattr(smtplib, "SMTP", Broken)
    mail = EmailNotifier("당직", ["a@example.com"], SmtpConfig(host="smtp.local"))
    with pytest.raises(NotifierError) as caught:
        mail._send(None)   # 접속에서 실패하므로 본문은 쓰이지 않는다
    assert caught.value.target_down is True
    # 받는 사람·메일 서버가 없는 것도 그 곳의 모든 알림이 같다
    for notifier in (EmailNotifier("빈 그룹", [], SmtpConfig(host="smtp.local")), EmailNotifier("당직", ["a@x"], SmtpConfig(host=""))):
        with pytest.raises(NotifierError) as caught:
            notifier._send(None)
        assert caught.value.target_down is True


def test_oracle(monkeypatch):
    notifier = OracleNotifier.__new__(OracleNotifier)
    notifier.conn, notifier.sql = None, "INSERT INTO t VALUES (:alert_id)"
    for error, down in ((oracle.OracleError("접속 실패: ORA-12541", unreachable=True), True),
                        (oracle.OracleError("ORA-01400: NULL 을 넣을 수 없습니다"), False)):
        def run(*args, _error=error, **kwargs):
            raise _error

        monkeypatch.setattr(oracle, "execute", run)
        with pytest.raises(NotifierError) as caught:
            notifier._execute({}, True)
        assert caught.value.target_down is down
