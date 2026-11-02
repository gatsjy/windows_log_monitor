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
    (_http_error(422), False),
    (_http_error(413), False),
    (_http_error(408), True),     # 잠시 — 같은 곳의 다른 알림도 같다 (3차 검토: 나눠 보내 같은 실패를 여러 번 받지 않게)
    # 주소·토큰이 지워졌거나 막힘 — 어떤 알림도 받지 않는다 (B-41 검토: 알림 하나의 문제로 보면 묶음을 하나씩 다시 보내 같은 거절을 수백 번)
    (_http_error(404), True),
    (_http_error(403), True),
    (_http_error(401), True),
    (_http_error(410), True),
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
    # 메일 하나의 본문·받는 사람 거절(554 등)은 그 메일만의 문제 — 다른 알림을 미루지 않는다
    class Rejecting:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self, **kwargs):
            pass

        def send_message(self, mail):
            raise smtplib.SMTPDataError(554, "content rejected")

    monkeypatch.setattr(smtplib, "SMTP", Rejecting)
    with pytest.raises(NotifierError) as caught:
        mail._send(None)
    assert caught.value.target_down is False
    monkeypatch.setattr(Rejecting, "send_message", lambda self, mail: (_ for _ in ()).throw(smtplib.SMTPDataError(451, "try later")))
    with pytest.raises(NotifierError) as caught:   # 4xx 는 잠시 — 받는 곳 문제
        mail._send(None)
    assert caught.value.target_down is True
    monkeypatch.setattr(Rejecting, "send_message", lambda self, mail: (_ for _ in ()).throw(smtplib.SMTPDataError(554, "rejected")))
    # 발신자 거절(530 인증·550 중계)·받는 사람 모두 거절은 이 그룹의 모든 메일이 같다 — 받는 곳 문제
    for refusal in (smtplib.SMTPSenderRefused(530, b"auth required", "x@y"), smtplib.SMTPRecipientsRefused({"a@x": (550, b"no")})):
        monkeypatch.setattr(Rejecting, "send_message", lambda self, mail, e=refusal: (_ for _ in ()).throw(e))
        with pytest.raises(NotifierError) as caught:
            mail._send(None)
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
