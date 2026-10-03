"""알림 전송기: 메일(수신 그룹) / 웹훅 / Oracle.

전송기는 환경설정(DB)에서 만들어진다 (app/alerts/targets.py):
  수신 그룹       → EmailNotifier  (그룹의 활성 수신자 이메일 전체에게 한 통)
  외부 연동 웹훅  → WebhookNotifier
  외부 연동 Oracle → OracleNotifier (app/oracle.py 로 접속, TNS/SID/서비스/접속 문자열)

모든 send() 는 실패하면 예외를 던진다 (엔진이 기록하고 재시도한다).
네트워크 I/O 는 표준 라이브러리/동기 드라이버를 스레드에서 실행해 이벤트 루프를 막지 않는다.
"""

from __future__ import annotations

import asyncio
import json
import re
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any
from urllib.parse import urlsplit

from .. import oracle
from .message import AlertMessage


class NotifierError(Exception):
    """전송 실패 (화면/로그에 그대로 표시)."""


SEVERITY_RANK = {"info": 1, "warning": 2, "error": 3, "critical": 4}
SEVERITY_LABELS = {"info": "정보", "warning": "경고", "error": "오류", "critical": "심각"}


class Notifier:
    type = "base"

    def __init__(self, name: str):
        self.name = name
        self.min_severity = "info"  # 이 수준 미만의 알림은 받지 않는다 (환경설정에서 그룹·연동별로 지정)

    def accepts(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 1) >= SEVERITY_RANK.get(self.min_severity, 1)

    def target(self) -> str:
        """화면 표시용 대상 설명 (비밀값 제외)."""
        return ""

    async def send(self, message: AlertMessage) -> None:
        raise NotImplementedError


# ------------------------------------------------------------------- 메일

@dataclass
class SmtpConfig:
    host: str
    port: int = 587
    security: str = "starttls"  # none | starttls | ssl
    user: str = ""
    password: str = ""
    sender: str = "log-monitor@localhost"


class EmailNotifier(Notifier):
    type = "email"

    def __init__(self, name: str, to: list[str], smtp: SmtpConfig, subject_prefix: str = "[Log Monitor]"):
        super().__init__(name)
        self.to = to
        self.smtp = smtp
        self.subject_prefix = subject_prefix

    def target(self) -> str:
        return ", ".join(self.to) or "(수신자 없음)"

    def build(self, message: AlertMessage) -> EmailMessage:
        mail = EmailMessage()
        mail["Subject"] = f"{self.subject_prefix} {message.title()}".strip()
        mail["From"] = self.smtp.sender
        mail["To"] = ", ".join(self.to)
        mail["Date"] = formatdate(localtime=False)
        mail["Message-ID"] = make_msgid(domain=self.smtp.sender.rsplit("@", 1)[-1] or "log-monitor")
        mail.set_content(message.text())
        mail.add_alternative(message.html(), subtype="html")
        return mail

    def _send(self, mail: EmailMessage) -> None:
        if not self.to:
            raise NotifierError(f"수신 그룹 '{self.name}' 에 이메일이 있는 활성 수신자가 없습니다 (환경설정 > 수신자)")
        if not self.smtp.host:
            raise NotifierError("메일 서버가 설정되지 않았습니다 (환경설정 > 메일 서버)")
        security = self.smtp.security.lower()
        smtp_cls = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP
        try:
            with smtp_cls(self.smtp.host, self.smtp.port, timeout=20) as smtp:
                if security == "starttls":
                    smtp.starttls(context=ssl.create_default_context())
                if self.smtp.user:
                    smtp.login(self.smtp.user, self.smtp.password)
                smtp.send_message(mail)
        except (OSError, smtplib.SMTPException) as exc:
            raise NotifierError(f"메일 전송 실패 ({self.smtp.host}:{self.smtp.port}): {exc}") from exc

    async def send(self, message: AlertMessage) -> None:
        await asyncio.to_thread(self._send, self.build(message))


# ------------------------------------------------------------------- 웹훅

class WebhookNotifier(Notifier):
    """format: json → {"source", "title", "text", "alert": {...}}  /  text → {"text": "..."} (Slack·Mattermost 호환)"""

    type = "webhook"

    def __init__(self, name: str, url: str, fmt: str = "json", headers: dict[str, str] | None = None,
                 timeout_sec: float = 10):
        super().__init__(name)
        if not url.startswith(("http://", "https://")):
            raise NotifierError("웹훅 주소는 http:// 또는 https:// 로 시작해야 합니다")
        self.url = url
        self.format = fmt
        self.headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self.timeout = float(timeout_sec)

    def target(self) -> str:
        # 경로·쿼리에 토큰이 들어가는 서비스가 많아서 호스트까지만 보여준다
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.hostname}{f':{parts.port}' if parts.port else ''}/…"

    def payload(self, message: AlertMessage) -> dict[str, Any]:
        if self.format == "text":
            text = f"{message.title()}\n{message.summary()}"
            return {"text": f"{text}\n{message.link}" if message.link else text}
        return {"source": "log-monitor", "title": message.title(), "text": message.summary(),
                "alert": message.to_dict()}

    def _post(self, body: bytes) -> None:
        request = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json; charset=utf-8", "User-Agent": "log-monitor", **self.headers})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read(1024)
        except urllib.error.HTTPError as exc:
            detail = exc.read(300).decode("utf-8", "replace")
            raise NotifierError(f"웹훅 응답 {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise NotifierError(f"웹훅 연결 실패 ({self.target()}): {getattr(exc, 'reason', exc)}") from exc

    async def send(self, message: AlertMessage) -> None:
        body = json.dumps(self.payload(message), ensure_ascii=False, default=str).encode("utf-8")
        await asyncio.to_thread(self._post, body)


# ----------------------------------------------------------------- Oracle

ORACLE_DEFAULT_TABLE = "LOGMON_ALERTS"
ORACLE_DEFAULT_SQL = (
    "INSERT INTO {table} (ALERT_ID, RULE_NAME, SEVERITY, HOST, EVENT_COUNT, WINDOW_SEC,\n"
    "  FIRST_EVENT_AT, LAST_EVENT_AT, FIRED_AT, TITLE, MESSAGE, LINK, DETAIL_JSON)\n"
    "VALUES (:alert_id, :rule_name, :severity, :host, :event_count, :window_sec,\n"
    "  :first_event_at, :last_event_at, :fired_at, :title, :message, :link, :detail_json)"
)
ORACLE_BINDS = ("alert_id", "rule_name", "severity", "host", "event_count", "window_sec", "first_event_at",
                "last_event_at", "fired_at", "title", "message", "link", "detail_json")
_BIND_RE = re.compile(r"(?<![:\w]):([A-Za-z_][A-Za-z0-9_]*)")


def oracle_binds(sql: str, message: AlertMessage) -> dict[str, Any]:
    """SQL 에 실제로 쓰인 바인드만 (없는 바인드를 넘기면 드라이버가 오류를 낸다). 시각은 UTC 기준 TIMESTAMP."""

    def naive_utc(value):
        return value.astimezone(UTC).replace(tzinfo=None) if value else None

    values = {
        "alert_id": message.alert_id,
        "rule_name": message.rule[:200],
        "severity": message.severity,
        "host": message.group_key[:255] or None,
        "event_count": message.event_count,
        "window_sec": message.window_sec,
        "first_event_at": naive_utc(message.first_event_at),
        "last_event_at": naive_utc(message.last_event_at),
        "fired_at": naive_utc(message.fired_at),
        "title": message.title()[:500],
        "message": message.text()[:4000],
        "link": message.link[:1000] or None,
        "detail_json": json.dumps(message.to_dict(), ensure_ascii=False, default=str),
    }
    used = set(_BIND_RE.findall(_strip_strings(sql)))
    unknown = used - set(values)
    if unknown:
        raise NotifierError(f"SQL 에 알 수 없는 바인드 변수: {', '.join(sorted(unknown))} (사용 가능: {', '.join(ORACLE_BINDS)})")
    return {k: v for k, v in values.items() if k in used}


def _strip_strings(sql: str) -> str:
    """'문자열' 안의 :xx 는 바인드가 아니다."""
    return re.sub(r"'(?:[^']|'')*'", "''", sql)


class OracleNotifier(Notifier):
    """사내 Oracle 에 SQL 한 문장 실행 (기본: LOGMON_ALERTS 에 INSERT, 테이블 DDL 은 docs/oracle_alerts.sql).
    프로시저를 부르려면 SQL 에 BEGIN 프로시저(:rule_name, ...); END; 처럼 쓴다."""

    type = "oracle"

    def __init__(self, name: str, conn: oracle.OracleConn, sql: str):
        super().__init__(name)
        self.conn = conn
        self.sql = sql.strip().rstrip(";") if not sql.strip().upper().endswith("END;") else sql.strip()

    def target(self) -> str:
        return self.conn.describe()

    def binds(self, message: AlertMessage) -> dict[str, Any]:
        return oracle_binds(self.sql, message)

    def _execute(self, binds: dict[str, Any], commit: bool) -> int:
        try:
            return oracle.execute(self.conn, self.sql, binds, commit=commit, clob_binds=("detail_json",))
        except oracle.OracleError as exc:
            raise NotifierError(str(exc)) from exc

    async def send(self, message: AlertMessage) -> None:
        await asyncio.to_thread(self._execute, self.binds(message), True)

    async def dry_run(self, message: AlertMessage) -> int:
        """실행만 해 보고 되돌린다 (환경설정의 'SQL 시험 실행')."""
        return await asyncio.to_thread(self._execute, self.binds(message), False)
