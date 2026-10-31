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
import hashlib
import json
import re
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .. import oracle
from .message import AlertMessage, Notice
from .messenger import FORMATS


class NotifierError(Exception):
    """전송 실패 (화면/로그에 그대로 표시).
    target_down = 받는 곳 자체가 안 된다(연결 실패·시간 초과·5xx·429·설정 없음) — 전송기가 그 곳의 다른 대기 알림도
    이번에는 시도하지 않고 실패로 넘긴다(같은 곳에 30초씩 줄줄이 기다리지 않게, ADR-045). 알림 하나의 문제(4xx 등)는 False."""

    def __init__(self, message: str, *, target_down: bool = False):
        super().__init__(message)
        self.target_down = target_down


SEVERITY_RANK = {"info": 1, "warning": 2, "error": 3, "critical": 4}
SEVERITY_LABELS = {"info": "정보", "warning": "경고", "error": "오류", "critical": "심각"}


class Notifier:
    type = "base"

    def __init__(self, name: str):
        self.name = name
        self.min_severity = "info"  # 이 수준 미만의 알림은 받지 않는다 (환경설정에서 그룹·연동별로 지정)

    def accepts(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 1) >= SEVERITY_RANK.get(self.min_severity, 1)

    def accepts_resolve(self) -> str | None:
        """해소 통지를 받을 수 없으면 그 이유 (B-35 2단계). 사람이 읽는 메일·메신저는 언제나 받는다."""
        return None

    def target(self) -> str:
        """화면 표시용 대상 설명 (비밀값 제외)."""
        return ""

    async def send(self, message: AlertMessage) -> None:
        raise NotImplementedError

    async def send_notice(self, notice: Notice) -> None:
        """공지(점검 보고서). 메일·웹훅만 받는다 — Oracle 은 알림 표에 넣는 연동이라 보고서를 보내지 않는다."""
        raise NotifierError(f"'{self.name}' ({self.type}) 은(는) 보고서를 받을 수 없습니다 — 수신 그룹이나 웹훅을 고르세요")


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
            raise NotifierError(f"수신 그룹 '{self.name}' 에 이메일이 있는 활성 수신자가 없습니다 (환경설정 > 수신자)",
                                target_down=True)
        if not self.smtp.host:
            raise NotifierError("메일 서버가 설정되지 않았습니다 (환경설정 > 메일 서버)", target_down=True)
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
            # 접속·인증 실패는 같은 메일 서버로 가는 알림 모두 같은 결과(받는 곳 장애). 본문·받는 사람 거절(554 등)은
            # 그 메일 하나의 문제 — 받는 곳 장애로 보면 다른 알림까지 미뤄진다(검토에서 재현)
            per_message = isinstance(exc, (smtplib.SMTPDataError, smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused))
            raise NotifierError(f"메일 전송 실패 ({self.smtp.host}:{self.smtp.port}): {exc}",
                                target_down=not per_message) from exc

    async def send(self, message: AlertMessage) -> None:
        await asyncio.to_thread(self._send, self.build(message))

    def build_notice(self, notice: Notice) -> EmailMessage:
        mail = EmailMessage()
        mail["Subject"] = f"{self.subject_prefix} {notice.title}".strip()
        mail["From"] = self.smtp.sender
        mail["To"] = ", ".join(self.to)
        mail["Date"] = formatdate(localtime=False)
        mail["Message-ID"] = make_msgid(domain=self.smtp.sender.rsplit("@", 1)[-1] or "log-monitor")
        mail.set_content(notice.plain())
        if notice.html:
            mail.add_alternative(notice.html, subtype="html")
        return mail

    async def send_notice(self, notice: Notice) -> None:
        await asyncio.to_thread(self._send, self.build_notice(notice))


# ------------------------------------------------------------------- 웹훅

# 같은 주소로 보내는 간격 (형식의 min_interval_sec). 전송기는 매 주기 새로 만들어지므로 모듈에 둔다.
# 키 = (이벤트 루프, 주소 해시) — 주소를 그대로 들고 있지 않고, 루프가 바뀌면(테스트) 잠금도 새로 만든다
_SEND_LOCKS: dict[tuple[int, str], asyncio.Lock] = {}
_LAST_SENT: dict[tuple[int, str], float] = {}
_LOOPBACK = ("127.0.0.1", "localhost", "::1")
# 클라우드 메신저 호스트는 고른 형식(json·text 포함)과 상관없이 https 만 — 주소 자체에 토큰이 있다
_HTTPS_HOSTS = tuple(h for f in FORMATS.values() if f.https_only for h in f.hosts)
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """웹훅은 넘김(30x)을 따라가지 않는다. 따라가면 POST 가 본문 없는 GET 으로 바뀌어 아무것도 안 보내고도 '전송됨'이 되고,
    사용자가 넣은 인증 헤더가 다른 호스트(http 포함)로 간다. 넘김은 오류로 보여 최종 주소를 넣게 한다."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # 표준 라이브러리 서명 그대로
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class WebhookNotifier(Notifier):
    """보내는 형식(format)은 messenger.FORMATS: json · text · slack · teams · dooray · jandi (BACKLOG B-04, ADR-030)."""

    type = "webhook"

    def __init__(self, name: str, url: str, fmt: str = "json", headers: dict[str, str] | None = None,
                 timeout_sec: float = 10):
        super().__init__(name)
        if not url.startswith(("http://", "https://")):
            raise NotifierError("웹훅 주소는 http:// 또는 https:// 로 시작해야 합니다")
        # 공백·제어 문자가 섞이면 전송 때 http.client 가 주소 전체(토큰 포함)를 오류 문구에 넣는다 → 저장 전에 막는다
        if _BAD_URL_CHARS.search(url):
            raise NotifierError("웹훅 주소에 공백이나 줄바꿈이 섞여 있습니다. 주소를 다시 복사해 넣으세요")
        self.url = url
        self.format = fmt if fmt in FORMATS else "json"
        spec = FORMATS[self.format]
        # 클라우드 메신저는 http 로도 받아 버려서(리다이렉트 없음) 주소의 토큰이 평문으로 나간다. 같은 서버 안 중계만 예외.
        # 형식을 json·text 로 바꿔 우회하지 못하게 메신저 호스트면 형식과 상관없이 막는다
        host = (urlsplit(url).hostname or "").lower()
        known_host = any(host == h or host.endswith(f".{h}") for h in _HTTPS_HOSTS)
        if url.startswith("http://") and host not in _LOOPBACK and (spec.https_only or known_host):
            what = f"'{spec.label.split(' —')[0]}' 형식" if spec.https_only else "메신저 웹훅 주소"
            raise NotifierError(f"{what}은 https:// 주소만 씁니다 (주소에 든 토큰이 평문으로 나가지 않게)")
        self.headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self.timeout = float(timeout_sec)

    def target(self) -> str:
        # 경로·쿼리에 토큰이 들어가는 서비스가 많아서 호스트까지만 보여준다
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.hostname}{f':{parts.port}' if parts.port else ''}/…"

    def payload(self, message: AlertMessage) -> dict[str, Any]:
        return FORMATS[self.format].build(message)

    def request_headers(self) -> dict[str, str]:
        """기본 → 형식이 요구하는 헤더(잔디 Accept 등) → 사용자가 넣은 헤더 순으로 덮어쓴다."""
        return {"Content-Type": "application/json; charset=utf-8", "User-Agent": "log-monitor",
                **FORMATS[self.format].headers, **self.headers}

    def redact(self, text: str) -> str:
        """주소의 경로·쿼리(토큰)를 가린다. 두레이처럼 오류 본문에 요청 경로를 그대로 돌려주는 서비스가 있어서,
        그대로 두면 전송 이력·화면·감사로그에 토큰이 남는다 (AGENTS.md 절대 규칙 6)."""
        parts = urlsplit(self.url)
        userinfo = parts.netloc.rpartition("@")[0]  # https://사용자:비밀번호@호스트 형식의 인증 정보
        secret = [parts.path, parts.query, userinfo, parts.password or "",
                  *(seg for seg in parts.path.split("/") if len(seg) >= 8),
                  *(v for _, v in parse_qsl(parts.query) if len(v) >= 8)]
        for piece in sorted({p for p in secret if p and p != "/"}, key=len, reverse=True):
            text = text.replace(piece, "…")
        return text

    def _post(self, body: bytes) -> None:
        request = urllib.request.Request(self.url, data=body, method="POST", headers=self.request_headers())
        try:
            with _OPENER.open(request, timeout=self.timeout) as response:
                response.read(1024)
        except urllib.error.HTTPError as exc:
            # 넉넉히 읽어 가린 '뒤에' 자른다 — 먼저 자르면 경계에 걸친 토큰 앞부분이 가려지지 않고 남는다
            detail = self.redact(exc.read(4096).decode("utf-8", "replace"))[:300]
            moved = " — 다른 주소로 넘기려 합니다. 넘어간 뒤의 최종 주소를 넣으세요" if 300 <= exc.code < 400 else ""
            raise NotifierError(f"웹훅 응답 {exc.code}{moved}: {detail}",
                                target_down=exc.code >= 500 or exc.code == 429) from exc
        except (urllib.error.URLError, OSError) as exc:
            reason = self.redact(str(getattr(exc, "reason", exc)))
            raise NotifierError(f"웹훅 연결 실패 ({self.target()}): {reason}", target_down=True) from exc
        except Exception as exc:  # http.client.InvalidURL·ValueError 등도 주소를 문구에 넣는다 → 가려서
            raise NotifierError(f"웹훅 전송 실패 ({self.target()}): {self.redact(str(exc))[:300]}") from exc

    async def send(self, message: AlertMessage) -> None:
        await self._deliver(self.payload(message))

    async def send_notice(self, notice: Notice) -> None:
        await self._deliver(FORMATS[self.format].notice(notice))

    async def _deliver(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        interval = FORMATS[self.format].min_interval_sec
        if not interval:
            await asyncio.to_thread(self._post, body)
            return
        # 두레이는 1초에 1건을 넘으면 200 을 주고도 버린다(재시도로도 못 찾음), Slack·잔디는 429.
        # 알림이 몰려도 주소마다 차례로 간격을 두고 보낸다 (기다리다 엔진의 전송 시간 제한에 걸리면 다음 재시도에서 보냄)
        key = (id(asyncio.get_running_loop()), hashlib.sha256(self.url.encode()).hexdigest())
        lock = _SEND_LOCKS.setdefault(key, asyncio.Lock())
        async with lock:
            wait = _LAST_SENT.get(key, 0.0) + interval - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                await asyncio.to_thread(self._post, body)
            finally:
                _LAST_SENT[key] = time.monotonic()


# ----------------------------------------------------------------- Oracle

ORACLE_DEFAULT_TABLE = "LOGMON_ALERTS"
ORACLE_DEFAULT_SQL = (
    "INSERT INTO {table} (ALERT_ID, RULE_NAME, SEVERITY, HOST, EVENT_COUNT, WINDOW_SEC,\n"
    "  FIRST_EVENT_AT, LAST_EVENT_AT, FIRED_AT, TITLE, MESSAGE, LINK, DETAIL_JSON)\n"
    "VALUES (:alert_id, :rule_name, :severity, :host, :event_count, :window_sec,\n"
    "  :first_event_at, :last_event_at, :fired_at, :title, :message, :link, :detail_json)"
)
ORACLE_BINDS = ("alert_id", "rule_name", "severity", "host", "event_count", "window_sec", "first_event_at",
                "last_event_at", "fired_at", "title", "message", "link", "detail_json", "dedup_key", "event_action")
_BIND_RE = re.compile(r"(?<![:\w]):([A-Za-z_][A-Za-z0-9_]*)")
# 생존 신호 SQL (B-34, 선택): 1분마다 실행 — 서버 전체가 멈추면 이 행이 갱신되지 않아 병원 DB 감시가 알아챈다
HEARTBEAT_BINDS = ("at", "status", "version", "problems")
# Oracle 호출은 전용 스레드에서 — 응답 없는 Oracle(접속 뒤 로그인 단계에서 멈춤)은 asyncio 의 시간 초과로 스레드를 멈추지 못한다.
# 기본 스레드 풀을 나눠 쓰면 멈춘 호출이 쌓여 로그인(scrypt)·메일·웹훅까지 막혔다(검토에서 재현). 여기서는 넷까지만 쌓이고,
# 생존 신호는 연동마다 앞의 것이 끝나야 다음을 낸다
_ORACLE_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="oracle-notify")
_HEARTBEAT_INFLIGHT: dict[str, Future] = {}


async def _in_oracle_pool(fn: Any, *args: Any) -> Any:
    return await asyncio.get_running_loop().run_in_executor(_ORACLE_POOL, fn, *args)


def _binds_in(sql: str) -> set[str]:
    return set(_BIND_RE.findall(_strip_strings(sql)))


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
        "dedup_key": message.dedup_key,
        "event_action": message.event_action,
    }
    used = set(_BIND_RE.findall(_strip_strings(sql)))
    unknown = used - set(values)
    if unknown:
        raise NotifierError(f"SQL 에 알 수 없는 바인드 변수: {', '.join(sorted(unknown))} (사용 가능: {', '.join(ORACLE_BINDS)})")
    return {k: v for k, v in values.items() if k in used}


def _strip_strings(sql: str) -> str:
    """'문자열' 안의 :xx 는 바인드가 아니다."""
    return re.sub(r"'(?:[^']|'')*'", "''", sql)


def _one_statement(sql: str) -> str:
    """끝의 ; 는 드라이버가 받지 않는다 — PL/SQL 블록(END;)만 그대로."""
    return sql.strip().rstrip(";") if not sql.strip().upper().endswith("END;") else sql.strip()


class OracleNotifier(Notifier):
    """사내 Oracle 에 SQL 한 문장 실행 (기본: LOGMON_ALERTS 에 INSERT, 테이블 DDL 은 docs/oracle_alerts.sql).
    프로시저를 부르려면 SQL 에 BEGIN 프로시저(:rule_name, ...); END; 처럼 쓴다."""

    type = "oracle"

    def __init__(self, name: str, conn: oracle.OracleConn, sql: str, heartbeat_sql: str = ""):
        super().__init__(name)
        self.conn = conn
        self.sql = _one_statement(sql)
        self.heartbeat_sql = _one_statement(heartbeat_sql) if heartbeat_sql.strip() else ""
        unknown = _binds_in(self.heartbeat_sql) - set(HEARTBEAT_BINDS)
        if unknown:
            raise NotifierError(f"생존 신호 SQL 에 알 수 없는 바인드 변수: {', '.join(sorted(unknown))}"
                                f" (사용 가능: {', '.join(HEARTBEAT_BINDS)})")

    def target(self) -> str:
        return self.conn.describe()

    def binds(self, message: AlertMessage) -> dict[str, Any]:
        return oracle_binds(self.sql, message)

    def accepts_resolve(self) -> str | None:
        # 예전 SQL(기본 INSERT)은 알림과 해소를 가리지 못한다 — 같은 알림 번호의 줄이 하나 더 생겨 사고관리가 새 사고로 본다
        if "event_action" in _binds_in(self.sql):
            return None
        return "SQL 에 :event_action 이 없어 해소 통지를 보내지 않습니다"

    def _execute(self, binds: dict[str, Any], commit: bool, sql: str | None = None) -> int:
        try:
            if sql is not None:
                return oracle.execute(self.conn, sql, binds, commit=commit)
            return oracle.execute(self.conn, self.sql, binds, commit=commit, clob_binds=("detail_json",))
        except oracle.OracleError as exc:
            raise NotifierError(str(exc), target_down=exc.unreachable) from exc

    async def heartbeat(self, values: dict[str, Any]) -> None:
        """생존 신호 한 번 (SQL 에 쓴 바인드만 넘긴다). 앞의 것이 아직 끝나지 않았으면 내지 않고 실패로 — 멈춘 Oracle 에
        1분마다 스레드가 하나씩 쌓이지 않게."""
        previous = _HEARTBEAT_INFLIGHT.get(self.name)
        if previous is not None and not previous.done():
            raise NotifierError("앞의 생존 신호가 아직 끝나지 않았습니다 — Oracle 이 응답하지 않습니다", target_down=True)
        used = _binds_in(self.heartbeat_sql)
        future = _ORACLE_POOL.submit(self._execute, {k: v for k, v in values.items() if k in used}, True, self.heartbeat_sql)
        _HEARTBEAT_INFLIGHT[self.name] = future
        await asyncio.wrap_future(future)

    async def send(self, message: AlertMessage) -> None:
        await _in_oracle_pool(self._execute, self.binds(message), True)

    async def dry_run(self, message: AlertMessage) -> int:
        """실행만 해 보고 되돌린다 (환경설정의 'SQL 시험 실행')."""
        return await _in_oracle_pool(self._execute, self.binds(message), False)
