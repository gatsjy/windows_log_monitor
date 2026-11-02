"""정규화 공통 타입과 헬퍼.

정규화(normalize) = 에이전트가 보낸 원본 레코드(dict)를 공통 컬럼으로 뽑아내는 것.
원본은 raw 컬럼에 그대로 저장하므로, 여기서 뽑지 않은 필드도 잃어버리지 않는다.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .. import wincatalog

# 공통 수준(level). Windows 이벤트 로그의 Level 값과 같은 체계를 쓴다.
CRITICAL, ERROR, WARNING, INFO, VERBOSE = 1, 2, 3, 4, 5
LEVEL_NAMES = {CRITICAL: "Critical", ERROR: "Error", WARNING: "Warning", INFO: "Information", VERBOSE: "Verbose"}

MESSAGE_MAX = 16_000  # message 컬럼 최대 길이 (원본 전체는 raw 에 있음)


@dataclass
class Event:
    ts: datetime
    host: str
    source: str
    level: int
    message: str
    raw: dict[str, Any]
    channel: str | None = None
    provider: str | None = None
    event_id: int | None = None
    category: str | None = None   # 분류 — 비워 두면 normalize() 가 categories.classify() 로 채운다
    username: str | None = None   # 공통 필드: 관련 사용자
    src_ip: str | None = None     # 공통 필드: 접속해 온 쪽 IP

    def to_live(self, received_at: datetime) -> dict[str, Any]:
        """실시간 스트림(SSE)으로 보낼 형태."""
        return {
            "id": None,
            "ts": self.ts.isoformat(),
            "received_at": received_at.isoformat(),
            "host": self.host,
            "source": self.source,
            "category": self.category,
            "channel": self.channel,
            "provider": self.provider,
            "event_id": self.event_id,
            "level": self.level,
            "username": self.username,
            "src_ip": self.src_ip,
            "message": self.message,
            "raw": without_nul(self.raw),   # 저장(repository._json)과 같은 값 — 화면 매처가 검색과 다르게 보지 않게
            "summary": wincatalog.summarize(self.provider, self.event_id, self.raw) if self.source == "winevtlog" else None,
        }


@dataclass
class Heartbeat:
    host: str
    meta: dict[str, Any] = field(default_factory=dict)
    sent_at: datetime | None = None   # PC 시계로 만든 시각 (Fluent Bit 의 date) — 시계 차이 (B-57)


# ---------------------------------------------------------------- helpers

def _no_nul(text: str) -> str:
    return text.replace("\x00", "") if "\x00" in text else text


def without_nul(value: Any) -> Any:
    """문자열·키의 NUL 을 뺀 사본 — jsonb 는 NUL 을 받지 못해 저장할 때 빠진다(repository._json). 실시간으로 보내는 원본도
    같게 해야 화면의 실시간 매처(web/js/querylang.js)가 검색(SQL)과 같은 값을 본다(ADR-033 남는 차이, B-23).
    재귀하지 않는다 — 깊게 겹친 레코드 하나가 RecursionError 로 수집 응답을 500 으로 만들었다(저장은 끝난 뒤라 에이전트가 다시 보냄,
    검토에서 재현). 수집의 _fix_surrogates 와 같은 방식."""
    if isinstance(value, str):
        return _no_nul(value)
    if not isinstance(value, (dict, list)):
        return value
    root: dict | list = {} if isinstance(value, dict) else []
    stack: list[tuple[Any, Any]] = [(value, root)]
    while stack:
        src, dst = stack.pop()
        for key, item in (src.items() if isinstance(src, dict) else enumerate(src)):
            if isinstance(item, str):
                copy: Any = _no_nul(item)
            elif isinstance(item, (dict, list)):
                copy = {} if isinstance(item, dict) else []
                stack.append((item, copy))
            else:
                copy = item
            if isinstance(dst, dict):
                dst[_no_nul(key) if isinstance(key, str) else key] = copy
            else:
                dst.append(copy)
    return root


_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S %z",  # Fluent Bit winevtlog TimeCreated
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
)


def parse_time(value: Any) -> datetime | None:
    """여러 형식의 시각을 UTC aware datetime 으로. 해석 불가면 None."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value  # epoch ms / s
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):   # 범위 밖·NaN — 다음 키나 수신 시각으로 (레코드 전체가 실패하지 않게)
            return None
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        dt = None
        for fmt in _TIME_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)  # noqa: DTZ007, RUF100 - 모든 형식에 %z 포함 (ruff 0.16 은 이를 몰라 경고)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    try:
        return dt.astimezone(UTC)
    except OverflowError:   # 0001-01-01T00:00+09:00 처럼 UTC 로 옮기면 범위를 벗어남 (시계가 0 인 장비)
        return None


def pick_time(record: dict, *keys: str, now: datetime) -> datetime:
    """keys 순서대로 해석 가능한 첫 시각. 모두 실패하면 Fluent Bit 의 date, 그래도 없으면 now."""
    for key in (*keys, "date"):
        dt = parse_time(record.get(key))
        if dt is not None:
            return dt
    return now


def pick_host(record: dict, *keys: str) -> str:
    """agent_host(에이전트가 붙인 이름)를 최우선으로 쓴다. 호스트 기준이 소스마다 달라지지 않게 하기 위함."""
    for key in ("agent_host", *keys):
        value = record.get(key)
        if value and (text := str(value).replace("\x00", "").strip()):
            return text[:255]
    return "unknown"


def clean_text(value: Any, limit: int = MESSAGE_MAX) -> str:
    """PostgreSQL TEXT 는 NUL 문자를 저장할 수 없어서 제거한다."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return text.replace("\x00", "").strip()[:limit]


def to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):   # inf 도
        return None


_LEVEL_WORDS = (
    (re.compile(r"\b(fatal|critical|crit|emerg|emergency|alert|panic)\b", re.IGNORECASE), CRITICAL),
    (re.compile(r"\b(error|err|exception)\b", re.IGNORECASE), ERROR),
    (re.compile(r"\b(warn|warning)\b", re.IGNORECASE), WARNING),
    (re.compile(r"\b(debug|trace|verbose)\b", re.IGNORECASE), VERBOSE),
)


def level_from_text(text: str) -> int:
    """레벨 정보가 없는 텍스트 로그용 추정. 앞부분(200자)만 본다."""
    head = text[:200]
    for pattern, level in _LEVEL_WORDS:
        if pattern.search(head):
            return level
    return INFO


# syslog severity(0~7) → 공통 level
SYSLOG_SEVERITY_TO_LEVEL = {0: CRITICAL, 1: CRITICAL, 2: CRITICAL, 3: ERROR, 4: WARNING, 5: INFO, 6: INFO, 7: VERBOSE}

SYSLOG_FACILITIES = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)


# ------------------------------------------------------- 공통 필드 정리

def clean_ip(value: Any) -> str | None:
    """'::ffff:10.0.0.5' → '10.0.0.5', '10.0.0.5:51234'·'[fe80::1%12]:443' → 주소만(표준 표기). IP 가 아니거나('-'·호스트 이름·
    'LOCAL') 자기 자신(루프백·0.0.0.0)이면 None — 예전에는 아무 글자나 src_ip(검색 ip:·알림 묶음 키)에 들어갔다(B-23).
    원본 값은 raw 에 그대로 있다."""
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    if not text or len(text) > 64:
        return None
    if text.startswith("["):                 # [v6]:포트
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:               # v4:포트
        text = text.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])   # v6 영역 표시(%12)는 뗀다
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return None if addr.is_loopback or addr.is_unspecified else str(addr)


def clean_user(value: Any) -> str | None:
    """'-', 빈 값, 컴퓨터 계정(이름$), NULL SID 는 None."""
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    if not text or text in ("-", "N/A", "S-1-0-0") or text.endswith("$"):
        return None
    return text[:128]
