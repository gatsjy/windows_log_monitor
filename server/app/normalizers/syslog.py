"""Linux / 네트워크 장비 syslog, systemd journald.

syslog (Fluent Bit syslog 입력 + syslog-rfc5424 / syslog-rfc3164 파서):
    pri, time, host, ident, pid, msgid, extradata, message (+ source_ip: 보낸 장비 IP)
journald (Fluent Bit systemd 입력):
    PRIORITY, _HOSTNAME, SYSLOG_IDENTIFIER, SYSLOG_FACILITY, _SYSTEMD_UNIT, _PID, MESSAGE
"""

from __future__ import annotations

import re
from datetime import datetime

from .base import (
    INFO,
    SYSLOG_FACILITIES,
    SYSLOG_SEVERITY_TO_LEVEL,
    Event,
    clean_ip,
    clean_text,
    clean_user,
    pick_host,
    pick_time,
    to_int,
)

# SSH 로그인 기록에서 사용자·IP (Linux 서버의 가장 흔한 보안 이벤트)
_SSH = re.compile(
    r"(?:Failed|Accepted) \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"
    r"|Invalid user (?P<user2>\S+) from (?P<ip2>[0-9a-fA-F.:]+)"
)


def ssh_fields(message: str) -> tuple[str | None, str | None]:
    m = _SSH.search(message)
    if not m:
        return None, None
    return clean_user(m.group("user") or m.group("user2")), clean_ip(m.group("ip") or m.group("ip2"))


def _facility_name(code: int | None) -> str | None:
    if code is None or not 0 <= code < len(SYSLOG_FACILITIES):
        return None
    return SYSLOG_FACILITIES[code]


# ------------------------------------------------------------------ syslog

SYSLOG_SOURCE = "syslog"


def detect_syslog(record: dict) -> bool:
    return "pri" in record or ("ident" in record and "message" in record)


def normalize_syslog(record: dict, now: datetime) -> Event:
    pri = to_int(record.get("pri"))
    severity = pri % 8 if pri is not None else None
    facility = pri // 8 if pri is not None else None
    message = clean_text(record.get("message") or record.get("log"))
    username, src_ip = ssh_fields(message)
    return Event(
        # RFC5424 time 은 시간대가 있어 그대로 쓰고, RFC3164 time("Oct  3 14:22:01")은
        # 해석되지 않으므로 수신기의 수신 시각(date)으로 대체된다
        ts=pick_time(record, "time", now=now),
        host=pick_host(record, "host", "hostname", "source_ip"),
        source=SYSLOG_SOURCE,
        channel=_facility_name(facility),
        provider=clean_text(record.get("ident"), 255) or None,
        event_id=None,
        level=SYSLOG_SEVERITY_TO_LEVEL.get(severity, INFO),
        message=message,
        raw=record,
        username=username,
        src_ip=src_ip,
    )


# ----------------------------------------------------------------- journald

JOURNALD_SOURCE = "journald"


def detect_journald(record: dict) -> bool:
    return "MESSAGE" in record and ("_HOSTNAME" in record or "PRIORITY" in record)


def normalize_journald(record: dict, now: datetime) -> Event:
    priority = to_int(record.get("PRIORITY"))
    channel = record.get("_SYSTEMD_UNIT") or _facility_name(to_int(record.get("SYSLOG_FACILITY")))
    message = clean_text(record.get("MESSAGE"))
    username, src_ip = ssh_fields(message)
    return Event(
        ts=pick_time(record, "date", now=now),
        host=pick_host(record, "_HOSTNAME"),
        source=JOURNALD_SOURCE,
        channel=clean_text(channel, 255) or None,
        provider=clean_text(record.get("SYSLOG_IDENTIFIER"), 255) or None,
        event_id=None,
        level=SYSLOG_SEVERITY_TO_LEVEL.get(priority, INFO),
        message=message,
        raw=record,
        username=username,
        src_ip=src_ip,
    )
