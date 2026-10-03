"""Windows 이벤트 로그 (Fluent Bit winevtlog 입력).

winevtlog 레코드 키: ProviderName, ProviderGuid, Qualifiers, EventID, Version, Level, Task,
Opcode, Keywords("0x8020000000000000" 형태 문자열), TimeCreated("2026-10-03 14:22:01 +0900"),
EventRecordID, ActivityID, RelatedActivityID, ProcessID, ThreadID, Channel, Computer, UserID,
Message, StringInserts(배열), EventData(이름 있는 맵 — 에이전트 event_data_as_map: true 일 때)

공통 필드:
  username ← EventData.TargetUserName / SubjectUserName … (없으면 StringInserts 위치표, MSSQL 은 메시지)
  src_ip   ← EventData.IpAddress / SourceAddress …
"""

from __future__ import annotations

import re
from datetime import datetime

from .base import (
    CRITICAL,
    INFO,
    VERBOSE,
    WARNING,
    Event,
    clean_ip,
    clean_text,
    clean_user,
    pick_host,
    pick_time,
    to_int,
)

SOURCE = "winevtlog"

# Keywords 비트: 보안 로그의 감사 실패/성공
AUDIT_FAILURE = 0x10_0000_0000_0000
AUDIT_SUCCESS = 0x20_0000_0000_0000


# EventData 의 이름 (앞에 있을수록 우선)
USER_FIELDS = ("TargetUserName", "SubjectUserName", "UserName", "User", "AccountName", "SamAccountName")
IP_FIELDS = ("IpAddress", "SourceAddress", "ClientAddress", "SourceIp", "ClientIP", "Address")

# EventData 맵이 없을 때(구버전 에이전트) StringInserts 위치표: 이벤트 ID → (사용자 위치, IP 위치)
# Microsoft 문서의 필드 순서 기준. Windows 버전에 따라 다를 수 있어 자주 쓰는 것만 둔다.
STRING_INSERT_POSITIONS: dict[int, tuple[int | None, int | None]] = {
    4624: (5, 18),   # 로그온 성공
    4625: (5, 19),   # 로그온 실패
    4648: (5, 12),   # 명시적 자격 증명 로그온
    4740: (0, None),  # 계정 잠금
    4771: (0, 6),    # Kerberos 사전 인증 실패
    4776: (1, None),  # NTLM 자격 증명 확인
    4720: (0, None),  # 계정 생성 (새 계정)
}

# MSSQL: "Login failed for user 'sa'. Reason: ... [CLIENT: 10.0.0.5]"
_MSSQL_LOGIN = re.compile(r"Login (?:failed|succeeded) for user '([^']*)'.*?\[CLIENT: ([^\]]+)\]", re.DOTALL)


def common_fields(record: dict, event_id: int | None, message: str) -> tuple[str | None, str | None]:
    """(username, src_ip) 추출."""
    data = record.get("EventData")
    user = ip = None
    if isinstance(data, dict):
        user = next((u for f in USER_FIELDS if (u := clean_user(data.get(f)))), None)
        ip = next((a for f in IP_FIELDS if (a := clean_ip(data.get(f)))), None)
    inserts = record.get("StringInserts")
    if (user is None or ip is None) and isinstance(inserts, list) and event_id in STRING_INSERT_POSITIONS:
        u_pos, ip_pos = STRING_INSERT_POSITIONS[event_id]
        if user is None and u_pos is not None and u_pos < len(inserts):
            user = clean_user(inserts[u_pos])
        if ip is None and ip_pos is not None and ip_pos < len(inserts):
            ip = clean_ip(inserts[ip_pos])
    if user is None and "Login" in message:
        m = _MSSQL_LOGIN.search(message)
        if m:
            user, ip = clean_user(m.group(1)), ip or clean_ip(m.group(2))
    return user, ip


def detect(record: dict) -> bool:
    return "EventID" in record and "Channel" in record


def _keywords(value) -> int:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return 0


def normalize(record: dict, now: datetime) -> Event:
    level = to_int(record.get("Level"))
    if level is None or not CRITICAL <= level <= VERBOSE:
        level = INFO  # 0(LogAlways) 등은 '정보'로 취급
    # 보안 로그는 전부 Level 0(정보)이라 '감사 실패'(로그온 실패 등)가 묻힌다 → '경고'로 올린다.
    # 원래 Level 값은 raw.Level 에 그대로 남아 있다. (docs/PROJECT.md 정규화 규칙 참고)
    if _keywords(record.get("Keywords")) & AUDIT_FAILURE and level > WARNING:
        level = WARNING

    message = clean_text(record.get("Message"))
    if not message and isinstance(record.get("StringInserts"), list):
        message = clean_text(" | ".join(str(s) for s in record["StringInserts"]))
    event_id = to_int(record.get("EventID"))
    username, src_ip = common_fields(record, event_id, message)

    return Event(
        ts=pick_time(record, "TimeCreated", now=now),
        host=pick_host(record, "Computer"),
        source=SOURCE,
        channel=clean_text(record.get("Channel"), 255) or None,
        provider=clean_text(record.get("ProviderName"), 255) or None,
        event_id=event_id,
        level=level,
        message=message,
        raw=record,
        username=username,
        src_ip=src_ip,
    )

