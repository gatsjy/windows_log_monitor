"""Windows 이벤트 로그 (Fluent Bit winevtlog 입력).

winevtlog 레코드 키: ProviderName, ProviderGuid, Qualifiers, EventID, Version, Level, Task,
Opcode, Keywords("0x8020000000000000" 형태 문자열), TimeCreated("2026-10-03 14:22:01 +0900"),
EventRecordID, ActivityID, RelatedActivityID, ProcessID, ThreadID, Channel, Computer, UserID,
Message, StringInserts(배열), EventData(이름 있는 맵 — Fluent Bit 5.1+ 의 event_data_as_map 일 때만)

지금 에이전트(Fluent Bit 4.0)는 EventData 를 이름 없이 StringInserts 로만 보낸다(실측, tests/fixtures/winevtlog).
알려진 이벤트(win_templates)면 서버가 이름을 붙여 raw.winevtlog.EventData 에 덧붙인다 — 원본은 그대로(ADR-038).
검색·규칙의 f.EventData.<이름> 은 에이전트가 보낸 값이 먼저, 없으면 이 값을 본다(querylang.RAW_ALIAS).

공통 필드:
  username ← EventData.TargetUserName / SubjectUserName … (이름 → 서버가 붙인 이름 → StringInserts 위치표, MSSQL 은 메시지)
  src_ip   ← EventData.IpAddress / SourceAddress …
"""

from __future__ import annotations

import re
from datetime import datetime

from . import win_templates
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

# 그룹 구성원 변경: TargetUserName 은 그룹 이름이다 → 사용자는 바꾼 사람(SubjectUserName)
SUBJECT_USER_EVENTS = frozenset({4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757,
                                 4758})

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


def derived_event_data(record: dict, event_id: int | None) -> dict | None:
    """에이전트가 EventData 맵을 보내지 않았을 때 StringInserts 에 템플릿 이름을 붙인 맵 (모르는 이벤트면 None)."""
    if isinstance(record.get("EventData"), dict):
        return None
    return win_templates.named(record.get("ProviderName"), event_id, record.get("StringInserts"), record.get("Version"))


def common_fields(record: dict, event_id: int | None, message: str,
                  derived: dict | None = None) -> tuple[str | None, str | None]:
    """(username, src_ip) 추출."""
    data = record.get("EventData") if isinstance(record.get("EventData"), dict) else derived
    user = ip = None
    if isinstance(data, dict):
        fields = ("SubjectUserName",) if event_id in SUBJECT_USER_EVENTS else USER_FIELDS
        user = next((u for f in fields if (u := clean_user(data.get(f)))), None)
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
    derived = derived_event_data(record, event_id)
    username, src_ip = common_fields(record, event_id, message, derived)

    return Event(
        ts=pick_time(record, "TimeCreated", now=now),
        host=pick_host(record, "Computer"),
        source=SOURCE,
        channel=clean_text(record.get("Channel"), 255) or None,
        provider=clean_text(record.get("ProviderName"), 255) or None,
        event_id=event_id,
        level=level,
        message=message,
        raw={**record, SOURCE: {"EventData": derived}} if derived and SOURCE not in record else record,
        username=username,
        src_ip=src_ip,
    )

