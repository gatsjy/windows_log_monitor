"""SQL Server ERRORLOG 파일 (선택 수집).

  C:\\Program Files\\Microsoft SQL Server\\MSSQL<버전>.<인스턴스>\\MSSQL\\Log\\ERRORLOG  (UTF-16LE)

SQL Server 는 중요한 오류·로그인 실패를 Windows '응용 프로그램' 이벤트 로그에도 남기므로(공급자 MSSQLSERVER),
에이전트를 설치하면 별도 설정 없이 분류 'mssql' 로 수집된다. ERRORLOG 는 더 자세한 내용이 필요할 때만 켠다.

한 줄 예:
  2026-10-04 10:15:22.53 Logon       Error: 18456, Severity: 14, State: 8.
  2026-10-04 10:15:22.53 Logon       Login failed for user 'sa'. Reason: Password did not match ... [CLIENT: 10.0.0.5]

오류는 항상 두 줄이다: 'Error: 번호, Severity, State' 머리줄 + 같은 시각·프로세스의 본문 줄.
머리줄까지 같은 번호로 세면 로그인 실패 등이 2배로 집계되므로, 머리줄은 '상세'(5)·번호 없음으로 두고
번호·심각도는 바로 다음 본문 줄에 붙인다. 머리줄 기억(_pending)은 프로세스 메모리라 워커 1개 전제(ADR-006).

ERRORLOG 시각에는 시간대가 없다 → 서버의 WLM_DISPLAY_TZ(기본 Asia/Seoul)로 해석한다.
해석한 값은 raw.mssql.* 에 덧붙인다 (원본 log 는 그대로).
"""

from __future__ import annotations

import re
from datetime import datetime
from zoneinfo import ZoneInfo

from ..config import settings
from .base import (
    CRITICAL,
    ERROR,
    INFO,
    VERBOSE,
    WARNING,
    Event,
    clean_ip,
    clean_text,
    clean_user,
    level_from_text,
    pick_host,
)

SOURCE = "mssql"

_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\S+)\s+(.*)$")
_ERROR = re.compile(r"Error:\s*(\d+),\s*Severity:\s*(\d+),\s*State:\s*(\d+)")
_LOGIN = re.compile(r"Login (failed|succeeded) for user '([^']*)'.*?\[CLIENT: ([^\]]+)\]", re.DOTALL)

# (host, process) → (시각 문자열, 머리줄 해석값). 본문 줄이 오면 꺼내서 합친다.
_pending: dict[tuple[str, str], tuple[str, dict]] = {}
_PENDING_MAX = 1000


def severity_level(severity: int) -> int:
    """SQL Server 심각도 → 공통 수준. 20 이상은 연결이 끊기는 치명적 오류."""
    if severity >= 20:
        return CRITICAL
    if severity >= 17:
        return ERROR
    if severity >= 11:
        return WARNING
    return INFO


def _tz():
    try:
        return ZoneInfo(settings.display_tz)
    except Exception:  # noqa: BLE001
        return ZoneInfo("UTC")


def normalize(record: dict, now: datetime) -> Event | None:
    line = str(record.get("log") or record.get("message") or "").strip("\ufeff\r\n ")
    if not line:
        return None
    host = pick_host(record, "host", "hostname")
    m = _LINE.match(line)
    if not m:  # 여러 줄 메시지의 이어지는 줄 등 — 그대로 저장
        return Event(ts=now, host=host, source=SOURCE, level=level_from_text(line), message=clean_text(line),
                     raw=record, channel="MSSQL/ERRORLOG", provider=None)
    stamp, process, text = m.groups()
    try:
        fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in stamp else "%Y-%m-%d %H:%M:%S"
        ts = datetime.strptime(stamp[:23], fmt).replace(tzinfo=_tz())
    except ValueError:
        ts = now

    parsed: dict[str, object] = {"process": process, "text": text}
    level, event_id, user, ip = level_from_text(text), None, None, None
    key = (host, process)
    if err := _ERROR.match(text):  # 머리줄: 기억만 하고 '상세'로 저장
        parsed.update(error=int(err.group(1)), severity=int(err.group(2)), state=int(err.group(3)), header=True)
        if len(_pending) >= _PENDING_MAX:
            _pending.pop(next(iter(_pending)))
        _pending[key] = (stamp, parsed)
        return Event(ts=ts, host=host, source=SOURCE, channel="MSSQL/ERRORLOG", provider=process,
                     level=VERBOSE, message=clean_text(text), raw={**record, "mssql": parsed})
    head = _pending.pop(key, None)
    if head and head[0] == stamp:
        event_id, severity = head[1]["error"], head[1]["severity"]
        parsed.update(error=event_id, severity=severity, state=head[1]["state"])
        level = severity_level(severity)
    if login := _LOGIN.search(text):
        result, user, ip = login.group(1), clean_user(login.group(2)), clean_ip(login.group(3))
        parsed.update(login=result, user=login.group(2), client=login.group(3))
        event_id = 18456 if result == "failed" else 18453
        level = WARNING if result == "failed" else INFO
    return Event(
        ts=ts,
        host=host,
        source=SOURCE,
        channel="MSSQL/ERRORLOG",
        provider=process,  # Logon, spid51, Server, Backup …
        event_id=event_id,
        level=level,
        message=clean_text(text),
        raw={**record, "mssql": parsed},
        username=user,
        src_ip=ip,
    )
