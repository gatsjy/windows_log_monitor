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
키는 (PC, 파일, 프로세스) — 한 PC 의 여러 인스턴스가 섞이지 않게. 서버 재시작이 짝 사이에 끼면 놓친다(B-20).

여러 줄 레코드 (ADR-037): 에이전트 0.4.0 부터 시각으로 시작하지 않는 줄(시작 배너, Registry startup parameters 의
이어지는 줄, 여러 줄 메시지)은 앞 레코드에 붙어 온다(Fluent Bit multiline). 시각·프로세스·오류 번호는 첫 줄로 읽고
나머지 줄은 message 에 붙인다(raw.mssql.lines = 줄 수). 줄마다 오는 0.3.0 이하와 같은 방식으로 센다.

ERRORLOG 시각에는 시간대가 없다 → 서버의 WLM_DISPLAY_TZ(기본 Asia/Seoul)로 해석한다.
해석한 값은 raw.mssql.* 에 덧붙인다 (원본 log 는 그대로).
"""

from __future__ import annotations

import re
from datetime import datetime

from ..config import display_zone
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

# (host, file, process) → (시각 문자열, 머리줄 해석값). 본문 줄이 오면 꺼내서 합친다.
_pending: dict[tuple[str, str, str], tuple[str, dict]] = {}
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


def normalize(record: dict, now: datetime) -> Event | None:
    whole = str(record.get("log") or record.get("message") or "").replace("\r", "").strip("\ufeff\n ")
    lines = [ln for ln in whole.split("\n") if ln.strip()]
    if not lines:
        return None
    host = pick_host(record, "host", "hostname")
    first, rest = lines[0], lines[1:]
    m = _LINE.match(first)
    if not m:  # 앞이 끊긴 이어지는 줄 (0.3.0 이하는 줄마다 온다) — 그대로 저장
        text = "\n".join(lines)
        return Event(ts=now, host=host, source=SOURCE, level=level_from_text(text), message=clean_text(text),
                     raw=record, channel="MSSQL/ERRORLOG", provider=None)
    stamp, process, text = m.groups()
    try:
        fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in stamp else "%Y-%m-%d %H:%M:%S"
        ts = datetime.strptime(stamp[:23], fmt).replace(tzinfo=display_zone())
    except ValueError:
        ts = now

    message = "\n".join([text, *rest])
    parsed: dict[str, object] = {"process": process, "text": text}
    if rest:
        parsed["lines"] = len(lines)
    level, event_id, user, ip = level_from_text(message), None, None, None
    key = (host, str(record.get("file") or ""), process)
    if err := _ERROR.match(text):  # 머리줄: 기억만 하고 '상세'로 저장
        parsed.update(error=int(err.group(1)), severity=int(err.group(2)), state=int(err.group(3)), header=True)
        if len(_pending) >= _PENDING_MAX:
            _pending.pop(next(iter(_pending)))
        _pending[key] = (stamp, parsed)
        return Event(ts=ts, host=host, source=SOURCE, channel="MSSQL/ERRORLOG", provider=process,
                     level=VERBOSE, message=clean_text(message), raw={**record, "mssql": parsed})
    head = _pending.pop(key, None)
    if head and head[0] == stamp:
        event_id, severity = head[1]["error"], head[1]["severity"]
        parsed.update(error=event_id, severity=severity, state=head[1]["state"])
        level = severity_level(severity)
    if login := _LOGIN.search(message):
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
        message=clean_text(message),
        raw={**record, "mssql": parsed},
        username=user,
        src_ip=ip,
    )
