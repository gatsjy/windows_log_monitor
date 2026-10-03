"""그 외 모든 로그 (파일 tail, JSON 앱 로그 등). 어떤 형태든 받아서 저장한다.

에이전트 쪽 규칙(권장):
    log_source  = "file"                  # 정규화기 선택용
    log_channel = "iis" / "nginx" / ...   # 화면에서 채널로 보일 이름
    file        = 파일 경로 (Fluent Bit tail 의 path_key)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import PureWindowsPath

from .base import SYSLOG_SEVERITY_TO_LEVEL, Event, clean_text, level_from_text, pick_host, pick_time, to_int

SOURCE = "file"

_LEVEL_FIELDS = ("level", "severity", "lvl", "loglevel")
_LEVEL_NAMES = {
    "fatal": 1, "critical": 1, "crit": 1, "emerg": 1, "alert": 1,
    "error": 2, "err": 2,
    "warn": 3, "warning": 3,
    "info": 4, "information": 4, "notice": 4,
    "debug": 5, "trace": 5, "verbose": 5,
}


def _level(record: dict, message: str) -> int:
    for key in _LEVEL_FIELDS:
        value = record.get(key)
        if value is None:
            continue
        name = str(value).strip().lower()
        if name in _LEVEL_NAMES:
            return _LEVEL_NAMES[name]
        number = to_int(value)
        if number is not None and 0 <= number <= 7:
            return SYSLOG_SEVERITY_TO_LEVEL[number]
    return level_from_text(message)


def normalize(record: dict, now: datetime) -> Event:
    message = clean_text(record.get("log") or record.get("message") or record.get("msg"))
    path = record.get("file")
    channel = record.get("log_channel") or (PureWindowsPath(str(path)).name if path else None)
    return Event(
        ts=pick_time(record, "time", "timestamp", "@timestamp", now=now),
        host=pick_host(record, "host", "hostname"),
        source=clean_text(record.get("log_source"), 64) or SOURCE,
        channel=clean_text(channel, 255) or None,
        provider=clean_text(path, 255) or None,
        event_id=None,
        level=_level(record, message),
        message=message,
        raw=record,
    )
