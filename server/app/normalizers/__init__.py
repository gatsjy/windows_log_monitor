"""소스별 정규화기 레지스트리.

새 로그 소스 추가 방법 (예: 방화벽 전용 포맷):
  1. normalizers/firewall.py 에 normalize(record, now) -> Event | None 작성 (None = 저장하지 않는 줄, 예: 머리줄)
  2. 아래 BY_SOURCE 에 log_source 값으로 등록 (+ 필요하면 DETECTORS 에 형태 감지 추가)
  3. categories.py 에 분류 규칙 추가 (+ web/js/levels.js 의 CATEGORY_LABELS)
  4. 에이전트 설정에서 레코드에 log_source: firewall 을 붙인다
  5. tests/test_normalizers.py 에 샘플 레코드 테스트 추가
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from . import generic, iis, mssql, syslog, windows
from .base import Event, Heartbeat, pick_host
from .categories import classify

Normalizer = Callable[[dict, datetime], Event | None]

# 1순위: 에이전트가 붙인 log_source 값으로 선택
BY_SOURCE: dict[str, Normalizer] = {
    windows.SOURCE: windows.normalize,
    syslog.SYSLOG_SOURCE: syslog.normalize_syslog,
    syslog.JOURNALD_SOURCE: syslog.normalize_journald,
    iis.SOURCE: iis.normalize,
    mssql.SOURCE: mssql.normalize,
}

# 2순위: log_source 가 없으면 레코드 형태로 추정 (위에서부터 검사)
DETECTORS: list[tuple[Callable[[dict], bool], Normalizer]] = [
    (windows.detect, windows.normalize),
    (syslog.detect_journald, syslog.normalize_journald),
    (syslog.detect_syslog, syslog.normalize_syslog),
]


def normalize(record: dict, now: datetime) -> Event | Heartbeat | None:
    """None = 저장하지 않는 줄 (IIS 머리줄, 빈 줄 등)."""
    if record.get("type") == "heartbeat":
        meta = {k: v for k, v in record.items() if k not in ("type", "agent_host", "date")}
        return Heartbeat(host=pick_host(record, "host", "hostname"), meta=meta)

    source = record.get("log_source")
    if source:
        handler = BY_SOURCE.get(str(source), generic.normalize)
    else:
        handler = next((fn for detect, fn in DETECTORS if detect(record)), generic.normalize)
    event = handler(record, now)
    if event is not None and not event.category:
        event.category = classify(event.source, event.channel, event.provider)
    return event


__all__ = ["Event", "Heartbeat", "normalize"]
