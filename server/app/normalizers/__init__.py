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
from .base import Event, Heartbeat, clean_ip, clean_user, pick_host
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


def normalize(record: dict, now: datetime, iis_ctx: iis.IisContext | None = None) -> Event | Heartbeat | None:
    """None = 저장하지 않는 줄 (IIS 머리줄, 빈 줄 등).
    iis_ctx = 한 수집 요청의 IIS 열 순서 문맥 (routers/ingest 가 repository.iis_context 로 만든다, ADR-037)."""
    if record.get("type") == "heartbeat":
        meta = {k: v for k, v in record.items() if k not in ("type", "agent_host", "date")}
        return Heartbeat(host=pick_host(record, "host", "hostname"), meta=meta)

    source = record.get("log_source")
    if source:
        handler = BY_SOURCE.get(str(source), generic.normalize)
    else:
        handler = next((fn for detect, fn in DETECTORS if detect(record)), generic.normalize)
    event = iis.normalize(record, now, iis_ctx) if handler is iis.normalize else handler(record, now)
    if event is not None and not event.category:
        event.category = classify(event.source, event.channel, event.provider)
    if event is not None:
        _scrub(event)
    return event


_TEXT_FIELDS = ("host", "source", "category", "channel", "provider", "username", "src_ip", "message")


def _scrub(event: Event) -> None:
    """PostgreSQL TEXT 는 NUL 을 받지 못한다. 레코드 하나의 NUL 때문에 그 요청 전체가 500 이 되면 에이전트가 같은 청크를
    끝없이 다시 보내 그 PC(수집기면 모든 장비)의 로그가 멈춘다(벤치마킹 검토에서 재현). 정규화 단계에서 지워 실시간·검색·저장이
    같은 값을 본다. 원본 raw 는 저장할 때 \\u0000 만 뺀다(repository._json)."""
    for name in _TEXT_FIELDS:
        value = getattr(event, name)
        if isinstance(value, str) and "\x00" in value:
            cleaned = value.replace("\x00", "")
            setattr(event, name, cleaned or (None if name in _NULLABLE else cleaned))


_NULLABLE = frozenset({"username", "src_ip", "channel", "provider", "category"})


def derive_common(source: str | None, channel: str | None, provider: str | None, event_id: int | None,
                  message: str | None, raw: dict | None) -> tuple[str | None, str | None, str | None]:
    """저장된 행(원본 + 서버가 덧붙인 raw.<소스>)만으로 (category, username, src_ip) 를 다시 구한다.
    옛 보관 파일(형식 v1)은 이 세 컬럼이 빠져 있어 복원할 때 쓴다 — 정규화기를 다시 돌리지 않는 것은
    IIS 열 순서(요청 문맥)·MSSQL 짝(메모리 상태) 없이도 저장 당시와 같은 값을 얻기 위해서다(test_normalizers 왕복 시험)."""
    raw = raw if isinstance(raw, dict) else {}
    message = message or ""
    category = classify(source, channel, provider)
    if source == windows.SOURCE:
        derived = (raw.get(windows.SOURCE) or {}).get("EventData") if isinstance(raw.get(windows.SOURCE), dict) else None
        user, ip = windows.common_fields(raw, event_id, message, derived if isinstance(derived, dict) else None)
    elif source == iis.SOURCE:
        parsed = raw.get("iis") if isinstance(raw.get("iis"), dict) else {}
        user, ip = clean_user(parsed.get("username")), clean_ip(parsed.get("client_ip"))
    elif source == mssql.SOURCE:
        parsed = raw.get("mssql") if isinstance(raw.get("mssql"), dict) else {}
        user, ip = (clean_user(parsed.get("user")), clean_ip(parsed.get("client"))) if parsed.get("login") else (None, None)
    elif source in (syslog.SYSLOG_SOURCE, syslog.JOURNALD_SOURCE):
        user, ip = syslog.ssh_fields(message)
    else:
        user = ip = None
    return category, user, ip


IisContext = iis.IisContext
layout_keys = iis.layout_keys

__all__ = ["Event", "Heartbeat", "IisContext", "derive_common", "layout_keys", "normalize"]
