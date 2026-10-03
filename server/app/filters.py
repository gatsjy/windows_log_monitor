"""이벤트 필터: URL 쿼리 파라미터 해석 + 실시간 스트림용 매칭.

지원 파라미터 (모두 선택):
  since, until                    상대시간(15m, 1h, 24h, 7d) 또는 ISO8601
  host, channel, provider, source, category, user, ip   콤마로 여러 값
  level, event_id                 콤마로 여러 정수
  q                               message 부분일치 (대소문자 무시). 'a|b' = a 또는 b
  f.<경로>=<값>                    원본 JSON(raw) 필드 일치. 예) f.EventData.TargetUserName=admin

SQL 변환은 repository.py (저장소 백엔드 종속 코드는 그곳에만 둔다).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
MAX_FIELD_FILTERS = 10


class FilterError(ValueError):
    """잘못된 필터 파라미터 (HTTP 400 으로 응답)."""


def parse_duration(text: str | None) -> timedelta | None:
    if not text:
        return None
    m = _DURATION_RE.match(text.strip().lower())
    if not m:
        return None
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


def parse_time(text: str | None, now: datetime) -> datetime | None:
    if not text:
        return None
    delta = parse_duration(text)
    if delta is not None:
        return now - delta
    try:
        dt = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise FilterError(f"시간 형식을 해석할 수 없습니다: {text}") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _values(params, name: str) -> list[str]:
    raw = params.getlist(name) if hasattr(params, "getlist") else [params.get(name)]
    out: list[str] = []
    for item in raw:
        if item:
            out.extend(v.strip() for v in str(item).split(",") if v.strip())
    return out


def _ints(params, name: str) -> list[int]:
    try:
        return [int(v) for v in _values(params, name)]
    except ValueError as exc:
        raise FilterError(f"{name} 는 정수여야 합니다") from exc


def raw_text(value: Any) -> str:
    """PostgreSQL `raw #>> path` 와 같은 문자열 표현."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))


@dataclass
class EventFilter:
    since: datetime | None = None
    until: datetime | None = None
    hosts: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    levels: list[int] = field(default_factory=list)
    event_ids: list[int] = field(default_factory=list)
    q: str = ""
    fields: list[tuple[list[str], str]] = field(default_factory=list)
    # 내부용(URL 파라미터 아님): 서버 수신 시각 하한. 알림 규칙이 '최근 N분 동안 들어온' 이벤트를 셀 때 사용
    received_since: datetime | None = None

    @classmethod
    def from_params(cls, params, *, default_since: str | None = "24h",
                    now: datetime | None = None) -> EventFilter:
        now = now or datetime.now(UTC)
        items = params.multi_items() if hasattr(params, "multi_items") else params.items()
        field_filters = []
        for key, value in items:
            if key.startswith("f.") and len(key) > 2:
                path = [p for p in key[2:].split(".") if p]
                if path:
                    field_filters.append((path, str(value)))
        if len(field_filters) > MAX_FIELD_FILTERS:
            raise FilterError(f"필드 필터는 최대 {MAX_FIELD_FILTERS}개입니다")
        since = parse_time(params.get("since") or default_since, now)
        until = parse_time(params.get("until"), now)
        if since and until and since >= until:
            raise FilterError("since 는 until 보다 이전이어야 합니다")
        return cls(
            since=since,
            until=until,
            hosts=_values(params, "host"),
            channels=_values(params, "channel"),
            providers=_values(params, "provider"),
            sources=_values(params, "source"),
            categories=_values(params, "category"),
            users=_values(params, "user"),
            ips=_values(params, "ip"),
            levels=_ints(params, "level"),
            event_ids=_ints(params, "event_id"),
            q=(params.get("q") or "").strip()[:200],
            fields=field_filters,
        )

    @property
    def q_terms(self) -> list[str]:
        """'timeout|refused' → ['timeout', 'refused'] (하나라도 포함되면 일치)."""
        return [t.strip() for t in self.q.split("|") if t.strip()]

    def matches(self, event: dict) -> bool:
        """실시간 스트림용: 정규화된 이벤트(dict) 하나가 조건에 맞는지 (시간 조건은 무시)."""
        if self.hosts and event.get("host") not in self.hosts:
            return False
        if self.channels and event.get("channel") not in self.channels:
            return False
        if self.providers and event.get("provider") not in self.providers:
            return False
        if self.sources and event.get("source") not in self.sources:
            return False
        if self.categories and event.get("category") not in self.categories:
            return False
        if self.users and event.get("username") not in self.users:
            return False
        if self.ips and event.get("src_ip") not in self.ips:
            return False
        if self.levels and event.get("level") not in self.levels:
            return False
        if self.event_ids and event.get("event_id") not in self.event_ids:
            return False
        if self.q_terms:
            message = (event.get("message") or "").lower()
            if not any(term.lower() in message for term in self.q_terms):
                return False
        for path, expected in self.fields:
            current: Any = event.get("raw")
            for part in path:
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                    current = current[int(part)]
                else:
                    current = None
            if current is None or raw_text(current) != expected:
                return False
        return True
