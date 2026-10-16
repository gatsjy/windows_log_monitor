"""이벤트 필터: URL 쿼리 파라미터 해석 + 실시간 스트림용 매칭.

지원 파라미터 (모두 선택):
  since, until                    상대시간(15m, 1h, 24h, 7d) 또는 ISO8601
  host, channel, provider, source, category, user, ip   콤마로 여러 값
  level, event_id                 콤마로 여러 정수
  q                               message 부분일치 (대소문자 무시). 'a|b' = a 또는 b
  f.<경로>=<값>                    원본 JSON(raw) 필드 일치. 예) f.EventData.TargetUserName=admin
  query                           검색 문장 (B-01, app/querylang.py). 위 조건들과 AND.
                                  예) event_id:4625 -user:svc_backup level:오류,심각 "잘못된 암호"

문장의 포함 조건은 위 파라미터 필드(hosts, levels, fields …)에 교집합으로 합친다 — 같은 뜻의 조건은 SQL 이 같다
(tests/test_querylang.py same_sql). 제외는 값이 없는(NULL) 이벤트를 남긴다.
SQL 변환은 repository.py (저장소 백엔드 종속 코드는 그곳에만 둔다).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import cached_property
from typing import Any

from .querylang import FilterError, QueryError, Term, fold, parse_terms, raw_text, walk_raw

__all__ = ["EventFilter", "FilterError", "QueryError", "Scope", "parse_duration", "parse_query", "parse_time",
           "raw_text", "scopes_allow"]

_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
MAX_FIELD_FILTERS = 10
# 문장의 키 → 이벤트(정규화된 dict·컬럼) 이름. 문장 키와 같으면 생략
EVENT_FIELD = {"user": "username", "ip": "src_ip"}
# 키 → 포함 조건을 담는 EventFilter 필드
INCLUDE_FIELD = {"host": "hosts", "channel": "channels", "provider": "providers", "source": "sources",
                 "category": "categories", "user": "users", "ip": "ips", "level": "levels", "event_id": "event_ids"}


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


def _host_regex(pattern: str) -> re.Pattern[str]:
    """'MED-*' → 대소문자 무시 전체 일치. * 만 와일드카드."""
    return re.compile("^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$", re.IGNORECASE)


@dataclass(frozen=True)
class Scope:
    """사용자 그룹의 조회 범위 (auth/groups.py). 비어 있는 쪽은 제한하지 않는다."""

    categories: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()   # 'MED-*' 처럼 * 사용 가능, 대소문자 무시

    @property
    def unrestricted(self) -> bool:
        return not self.categories and not self.hosts

    def allows(self, category: str | None, host: str | None) -> bool:
        if self.categories and category not in self.categories:
            return False
        return self.allows_host(host)

    def allows_host(self, host: str | None) -> bool:
        return not self.hosts or any(_host_regex(p).match(host or "") for p in self.hosts)


def scopes_allow(scopes: tuple[Scope, ...] | None, category: str | None, host: str | None) -> bool:
    """여러 그룹의 범위는 합집합. None = 제한 없음."""
    return scopes is None or any(s.allows(category, host) for s in scopes)


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
    # ---- 검색 문장(query)에서만 생기는 조건 (merged). 만든 뒤에는 고치지 않는다 — replace() 는 얕은 복사라서
    # 제외: 'host'…'event_id' | 'f.<a.b>' → 값들 (하나라도 같으면 제외, 값이 없는 이벤트는 남김)
    excludes: dict[str, list[Any]] = field(default_factory=dict)
    msg_all: list[list[str]] = field(default_factory=list)      # 각 원소 = OR 묶음, 묶음끼리 AND
    msg_not: list[str] = field(default_factory=list)            # 하나라도 포함하면 제외
    field_any: list[tuple[list[str], list[str]]] = field(default_factory=list)   # f.p:a,b (값 2개 이상)
    never: bool = False                                         # 포함 조건 교집합이 비면 결과 없음
    # 내부용(URL 파라미터 아님): 서버 수신 시각 하한. 알림 규칙이 '최근 N분 동안 들어온' 이벤트를 셀 때 사용
    received_since: datetime | None = None
    # 내부용: 로그인한 사용자의 조회 범위 (사용자 그룹). None 이면 제한 없음
    scopes: tuple[Scope, ...] | None = None

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
        f = cls(
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
        # 검색 문장: 쉼표가 문법 기호라 _values 로 나누지 않는다. 다른 조건과 AND
        raw = params.getlist("query") if hasattr(params, "getlist") else [params.get("query")]
        texts = [str(v) for v in raw if v is not None and str(v).strip()]
        if len(texts) > 1:
            raise FilterError("query 는 한 번만 쓸 수 있습니다")
        if texts:
            f = f.merged(parse_terms(texts[0], field_budget=MAX_FIELD_FILTERS - len(field_filters)))
        return f

    def merged(self, terms: list[Term]) -> EventFilter:
        """문장의 term 들을 AND 로 더한 새 필터. 포함은 기존 목록과 교집합(비면 never), 제외는 합집합."""
        changes: dict[str, Any] = {}

        def current(name: str) -> Any:
            return changes.get(name, getattr(self, name))

        excludes = {k: list(v) for k, v in self.excludes.items()}
        never = self.never
        for term in terms:
            values = list(term.values)
            if term.neg:
                key = "f." + ".".join(term.path) if term.key == "f" else term.key
                if term.key == "msg":
                    changes["msg_not"] = current("msg_not") + [v for v in values if v not in current("msg_not")]
                    continue
                bucket = excludes.setdefault(key, [])
                bucket.extend(v for v in values if v not in bucket)
            elif term.key == "msg":
                changes["msg_all"] = [*current("msg_all"), values]
            elif term.key == "f":
                if len(values) == 1:
                    changes["fields"] = [*current("fields"), (list(term.path), values[0])]
                else:
                    changes["field_any"] = [*current("field_any"), (list(term.path), values)]
            else:
                name = INCLUDE_FIELD[term.key]
                existing = current(name)
                if existing:
                    allowed = set(values)
                    narrowed = [v for v in existing if v in allowed]
                    never = never or not narrowed
                    changes[name] = narrowed
                else:
                    changes[name] = values
        return replace(self, **changes, excludes=excludes, never=never)

    @property
    def q_terms(self) -> list[str]:
        """'timeout|refused' → ['timeout', 'refused'] (하나라도 포함되면 일치)."""
        return [t.strip() for t in self.q.split("|") if t.strip()]

    @cached_property
    def _msg_all_folded(self) -> list[list[str]]:
        return [[fold(v) for v in group] for group in self.msg_all]

    @cached_property
    def _msg_not_folded(self) -> list[str]:
        return [fold(v) for v in self.msg_not]

    def matches(self, event: dict) -> bool:
        """실시간 스트림용: 정규화된 이벤트(dict) 하나가 조건에 맞는지 (시간 조건은 무시).
        repository.where_clause 와 같은 뜻이어야 한다 (NULL·대소문자·원본 값 글자 표현) — querylang_cases.json 으로 함께 시험."""
        if not scopes_allow(self.scopes, event.get("category"), event.get("host")):
            return False
        if self.never:
            return False
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
        message = fold(event.get("message") or "")     # NULL 메시지 → '' → 포함 조건에 안 맞음 (ILIKE on NULL)
        if self.q_terms and not any(fold(term) in message for term in self.q_terms):
            return False
        for group in self._msg_all_folded:
            if not any(v in message for v in group):
                return False
        for path, expected in self.fields:
            current = walk_raw(event.get("raw"), path)
            if current is None or raw_text(current) != expected:
                return False
        for path, values in self.field_any:
            current = walk_raw(event.get("raw"), path)
            if current is None or raw_text(current) not in values:
                return False
        for key, values in self.excludes.items():
            if key.startswith("f."):
                current = walk_raw(event.get("raw"), key[2:].split("."))
                if current is not None and raw_text(current) in values:
                    return False
            else:
                current = event.get(EVENT_FIELD.get(key, key))
                if current is not None and current in values:   # 값이 없으면 남김 = SQL 의 IS NOT TRUE
                    return False
        return not any(v in message for v in self._msg_not_folded)   # NULL 메시지는 남김 ('' 에는 없음)


def parse_query(text: str) -> EventFilter:
    """검색 문장만으로 필터 (BACKLOG B-01 의 이름). 틀리면 QueryError."""
    return EventFilter().merged(parse_terms(text))
