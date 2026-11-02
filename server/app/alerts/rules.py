"""알림 규칙 파일(config/alerts.yaml) 읽기와 검증.

형식은 docs/PROJECT.md '알림' 절과 config/alerts.yaml 의 주석 참고.
알림 대상(수신 그룹·외부 연동)은 파일이 아니라 환경설정 화면(DB)에서 관리한다 → app/alerts/targets.py
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from ..filters import EventFilter, FilterError, parse_duration
from ..repository import COLUMN_EXPR
from .builtin import BUILTIN_RULES

SEVERITIES = ("critical", "error", "warning", "info")
RULE_KINDS = ("count", "agent_silent", "stream_silent")
SILENT_KINDS = ("agent_silent", "stream_silent")   # 끊김 규칙: 다시 들어오면 끝난 것이 분명해 자동 해결이 기본
# 해결 방식 (B-35 2단계): manual = 사람이 해결, auto = 조건이 풀리면 엔진이 해결하고 해소 통지.
# PC 수신 끊김은 하트비트가 돌아오면 끝난 것이 분명해 auto 가 기본. 건수 규칙은 manual 이 기본 —
# 사람이 검토하지 않은 보안 알림이 '해결됨'으로 보고서에 남지 않게 운영 규칙에만 auto 를 단다
RESOLVE_MODES = ("manual", "auto")
# 관찰 모드(B-52): 알림은 기록하되 보내지 않는다(무음과 같은 경로) — 새 규칙의 오탐을 보고 '켜기(승격)'. 탐지 약화로 친다
RULE_MODES = ("active", "observe")
# query = 검색 문장 (B-01). 다른 키와 AND
# saved = 저장한 검색의 이름(B-64) — 엔진이 그 문장을 규칙 문장 앞에 붙인다(engine.rule_filter)
MATCH_KEYS = {"host", "channel", "provider", "source", "category", "user", "ip", "level", "event_id", "q", "query", "saved"}


class ConfigError(ValueError):
    """설정 파일 오류 (화면에 그대로 보여준다)."""


@dataclass(frozen=True)
class Rule:
    name: str
    kind: str                       # count: 이벤트 수 기준 | agent_silent: PC 수신 끊김 | stream_silent: 늘 오던 채널 끊김
    severity: str
    notify: tuple[str, ...]
    description: str = ""
    enabled: bool = True
    match: dict[str, str] = field(default_factory=dict)
    window: timedelta = timedelta(minutes=5)
    threshold: int = 1
    group_by: str = "host"
    cooldown: timedelta = timedelta(minutes=30)
    silent_for: timedelta = timedelta(minutes=10)
    hosts: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()   # stream_silent: 볼 채널(비우면 전부). 채널이 없는 소스는 소스 이름으로
    tags: tuple[str, ...] = ()   # 예: "MITRE T1110", "ISMS 2.11.3" (화면·알림 본문에 표시)
    sid: int | None = None       # 규칙 번호 (Snort 의 sid 처럼 고유). 화면에서 만들면 자동 부여
    group: str = "기타"          # 규칙 묶음 (화면 왼쪽 목록, 묶음 단위로 켜고 끄기)
    # 이 규칙이 감시하는 분류 (match.category 와 match.query 의 category: 를 합친 포함 조건). 조회 범위 판단용 (visibility)
    categories: tuple[str, ...] = ()
    # 서로 다른 값 수 (ADR-041): group_by 마다 이 필드의 서로 다른 값이 distinct_min 개 이상일 때만 (건수 기준과 함께)
    #   예) 패스워드 스프레이 = 출발지 IP 마다 서로 다른 계정 10개 이상. 값이 없는(NULL) 이벤트는 세지 않는다
    distinct_field: str | None = None
    distinct_min: int = 0
    resolve: str = "manual"
    mode: str = "active"

    def event_filter(self, exceptions: tuple[str, ...] | list[str] = (), saved: str | None = None) -> EventFilter:
        """exceptions: 규칙 예외(B-46)의 조건들(정본 표기) — 문장에 제외 항(-조건)으로 덧붙인다. 검색 문장의 제외 의미 그대로
        (값이 없는 이벤트는 남김, 케이스 표가 보장). 예외끼리는 각각 뺀다(하나라도 맞으면 제외).
        saved: match.saved 가 가리키는 저장한 검색의 문장(B-64) — 규칙 문장 앞에 붙인다(AND). 찾는 일은 engine.rule_filter 가."""
        match = {k: v for k, v in self.match.items() if k != "saved"}
        if not exceptions and not saved:
            return EventFilter.from_params(match, default_since=None)
        match["query"] = " ".join([saved or "", str(match.get("query") or ""), *(f"-{t}" for t in exceptions)]).strip()
        return EventFilter.from_params(match, default_since=None)


ESCALATE_UNLESS = ("acked", "resolved")   # 이 상태가 되면 그 단계는 보내지 않는다
ESCALATE_MAX_AFTER = timedelta(days=7)
ESCALATE_MAX_STEPS = 5
ACK_TIMEOUT_MIN, ACK_TIMEOUT_MAX = timedelta(minutes=5), timedelta(days=7)


@dataclass(frozen=True)
class EscalationStep:
    after: timedelta                 # 알림 발생 뒤 이만큼 지나도
    unless: str                      # acked(확인 안 됨) / resolved(해결 안 됨) 이면
    notify: tuple[str, ...]          # 이 받는 곳에 다시 알린다

    @property
    def action(self) -> str:
        """alert_deliveries.action — 단계마다 한 번만 넣는 키 (마이그레이션 029)."""
        return f"escalate:{int(self.after.total_seconds())}:{self.unless}"


@dataclass(frozen=True)
class Escalation:
    """확인 안 된 알림 에스컬레이션 (B-43, ADR-055): 새벽 3시의 심각 알림이 아침까지 읽히지 않는 것을 막는다."""

    name: str
    steps: tuple[EscalationStep, ...]
    severities: tuple[str, ...] = ()   # 비우면 모든 심각도
    rules: tuple[str, ...] = ()        # 비우면 모든 규칙
    # 확인 시간 초과 (B-43 2단계): 확인한 뒤 이만큼 지나도 해결되지 않으면 다시 열고 첫 단계 받는 곳에 다시 알린다 (없으면 안 함)
    ack_timeout: timedelta | None = None

    def ack_timeout_action(self, round_: int) -> str:
        """alert_deliveries.action — 회차마다 한 번 (마이그레이션 034)."""
        return f"acktimeout:{int(self.ack_timeout.total_seconds())}:{round_}"

    def matches(self, rule: str, severity: str) -> bool:
        return (not self.severities or severity in self.severities) and (not self.rules or rule in self.rules)


@dataclass(frozen=True)
class Route:
    """받는 곳 경로 (B-26): 규칙마다 notify 를 고치지 않고 '보안 태그 규칙은 보안팀에게도'를 한 번에. 위에서부터 맞는 것을 적용,
    continue 가 아니면 거기서 멈춘다. replace 면 규칙의 notify 대신, 아니면 더한다. 모든 조건이 비면 모든 알림."""

    name: str
    notify: tuple[str, ...]
    groups: tuple[str, ...] = ()       # 규칙 묶음(group)
    tags: tuple[str, ...] = ()         # 규칙 태그 중 하나라도
    severities: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()        # 규칙 이름
    hosts: tuple[str, ...] = ()        # 대상 PC 이름 패턴('MED-*', 대소문자 무시) — PC 로 묶는 규칙만 맞을 수 있다
    continue_: bool = False
    replace: bool = False

    def matches(self, rule: Rule, host: str | None) -> bool:
        if self.groups and rule.group not in self.groups:
            return False
        if self.tags and not set(self.tags) & set(rule.tags):
            return False
        if self.severities and rule.severity not in self.severities:
            return False
        if self.rules and rule.name not in self.rules:
            return False
        if self.hosts:
            return host is not None and any(fnmatch.fnmatchcase(host.casefold(), p.casefold()) for p in self.hosts)
        return True


GROUP_WAIT_DEFAULT = 30
GROUP_INTERVAL_DEFAULT = 300
GROUP_WAIT_MAX = 300
GROUP_INTERVAL_MAX = 3600
CRITICAL_GROUP_INTERVAL = 60


@dataclass(frozen=True)
class AlertConfig:
    interval_sec: int = 30
    rules: tuple[Rule, ...] = ()
    # 알림 기능 자체의 문제(엔진 멈춤·전송 실패·규칙 동작 안 함)를 받을 곳 (ADR-045). 비우면 점검 보고서 받는 곳
    fallback_notify: tuple[str, ...] = ()
    escalations: tuple[Escalation, ...] = ()
    routes: tuple[Route, ...] = ()
    # 묶음 전송 (B-41, ADR-057): 사람이 읽는 받는 곳(메일·메신저)에 같은 규칙 알림을 모아 한 통으로. interval 0 = 묶지 않음(예전처럼)
    group_wait_sec: int = GROUP_WAIT_DEFAULT
    group_interval_sec: int = GROUP_INTERVAL_DEFAULT

    def group_timing(self, severity: str) -> tuple[int, int]:
        """(모으는 시간, 묶음 간격) 초. 심각은 바로 보내고 간격도 짧게 — 한 통이 이미 갔으니 같은 규칙의 다음 대상은 1분 안에."""
        if self.group_interval_sec == 0:
            return 0, 0
        if severity == "critical":
            return 0, min(CRITICAL_GROUP_INTERVAL, self.group_interval_sec)
        return self.group_wait_sec, self.group_interval_sec

    def targets_for(self, rule: Rule, key: str | None = None) -> tuple[tuple[str, ...], list[str]]:
        """이 규칙·대상의 알림을 받을 곳과 거친 경로 이름 (B-26). 경로가 없으면 규칙의 notify 그대로(예전과 같음)."""
        notify, used = list(rule.notify), []
        host = _route_host(rule, key)
        for route in self.routes:
            if not route.matches(rule, host):
                continue
            used.append(route.name)
            notify = list(route.notify) if route.replace else notify + [n for n in route.notify if n not in notify]
            if not route.continue_:
                break
        return tuple(dict.fromkeys(notify)), used

    def host_samples(self) -> tuple[str | None, ...]:
        """경로의 PC 패턴마다 그 패턴에 맞는 PC 이름 하나와, 어느 패턴에도 맞지 않는 경우(None).
        PC 마다 받는 곳을 다 볼 수 없어 패턴마다 대표 이름으로 본다 — 설정 변경 판단·시험 전송·상태 판단의 받는 곳."""
        samples: list[str | None] = [None]
        for route in self.routes:
            for pattern in route.hosts:
                sample = _sample_host(pattern)
                if sample is not None and sample not in samples:
                    samples.append(sample)
        return tuple(samples)

    def reachable(self, rule: Rule, hosts: tuple[str | None, ...] | None = None) -> tuple[str, ...]:
        """이 규칙의 알림이 갈 수 있는 받는 곳 전부 (경로 포함, PC 패턴마다). 규칙의 notify 만 보면 경로로만 받는 곳
        (보안 태그 → 보안팀)이 시험 전송·상태 판단·설정 변경 알림에서 빠졌다(검토에서 재현)."""
        out: dict[str, None] = {}
        for host in self.host_samples() if hosts is None else hosts:
            out.update(dict.fromkeys(self.targets_for(rule, host)[0]))
        return tuple(out)

    def delivery_targets(self) -> tuple[str, ...]:
        """켜진 규칙의 알림이 갈 수 있는 받는 곳 — 경로 포함 (시험 전송·상태 판단·운영 준비도·관리 작업 알림)."""
        hosts = self.host_samples()
        return tuple(dict.fromkeys(n for r in self.rules if r.enabled for n in self.reachable(r, hosts)))

    def used_targets(self) -> dict[str, list[str]]:
        """알림 대상 이름 → 그 대상을 쓰는 규칙 이름들 (대상 삭제·이름 변경 막을 때 사용)."""
        used: dict[str, list[str]] = {}
        for rule in self.rules:
            for name in rule.notify:
                used.setdefault(name, []).append(rule.name)
        for name in self.fallback_notify:
            used.setdefault(name, []).append("(대체 경로)")
        for route in self.routes:
            for name in route.notify:
                used.setdefault(name, []).append(f"(경로 {route.name})")
        for policy in self.escalations:
            for step in policy.steps:
                for name in step.notify:
                    if f"(에스컬레이션 {policy.name})" not in used.setdefault(name, []):
                        used[name].append(f"(에스컬레이션 {policy.name})")
        return used


def _duration(value: Any, where: str) -> timedelta:
    delta = parse_duration(str(value)) if value is not None else None
    if delta is None or delta.total_seconds() <= 0:
        raise ConfigError(f"{where}: 기간 형식이 잘못되었습니다 ({value!r}). 예) 30s, 5m, 1h, 1d")
    return delta


def _str_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, (str, int)) for v in value):
        raise ConfigError(f"{where}: 문자열 목록이어야 합니다")
    # 같은 값을 두 번 쓴 것은 한 번으로 — 받는 곳이 겹치면 전송 대기열 기본 키(알림·받는 곳·종류)에 걸려 그 알림이 통째로
    # 기록되지 않았다(검토에서 재현: 경로 notify [보안팀, 보안팀] 하나로 그 경로에 맞는 모든 알림이 매 주기 실패)
    return tuple(dict.fromkeys(str(v) for v in value))


def _check_rule(index: int, raw: Any) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"rules[{index}]: 객체여야 합니다")
    name = str(raw.get("name") or "").strip()
    where = f"rules[{index}] ({name or '이름 없음'})"
    if not name:
        raise ConfigError(f"{where}.name 이 필요합니다")
    if name in BUILTIN_RULES:
        raise ConfigError(f"{where}.name: '{name}' 은 내장 알림 이름이라 규칙 이름으로 쓸 수 없습니다")
    kind = raw.get("kind", "count")
    if kind not in RULE_KINDS:
        raise ConfigError(f"{where}.kind 는 {', '.join(RULE_KINDS)} 중 하나여야 합니다")
    severity = raw.get("severity", "warning")
    if severity not in SEVERITIES:
        raise ConfigError(f"{where}.severity 는 {', '.join(SEVERITIES)} 중 하나여야 합니다")
    notify = _str_list(raw.get("notify"), f"{where}.notify")
    if not notify:
        raise ConfigError(f"{where}.notify: 알림 대상(수신 그룹 또는 외부 연동 이름)이 필요합니다")

    sid = raw.get("sid")
    if sid is not None and (not isinstance(sid, int) or isinstance(sid, bool) or sid < 1):
        raise ConfigError(f"{where}.sid 는 1 이상의 정수")
    common = {
        "name": name, "kind": kind, "severity": severity, "notify": notify,
        "description": str(raw.get("description") or ""), "enabled": bool(raw.get("enabled", True)),
        # 태그는 공백을 하나로·중복 없이 — 'ISMS  2.11.3' 과 'ISMS 2.11.3' 이 심사 대응(B-73)에서 다른 항목이 되지 않게
        "tags": tuple(dict.fromkeys(" ".join(t.split()) for t in _str_list(raw.get("tags"), f"{where}.tags") if t.strip())),
        "sid": sid, "group": str(raw.get("group") or "기타").strip() or "기타",
    }
    mode = raw.get("mode", "active")
    if mode not in RULE_MODES:
        raise ConfigError(f"{where}.mode 는 {', '.join(RULE_MODES)} 중 하나여야 합니다")
    common["mode"] = mode

    resolve = raw.get("resolve", "auto" if kind in SILENT_KINDS else "manual")
    if resolve not in RESOLVE_MODES:
        raise ConfigError(f"{where}.resolve 는 {', '.join(RESOLVE_MODES)} 중 하나여야 합니다")
    common["resolve"] = resolve

    if kind == "agent_silent":
        return Rule(**common, silent_for=_duration(raw.get("silent_for", "10m"), f"{where}.silent_for"),
                    hosts=_str_list(raw.get("hosts"), f"{where}.hosts"), group_by="host")
    if kind == "stream_silent":
        # 끊김 판단은 수집 PC 화면·보고서와 같은 것(repository.silent_streams: 7일 중 5일 이상, 평소 간격의 10배·최소 6시간,
        # PC 는 살아 있음)이라 기간 키가 없다 — 규칙마다 다르면 화면과 알림이 다른 말을 한다
        return Rule(**common, hosts=_str_list(raw.get("hosts"), f"{where}.hosts"),
                    channels=_str_list(raw.get("channels"), f"{where}.channels"), group_by="host")

    match = raw.get("match") or {}
    if not isinstance(match, dict):
        raise ConfigError(f"{where}.match 는 객체여야 합니다")
    # 검색 문장은 쉼표가 문법이라 YAML 목록을 이어 붙이면 뜻이 바뀐다 → 문자열만 받는다
    if "query" in match and (isinstance(match["query"], bool) or not isinstance(match["query"], (str, int))):
        raise ConfigError(f"{where}.match.query 는 문자열이어야 합니다")
    match = {str(k): ",".join(map(str, v)) if isinstance(v, list) else str(v) for k, v in match.items()}
    bad = [k for k in match if k not in MATCH_KEYS and not k.startswith("f.")]
    if bad:
        raise ConfigError(f"{where}.match: 알 수 없는 조건 {bad} (사용 가능: {sorted(MATCH_KEYS)}, f.<경로>)")
    try:
        checked = EventFilter.from_params(match, default_since=None)
    except FilterError as exc:
        raise ConfigError(f"{where}.match: {exc}") from exc

    group_by = str(raw.get("group_by", "host"))
    if group_by != "none" and group_by not in COLUMN_EXPR and not group_by.startswith("f."):
        raise ConfigError(f"{where}.group_by 는 none, {', '.join(COLUMN_EXPR)}, f.<경로> 중 하나")
    threshold = raw.get("threshold", 1)
    if not isinstance(threshold, int) or threshold < 1:
        raise ConfigError(f"{where}.threshold 는 1 이상의 정수")
    window = _duration(raw.get("window", "5m"), f"{where}.window")
    cooldown = _duration(raw.get("cooldown", "30m"), f"{where}.cooldown")
    # 재알림 간격이 집계 구간보다 짧으면 같은 이벤트로 알림이 반복된다
    cooldown = max(cooldown, window)
    distinct_field, distinct_min = _distinct(raw.get("distinct"), group_by, window, where)
    if resolve == "auto" and distinct_field:
        # 풀렸는지를 건수로만 본다 — 서로 다른 값 수 규칙(패스워드 스프레이 등)은 보안 규칙이라 사람이 해결한다
        raise ConfigError(f"{where}.resolve: 서로 다른 값 수(distinct) 규칙은 자동 해결할 수 없습니다")
    return Rule(**common, match=match, window=window, threshold=threshold, group_by=group_by, cooldown=cooldown,
                categories=tuple(checked.categories), distinct_field=distinct_field, distinct_min=distinct_min)


DISTINCT_MAX_WINDOW = timedelta(days=1)   # count(DISTINCT) 는 구간이 길수록 비싸다 — 엔진이 30초마다 다시 센다


def _distinct(value: Any, group_by: str, window: timedelta, where: str) -> tuple[str | None, int]:
    if value is None:
        return None, 0
    if not isinstance(value, dict) or set(value) - {"field", "min"}:
        raise ConfigError(f"{where}.distinct 는 {{field: user, min: 10}} 모양이어야 합니다")
    field_name = str(value.get("field") or "").strip()
    if field_name not in COLUMN_EXPR and not (field_name.startswith("f.") and len(field_name) > 2):
        raise ConfigError(f"{where}.distinct.field 는 {', '.join(COLUMN_EXPR)}, f.<경로> 중 하나")
    if field_name == group_by:
        raise ConfigError(f"{where}.distinct.field 가 group_by 와 같으면 늘 1개입니다")
    try:   # 화면에서 저장하면 조건 값처럼 문자열로 올 수 있다
        minimum = int(str(value.get("min", "")).strip())
    except ValueError:
        minimum = 0
    if minimum < 2:
        raise ConfigError(f"{where}.distinct.min 은 2 이상의 정수")
    if window > DISTINCT_MAX_WINDOW:
        raise ConfigError(f"{where}: 서로 다른 값 수를 세는 규칙의 window 는 1d 이하")
    return field_name, minimum


def _sample_host(pattern: str) -> str | None:
    """fnmatch 패턴에 맞는 이름 하나 ('MED-*' → 'med-', 'PC-0?' → 'pc-0x'). 만들지 못하면 None."""
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        end = pattern.find("]", i + 2) if ch == "[" else -1
        if ch == "*":
            pass
        elif ch == "?":
            out.append("x")
        elif end != -1:
            body = pattern[i + 1:end]
            out.append(next((c for c in "xyz0123456789" if c not in body), "_") if body.startswith("!") else body[0])
            i = end
        else:
            out.append(ch)
        i += 1
    sample = "".join(out).casefold() or "x"   # '*' — 빈 이름은 'PC 아님'(None)과 같아져 패턴이 맞지 않는다
    return sample if fnmatch.fnmatchcase(sample, pattern.casefold()) else None


def _route_host(rule: Rule, key: str | None) -> str | None:
    """경로의 hosts 를 견줄 PC 이름 — PC 로 묶는 규칙·끊김 규칙만 대상 이름이 PC 다(채널 끊김은 'PC · 채널')."""
    if not key:
        return None
    if rule.kind == "stream_silent":
        return key.rsplit(" · ", 1)[0]
    return key if rule.kind == "agent_silent" or rule.group_by == "host" else None


def _check_routes(raw: Any, rule_names: set[str]) -> tuple[Route, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("routes 는 목록이어야 합니다")
    out, names = [], set()
    for i, r in enumerate(raw):
        where = f"routes[{i}]"
        if not isinstance(r, dict) or not str(r.get("name") or "").strip():
            raise ConfigError(f"{where}: name 이 필요합니다")
        name = str(r["name"]).strip()
        if name in names:
            raise ConfigError(f"{where}: 이름이 중복됩니다 ({name})")
        names.add(name)
        match = r.get("match") or {}
        if not isinstance(match, dict):
            raise ConfigError(f"{where}.match 는 객체여야 합니다")
        if bad := sorted(set(match) - {"group", "tags", "severity", "rules", "hosts"}):
            raise ConfigError(f"{where}.match: 알 수 없는 조건 {bad} (사용 가능: group, tags, severity, rules, hosts)")
        severities = _str_list(match.get("severity"), f"{where}.match.severity")
        if bad := [s for s in severities if s not in SEVERITIES]:
            raise ConfigError(f"{where}.match.severity: {bad}")
        rules = _str_list(match.get("rules"), f"{where}.match.rules")
        if missing := [n for n in rules if n not in rule_names]:
            raise ConfigError(f"{where}.match.rules: 없는 규칙 {missing}")
        notify = _str_list(r.get("notify"), f"{where}.notify")
        if not notify:
            raise ConfigError(f"{where}.notify: 받는 곳이 필요합니다")
        for flag in ("continue", "replace"):
            if flag in r and not isinstance(r[flag], bool):
                raise ConfigError(f"{where}.{flag} 는 true/false")
        out.append(Route(name=name, notify=notify, groups=_str_list(match.get("group"), f"{where}.match.group"),
                         tags=tuple(" ".join(t.split()) for t in _str_list(match.get("tags"), f"{where}.match.tags")),
                         severities=severities, rules=rules, hosts=_str_list(match.get("hosts"), f"{where}.match.hosts"),
                         continue_=bool(r.get("continue", False)), replace=bool(r.get("replace", False))))
    return tuple(out)


def _check_escalations(raw: Any, rule_names: set[str]) -> tuple[Escalation, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("escalations 는 목록이어야 합니다")
    out, names = [], set()
    for i, p in enumerate(raw):
        where = f"escalations[{i}]"
        if not isinstance(p, dict) or not str(p.get("name") or "").strip():
            raise ConfigError(f"{where}: name 이 필요합니다")
        name = str(p["name"]).strip()
        if name in names:
            raise ConfigError(f"{where}: 이름이 중복됩니다 ({name})")
        names.add(name)
        severities = _str_list(p.get("severity"), f"{where}.severity")
        if bad := [s for s in severities if s not in SEVERITIES]:
            raise ConfigError(f"{where}.severity: {bad} (사용 가능: {', '.join(SEVERITIES)})")
        rules = _str_list(p.get("rules"), f"{where}.rules")
        if missing := [r for r in rules if r not in rule_names]:
            raise ConfigError(f"{where}.rules: 없는 규칙 {missing}")
        raw_steps = p.get("steps")
        if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= ESCALATE_MAX_STEPS:
            raise ConfigError(f"{where}.steps: 단계 1~{ESCALATE_MAX_STEPS}개가 필요합니다")
        steps = []
        for j, s in enumerate(raw_steps):
            sw = f"{where}.steps[{j}]"
            if not isinstance(s, dict):
                raise ConfigError(f"{sw}: 객체여야 합니다")
            after = _duration(s.get("after"), f"{sw}.after")
            if after > ESCALATE_MAX_AFTER:
                raise ConfigError(f"{sw}.after: 7일 이하")
            unless = str(s.get("unless") or "acked")
            if unless not in ESCALATE_UNLESS:
                raise ConfigError(f"{sw}.unless 는 acked(확인되면 멈춤)·resolved(해결되면 멈춤) 중 하나")
            notify = _str_list(s.get("notify"), f"{sw}.notify")
            if not notify:
                raise ConfigError(f"{sw}.notify: 받는 곳이 필요합니다")
            steps.append(EscalationStep(after=after, unless=unless, notify=notify))
        keys = [s.action for s in steps]
        if len(set(keys)) != len(keys):
            raise ConfigError(f"{where}.steps: 같은 시간·조건의 단계가 겹칩니다")
        ack_timeout = None
        if p.get("ack_timeout") is not None:
            ack_timeout = _duration(p.get("ack_timeout"), f"{where}.ack_timeout")
            if not ACK_TIMEOUT_MIN <= ack_timeout <= ACK_TIMEOUT_MAX:
                raise ConfigError(f"{where}.ack_timeout: 5분~7일")
        out.append(Escalation(name=name, steps=tuple(steps), severities=severities, rules=rules, ack_timeout=ack_timeout))
    return tuple(out)


def parse(doc: Any) -> AlertConfig:
    """YAML 을 읽은 dict → AlertConfig. 문제가 있으면 ConfigError."""
    if doc is None:
        return AlertConfig()
    if not isinstance(doc, dict):
        raise ConfigError("최상위는 settings / rules 를 가진 객체여야 합니다")
    settings = doc.get("settings") or {}
    if not isinstance(settings, dict):
        raise ConfigError("settings 는 interval_sec 등을 가진 객체여야 합니다")
    interval = settings.get("interval_sec", 30)
    if not isinstance(interval, int) or not 5 <= interval <= 3600:
        raise ConfigError("settings.interval_sec 는 5~3600 사이 정수")
    group_wait = settings.get("group_wait_sec", GROUP_WAIT_DEFAULT)
    if isinstance(group_wait, bool) or not isinstance(group_wait, int) or not 0 <= group_wait <= GROUP_WAIT_MAX:
        raise ConfigError(f"settings.group_wait_sec 는 0~{GROUP_WAIT_MAX} 사이 정수 (같은 규칙 알림을 모으는 시간)")
    group_interval = settings.get("group_interval_sec", GROUP_INTERVAL_DEFAULT)
    if isinstance(group_interval, bool) or not isinstance(group_interval, int) or not 0 <= group_interval <= GROUP_INTERVAL_MAX:
        raise ConfigError(f"settings.group_interval_sec 는 0~{GROUP_INTERVAL_MAX} 사이 정수 (0 = 묶지 않음)")

    if doc.get("notifiers"):
        raise ConfigError("notifiers 항목은 환경설정 화면(수신 그룹·외부 연동)으로 옮겨졌습니다. alerts.yaml 에서 지우세요")

    raw_rules = doc.get("rules") or []
    if not isinstance(raw_rules, list):
        raise ConfigError("rules 는 목록이어야 합니다")
    fallback = _str_list(settings.get("fallback_notify"), "settings.fallback_notify")
    rules = [_check_rule(i, r) for i, r in enumerate(raw_rules)]
    names = [r.name for r in rules]
    duplicated = {n for n in names if names.count(n) > 1}
    if duplicated:
        raise ConfigError(f"규칙 이름이 중복됩니다: {sorted(duplicated)}")
    sids = [r.sid for r in rules if r.sid is not None]
    dup_sids = {s for s in sids if sids.count(s) > 1}
    if dup_sids:
        raise ConfigError(f"규칙 번호(sid)가 중복됩니다: {sorted(dup_sids)}")
    escalations = _check_escalations(doc.get("escalations"), set(names))
    routes = _check_routes(doc.get("routes"), set(names))
    return AlertConfig(interval_sec=interval, rules=tuple(rules), fallback_notify=fallback, escalations=escalations,
                       routes=routes, group_wait_sec=group_wait, group_interval_sec=group_interval)


def parse_text(text: str) -> AlertConfig:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML 문법 오류: {exc}") from exc
    return parse(doc)


def load(path: str | Path) -> AlertConfig:
    path = Path(path)
    if not path.exists():
        return AlertConfig()
    return parse_text(path.read_text(encoding="utf-8"))
