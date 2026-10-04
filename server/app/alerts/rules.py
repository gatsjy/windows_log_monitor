"""알림 규칙 파일(config/alerts.yaml) 읽기와 검증.

형식은 docs/PROJECT.md '알림' 절과 config/alerts.yaml 의 주석 참고.
알림 대상(수신 그룹·외부 연동)은 파일이 아니라 환경설정 화면(DB)에서 관리한다 → app/alerts/targets.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from ..filters import EventFilter, FilterError, parse_duration
from ..repository import COLUMN_EXPR

SEVERITIES = ("critical", "error", "warning", "info")
RULE_KINDS = ("count", "agent_silent")
MATCH_KEYS = {"host", "channel", "provider", "source", "category", "user", "ip", "level", "event_id", "q"}


class ConfigError(ValueError):
    """설정 파일 오류 (화면에 그대로 보여준다)."""


@dataclass(frozen=True)
class Rule:
    name: str
    kind: str                       # count: 이벤트 수 기준 | agent_silent: PC 수신 끊김
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
    tags: tuple[str, ...] = ()   # 예: "MITRE T1110", "ISMS 2.11.3" (화면·알림 본문에 표시)
    sid: int | None = None       # 규칙 번호 (Snort 의 sid 처럼 고유). 화면에서 만들면 자동 부여
    group: str = "기타"          # 규칙 묶음 (화면 왼쪽 목록, 묶음 단위로 켜고 끄기)

    def event_filter(self) -> EventFilter:
        return EventFilter.from_params(self.match, default_since=None)


@dataclass(frozen=True)
class AlertConfig:
    interval_sec: int = 30
    rules: tuple[Rule, ...] = ()

    def used_targets(self) -> dict[str, list[str]]:
        """알림 대상 이름 → 그 대상을 쓰는 규칙 이름들 (대상 삭제·이름 변경 막을 때 사용)."""
        used: dict[str, list[str]] = {}
        for rule in self.rules:
            for name in rule.notify:
                used.setdefault(name, []).append(rule.name)
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
    return tuple(str(v) for v in value)


def _check_rule(index: int, raw: Any) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"rules[{index}]: 객체여야 합니다")
    name = str(raw.get("name") or "").strip()
    where = f"rules[{index}] ({name or '이름 없음'})"
    if not name:
        raise ConfigError(f"{where}.name 이 필요합니다")
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
        "tags": _str_list(raw.get("tags"), f"{where}.tags"),
        "sid": sid, "group": str(raw.get("group") or "기타").strip() or "기타",
    }

    if kind == "agent_silent":
        return Rule(**common, silent_for=_duration(raw.get("silent_for", "10m"), f"{where}.silent_for"),
                    hosts=_str_list(raw.get("hosts"), f"{where}.hosts"), group_by="host")

    match = raw.get("match") or {}
    if not isinstance(match, dict):
        raise ConfigError(f"{where}.match 는 객체여야 합니다")
    match = {str(k): ",".join(map(str, v)) if isinstance(v, list) else str(v) for k, v in match.items()}
    bad = [k for k in match if k not in MATCH_KEYS and not k.startswith("f.")]
    if bad:
        raise ConfigError(f"{where}.match: 알 수 없는 조건 {bad} (사용 가능: {sorted(MATCH_KEYS)}, f.<경로>)")
    try:
        EventFilter.from_params(match, default_since=None)
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
    return Rule(**common, match=match, window=window, threshold=threshold, group_by=group_by, cooldown=cooldown)


def parse(doc: Any) -> AlertConfig:
    """YAML 을 읽은 dict → AlertConfig. 문제가 있으면 ConfigError."""
    if doc is None:
        return AlertConfig()
    if not isinstance(doc, dict):
        raise ConfigError("최상위는 settings / rules 를 가진 객체여야 합니다")
    settings = doc.get("settings") or {}
    interval = settings.get("interval_sec", 30)
    if not isinstance(interval, int) or not 5 <= interval <= 3600:
        raise ConfigError("settings.interval_sec 는 5~3600 사이 정수")

    if doc.get("notifiers"):
        raise ConfigError("notifiers 항목은 환경설정 화면(수신 그룹·외부 연동)으로 옮겨졌습니다. alerts.yaml 에서 지우세요")

    raw_rules = doc.get("rules") or []
    if not isinstance(raw_rules, list):
        raise ConfigError("rules 는 목록이어야 합니다")
    rules = [_check_rule(i, r) for i, r in enumerate(raw_rules)]
    names = [r.name for r in rules]
    duplicated = {n for n in names if names.count(n) > 1}
    if duplicated:
        raise ConfigError(f"규칙 이름이 중복됩니다: {sorted(duplicated)}")
    sids = [r.sid for r in rules if r.sid is not None]
    dup_sids = {s for s in sids if sids.count(s) > 1}
    if dup_sids:
        raise ConfigError(f"규칙 번호(sid)가 중복됩니다: {sorted(dup_sids)}")
    return AlertConfig(interval_sec=interval, rules=tuple(rules))


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
