"""조사 플레이북 (BACKLOG B-66, ISMS 2.11.4): 알림을 받은 당직이 무엇부터 볼지 — 규칙마다 질문·이유·검색 문장.

config/playbooks/<sid>.yaml (규칙 번호 — 이름을 바꿔도 이어진다):
    title: 로그온 실패 급증
    steps:
      - question: 이 PC 에서 실패 뒤 같은 계정이 성공했나?
        why: 실패 뒤 성공이면 비밀번호를 맞혔을 수 있다
        query: 'event_id:4624 host:{host} user:{user}'
        window: 24h          # 알림 시각 앞쪽 (기본 24h)
        after: 1h            # 알림 시각 뒤쪽 (기본 1h)
        top: ip              # 상위 값을 볼 필드 (선택)
    false_positive: |       # 오탐 판단 기준 (선택)
      백업·모니터링 계정이 바뀐 비밀번호로 계속 시도하는 경우

자리표시자 {host} {user} {ip} {key}(알림 대상 이름)는 알림 값으로 채우되 **검색 문장 정규형의 따옴표 규칙**(querylang.format_value)으로
감싼다 — 로그에서 온 값(사용자 이름 등)이 문장의 다른 조건이 되지 않게(문장 주입). 값이 없으면 그 질문은 건너뛴다(조건을 빼고 넓게 찾지 않는다).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from ..config import settings
from ..filters import parse_duration
from ..querylang import QueryError, format_value, parse_terms

SLOTS = ("host", "user", "ip", "key")
_SLOT = re.compile(r"\{(" + "|".join(SLOTS) + r")\}")
MAX_STEPS = 8
MAX_WINDOW = timedelta(days=30)
TOP_FIELDS = ("host", "user", "ip", "event_id", "channel", "source", "category")
SAMPLE_VALUES = {"host": "PC-01", "user": "kim", "ip": "10.0.0.1", "key": "PC-01"}   # 문장 검사용


class PlaybookError(ValueError):
    """플레이북 파일이 틀림 — 화면에는 오류로, 시험(test_shipped_playbooks)은 실패로."""


@dataclass(frozen=True)
class Step:
    question: str
    why: str
    query: str
    window: timedelta
    after: timedelta
    top: str | None


@dataclass(frozen=True)
class Playbook:
    sid: int
    title: str
    steps: tuple[Step, ...]
    false_positive: str


def directory() -> Path:
    return Path(settings.alerts_file).parent / "playbooks"


def _duration(raw: Any, default: str, where: str) -> timedelta:
    value = parse_duration(str(raw if raw is not None else default))
    if value is None or value > MAX_WINDOW:
        raise PlaybookError(f"{where}: 기간은 15m·24h·7d 처럼 30일 이하")
    return value


def fill(template: str, values: dict[str, str | None]) -> tuple[str | None, list[str]]:
    """자리표시자를 문장 정규형 값으로. 빠진 값이 있으면 (None, [빠진 이름])."""
    missing = sorted({m for m in _SLOT.findall(template) if not values.get(m)})
    if missing:
        return None, missing
    return _SLOT.sub(lambda m: format_value(values[m.group(1)]), template), []


def parse(sid: int, text: str) -> Playbook:
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise PlaybookError(f"YAML 오류: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("steps"), list) or not raw["steps"]:
        raise PlaybookError("steps 목록이 필요합니다")
    if len(raw["steps"]) > MAX_STEPS:
        raise PlaybookError(f"질문은 {MAX_STEPS}개까지")
    steps = []
    for i, s in enumerate(raw["steps"]):
        where = f"steps[{i}]"
        if not isinstance(s, dict) or not str(s.get("question") or "").strip() or not str(s.get("query") or "").strip():
            raise PlaybookError(f"{where}: question·query 가 필요합니다")
        query = str(s["query"])
        unknown = set(re.findall(r"\{(\w+)\}", query)) - set(SLOTS)
        if unknown:
            raise PlaybookError(f"{where}.query: 모르는 자리표시자 {sorted(unknown)} (쓸 수 있는 것: {', '.join(SLOTS)})")
        filled, _ = fill(query, SAMPLE_VALUES)
        try:
            parse_terms(filled or "")
        except QueryError as exc:
            raise PlaybookError(f"{where}.query: {exc}") from exc
        top = s.get("top")
        if top is not None and top not in TOP_FIELDS:
            raise PlaybookError(f"{where}.top 은 {', '.join(TOP_FIELDS)} 중 하나")
        steps.append(Step(question=str(s["question"]).strip(), why=str(s.get("why") or "").strip(), query=query,
                          window=_duration(s.get("window"), "24h", f"{where}.window"),
                          after=_duration(s.get("after"), "1h", f"{where}.after"), top=top))
    return Playbook(sid=sid, title=str(raw.get("title") or ""), steps=tuple(steps),
                    false_positive=str(raw.get("false_positive") or "").strip())


def load(sid: int | None) -> Playbook | None:
    """규칙 번호의 플레이북. 없으면 None, 틀렸으면 PlaybookError."""
    if sid is None:
        return None
    path = directory() / f"{int(sid)}.yaml"
    if not path.is_file():
        return None
    return parse(int(sid), path.read_text(encoding="utf-8"))


def values_for(alert: dict[str, Any], group_by: str | None, event: dict[str, Any] | None) -> dict[str, str | None]:
    """알림의 값: 대상 이름(key)과, 그 알림의 최근 이벤트 하나에서 PC·사용자·IP. 묶음 기준이 그 필드면 대상 이름이 정본."""
    event = event or {}
    values = {"key": alert.get("group_key") or None, "host": event.get("host"), "user": event.get("username"),
              "ip": event.get("src_ip")}
    if group_by in ("host", "user", "ip") and alert.get("group_key"):
        values[group_by] = alert["group_key"]
    return values
