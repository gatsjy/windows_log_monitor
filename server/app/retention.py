"""이벤트 보관 등급 (BACKLOG B-70, ISMS 2.9.4, ADR-061) — config/retention.yaml.

로그 보관기간(WLM_RETENTION_DAYS)은 하나라, 민감정보 처리 시스템의 접속기록을 2년 두려면 IIS·상세 로그까지 2년이 됐다. 등급은 검색 문장으로
고른 로그의 보관 파일 기간만 따로 정한다:

- 나누는 때는 **보관 파일을 만들 때**(DB 보관기간이 지난 달). DB 에서는 월 파티션째 지우므로(행을 고치지 않는다 — 다이제스트) DB 기간은 그대로다.
- 한 로그가 여러 등급에 맞으면 **가장 긴 쪽** — 접속기록이 '웹 요청 90일' 등급에도 맞아 짧아지는 일이 없게. 어느 등급에도 안 맞으면 기본(WLM_RETENTION_DAYS).
- 등급 파일은 `events_2026_10.<등급>.jsonl.gz`. 만료 = 그 달 끝 + max(만들 때 기간, 지금 설정의 같은 등급 기간) — 설정을 늘리면 이미 만든 파일도
  늘어나고, 줄여도 만들 때 약속한 기간보다 일찍 지우지 않는다. 기본 파일(등급 없음)은 지금처럼 WLM_RETENTION_DAYS 로.
- 설정 파일이 틀리면 보관·삭제를 멈춘다(로그는 DB 에 그대로) — 틀린 설정으로 접속기록을 짧은 등급에 넣거나 일찍 지우지 않게. 화면·준비도가 알린다.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .config import settings
from .filters import EventFilter, parse_query
from .querylang import QueryError

log = logging.getLogger(__name__)

TIER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")   # 파일 이름에 들어간다 (backup.sh 도 이 모양만 받는다)
MAX_TIERS = 10
MIN_KEEP_DAYS, MAX_KEEP_DAYS = 1, 3650


@dataclass(frozen=True)
class Tier:
    id: str
    name: str
    query: str
    keep_days: int
    filter: EventFilter

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "query": self.query, "keep_days": self.keep_days}


@dataclass(frozen=True)
class Config:
    tiers: tuple[Tier, ...] = ()
    error: str | None = None
    exists: bool = False

    def tier(self, tier_id: str | None) -> Tier | None:
        return next((t for t in self.tiers if t.id == tier_id), None)

    def max_keep_days(self) -> int:
        """보관 파일이 가장 오래 남는 기간 — 이보다 오래된 달은 파일 없이 지운다."""
        return max([settings.retention_days, *(t.keep_days for t in self.tiers)])


def parse(text: str) -> Config:
    """YAML → 등급. 틀리면 Config(error=…) — 어느 줄이 왜 틀렸는지."""
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return Config(error=f"YAML 문법 오류: {exc}", exists=True)
    if not isinstance(doc, dict) or not isinstance(doc.get("tiers") or [], list):
        return Config(error="tiers: 목록이 필요합니다", exists=True)
    raw = doc.get("tiers") or []
    if len(raw) > MAX_TIERS:
        return Config(error=f"등급은 {MAX_TIERS}개까지", exists=True)
    tiers, seen = [], set()
    for i, t in enumerate(raw):
        where = f"tiers[{i}]"
        if not isinstance(t, dict):
            return Config(error=f"{where}: id·name·query·keep_days 를 가진 항목이어야 합니다", exists=True)
        tid, query, keep = t.get("id"), t.get("query"), t.get("keep_days")
        if not isinstance(tid, str) or not TIER_ID_RE.match(tid):
            return Config(error=f"{where}.id 는 영문 소문자로 시작하는 32자 이내(소문자·숫자·-) — 보관 파일 이름에 들어갑니다", exists=True)
        if tid in seen:
            return Config(error=f"{where}.id 가 겹칩니다 ({tid})", exists=True)
        seen.add(tid)
        if not isinstance(query, str) or not query.strip():
            return Config(error=f"{where}.query 에 검색 문장이 필요합니다 (모든 로그를 고르는 등급은 WLM_RETENTION_DAYS 로)", exists=True)
        if isinstance(keep, bool) or not isinstance(keep, int) or not MIN_KEEP_DAYS <= keep <= MAX_KEEP_DAYS:
            return Config(error=f"{where}.keep_days 는 {MIN_KEEP_DAYS}~{MAX_KEEP_DAYS} 일", exists=True)
        try:
            flt = parse_query(query)
        except QueryError as exc:
            return Config(error=f"{where}.query: {exc}", exists=True)
        name = t.get("name")
        tiers.append(Tier(tid, name.strip() if isinstance(name, str) and name.strip() else tid, query.strip(), keep, flt))
    return Config(tuple(tiers), exists=True)


def load() -> Config:
    """파일이 없으면 등급 없음(지금까지와 같음). 읽을 때마다 새로 — 한 시간에 한 번 정리할 때만 부른다."""
    path = Path(settings.retention_config)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Config()
    except OSError as exc:
        return Config(error=f"{path.name} 을(를) 읽을 수 없습니다: {exc}", exists=True)
    config = parse(text)
    if config.error:
        log.error("보관 등급 설정 오류 (%s) — 보관 파일 만들기·삭제를 멈춥니다: %s", path, config.error)
    return config


def classify(tiers: tuple[Tier, ...], event: dict[str, Any]) -> Tier | None:
    """맞는 등급 중 가장 긴 것 (같으면 앞의 것). 없으면 None = 기본."""
    best = None
    for t in tiers:
        if (best is None or t.keep_days > best.keep_days) and t.filter.matches(event):
            best = t
    return best


def keep_days(meta: dict[str, Any], config: Config) -> int:
    """보관 파일(메타) 하나의 보관기간. 등급 파일은 만들 때 기간과 지금 설정 중 긴 쪽, 기본 파일은 WLM_RETENTION_DAYS."""
    if not meta.get("tier"):
        return settings.retention_days
    current = config.tier(meta["tier"])
    return max(int(meta.get("keep_days") or 0), current.keep_days if current else 0) or settings.retention_days


def expires_at(meta: dict[str, Any], config: Config) -> datetime:
    return datetime.fromisoformat(meta["to"]) + timedelta(days=keep_days(meta, config))


def notes(config: Config) -> list[str]:
    """화면 안내 — 판정이 아니라 사이트가 확인할 것 (어떤 로그가 접속기록인지는 사이트가 정한다)."""
    out = []
    for t in config.tiers:
        if t.keep_days < settings.db_retention_days:
            out.append(f"등급 '{t.name}' {t.keep_days}일 — DB 보관기간({settings.db_retention_days}일)보다 짧아 보관 파일을 만들지 않고 "
                       "DB 에서 지울 때 함께 사라집니다")
        elif t.keep_days < 365:
            out.append(f"등급 '{t.name}' {t.keep_days}일 — 접속기록(법정 최소 1년)이 이 등급에 들어가지 않는지 확인하세요")
    return out
