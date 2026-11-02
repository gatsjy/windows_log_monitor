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
from .querylang import QueryError, fold

log = logging.getLogger(__name__)

TIER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")   # 파일 이름에 들어간다 (backup.sh 도 이 모양만 받는다)
MAX_TIERS = 10
MIN_KEEP_DAYS, MAX_KEEP_DAYS = 1, 3650
TIER_KEYS = {"id", "name", "query", "keep_days"}


class _UniqueKeys(yaml.SafeLoader):
    """같은 키가 두 번이면 오류 — safe_load 는 뒤의 값을 조용히 쓴다. 기본 파일의 예시 주석을 풀고 'tiers: []' 를 남기면 등급이 0개가 되어
    접속기록이 기본 기간에 지워졌다(검토에서 재현)."""


def _mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(None, None, f"같은 키가 두 번 있습니다: {key}", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeys.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True)
class Tier:
    id: str
    name: str
    query: str
    keep_days: int
    filter: EventFilter

    @property
    def uses_message(self) -> bool:
        return bool(self.filter.q_terms or self.filter.msg_all or self.filter.msg_not)

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
        doc = yaml.load(text, Loader=_UniqueKeys) or {}   # SafeLoader 를 이어받은 것 (같은 키만 더 막음)
    except (yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:   # 2026-02-30 같은 날짜 값·깊은 중첩도 (서버 기동이 멈췄다)
        return Config(error=f"YAML 오류: {exc}", exists=True)
    if not isinstance(doc, dict) or not isinstance(doc.get("tiers") or [], list):
        return Config(error="tiers: 목록이 필요합니다", exists=True)
    if extra := sorted(str(k) for k in doc if k != "tiers"):
        return Config(error=f"알 수 없는 키: {', '.join(extra)} (tiers 만 씁니다)", exists=True)
    raw = doc.get("tiers") or []
    if len(raw) > MAX_TIERS:
        return Config(error=f"등급은 {MAX_TIERS}개까지", exists=True)
    tiers, seen = [], set()
    for i, t in enumerate(raw):
        where = f"tiers[{i}]"
        if not isinstance(t, dict):
            return Config(error=f"{where}: id·name·query·keep_days 를 가진 항목이어야 합니다", exists=True)
        if extra := sorted(str(k) for k in t if k not in TIER_KEYS):
            return Config(error=f"{where}: 알 수 없는 키 {', '.join(extra)} (id·name·query·keep_days 만)", exists=True)
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
        if flt.never:
            return Config(error=f"{where}.query: 어떤 로그에도 맞을 수 없는 문장입니다 (같은 키에 서로 다른 값)", exists=True)
        name = t.get("name")
        tiers.append(Tier(tid, name.strip() if isinstance(name, str) and name.strip() else tid, query.strip(), keep, flt))
    return Config(tuple(tiers), exists=True)


def load() -> Config:
    """파일이 없으면 등급 없음(지금까지와 같음). 읽을 때마다 새로 — 한 시간에 한 번 정리할 때만 부른다."""
    path = Path(settings.retention_config)
    try:
        text = path.read_text(encoding="utf-8-sig")   # BOM 붙은 UTF-8 도
    except FileNotFoundError:
        return Config()
    except (OSError, UnicodeError) as exc:   # 한글 메모장 ANSI(CP949)로 저장하면 UnicodeDecodeError 로 서버 기동이 멈췄다
        return Config(error=f"{path.name} 을(를) 읽을 수 없습니다 (UTF-8 로 저장하세요): {exc}", exists=True)
    config = parse(text)
    if config.error:
        log.error("보관 등급 설정 오류 (%s) — 보관 파일 만들기·삭제를 멈춥니다: %s", path, config.error)
    return config


def classify(tiers: tuple[Tier, ...], event: dict[str, Any]) -> Tier | None:
    """맞는 등급 중 가장 긴 것 (같으면 앞의 것). 없으면 None = 기본. 메시지 접기는 한 번만 — 등급마다 접으면 한 달 보관이 몇 시간 늘었다."""
    best = None
    folded = fold(event.get("message") or "") if any(t.uses_message for t in tiers) else None
    for t in tiers:
        if (best is None or t.keep_days > best.keep_days) and t.filter.matches(event, folded):
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


def sensitive_tier(config: Config) -> Tier | None:
    """민감정보 처리 시스템의 접속기록(2년)을 맡는 등급 — 있으면 WLM_RETENTION_DAYS 가 2년보다 짧아도 법정 미달로 보지 않는다."""
    from .partitions import LEGAL_SENSITIVE_LOG_DAYS

    return next((t for t in config.tiers if t.keep_days >= LEGAL_SENSITIVE_LOG_DAYS), None)


def notes(config: Config) -> list[str]:
    """화면 안내 — 판정이 아니라 사이트가 확인할 것 (어떤 로그가 접속기록인지는 사이트가 정한다)."""
    out = []
    if settings.sensitive_access_log and settings.retention_days < 730 and (t := sensitive_tier(config)):
        out.append(f"민감정보 처리 시스템의 접속기록은 등급 '{t.name}'({t.keep_days}일)이 맡습니다 — 그 시스템의 로그가 이 등급 문장에 모두 맞는지 확인하세요")
    for t in config.tiers:
        if t.keep_days < settings.db_retention_days:
            out.append(f"등급 '{t.name}' {t.keep_days}일 — DB 보관기간({settings.db_retention_days}일)보다 짧아 보관 파일을 만들지 않고 "
                       "DB 에서 지울 때 함께 사라집니다")
        elif t.keep_days < 365:
            out.append(f"등급 '{t.name}' {t.keep_days}일 — 접속기록(법정 최소 1년)이 이 등급에 들어가지 않는지 확인하세요")
    return out
