"""알림 엔진: interval_sec 마다 규칙을 평가 → 알림 기록. 보내기와 재시도는 전송기(dispatcher.py)가 한다 (ADR-045).

- 규칙 파일(config/alerts.yaml)이 바뀌면 다음 주기에 자동으로 다시 읽는다 (재시작 불필요).
- 규칙마다 쿼리 시간 상한(WLM_ALERT_RULE_TIMEOUT_SEC) — 넘기거나 실패하면 그 규칙만 '시간 초과·오류'로 남기고 다음 규칙으로.
  규칙마다 마지막 평가(RuleRun)를 기억해 화면·/healthz/alerts·점검 보고서가 '평가가 멈춤·느림·일부만'을 보인다(health.py).
  잘못된 파일이면 이전 설정을 유지하고 오류를 화면에 보여준다.
- 같은 규칙·같은 대상(PC)은 cooldown 동안 다시 알리지 않는다.
- 무음(alert_silences) 중이면 알림은 기록하되 보내지 않는다. 무음이 끝난 뒤에도 이벤트가 새로 들어오면
  cooldown 과 상관없이 다음 평가에서 다시 알린다 (무음 중에 쌓인 이벤트만으로는 다시 울리지 않는다).
- 여러 서버 인스턴스가 떠 있어도 PostgreSQL advisory lock 으로 한 곳에서만 평가한다.
- 적용한 설정은 판본(alert_config_versions)으로 남기고, 탐지를 약하게 하는 변경이면 바뀌기 전 받는 곳으로 알린다
  (ADR-043). 서버가 시작될 때 파일이 깨져 있으면 마지막 판본으로 감시를 계속한다.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .. import db, repository
from ..config import settings
from ..filters import EventFilter
from . import configdiff
from .builtin import CONFIG_RULE
from .dispatcher import dispatcher
from .message import AlertMessage, _window_text, local, search_link
from .rules import AlertConfig, ConfigError, Rule, parse_text

log = logging.getLogger(__name__)

_LOCK_ID = 727_003
SAMPLE_COUNT = 5
CANDIDATE_LIMIT = 100   # 한 번에 알리는 묶음 상한 — 넘으면 규칙에 '일부만' 표시 (ADR-045)
# 자동 해결 (B-35 2단계): 마지막 알림 뒤 적어도 이만큼(그리고 집계 기간) 지나야 본다 — 조건이 잠깐 풀렸다 다시 맞는
# 경계에서 알림·해소가 번갈아 쏟아지지 않게. 한 주기에 보는 대상 수 상한(오래된 것부터, 넘은 것은 다음 주기에)
AUTO_RESOLVE_HOLD = timedelta(minutes=5)
AUTO_RESOLVE_LIMIT = 200
# 이보다 오래된 알림은 해소 통지 없이 해결만 — 이 기능을 켠 뒤 처음 돌 때 몇 달 묵은 끊김 알림이 '해소'로 쏟아지지 않게
RECOVERY_NOTICE_MAX_AGE = timedelta(days=7)
_UNREAD = object()   # 아직 한 번도 읽지 않음 (파일이 없을 때의 서명 None 과 구별 — 시작 때 없는 파일도 읽은 것으로 쳐야 한다)
HISTORY_VERSIONS = 200   # 다시 켠 규칙을 비교하려고 거슬러 보는 판본 수
SOURCE_LABELS = {"ui": "화면에서 저장", "file": "서버에서 파일 직접 수정", "startup": "서버 시작 때 발견(꺼져 있는 동안 수정)"}


def _with_group(f: EventFilter, group_by: str, key: str) -> EventFilter:
    """묶음 값(예: PC 이름)을 필터에 더한다 → 그 묶음의 이벤트만."""
    if group_by == "none":
        return f
    if group_by.startswith("f."):
        path = [p for p in group_by[2:].split(".") if p]
        return replace(f, fields=[*f.fields, (path, key)])
    if group_by in ("level", "event_id"):
        if not key.lstrip("-").isdigit():
            return f
        attr = "levels" if group_by == "level" else "event_ids"
        return replace(f, **{attr: [int(key)]})
    attr = {"host": "hosts", "channel": "channels", "provider": "providers", "source": "sources",
            "category": "categories", "user": "users", "ip": "ips"}[group_by]
    return replace(f, **{attr: [key]})


def _silence_over(last: dict, now: datetime) -> bool:
    """마지막 알림이 무음 때문에 전송되지 않았고, 그 무음이 이제 끝났는가."""
    return last["silenced_until"] is not None and last["silenced_until"] <= now


def _in_cooldown(last: dict | None, now: datetime, cooldown: timedelta) -> bool:
    """재알림 간격 안인가. 무음으로 못 보낸 알림은 무음이 끝나면 간격을 기다리지 않는다
    (점검이 끝났는데도 문제가 계속되면 바로 알아야 하므로)."""
    if last is None or _silence_over(last, now):
        return False
    return now - last["fired_at"] < cooldown


async def _resumed(base: EventFilter, rule: Rule, key: str, last: dict, since: datetime) -> bool:
    """무음이 끝난 뒤에 이 묶음의 이벤트가 새로 들어왔는가 (문제가 계속되는가)."""
    return await _received_after(base, rule, key, max(since, last["silenced_until"]))


async def _received_after(base: EventFilter, rule: Rule, key: str, after: datetime) -> bool:
    return (await repository.count(_with_group(replace(base, received_since=after), rule.group_by, key)))["current"] > 0


def _recurred(last: dict | None) -> bool:
    """해결된 알림이 마지막이다 — 해결한 뒤 새 이벤트가 있으면 재알림 간격과 상관없이 다시 알린다 (B-35)."""
    return last is not None and last.get("status") == "resolved" and last.get("resolved_at") is not None


SINCE_PREVIOUS_MAX = timedelta(days=7)   # '지난 알림 이후 n건'을 셀 때 거슬러 보는 한도 (오래전 알림이면 세지 않는다)


def _link_params(rule: Rule, key: str, since: datetime) -> dict[str, str]:
    params = {"since": since.isoformat(), **rule.match}
    if rule.group_by != "none" and key:
        params[rule.group_by] = key
    return params


class AlertEngine:
    def __init__(self, path: str | None = None):
        self.path = Path(path or settings.alerts_file)
        self.config = AlertConfig()
        self.config_error: str | None = None
        self.last_run_at: datetime | None = None
        self.last_error: str | None = None
        # 평가 상태 (ADR-045): 나아간 시각(규칙·묶음마다 갱신), 한 바퀴 시간, 평가 중인 규칙, 규칙마다의 마지막 평가
        self.progress_at: datetime | None = None
        self.cycle_sec: float | None = None
        self.current_rule: str | None = None
        self.standby = False
        self.runs: dict[str, RuleRun] = {}
        self.sleep_interval: int | None = None   # 지금 쉬는 주기 (설정을 바꾼 직후에는 새 주기와 다를 수 있다)
        self.task: asyncio.Task | None = None   # main 이 넣는다 (상태 판단: 작업이 살아 있나)
        self._sig: object = _UNREAD
        # 판본 기록 (ADR-043). _applied = 마지막으로 기록한 판본 {id, sha, config, text} — None 이면 아직 DB 에서 읽지 않음
        self._applied: dict[str, Any] | None = None
        self._first = True                             # 시작한 뒤 첫 비교 (판본과 다르면 꺼져 있는 동안 바뀐 것)
        self._read: dict[str, Any] | None = None       # 파일에서 마지막으로 읽은 것 — 아직 판본과 비교하지 않음 (가장 새것만)
        self._invalid_done: dict[str, set[str]] = {}   # 깨진 내용(sha) → 끝낸 일(audit·notify) — 같은 내용은 한 번만
        self._loaded = False                           # 이번 실행에서 파일을 제대로 읽었나 (아니면 마지막 판본으로)
        self.fallback_version: int | None = None       # 마지막 판본으로 감시 중이면 그 번호 (화면의 규칙 편집을 막는다)
        self._owed: list[dict[str, Any]] = []          # 판본은 남겼지만 감사로그·알림을 아직 못 한 것 (다음에 다시)
        self._parsed: dict[int, AlertConfig | None] = {}  # 예전 판본 읽은 것 (다시 켠 규칙을 비교할 때)
        self._lock: tuple[Any, asyncio.Lock] | None = None
        self._fell_back = False

    # ------------------------------------------------------------ 설정
    def _signature(self) -> tuple | None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return None
        # 수정 시각만 보면 'touch -r' 로 시각을 되돌린 수정을 놓친다 — 되돌릴 수 없는 ctime·크기·inode 도 본다
        return (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)

    def reload(self, force: bool = False, *, source: str = "file", actor: str = "system") -> None:
        """파일이 바뀌었으면 다시 읽어 적용한다. 기록(판본·감사로그·알림)은 record() 가 한다 — 여기는 동기라서.
        source·actor 는 화면 저장(_store)이 넘긴다. 그 밖의 변경은 서버에서 파일을 직접 고친 것.
        깨졌거나 없어진 파일은 적용하지 않는다(이전 설정 유지). 무엇이 실패하든 깨진 파일로 다룬다 — 예외가 새면
        시각만 바뀐 채 다시 읽지 않아 오류도 기록도 없이 옛 설정으로 돌았다(검토에서 재현)."""
        sig = self._signature()
        if not force and sig == self._sig:
            return
        self._sig = sig
        data: bytes | None = None
        config, error, text = None, None, ""
        try:
            data = self.path.read_bytes()
            text = data.decode("utf-8")
            config = parse_text(text) if text.strip() else AlertConfig()
        except FileNotFoundError:
            error = "설정 파일이 없습니다"
        except UnicodeDecodeError:
            error = "UTF-8 로 저장된 파일이 아닙니다 (메모장이면 '다른 이름으로 저장'에서 인코딩을 UTF-8 로)"
        except ConfigError as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001 - 검증이 예상하지 못한 모양·읽기 오류도 깨진 파일
            error = f"설정을 읽을 수 없습니다 ({type(exc).__name__}: {exc})"
        self._read = {"sha": hashlib.sha256(data or b"").hexdigest(), "text": text, "config": config, "error": error,
                      "missing": data is None, "source": source, "actor": actor}
        if config is not None:
            self.config, self.config_error, self._loaded, self.fallback_version = config, None, True, None
            log.info("알림 규칙 적용: %d개", len(config.rules))
        elif self._loaded:
            self.config_error = f"{error} — 이전 설정으로 감시를 계속합니다. 파일을 고치면 바로 반영됩니다"
            log.error("알림 설정 오류 (이전 설정 유지): %s", error)
        # 시작할 때 깨졌거나 없으면: record() 가 마지막 판본으로 (처음 설치라 판본이 없으면 규칙 0개)

    def _record_lock(self) -> asyncio.Lock:
        # 판본 비교·기록은 하나씩 — 기록하는 사이 다른 저장이 끼면 옛 판본과 비교하게 된다(검토에서 재현).
        # 이벤트 루프마다 새로 (시험은 TestClient 마다 루프가 다르다, db._search_slots 와 같은 이유)
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock[0] is not loop:
            self._lock = (loop, asyncio.Lock())
        return self._lock[1]

    async def record(self) -> None:
        """적용한 설정을 판본으로 남기고(감사로그 alerts.config.apply), 탐지가 약해졌으면 알린다.
        처음 부르면 DB 의 마지막 판본을 기준으로 삼는다 — 서버가 꺼져 있는 동안 고친 것도 여기서 드러난다."""
        async with self._record_lock():
            if self._applied is None:
                latest = await repository.latest_alert_config_version()
                self._applied = ({"id": latest["id"], "sha": latest["sha256"], "config": _parse_or_none(latest["yaml"]),
                                  "text": latest["yaml"], "at": latest["applied_at"]} if latest
                                 else {"id": None, "sha": None, "config": None, "text": ""})
            await self._send_owed()
            original = read = self._read
            if read is None:
                return
            if read["config"] is None and read["missing"] and not self._applied["text"].strip():
                read = {**read, "config": AlertConfig(), "error": None}   # 처음 설치 — 파일이 없으면 규칙 0개
            if read["config"] is None:
                if not self._loaded and not self._fell_back:
                    self._fall_back(read["error"])
                await self._record_invalid(read)
                self._first = False   # 시작 때의 모습은 기록했다 — 그 뒤에 고친 것은 실행 중 수정
                return
            await self._record_version(read)
            if self._read is original:   # 기록하는 사이 새로 읽은 것이 있으면 다음에 그것을
                self._read = None

    async def _record_version(self, read: dict[str, Any]) -> None:
        applied = self._applied
        if read["sha"] == applied["sha"]:
            self._first = False
            return
        source = "startup" if self._first and read["source"] == "file" else read["source"]
        old, new = applied["config"], read["config"]
        last_enabled = await self._last_enabled(old, new) if applied["sha"] else {}
        changes = configdiff.diff(old, new, last_enabled) if applied["sha"] else []   # 판본이 없으면 기준 판본
        await self._flag_silenced_names(changes)
        weakened = any(c["weakens"] for c in changes)
        version = await repository.insert_alert_config_version(source, read["actor"], read["sha"], read["text"],
                                                               changes, weakened)
        self._applied = {"id": version, "sha": read["sha"], "config": new, "text": read["text"]}
        self._first = False
        rules = configdiff.affected(old, new, changes, last_enabled) if weakened else []
        self._owed.append({"version": version, "source": source, "actor": read["actor"], "sha": read["sha"],
                           "previous": applied["sha"], "rules_n": len(new.rules), "changes": changes,
                           "weakened": weakened, "rules": rules, "done": set()})
        await self._send_owed()

    async def _send_owed(self) -> None:
        """판본마다 감사로그와 (약해졌으면) 알림. 실패하면 남겨 두고 다음에 다시 — 판본만 남고 알림이 사라지지 않게."""
        while self._owed:
            item = self._owed[0]
            if "audit" not in item["done"]:
                await db.audit(item["actor"], "alerts.config.apply", self.path.name,
                               {"version": item["version"], "source": item["source"], "sha256": item["sha"],
                                "previous_sha256": item["previous"], "rules": item["rules_n"],
                                "weakened": item["weakened"], "changes": [c["text"] for c in item["changes"]][:100]})
                item["done"].add("audit")
            if item["weakened"] and "notify" not in item["done"]:
                weak = [c for c in item["changes"] if c["weakens"]]
                who = SOURCE_LABELS[item["source"]] + (f" · {item['actor']}" if item["source"] == "ui" else "")
                await self.notify_change(
                    f"탐지를 약하게 하는 알림 설정 변경 {len(weak):,}건 ({who}, 판본 #{item['version']})",
                    [c["text"] for c in weak], item["rules"], who)
                item["done"].add("notify")
            self._owed.pop(0)

    async def _last_enabled(self, old: AlertConfig | None, new: AlertConfig) -> dict[str, tuple[Rule, int]]:
        """다시 켜거나 다시 추가한 규칙이 마지막으로 켜져 있던 판본의 모양 (끄고 → 고치고 → 켜는 우회를 막는다)."""
        wanted = configdiff.needs_history(old, new)
        if not wanted:
            return {}
        found: dict[str, tuple[Rule, int]] = {}
        for row in await repository.alert_config_history(HISTORY_VERSIONS):
            if row["id"] not in self._parsed:
                if len(self._parsed) > 2 * HISTORY_VERSIONS:
                    self._parsed.clear()
                self._parsed[row["id"]] = _parse_or_none(row["yaml"])
            for rule in (self._parsed[row["id"]] or AlertConfig()).rules:
                key = configdiff.rule_key(rule)
                if key in wanted and key not in found and rule.enabled:
                    found[key] = (rule, row["id"])
            if len(found) == len(wanted):
                break
        return found

    async def _flag_silenced_names(self, changes: list[dict]) -> None:
        """무음·재알림 간격은 규칙 이름이 열쇠다 — 무음이 걸린 이름으로 바꾸면(또는 그 이름으로 추가하면) 그 무음이
        이 규칙에 걸린다(검토에서 재현). 그 이름 바꾸기는 약해진 것으로 본다."""
        names = {c["rule"] for c in changes if c["change"] in ("renamed", "added")}
        if not names:
            return
        silenced = await repository.silenced_rule_names(datetime.now(UTC), sorted(names))
        for c in changes:
            if c["change"] in ("renamed", "added") and c["rule"] in silenced:
                c["weakens"] = True
                c["text"] += " — 이 이름에 걸린 무음이 이 규칙에 적용됩니다"

    def unrecorded_file_change(self) -> bool:
        """서버에서 고친 내용을 읽었는데 아직 판본으로 남기지 못했나 (화면 저장이 그것을 덮어 이름을 뒤집어쓰지 않게)."""
        read = self._read
        return (read is not None and read["source"] != "ui" and read["config"] is not None
                and (self._applied is None or read["sha"] != self._applied["sha"]))

    def forget(self) -> None:
        """시험용: 서버를 다시 시작한 것처럼 설정·판본 기억을 지운다 (forget_iis_layouts 와 같은 뜻)."""
        self.config, self.config_error, self.fallback_version = AlertConfig(), None, None
        self._sig, self._applied, self._read = _UNREAD, None, None
        self._first, self._loaded, self._fell_back = True, False, False
        self._invalid_done, self._owed, self._parsed = {}, [], {}

    def _fall_back(self, error: str | None) -> None:
        """서버가 시작될 때 파일이 깨졌거나 없었다 → 규칙 0개로 돌지 않고 마지막 판본으로 감시한다."""
        self._fell_back = True
        applied = self._applied
        if applied["config"] is None:
            self.config_error = (f"{error} — 마지막 판본도 읽을 수 없어 규칙 없이 돌고 있습니다. "
                                 "'고급 편집'에서 설정 전체를 저장하세요")
            log.error("알림 설정 파일 오류 — 마지막 판본도 읽을 수 없음")
            return
        self.config, self.fallback_version = applied["config"], applied["id"]
        self.config_error = (f"{error} — 마지막으로 적용한 판본 #{applied['id']}({local(applied.get('at'))})으로 "
                             "감시를 계속합니다. 파일을 고치거나 '고급 편집'에서 설정 전체를 저장하면 바로 반영됩니다")
        log.error("알림 설정 파일 오류 — 마지막 판본 #%s 로 감시 계속", applied["id"])

    async def _record_invalid(self, read: dict[str, Any]) -> None:
        done = self._invalid_done.setdefault(read["sha"], set())
        if "audit" not in done:
            await db.audit("system", "alerts.config.invalid", self.path.name,
                           {"sha256": read["sha"], "error": read["error"][:1000], "missing": read["missing"]})
            done.add("audit")
        if "notify" not in done:
            rules = [r for r in self.config.rules if r.enabled] or [
                r for r in (self._applied["config"] or AlertConfig()).rules if r.enabled]
            await self.notify_change(
                "알림 설정 파일 오류 — 고치기 전까지 파일의 변경이 반영되지 않습니다",
                [read["error"][:500], "지금은 이전 설정(또는 마지막 판본)으로 감시하고 있습니다"], rules, SOURCE_LABELS["file"])
            done.add("notify")

    async def notify_change(self, summary: str, lines: list[str], rules: list[Rule], who: str) -> int:
        """설정 변경·넓은 무음 알림. 받는 곳 = 그 규칙들의 알림을 받던 곳(바뀌기 전 설정) — 바꾼 사람이 받는 곳도
        같이 지울 수 있으니. 걸린 규칙이 없으면(규칙 0개) 받는 곳 없이 이력에만 남는다."""
        shown = lines[:30] + ([f"… 외 {len(lines) - 30:,}건"] if len(lines) > 30 else [])
        message = AlertMessage(
            rule=CONFIG_RULE, severity=configdiff.severity(rules), kind="config", group_by="none", group_key=who,
            event_count=len(lines), threshold=0, window_sec=0, fired_at=datetime.now(UTC),
            description=summary + "\n" + "\n".join(f"- {line}" for line in shown),
            link=f"{settings.public_url}/#/alerts",   # 감사로그 화면은 audit.view 가 있어야 열린다 — 받는 사람 누구나 열 곳으로
        )
        return await self.fire(message, configdiff.recipients(rules))

    # ------------------------------------------------------------ 루프
    async def run_forever(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            started = loop.time()
            try:
                await self.tick()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
                log.exception("알림 평가 실패")
            # 시작 시각 기준으로 다음 주기 — 오래 걸린 주기 뒤에 주기 하나를 통째로 더 쉬어 공백이 커지지 않게 (ADR-045).
            # 쉬는 동안 주기를 줄여도 상태 판단이 '멈춤'으로 보지 않게 실제로 쉬는 주기를 남긴다
            self.sleep_interval = self.config.interval_sec
            await asyncio.sleep(max(1.0, started + self.sleep_interval - loop.time()))

    async def tick(self) -> None:
        # 나아간 시각은 잠금을 잡은 뒤부터 — 매 주기 설정 읽기·연결에서 실패하는데도 '움직이는 중'으로 보이던 것(검토에서 재현)
        started = time.monotonic()
        self.reload()
        try:
            await self.record()
        except Exception:   # 기록이 실패해도 탐지는 계속한다 (다음 주기에 다시 기록)
            log.exception("알림 설정 판본 기록 실패")
        async with await db.connect_autocommit() as conn:
            cur = await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (_LOCK_ID,))
            if not (await cur.fetchone())["ok"]:
                self.standby, self.progress_at = True, datetime.now(UTC)   # 다른 서버가 평가 중
                return
            self.standby = False
            try:
                now = datetime.now(UTC)
                self.progress_at = now
                for rule in self.config.rules:
                    if rule.enabled:
                        await self._run_rule(rule, now)
                    elif rule.name in self.runs:
                        # 꺼진 동안은 '본 구간'을 이어 가지 않는다 — 다시 켰을 때 꺼져 있던 시간을 평가 공백으로 잘못 알렸다
                        self.runs[rule.name].last_query_at = self.runs[rule.name].last_gap = None
                self.current_rule = None
                names = {r.name for r in self.config.rules}
                self.runs = {name: run for name, run in self.runs.items() if name in names}
                self.last_run_at = now
                self.cycle_sec = time.monotonic() - started
            finally:
                self.current_rule = None
                await conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))

    async def _run_rule(self, rule: Rule, now: datetime) -> None:
        """규칙 하나 — 실패·시간 초과는 그 규칙에만 남기고 다음 규칙으로 (무거운 규칙 하나가 평가 전체를 멈추지 않게)."""
        run = self.runs.setdefault(rule.name, RuleRun())
        self.current_rule, self.progress_at = rule.name, datetime.now(UTC)
        started = time.monotonic()
        error = kind = None
        try:
            with db.background_time_limit(settings.alert_rule_timeout_sec):
                run.fired = len(await self.evaluate(rule, now, run))
        except db.QueryTimeout as exc:
            error, kind = str(exc), "timeout"
        except Exception as exc:  # 규칙 하나의 실패
            log.exception("규칙 평가 실패: %s", rule.name)
            error, kind = str(exc)[:500], "error"
        run.last_run_at, run.duration_ms = now, int((time.monotonic() - started) * 1000)
        if error:
            run.error, run.error_kind = error, kind
            run.errors_in_row += 1
            run.error_since = run.error_since or now
        else:
            run.error = run.error_kind = run.error_since = None
            run.errors_in_row, run.last_ok_at = 0, now
            if rule.kind == "count":
                # 앞 평가가 본 구간 끝(쿼리를 낸 시각)과 이번 구간 시작 사이에 틈이 있으면 그 사이 들어온 로그는 보지 못했다
                if run.last_query_at and now - rule.window > run.last_query_at:
                    run.last_gap = {"from": run.last_query_at, "to": now - rule.window,
                                    "sec": int((now - rule.window - run.last_query_at).total_seconds()), "at": now}
                    log.warning("규칙 '%s' 평가 공백 %s ~ %s", rule.name, run.last_query_at, now - rule.window)
                run.last_query_at = run.query_at or now
        self.progress_at = datetime.now(UTC)

    # ------------------------------------------------------------ 평가
    async def evaluate(self, rule: Rule, now: datetime, run: RuleRun | None = None) -> list[int]:
        if rule.kind == "agent_silent":
            return await self._evaluate_silent(rule, now)
        if rule.kind == "stream_silent":
            return await self._evaluate_stream_silent(rule, now)
        since = now - rule.window
        base = replace(rule.event_filter(), received_since=since)
        fired = []
        if run is not None:
            run.query_at = datetime.now(UTC)   # 이 쿼리가 본 구간의 끝 (주기 시작 시각이 아니라)
        # 재알림 간격에 든 묶음은 SQL 에서 미리 뺀다 — 빼지 않으면 늘 앞서는 100개가 매번 자리를 차지해 101번째부터는
        # 영영 알리지 못했다(검토에서 재현). 해결된 알림·끝난 무음은 빼지 않는다(아래 파이썬 판단이 정본)
        rows = await repository.alert_candidates(base, rule.group_by, rule.threshold, rule.distinct_field, rule.distinct_min,
                                                 limit=CANDIDATE_LIMIT + 1, cooldown=(rule.name, now - rule.cooldown, now))
        if run is not None:
            # 재알림 간격 밖의 묶음이 상한보다 많으면 일부만 알린다 — 알린 것은 다음 평가부터 간격에 들어 빠지므로 나머지가 이어서
            run.candidates, run.truncated = min(len(rows), CANDIDATE_LIMIT), len(rows) > CANDIDATE_LIMIT
        for row in rows[:CANDIDATE_LIMIT]:
            self.progress_at = datetime.now(UTC)
            key = "" if row["key"] is None else str(row["key"])
            last = await repository.last_alert(rule.name, key)
            if last is not None and _silence_over(last, now) and not await _resumed(base, rule, key, last, since):
                last = {**last, "silenced_until": None}  # 무음 뒤 새 이벤트가 없으면 점검 중 잡음 → 보통 재알림 간격
            # 담당자가 해결한 뒤 같은 문제가 다시 생겼다 — 해결 직후 창에 남은 같은 이벤트로는 울리지 않게 해결 뒤 수신분만 본다.
            # 예전에는 해결해도 재알림 간격(5분~2시간) 동안 다시 죽은 서비스를 알리지 않았다. 확인함(acked)은 간격을 지킨다
            recurred = _recurred(last) and await _received_after(base, rule, key, max(since, last["resolved_at"]))
            if not recurred and _in_cooldown(last, now, rule.cooldown):
                continue
            since_previous = 0
            if last is not None and now - last["fired_at"] <= SINCE_PREVIOUS_MAX:
                try:   # 지난 알림 이후 이 대상에서 몇 건이 더 왔나 (건너뛴 동안의 규모 — ISMS 2.11.5 '언제까지 계속됐나')
                    after = replace(base, received_since=last["fired_at"])
                    since_previous = (await repository.count(_with_group(after, rule.group_by, key)))["current"]
                except db.QueryTimeout:
                    since_previous = 0
            scoped = _with_group(base, rule.group_by, key)
            try:
                samples = await repository.list_events(scoped, SAMPLE_COUNT)
            except db.QueryTimeout:
                samples = []   # 표본 때문에 알림을 잃지 않는다
            message = AlertMessage(
                rule=rule.name, severity=rule.severity, kind=rule.kind, description=rule.description,
                group_by=rule.group_by, group_key=key, event_count=row["n"], threshold=rule.threshold,
                window_sec=int(rule.window.total_seconds()), fired_at=now,
                first_event_at=row["first_ts"], last_event_at=row["last_ts"],
                link=search_link(_link_params(rule, key, row["first_ts"] - timedelta(minutes=1))),
                samples=[_sample(s) for s in samples], tags=list(rule.tags),
                distinct_field=rule.distinct_field or "", distinct_min=rule.distinct_min,
                distinct_count=row.get("dn") or 0, distinct_values=[str(v) for v in (row.get("dvals") or [])],
                previous_id=last["id"] if last is not None else None,
                previous_fired_at=last["fired_at"] if last is not None else None,
                since_previous=since_previous, recurred=recurred,
            )
            fired.append(await self.fire(message, rule.notify))
        if rule.resolve == "auto":
            await self._resolve_quiet(rule, base, now)
        return fired

    async def _resolve_quiet(self, rule: Rule, base: EventFilter, now: datetime) -> None:
        """조건이 풀린 대상의 알림을 자동으로 해결한다 (resolve: auto). 풀림 = 지금 집계 기간의 건수가 기준 아래.
        방금 알린 대상(마지막 알림이 집계 기간·AUTO_RESOLVE_HOLD 안)은 보지 않는다."""
        hold = max(rule.window, AUTO_RESOLVE_HOLD)
        rows = await repository.unresolved_alert_keys(rule.name, now - hold, AUTO_RESOLVE_LIMIT + 1)
        if len(rows) > AUTO_RESOLVE_LIMIT:
            log.info("규칙 '%s' 자동 해결: 대상 %d개 넘음 — 나머지는 다음 주기에", rule.name, AUTO_RESOLVE_LIMIT)
        rows = rows[:AUTO_RESOLVE_LIMIT]
        # PC 마다 세는 규칙: PC 자체가 조용하면 건수 0 은 '나아짐'이 아니라 '모름'이다 — 꺼진 PC 의 오류가 멎었다고
        # 해소를 보내지 않는다(검토). agents 에 없는 이름(syslog 장비 등)은 판단할 수 없어 그대로 본다
        seen = (await repository.agents_last_seen([r["group_key"] for r in rows])) if rule.group_by == "host" else {}
        for row in rows:
            self.progress_at = datetime.now(UTC)
            key = row["group_key"]
            if key in seen and seen[key] < now - hold:
                continue
            n = (await repository.count(_with_group(base, rule.group_by, key)))["current"]
            if n >= rule.threshold:
                continue   # 아직 계속된다 (재알림 간격이 지나면 다시 알린다)
            await self._resolve(rule, key, now, f"최근 {_window_text(int(rule.window.total_seconds()))} 동안 조건에 맞는 "
                                                f"이벤트 {n:,}건 — 기준 {rule.threshold:,}건 아래로 내려가 자동으로 해결")

    async def _resolve(self, rule: Rule, key: str, now: datetime, reason: str) -> None:
        # 지금 무음이면 해소 통지도 보내지 않는다 — 점검 중에는 알림처럼 해소도 잡음이다
        silenced = await repository.active_silence(rule.name, key, now, _key_host(rule, key)) is not None
        changed, queued = await repository.auto_resolve(rule.name, key, reason, notify=() if silenced else rule.notify,
                                                        at=now, notify_since=now - RECOVERY_NOTICE_MAX_AGE)
        if changed:
            log.info("알림 자동 해결 %s · %s: %s (해소 통지 %d곳)", rule.name, key, changed, queued)
        if queued:
            dispatcher.wake()

    async def _evaluate_silent(self, rule: Rule, now: datetime) -> list[int]:
        fired = []
        if rule.resolve == "auto":
            # 먼저 해결한다 — 돌아온 PC 와 아직 끊긴 PC 는 겹치지 않는다(지금 끊김 판정 안에 수신이 있어야 돌아온 것)
            for row in await repository.returned_agents(rule.name, now - rule.silent_for):
                await self._resolve(rule, row["host"], now,
                                    f"로그/하트비트가 다시 들어와 자동으로 해결 (마지막 수신 {local(row['last_seen'])})")
        for row in await repository.silent_agents(now - rule.silent_for, rule.hosts):
            last = await repository.last_alert(rule.name, row["host"])
            # 한 번 끊긴 동안에는 한 번만. 다시 살아났다가(last_seen 갱신) 또 끊기면 다시 알린다.
            # 끊긴 알림이 무음으로 전송되지 않았는데 무음이 끝난 뒤에도 끊겨 있으면 다시 알린다
            if last and last["fired_at"] >= row["last_seen"] and not _silence_over(last, now):
                continue
            message = AlertMessage(
                rule=rule.name, severity=rule.severity, kind=rule.kind, description=rule.description,
                group_by="host", group_key=row["host"], event_count=0, threshold=0,
                window_sec=int(rule.silent_for.total_seconds()), fired_at=now,
                last_event_at=row["last_seen"], link=f"{settings.public_url}/#/agents", tags=list(rule.tags),
            )
            fired.append(await self.fire(message, rule.notify))
        return fired

    async def _evaluate_stream_silent(self, rule: Rule, now: datetime) -> list[int]:
        """늘 오던 (PC, 채널)이 끊김 (B-37 2단계) — 판단은 수집 PC 화면·점검 보고서와 같은 silent_streams.
        한 번 끊긴 동안 한 번만, 다시 들어왔다가 또 끊기면 다시. 먼저 돌아온 채널을 해결한다(resolve: auto)."""
        if rule.resolve == "auto":
            for row in await repository.returned_streams(rule.name):
                await self._resolve(rule, row["group_key"], now,
                                    f"로그가 다시 들어와 자동으로 해결 (마지막 수신 {local(row['last_at'])})")
        wanted = {c.casefold() for c in rule.channels}
        fired = []
        for row in await repository.silent_streams(now, list(rule.hosts) or None):
            if wanted and (row["channel"] or row["source"]).casefold() not in wanted:
                continue
            key = stream_key(row["host"], stream_label(row["source"], row["channel"]))
            last = await repository.last_alert(rule.name, key)
            if last and last["fired_at"] >= row["last_at"] and not _silence_over(last, now):
                continue
            quiet = int(row["quiet_limit"].total_seconds())
            message = AlertMessage(
                rule=rule.name, severity=rule.severity, kind=rule.kind, description=rule.description,
                group_by="host", group_key=key, event_count=0, threshold=0,
                window_sec=quiet - quiet % 3600 if quiet >= 3600 else quiet, fired_at=now,
                last_event_at=row["last_at"], link=f"{settings.public_url}/#/agents", tags=list(rule.tags),
                stream={"host": row["host"], "source": row["source"], "channel": row["channel"],
                        "per_day": round(row["n7"] / max(row["days"], 1))},
            )
            fired.append(await self.fire(message, rule.notify))
        return fired

    # ------------------------------------------------------------ 전송
    async def fire(self, message: AlertMessage, notify: tuple[str, ...]) -> int:
        """알림을 기록하고 전송기를 깨운다 — 보내는 것은 전송기(dispatcher)다. 여기서는 네트워크를 쓰지 않는다 (ADR-045)."""
        # 설정 변경 알림은 무음으로 막지 않는다 — '모든 규칙' 무음을 건 뒤 규칙을 끄면 아무도 모르게 된다
        host = (message.stream or {}).get("host")
        silence = (None if message.kind == "config"
                   else await repository.active_silence(message.rule, message.group_key, message.fired_at, host))
        alert_id = await repository.insert_alert(message.to_dict(), notify, silence)
        message.alert_id = alert_id
        if silence:
            log.info("알림 발생 #%s %s — 무음 #%s 중이라 보내지 않음", alert_id, message.title(), silence["id"])
            return alert_id
        log.warning("알림 발생 #%s %s", alert_id, message.title())
        dispatcher.wake()
        return alert_id

    async def send_test(self, name: str) -> None:
        """알림 대상 연결 확인 (대기열을 거치지 않는다). 실패하면 NotifierError 등."""
        await dispatcher.send_test(name)

    # ------------------------------------------------------------ 상태
    def status(self) -> dict[str, Any]:
        return {
            "file": str(self.path),
            "config_error": self.config_error,
            "interval_sec": self.config.interval_sec,
            "last_run_at": self.last_run_at,
            "last_error": self.last_error,
            "progress_at": self.progress_at,
            "cycle_sec": self.cycle_sec,
            "current_rule": self.current_rule,
            "standby": self.standby,
            "rule_timeout_sec": settings.alert_rule_timeout_sec,
            "sleep_interval_sec": self.sleep_interval,
        }

    def health_snapshot(self) -> dict[str, Any]:
        return {**self.status(), "running": self.task is not None and not self.task.done()}


@dataclass
class RuleRun:
    """규칙 하나의 마지막 평가 (메모리, 워커 1개 전제 — ADR-006). 다시 시작하면 한 주기 동안 '평가 전'."""

    last_run_at: datetime | None = None
    duration_ms: int = 0
    candidates: int = 0
    truncated: bool = False
    fired: int = 0
    error: str | None = None
    error_kind: str | None = None      # timeout | error
    errors_in_row: int = 0
    last_ok_at: datetime | None = None
    error_since: datetime | None = None
    last_query_at: datetime | None = None   # 마지막으로 본 수신 구간의 끝
    query_at: datetime | None = None        # 이번 평가의 쿼리를 낸 시각
    last_gap: dict[str, Any] | None = None  # 평가가 늦어 보지 못한 구간 {from, to, sec, at}

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def stream_label(source: str, channel: str) -> str:
    """채널 끊김 대상의 채널 부분: Windows 는 채널 이름, 다른 소스는 '소스/채널' — 한 PC 의 journald 'kern' 과 syslog 'kern' 이
    같은 이름이 되어 서로를 가리지 않게(검토)."""
    if source == "winevtlog" and channel:
        return channel
    return f"{source}/{channel}" if channel else source


def stream_key(host: str, label: str) -> str:
    """채널 끊김 알림의 대상 이름 'PC · 채널' — 재알림 간격·무음·조회 범위가 이 이름으로 걸린다(visibility.alert_host)."""
    return f"{host} · {label}"


def _key_host(rule: Rule, key: str) -> str | None:
    """대상 이름에서 PC — 채널 끊김 규칙만 'PC · 채널' 이다. 나머지는 None(대상 이름 그대로 무음과 비교)."""
    return key.rsplit(" · ", 1)[0] if rule.kind == "stream_silent" and " · " in key else None


def _parse_or_none(text: str) -> AlertConfig | None:
    """예전 판본 읽기. 그 사이 규칙 형식이 바뀌어 읽을 수 없으면 None (비교 불가로 다룬다)."""
    try:
        return parse_text(text) if text.strip() else AlertConfig()
    except ConfigError:
        return None


def _sample(row: dict) -> dict[str, Any]:
    sample = {k: row.get(k) for k in ("id", "ts", "host", "level", "channel", "provider", "event_id", "message")}
    sample["ts"] = sample["ts"].isoformat() if sample["ts"] else None
    return sample


engine = AlertEngine()
