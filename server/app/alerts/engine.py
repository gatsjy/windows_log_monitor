"""알림 엔진: interval_sec 마다 규칙을 평가 → 알림 기록 → 알림 대상으로 전송 → 실패분 재시도.

- 규칙 파일(config/alerts.yaml)이 바뀌면 다음 주기에 자동으로 다시 읽는다 (재시작 불필요).
- 알림 대상(수신 그룹·외부 연동·메일 서버)은 매 주기 환경설정(DB)에서 다시 만든다 → 화면에서 바꾸면 바로 반영.
  잘못된 파일이면 이전 설정을 유지하고 오류를 화면에 보여준다.
- 같은 규칙·같은 대상(PC)은 cooldown 동안 다시 알리지 않는다.
- 여러 서버 인스턴스가 떠 있어도 PostgreSQL advisory lock 으로 한 곳에서만 평가한다.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .. import db, repository
from ..config import settings
from ..filters import EventFilter
from . import targets
from .message import AlertMessage, search_link
from .notifiers import SEVERITY_LABELS, Notifier, NotifierError
from .rules import AlertConfig, ConfigError, Rule, load

log = logging.getLogger(__name__)

_LOCK_ID = 727_003
MAX_ATTEMPTS = 5
RETRY_BACKOFF = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15), timedelta(hours=1))
SEND_TIMEOUT_SEC = 30
SAMPLE_COUNT = 5


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
        self.notifiers: dict[str, Notifier] = {}
        self.notifier_errors: dict[str, str] = {}
        self.last_run_at: datetime | None = None
        self.last_error: str | None = None
        self._mtime: float | None = None

    # ------------------------------------------------------------ 설정
    def reload(self, force: bool = False) -> None:
        mtime = self.path.stat().st_mtime if self.path.exists() else None
        if not force and mtime == self._mtime:
            return
        self._mtime = mtime
        try:
            config = load(self.path)
        except ConfigError as exc:
            self.config_error = str(exc)
            log.error("알림 설정 오류 (이전 설정 유지): %s", exc)
            return
        self.config, self.config_error = config, None
        log.info("알림 규칙 적용: %d개", len(config.rules))

    async def load_targets(self) -> None:
        self.notifiers, self.notifier_errors = await targets.load_notifiers()

    # ------------------------------------------------------------ 루프
    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
                log.exception("알림 평가 실패")
            await asyncio.sleep(self.config.interval_sec)

    async def tick(self) -> None:
        self.reload()
        await self.load_targets()
        async with await db.connect_autocommit() as conn:
            cur = await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (_LOCK_ID,))
            if not (await cur.fetchone())["ok"]:
                return
            try:
                now = datetime.now(UTC)
                for rule in self.config.rules:
                    if not rule.enabled:
                        continue
                    try:
                        await self.evaluate(rule, now)
                    except Exception:
                        log.exception("규칙 평가 실패: %s", rule.name)
                await self.retry_failed(now)
                self.last_run_at = now
            finally:
                await conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))

    # ------------------------------------------------------------ 평가
    async def evaluate(self, rule: Rule, now: datetime) -> list[int]:
        if rule.kind == "agent_silent":
            return await self._evaluate_silent(rule, now)
        since = now - rule.window
        base = replace(rule.event_filter(), received_since=since)
        fired = []
        for row in await repository.alert_candidates(base, rule.group_by, rule.threshold):
            key = "" if row["key"] is None else str(row["key"])
            last = await repository.last_alert_at(rule.name, key)
            if last and now - last < rule.cooldown:
                continue
            scoped = _with_group(base, rule.group_by, key)
            samples = await repository.list_events(scoped, SAMPLE_COUNT)
            message = AlertMessage(
                rule=rule.name, severity=rule.severity, kind=rule.kind, description=rule.description,
                group_by=rule.group_by, group_key=key, event_count=row["n"], threshold=rule.threshold,
                window_sec=int(rule.window.total_seconds()), fired_at=now,
                first_event_at=row["first_ts"], last_event_at=row["last_ts"],
                link=search_link(_link_params(rule, key, row["first_ts"] - timedelta(minutes=1))),
                samples=[_sample(s) for s in samples], tags=list(rule.tags),
            )
            fired.append(await self.fire(message, rule.notify))
        return fired

    async def _evaluate_silent(self, rule: Rule, now: datetime) -> list[int]:
        fired = []
        for row in await repository.silent_agents(now - rule.silent_for, rule.hosts):
            last = await repository.last_alert_at(rule.name, row["host"])
            # 한 번 끊긴 동안에는 한 번만. 다시 살아났다가(last_seen 갱신) 또 끊기면 다시 알린다
            if last and last >= row["last_seen"]:
                continue
            message = AlertMessage(
                rule=rule.name, severity=rule.severity, kind=rule.kind, description=rule.description,
                group_by="host", group_key=row["host"], event_count=0, threshold=0,
                window_sec=int(rule.silent_for.total_seconds()), fired_at=now,
                last_event_at=row["last_seen"], link=f"{settings.public_url}/#/agents", tags=list(rule.tags),
            )
            fired.append(await self.fire(message, rule.notify))
        return fired

    # ------------------------------------------------------------ 전송
    async def fire(self, message: AlertMessage, notify: tuple[str, ...]) -> int:
        alert_id = await repository.insert_alert(message.to_dict(), notify)
        message.alert_id = alert_id
        log.warning("알림 발생 #%s %s", alert_id, message.title())
        await asyncio.gather(*(self.deliver(alert_id, name, message) for name in notify))
        return alert_id

    async def deliver(self, alert_id: int, name: str, message: AlertMessage) -> bool:
        notifier = self.notifiers.get(name)
        if notifier is not None and not message.test and not notifier.accepts(message.severity):
            reason = f"받을 최소 수준({SEVERITY_LABELS[notifier.min_severity]} 이상)보다 낮은 알림"
            await repository.skip_delivery(alert_id, name, reason)
            return False
        try:
            if notifier is None:
                raise NotifierError(self.notifier_errors.get(name) or f"알림 대상 '{name}' 이 설정에 없습니다")
            await asyncio.wait_for(notifier.send(message), timeout=SEND_TIMEOUT_SEC)
        except Exception as exc:  # noqa: BLE001 - 어떤 실패든 기록하고 재시도 대상으로
            error = "전송 시간 초과" if isinstance(exc, TimeoutError) else str(exc)
            await repository.mark_delivery(alert_id, name, "failed", error[:1000])
            log.warning("알림 #%s → %s 전송 실패: %s", alert_id, name, error)
            return False
        await repository.mark_delivery(alert_id, name, "sent")
        return True

    async def retry_failed(self, now: datetime) -> None:
        for row in await repository.failed_deliveries():
            attempts = row["attempts"]
            if attempts >= MAX_ATTEMPTS:
                await repository.give_up_delivery(row["alert_id"], row["notifier"])
                continue
            wait = RETRY_BACKOFF[min(attempts - 1, len(RETRY_BACKOFF) - 1)]
            if now - row["updated_at"] < wait:
                continue
            message = AlertMessage.from_dict(row["payload"])
            message.alert_id = row["alert_id"]
            await self.deliver(row["alert_id"], row["notifier"], message)

    async def send_test(self, name: str) -> None:
        """알림 대상 연결 확인. 실패하면 NotifierError."""
        await self.load_targets()
        notifier = self.notifiers.get(name)
        if notifier is None:
            raise NotifierError(self.notifier_errors.get(name) or f"알림 대상 '{name}' 이 설정에 없습니다")
        now = datetime.now(UTC)
        message = AlertMessage(
            rule="테스트 알림", severity="info", kind="test", group_by="none", group_key="", event_count=0,
            threshold=0, window_sec=0, fired_at=now, alert_id=0, test=True,
            description=f"알림 대상 '{name}' ({notifier.type}) 연결 확인", link=f"{settings.public_url}/#/alerts",
        )
        await asyncio.wait_for(notifier.send(message), timeout=SEND_TIMEOUT_SEC)

    # ------------------------------------------------------------ 상태
    def status(self) -> dict[str, Any]:
        return {
            "file": str(self.path),
            "config_error": self.config_error,
            "interval_sec": self.config.interval_sec,
            "last_run_at": self.last_run_at,
            "last_error": self.last_error,
        }


def _sample(row: dict) -> dict[str, Any]:
    sample = {k: row.get(k) for k in ("id", "ts", "host", "level", "channel", "provider", "event_id", "message")}
    sample["ts"] = sample["ts"].isoformat() if sample["ts"] else None
    return sample


engine = AlertEngine()
