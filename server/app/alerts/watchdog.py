"""알림 기능 감시 (ADR-045 2단계, BACKLOG B-34): 멈춘 평가·전송 작업을 다시 시작하고, 알림 기능 자체의 문제를 알린다.

상태 띠·/healthz/alerts·점검 보고서는 문제를 '보여' 주지만, 아무도 보고 있지 않으면 알림이 멈춘 채 하루가 간다.
- 평가가 멈추면(나아간 시각이 오래됨·작업이 죽음): 감사로그, 작업 다시 시작(10분에 한 번까지), '알림 엔진 멈춤'.
- 전송기가 멈추면: 다시 시작(10분에 한 번까지)·감사로그. 알림은 보내지 않는다(그것을 보낼 길이 멈춘 것이다).
- 받는 곳이 15분 넘게 실패하면: '알림 전송 실패'를 **그 곳을 뺀** 다른 받는 곳으로.
- 규칙이 세 번 잇달아 실패하면: '알림 규칙 동작 안 함'. 평가 공백은 감사로그에.
받는 곳 = settings.fallback_notify, 비우면 점검 보고서 받는 곳. 같은 문제는 한 시간에 한 번(해결하면 바로 다시).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import db, repository
from ..config import settings
from . import health
from .builtin import ENGINE_STALL_RULE, RULE_BROKEN_RULE, TARGET_DOWN_RULE
from .dispatcher import dispatcher
from .engine import engine
from .message import AlertMessage, local

log = logging.getLogger(__name__)

CHECK_SEC = 30
RESTART_MIN_GAP = timedelta(minutes=10)
RULE_BROKEN_AFTER = 3            # 잇달아 실패한 평가 수
SYSTEM_COOLDOWN = timedelta(hours=1)


class Watchdog:
    def __init__(self) -> None:
        self._restart_engine: Callable[[], asyncio.Task] | None = None
        self._restart_dispatcher: Callable[[], asyncio.Task] | None = None
        self._last_restart: dict[str, datetime] = {}
        self.engine_down_since: datetime | None = None
        self.targets_down: set[str] = set()
        self.rules_broken: set[str] = set()
        self._gaps_seen: dict[str, datetime] = {}

    def start(self, restart_engine: Callable[[], asyncio.Task], restart_dispatcher: Callable[[], asyncio.Task] | None) -> None:
        """main 이 넘긴다: 작업을 새로 만들어 돌려주는 함수 (멈춘 작업을 다시 시작할 때)."""
        self._restart_engine, self._restart_dispatcher = restart_engine, restart_dispatcher

    async def run_forever(self) -> None:
        while True:
            await asyncio.sleep(CHECK_SEC)
            try:
                await self.check(datetime.now(UTC))
            except Exception:
                log.exception("알림 기능 감시 실패")

    async def recipients(self, exclude: str | None = None) -> list[str]:
        """알림 기능 문제를 받을 곳 — 실패하는 그 곳은 뺀다 (그리로는 어차피 가지 않는다)."""
        from ..reports import config as report_config

        names = list(engine.config.fallback_notify) or list((await report_config.load())["targets"])
        return [n for n in names if n != exclude]

    async def check(self, now: datetime) -> None:
        await self._check_engine(now)
        await self._check_dispatcher(now)
        await self._check_targets(now)
        await self._check_rules(now)

    # ------------------------------------------------------------ 평가
    async def _check_engine(self, now: datetime) -> None:
        snap = engine.health_snapshot()
        interval = max(snap["interval_sec"], snap.get("sleep_interval_sec") or 0)
        progress = snap["progress_at"]
        stalled = not snap["standby"] and (not snap["running"] or progress is None
                                           or now - progress > health.engine_stall(interval, snap["rule_timeout_sec"]))
        if stalled and self.engine_down_since is None:
            self.engine_down_since = progress or now
            await db.audit("system", "alerts.health.engine_stall", "engine",
                           {"last_progress_at": progress.isoformat() if progress else None, "current_rule": snap["current_rule"]})
            restarted = self._restart("engine", now)
            await self._system_alert(
                ENGINE_STALL_RULE, "", "critical", now,
                f"알림 규칙 평가가 멈췄습니다 (마지막 진행 {local(progress)})",
                [f"평가 중이던 규칙: {snap['current_rule'] or '없음'}",
                 "평가 작업을 다시 시작했습니다" if restarted else "다시 시작은 10분에 한 번까지라 이번에는 하지 않았습니다",
                 "그 사이 들어온 로그는 규칙으로 확인되지 않았을 수 있습니다 — 서버 로그를 확인하세요"])
        elif stalled and now - self._last_restart.get("engine", datetime.min.replace(tzinfo=UTC)) >= RESTART_MIN_GAP:
            self._restart("engine", now)
        elif not stalled and self.engine_down_since is not None:
            since, self.engine_down_since = self.engine_down_since, None
            uncovered = sorted(name for name, run in engine.runs.items() if run.last_gap and run.last_gap["at"] >= since)
            await db.audit("system", "alerts.health.engine_resume", "engine",
                           {"from": since.isoformat(), "to": now.isoformat(), "sec": int((now - since).total_seconds()),
                            "uncovered": uncovered})

    def _restart(self, what: str, now: datetime) -> bool:
        factory = self._restart_engine if what == "engine" else self._restart_dispatcher
        last = self._last_restart.get(what)
        if factory is None or (last is not None and now - last < RESTART_MIN_GAP):
            return False
        self._last_restart[what] = now
        task = engine.task if what == "engine" else dispatcher.task
        if task is not None and not task.done():
            task.cancel()   # 알림 기록은 한 트랜잭션이라 반쪽이 남지 않는다. 보내던 행은 다음 잠금 때 풀린다
        new = factory()
        if what == "engine":
            engine.task = new
        else:
            dispatcher.task = new
        log.error("알림 %s 작업을 다시 시작했습니다", "평가" if what == "engine" else "전송")
        asyncio.get_running_loop().create_task(
            db.audit("system", f"alerts.health.{what}_restart", what, {"at": now.isoformat()}))
        return True

    # ------------------------------------------------------------ 전송
    async def _check_dispatcher(self, now: datetime) -> None:
        if not settings.alert_dispatcher:
            return
        snap = dispatcher.status()
        progress = snap["progress_at"]
        if not snap["standby"] and (not snap["running"] or progress is None or now - progress > health.DISPATCH_STALL):
            # 알림은 보내지 않는다 — 그것을 보낼 길이 멈춘 것이다 (상태 띠·/healthz/alerts·보고서가 알린다)
            self._restart("dispatcher", now)

    async def _check_targets(self, now: datetime) -> None:
        for name, t in list(dispatcher.targets.items()):
            if t.failing_since and now - t.failing_since >= health.TARGET_DOWN and name not in self.targets_down:
                self.targets_down.add(name)
                queued = sum(q["queued"] for q in await repository.delivery_queue(now) if q["notifier"] == name)
                await db.audit("system", "alerts.health.target_down", name,
                               {"since": t.failing_since.isoformat(), "error": (t.last_error or "")[:500], "queued": queued})
                await self._system_alert(
                    TARGET_DOWN_RULE, name, "error", now,
                    f"'{name}'(으)로 {int((now - t.failing_since).total_seconds() // 60)}분째 알림을 보내지 못하고 있습니다",
                    [f"마지막 오류: {(t.last_error or '')[:300]}", f"보내지 못하고 기다리는 알림 {queued:,}건",
                     "환경설정 > 메일 서버·외부 연동을 확인한 뒤 알림 화면 > 알림 대상에서 '테스트 발송'을 누르면 바로 다시 보냅니다"],
                    exclude=name)
            elif not t.failing_since and name in self.targets_down:
                self.targets_down.discard(name)
                await db.audit("system", "alerts.health.target_recovered", name, {"at": now.isoformat()})

    # ------------------------------------------------------------ 규칙
    async def _check_rules(self, now: datetime) -> None:
        for name, run in list(engine.runs.items()):
            if run.errors_in_row >= RULE_BROKEN_AFTER and name not in self.rules_broken:
                self.rules_broken.add(name)
                await db.audit("system", "alerts.health.rule_error", name,
                               {"errors_in_row": run.errors_in_row, "error": (run.error or "")[:500], "kind": run.error_kind})
                hint = ("조건을 좁히고(기간·PC·이벤트 ID) 규칙 편집의 미리보기로 확인하세요" if run.error_kind == "timeout"
                        else "규칙 조건을 확인하세요")
                await self._system_alert(
                    RULE_BROKEN_RULE, name, "error", now, f"알림 규칙 '{name}' 이(가) 동작하지 않습니다 ({run.errors_in_row}번 잇달아 실패)",
                    [f"오류: {(run.error or '')[:300]}", hint, "고칠 때까지 이 규칙으로는 알림이 오지 않습니다"])
            elif run.errors_in_row == 0 and name in self.rules_broken:
                self.rules_broken.discard(name)
                await db.audit("system", "alerts.health.rule_recovered", name, {"at": now.isoformat()})
            if run.last_gap and self._gaps_seen.get(name) != run.last_gap["at"]:
                self._gaps_seen[name] = run.last_gap["at"]
                gap = run.last_gap
                await db.audit("system", "alerts.health.rule_gap", name,
                               {"from": gap["from"].isoformat(), "to": gap["to"].isoformat(), "sec": gap["sec"]})

    # ------------------------------------------------------------ 알림
    async def _system_alert(self, rule: str, key: str, severity: str, now: datetime, summary: str, lines: list[str],
                            exclude: str | None = None) -> int | None:
        last = await repository.last_alert(rule, key)
        if last is not None and last["status"] != "resolved" and now - last["fired_at"] < SYSTEM_COOLDOWN:
            return None
        message = AlertMessage(
            rule=rule, severity=severity, kind="system", group_by="none", group_key=key, event_count=len(lines), threshold=0,
            window_sec=0, fired_at=now, description=summary + "\n" + "\n".join(f"- {line}" for line in lines),
            link=f"{settings.public_url}/#/alerts")
        return await engine.fire(message, tuple(await self.recipients(exclude)))

    def status(self) -> dict[str, Any]:
        return {"engine_down_since": self.engine_down_since, "targets_down": sorted(self.targets_down),
                "rules_broken": sorted(self.rules_broken)}


watchdog = Watchdog()
