"""알림 기능 감시 (ADR-045 2단계, BACKLOG B-34): 멈춘 평가·전송 작업을 다시 시작하고, 알림 기능 자체의 문제를 알린다.

상태 띠·/healthz/alerts·점검 보고서는 문제를 '보여' 주지만, 아무도 보고 있지 않으면 알림이 멈춘 채 하루가 간다.
- 평가가 멈추면(나아간 시각이 오래됨·작업이 죽음): 감사로그, 작업 다시 시작(10분에 한 번까지), '알림 엔진 멈춤'.
- 전송기가 멈추면: 다시 시작(10분에 한 번까지)·감사로그. 알림은 보내지 않는다(그것을 보낼 길이 멈춘 것이다).
- 받는 곳이 15분 넘게 실패하면: '알림 전송 실패'를 **그 곳을 뺀** 다른 받는 곳으로.
- 규칙이 세 번 잇달아 실패하면: '알림 규칙 동작 안 함'. 평가 공백은 감사로그에.
- 매주 정기 시험(WLM_ALERT_TEST_WEEKDAY·TIME): 쓰는 받는 곳마다 시험 알림 — 실패하면 그 곳을 '보내지 못하는 중'으로 두어
  15분 뒤 '알림 전송 실패'가 다른 곳으로 나간다. 알림 경로가 깨진 것을 실제 알림이 나기 전에 안다(B-34).
- Oracle 생존 신호(연동에 생존 신호 SQL 이 있으면): 1분마다 한 행 — 서버 전체가 멈추면 병원 DB 감시가 알아챈다(B-34).
받는 곳 = settings.fallback_notify, 비우면 점검 보고서 받는 곳. 같은 문제는 한 시간에 한 번(해결하면 바로 다시).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime, time, timedelta
from typing import Any

from .. import __version__, db, repository
from ..config import display_zone, settings
from . import health, targets
from .builtin import ENGINE_STALL_RULE, RULE_BROKEN_RULE, TARGET_DOWN_RULE
from .dispatcher import dispatcher
from .engine import engine
from .message import AlertMessage, local

log = logging.getLogger(__name__)

CHECK_SEC = 30
RESTART_MIN_GAP = timedelta(minutes=10)
RULE_BROKEN_AFTER = 3            # 잇달아 실패한 평가 수
SYSTEM_COOLDOWN = timedelta(hours=1)
HEARTBEAT_EVERY = timedelta(seconds=60)
HEARTBEAT_TIMEOUT_SEC = 30
RETEST_AFTER_SEC = 60   # 정기 시험이 실패하면 한 번 더 — 잠깐의 끊김(재시작 중인 메일 서버 등)으로 '알림 전송 실패'가 나지 않게


def test_moment(now: datetime) -> datetime | None:
    """이번 주(지금 이전의 가장 최근) 정기 시험 시각 (UTC). 꺼져 있으면 None.
    서버가 그 시각에 꺼져 있었으면 다음 감시 때 한다 — '지난 시각 뒤에 시험한 적이 없으면'으로 보므로."""
    weekday = settings.alert_test_weekday
    if not 1 <= weekday <= 7:
        return None
    try:
        hour, minute = (int(x) for x in settings.alert_test_time.split(":", 1))
        at = time(hour, minute)
    except ValueError:
        at = time(9, 0)
    zone = display_zone()
    local_now = now.astimezone(zone)
    day = local_now.date() - timedelta(days=(local_now.isoweekday() - weekday) % 7)
    moment = datetime.combine(day, at, zone)
    if moment > local_now:
        moment -= timedelta(days=7)
    return moment.astimezone(UTC)


class Watchdog:
    def __init__(self) -> None:
        self._restart_engine: Callable[[], asyncio.Task] | None = None
        self._restart_dispatcher: Callable[[], asyncio.Task] | None = None
        self._last_restart: dict[str, datetime] = {}
        self.engine_down_since: datetime | None = None
        self.targets_down: set[str] = set()
        self.rules_broken: set[str] = set()
        self._gaps_seen: dict[str, datetime] = {}
        # 정기 시험·생존 신호는 네트워크를 기다리므로 감시 주기를 막지 않게 따로 돈다
        self._tests_task: asyncio.Task | None = None
        self._tests_done_for: datetime | None = None    # 이번 주 시험을 마친 시각 (다시 시작하면 감사로그로 다시 판단)
        self._heartbeat_task: asyncio.Task | None = None
        self._heartbeat_at: datetime | None = None
        self.heartbeats: dict[str, dict[str, Any]] = {}  # Oracle 연동 이름 → {last_ok_at, failing_since, error}

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
        self._start_background(now)

    def _start_background(self, now: datetime) -> None:
        moment = test_moment(now)
        if moment is not None and moment != self._tests_done_for and (self._tests_task is None or self._tests_task.done()):
            self._tests_task = asyncio.get_running_loop().create_task(self._tests_then_mark(now, moment))
        if (self._heartbeat_at is None or now - self._heartbeat_at >= HEARTBEAT_EVERY) and (
                self._heartbeat_task is None or self._heartbeat_task.done()):
            self._heartbeat_at = now
            self._heartbeat_task = asyncio.get_running_loop().create_task(self.heartbeat(now))

    async def _tests_then_mark(self, now: datetime, moment: datetime) -> None:
        try:
            await self.scheduled_tests(now)
            self._tests_done_for = moment
        except Exception:
            log.exception("정기 시험 전송 실패 — 다음 감시 때 다시")

    # ------------------------------------------------------------ 정기 시험 (B-34)
    async def scheduled_tests(self, now: datetime) -> list[dict[str, Any]]:
        """이번 주 정기 시각 뒤로 시험한 적이 없는(화면의 테스트 발송도 센다) 받는 곳에 시험 알림 → [{target, ok, error}].
        받는 곳 = 켜진 규칙의 받는 곳 + 알림 기능 문제를 받을 곳. 실패하면 그 곳을 '보내지 못하는 중'으로 둔다 —
        15분 지나도록 고쳐지지 않으면 '알림 전송 실패'가 다른 곳으로 나간다(_check_targets)."""
        moment = test_moment(now)
        if moment is None:
            return []
        used = sorted({n for r in engine.config.rules if r.enabled for n in r.notify} | set(await self.recipients()))
        tested = await repository.latest_target_tests(used, moment)
        results = []
        for name in used:
            if name in tested:
                continue
            ok, error = True, None
            for attempt in (1, 2):
                try:
                    await dispatcher.send_test(name, scheduled=True)
                    ok, error = True, None
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - 어떤 실패든 그 곳의 문제로 기록
                    ok, error = False, (str(exc) or type(exc).__name__)[:500]
                    if attempt == 1:
                        await asyncio.sleep(RETEST_AFTER_SEC)
            if not ok:
                dispatcher.health(name).fail(datetime.now(UTC), f"정기 시험 전송 실패: {error}")
                log.warning("정기 시험 전송 실패 → %s: %s", name, error)
            await db.audit("system", "alerts.test.scheduled", name, {"ok": ok, "error": error, "week_of": moment.isoformat()})
            results.append({"target": name, "ok": ok, "error": error})
        return results

    # ------------------------------------------------------------ Oracle 생존 신호 (B-34)
    async def heartbeat(self, now: datetime) -> None:
        """생존 신호 SQL 이 있는 Oracle 연동마다 한 번. 실패·회복은 바뀔 때만 감사로그에 (1분마다 쌓이지 않게)."""
        try:
            notifiers, _ = await targets.load_notifiers()
        except Exception:
            log.exception("생존 신호: 알림 대상을 읽지 못함")
            return
        writers = {n: x for n, x in notifiers.items() if getattr(x, "heartbeat_sql", "")}
        for gone in set(self.heartbeats) - set(writers):
            del self.heartbeats[gone]
        if not writers:
            return
        state = await health.current()
        values = {"at": now.astimezone(UTC).replace(tzinfo=None), "status": state["status"], "version": __version__,
                  "problems": len(state["problems"])}
        for name, writer in writers.items():
            hb = self.heartbeats.setdefault(name, {"last_ok_at": None, "failing_since": None, "error": None})
            try:
                await asyncio.wait_for(writer.heartbeat(values), timeout=HEARTBEAT_TIMEOUT_SEC)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - 어떤 실패든 상태로
                error = (str(exc) or type(exc).__name__)[:300]
                if hb["failing_since"] is None:
                    hb["failing_since"] = now
                    await db.audit("system", "alerts.health.heartbeat_fail", name, {"error": error})
                hb["error"] = error
            else:
                if hb["failing_since"] is not None:
                    await db.audit("system", "alerts.health.heartbeat_ok", name,
                                   {"sec": int((now - hb["failing_since"]).total_seconds())})
                hb.update(last_ok_at=now, failing_since=None, error=None)

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

    def stop(self) -> None:
        """서버를 끌 때 — DB 풀을 닫기 전에 정기 시험·생존 신호 작업도 끈다."""
        for task in (self._tests_task, self._heartbeat_task):
            if task is not None and not task.done():
                task.cancel()

    def status(self) -> dict[str, Any]:
        return {"engine_down_since": self.engine_down_since, "targets_down": sorted(self.targets_down),
                "rules_broken": sorted(self.rules_broken)}


watchdog = Watchdog()
