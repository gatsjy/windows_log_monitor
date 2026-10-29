"""알림 전송기 (ADR-045, BACKLOG B-34): 평가와 전송을 나눈다.

예전에는 엔진이 평가 주기 안에서 알림을 보내고(받는 곳마다 최대 30초) 실패분 재시도도 같은 주기에서 했다. 메일 서버 하나가
멈추면 그동안 규칙 평가가 늦어졌고, 보내는 중 서버가 멈추면 그 알림은 '전송 중'으로 영영 남았다(아무도 pending 을 다시 보내지 않음).

- alert_deliveries 가 대기열이다. 엔진은 행만 넣고(fire) 깨운다. 전송기는 next_attempt_at 이 지난 pending·failed 행을
  하나씩 잡아(claimed_at) 보낸다. 받는 곳마다 한 줄(lane)씩, 한꺼번에 최대 CONCURRENCY 곳. 보내는 동안 DB 연결을 쥐지 않는다.
- 재시도 간격 1·5·15·60분, 다섯 번째 실패면 gave_up (ADR-011 그대로).
- 받는 곳 자체가 안 될 때(연결 실패·시간 초과·5xx) 그 곳의 다른 대기 행은 한 번에 실패로 넘긴다 — 같은 곳에 30초씩 줄줄이 기다리지 않게.
- 서버가 보내는 도중 멈춘 행(claimed_at 이 남음)은 다음에 잠금을 잡을 때 풀어 다시 보낸다(같은 알림을 두 번 받을 수 있음).
- 하루가 지난 대기 행은 보내지 않는다(gave_up).
- PostgreSQL advisory lock 727_004 로 한 곳에서만. 워커 1개 전제의 메모리 상태(ADR-006).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import db, repository
from ..config import settings
from . import targets
from .message import AlertMessage
from .notifiers import SEVERITY_LABELS, Notifier, NotifierError

log = logging.getLogger(__name__)

_LOCK_ID = 727_004
MAX_ATTEMPTS = 5
RETRY_BACKOFF = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15), timedelta(hours=1))
SEND_TIMEOUT_SEC = 30
MAX_AGE = timedelta(hours=24)
CONCURRENCY = 4
POLL_SEC = 5
HOUSEKEEPING_SEC = 60
RELEASE_ERROR = "서버가 보내는 도중 멈춰 다시 보냅니다 (같은 알림을 두 번 받을 수 있음)"
EXPIRE_ERROR = "하루가 지나 보내지 않았습니다"
DOWN_NOTE = " (같은 곳으로 방금 보낸 알림이 실패해 이번에는 시도하지 않음)"


@dataclass
class TargetHealth:
    """받는 곳의 최근 상태 (메모리 — 다시 시작하면 처음부터)."""

    last_ok_at: datetime | None = None
    failing_since: datetime | None = None
    consecutive_failures: int = 0
    last_error: str | None = None
    last_attempt_at: datetime | None = None

    def ok(self, now: datetime) -> None:
        self.last_ok_at = self.last_attempt_at = now
        self.failing_since, self.consecutive_failures, self.last_error = None, 0, None

    def fail(self, now: datetime, error: str) -> None:
        self.last_attempt_at = now
        self.failing_since = self.failing_since or now
        self.consecutive_failures += 1
        self.last_error = error

    def as_dict(self) -> dict[str, Any]:
        return {"last_ok_at": self.last_ok_at, "failing_since": self.failing_since, "last_error": self.last_error,
                "consecutive_failures": self.consecutive_failures, "last_attempt_at": self.last_attempt_at}


def _backoff_seconds() -> list[int]:
    return [int(d.total_seconds()) for d in RETRY_BACKOFF]


class Dispatcher:
    def __init__(self) -> None:
        self.progress_at: datetime | None = None
        self.standby = False
        self.targets: dict[str, TargetHealth] = {}
        self._wake: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lanes: dict[str, asyncio.Task] = {}
        self._slots: asyncio.Semaphore | None = None
        self._housekept: datetime | None = None
        self.task: asyncio.Task | None = None   # main 이 넣는다 (상태 판단: 작업이 살아 있나)

    # ------------------------------------------------------------ 바깥에서
    def wake(self) -> None:
        """엔진이 알림을 넣은 뒤 부른다. 전송기가 돌고 있지 않으면(시험) 아무 일도 하지 않는다 — drain() 으로 보낸다."""
        if self._wake is not None and self._loop is not None and not self._loop.is_closed():
            try:
                if asyncio.get_running_loop() is self._loop:
                    self._wake.set()
                    return
            except RuntimeError:
                pass
            self._loop.call_soon_threadsafe(self._wake.set)

    def health(self, name: str) -> TargetHealth:
        return self.targets.setdefault(name, TargetHealth())

    async def drain(self, now: datetime | None = None, rounds: int = 5) -> None:
        """보낼 차례인 것을 모두 보낸다 (시험·실제 루프 공용). 실패해 뒤로 미뤄진 것은 그 시각까지 기다리지 않는다."""
        self._prepare()
        for _ in range(rounds):
            if not await self._pass(now or datetime.now(UTC), wait=True):
                return

    async def send_test(self, name: str) -> None:
        """알림 대상 연결 확인 — 대기열을 거치지 않는다. 성공하면 그 곳의 실패분을 바로 다시 보낼 차례로 (고친 뒤 기다리지 않게)."""
        notifiers, errors = await targets.load_notifiers()
        notifier = notifiers.get(name)
        if notifier is None:
            raise NotifierError(errors.get(name) or f"알림 대상 '{name}' 이 설정에 없습니다")
        now = datetime.now(UTC)
        message = AlertMessage(
            rule="테스트 알림", severity="info", kind="test", group_by="none", group_key="", event_count=0,
            threshold=0, window_sec=0, fired_at=now, alert_id=0, test=True,
            description=f"알림 대상 '{name}' ({notifier.type}) 연결 확인", link=f"{settings.public_url}/#/alerts",
        )
        await asyncio.wait_for(notifier.send(message), timeout=SEND_TIMEOUT_SEC)
        now = datetime.now(UTC)
        self.health(name).ok(now)
        if await repository.retry_target_now(name, now):
            self.wake()

    # ------------------------------------------------------------ 루프
    async def run_forever(self) -> None:
        self._prepare()
        while True:
            try:
                async with await db.connect_autocommit() as conn:
                    cur = await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (_LOCK_ID,))
                    if not (await cur.fetchone())["ok"]:
                        self.standby, self.progress_at = True, datetime.now(UTC)   # 다른 서버가 보내는 중
                        await asyncio.sleep(10)
                        continue
                    self.standby = False
                    # 잠금을 잡은 쪽에는 아직 보내는 줄이 없다 → 남아 있는 '보내는 중'은 멈춘 서버의 것
                    released = await repository.release_delivery_claims(datetime.now(UTC), RELEASE_ERROR, MAX_ATTEMPTS)
                    if released:
                        log.warning("보내는 도중 멈춘 알림 %d건을 다시 보냅니다", released)
                    while True:
                        self._wake.clear()   # 비운 뒤에 훑는다 — 훑는 사이 들어온 깨우기를 잃지 않게
                        await self._pass(datetime.now(UTC), wait=False)
                        await conn.execute("SELECT 1")   # 잠금 연결이 살아 있나 (끊기면 잠금도 풀렸다)
                        try:
                            await asyncio.wait_for(self._wake.wait(), POLL_SEC)
                        except TimeoutError:
                            pass
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("알림 전송기 오류 — 잠시 뒤 다시")
                await self._join_lanes()   # 내 줄이 끝난 뒤에 잠금을 다시 잡는다 (다른 쪽이 그 행을 풀지 않게)
                await asyncio.sleep(5)

    def _prepare(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is not loop:   # 시험은 TestClient 마다 루프가 다르다
            self._loop, self._wake, self._slots, self._lanes = loop, asyncio.Event(), asyncio.Semaphore(CONCURRENCY), {}

    async def _join_lanes(self) -> None:
        lanes = [t for t in self._lanes.values() if not t.done()]
        if lanes:
            await asyncio.gather(*lanes, return_exceptions=True)

    async def _pass(self, now: datetime, wait: bool) -> bool:
        """한 번 훑기. 돌려주는 값 = 보낼 것이 있었나."""
        if self._housekept is None or now - self._housekept >= timedelta(seconds=HOUSEKEEPING_SEC):
            self._housekept = now
            expired = await repository.expire_stale_deliveries(now - MAX_AGE, EXPIRE_ERROR)
            if expired:
                log.warning("하루가 지나 보내지 않은 알림 %d건", expired)
        due = await repository.due_notifiers(now)
        if due:
            notifiers, errors = await targets.load_notifiers()   # 환경설정에서 바꾼 것이 바로 반영되게 훑을 때마다
            for name in due:
                lane = self._lanes.get(name)
                if lane is None or lane.done():
                    self._lanes[name] = asyncio.create_task(self._lane(name, notifiers.get(name), errors.get(name)))
        self.progress_at = now
        if wait:
            await self._join_lanes()
        return bool(due)

    async def _lane(self, name: str, notifier: Notifier | None, error: str | None) -> None:
        """한 받는 곳의 대기 행을 차례로 (심각한 것부터). 같은 곳으로는 한 번에 하나만 보낸다."""
        async with self._slots:
            if notifier is None:   # 지워졌거나 설정이 틀렸다 — 네트워크 없이 바로 실패로 (예전과 같은 문구·간격)
                await repository.fail_due_deliveries(name, error or f"알림 대상 '{name}' 이 설정에 없습니다",
                                                     datetime.now(UTC), _backoff_seconds(), MAX_ATTEMPTS)
                return
            while True:
                now = datetime.now(UTC)
                job = await repository.claim_delivery(name, now)
                if job is None:
                    return
                if not notifier.accepts(job["severity"]):
                    reason = f"받을 최소 수준({SEVERITY_LABELS[notifier.min_severity]} 이상)보다 낮은 알림"
                    await repository.finish_delivery(job, "skipped", reason, tried=0)
                    continue
                message = AlertMessage.from_dict(job["payload"])
                message.alert_id = job["alert_id"]
                try:
                    await asyncio.wait_for(notifier.send(message), timeout=SEND_TIMEOUT_SEC)
                except asyncio.CancelledError:
                    raise   # 멈출 때: 행은 '보내는 중'으로 남고 다음 시작 때 풀어 다시 보낸다
                except Exception as exc:  # noqa: BLE001 - 어떤 실패든 기록하고 재시도 대상으로
                    timed_out = isinstance(exc, TimeoutError)
                    error = "전송 시간 초과" if timed_out else str(exc)[:1000]
                    attempts = job["attempts"] + 1
                    now = datetime.now(UTC)
                    if attempts >= MAX_ATTEMPTS:
                        await repository.finish_delivery(job, "gave_up", error)
                    else:
                        await repository.finish_delivery(job, "failed", error,
                                                         next_attempt_at=now + RETRY_BACKOFF[min(attempts - 1, 3)])
                    self.health(name).fail(now, error)
                    log.warning("알림 #%s → %s 전송 실패: %s", job["alert_id"], name, error)
                    if timed_out or getattr(exc, "target_down", False):
                        await repository.fail_due_deliveries(name, error[:900] + DOWN_NOTE, now, _backoff_seconds(),
                                                             MAX_ATTEMPTS)
                        return
                    continue
                await repository.finish_delivery(job, "sent", None)
                self.health(name).ok(datetime.now(UTC))

    def status(self) -> dict[str, Any]:
        running = self.task is not None and not self.task.done()
        return {"enabled": settings.alert_dispatcher, "progress_at": self.progress_at, "standby": self.standby,
                "running": running,
                "sending": sorted(n for n, t in self._lanes.items() if not t.done()),
                "targets": {n: h.as_dict() for n, h in self.targets.items()}}


dispatcher = Dispatcher()
