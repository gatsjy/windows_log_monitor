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
from .builtin import BUILTIN_RULES
from .message import SEVERITY_RANK, AlertMessage, escalation_from_action
from .notifiers import SEVERITY_LABELS, Notifier, NotifierError
from .rules import AlertConfig

log = logging.getLogger(__name__)

_LOCK_ID = 727_004
MAX_ATTEMPTS = 5
RETRY_BACKOFF = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15), timedelta(hours=1))
SEND_TIMEOUT_SEC = 30
MAX_AGE = timedelta(hours=24)
STALE_CLAIM = timedelta(minutes=10)   # 한 건은 SEND_TIMEOUT_SEC 안에 끝난다 — 이보다 오래 잡혀 있으면 버려진 것
CONCURRENCY = 4
POLL_SEC = 5
HOUSEKEEPING_SEC = 60
RELEASE_ERROR = "서버가 보내는 도중 멈춰 다시 보냅니다 (같은 알림을 두 번 받을 수 있음)"
EXPIRE_ERROR = "하루가 지나 보내지 않았습니다"
DOWN_NOTE = " (같은 곳으로 방금 보낸 알림이 실패해 이번에는 시도하지 않음)"
SPLIT_NOTE = " (묶음을 받는 쪽이 거절해 반씩 나눠 다시 보냅니다)"
GROUP_MAX = 500   # 묶음 한 통에 담는 알림 상한 (B-41) — 넘는 것은 다음 묶음 간격에 '추가 n건'으로


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

    async def send_test(self, name: str, scheduled: bool = False) -> None:
        """알림 대상 연결 확인 — 대기열을 거치지 않는다. 성공하면 그 곳의 실패분을 바로 다시 보낼 차례로 (고친 뒤 기다리지 않게).
        scheduled = 매주 정기 시험(B-34, 감시가 부른다). Oracle 은 실행만 해 보고 되돌린다 — 매주 사내 알림 표에 시험 행이 쌓이지 않게."""
        notifiers, errors = await targets.load_notifiers()
        notifier = notifiers.get(name)
        if notifier is None:
            raise NotifierError(errors.get(name) or f"알림 대상 '{name}' 이 설정에 없습니다")
        now = datetime.now(UTC)
        message = AlertMessage(
            rule="정기 시험 알림" if scheduled else "테스트 알림", severity="info", kind="test", group_by="none", group_key="",
            event_count=0, threshold=0, window_sec=0, fired_at=now, alert_id=0, test=True,
            description=(f"매주 알림 경로가 살아 있는지 확인하는 시험 알림입니다 — 알림 대상 '{name}' ({notifier.type}). 답할 필요는 없습니다"
                         if scheduled else f"알림 대상 '{name}' ({notifier.type}) 연결 확인"),
            link=f"{settings.public_url}/#/alerts",
        )
        dry_run = getattr(notifier, "dry_run", None)
        if scheduled and dry_run is not None:
            await asyncio.wait_for(dry_run(message), timeout=SEND_TIMEOUT_SEC)
        else:
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
            # 잠금을 쥔 채로 잡힌 지 오래된 행 = 줄이 죽었는데 풀지 못한 것 (보내기는 30초면 끝난다)
            stale = await repository.release_delivery_claims(now, RELEASE_ERROR, MAX_ATTEMPTS, claimed_before=now - STALE_CLAIM)
            if stale:
                log.warning("오래 '보내는 중'이던 알림 %d건을 다시 보냅니다", stale)
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
        """한 받는 곳의 대기 행을 차례로 (덜 실패한 것·심각한 것부터). 같은 곳으로는 한 번에 하나만 보낸다.
        동시 자리(CONCURRENCY)는 한 건 보낼 때마다 잡고 놓는다 — 줄 하나가 대기열을 다 비울 때까지 쥐고 있으면
        다섯째 받는 곳(당직 메신저의 심각 알림 등)이 몇 분씩 기다렸다(검토에서 재현)."""
        if notifier is None:   # 지워졌거나 설정이 틀렸다 — 네트워크 없이 바로 실패로 (예전과 같은 문구·간격, 시도로 셈)
            now = datetime.now(UTC)
            error = error or f"알림 대상 '{name}' 이 설정에 없습니다"
            await repository.fail_due_deliveries(name, error, now, _backoff_seconds(), MAX_ATTEMPTS)
            self.health(name).fail(now, error)   # 설정 문제도 '보내지 못하는 중'이다 — 모든 받는 곳이 이러면 알림 멈춤
            return
        while True:
            async with self._slots:
                done = await self._send_one(name, notifier)
            if done:
                return

    async def _send_one(self, name: str, notifier: Notifier) -> bool:
        """한 통. 묶음을 받는 곳(B-41)이면 같은 규칙·종류의 대기 행을 함께 잡아 한 통으로 — 모으는 시간·묶음 간격 안이면
        시도로 세지 않고 미룬다. 돌려주는 값 = 이 줄을 끝낼까 (보낼 것이 없거나 받는 곳 자체가 안 됨)."""
        now = datetime.now(UTC)
        config = _config()
        grouping = notifier.groups() and config.group_interval_sec > 0
        if grouping:
            jobs = await repository.claim_group(name, now, GROUP_MAX, solo_rules=sorted(BUILTIN_RULES))
        else:
            job = await repository.claim_delivery(name, now)
            jobs = [job] if job else []
        if not jobs:
            return True
        try:
            # 묶지 않는 행(내장 알림)·거절돼 나눈 반쪽(split_key)은 모으지도 기다리지도 않는다 — 반쪽이 묶음 간격에 걸려 늦지 않게
            if grouping and jobs[0]["rule"] not in BUILTIN_RULES and jobs[0]["split_key"] is None:
                hold = await _group_hold(name, jobs, config, now)
                if hold is not None:
                    await repository.hold_deliveries(jobs, hold)
                    return False
            ready = []
            for job in jobs:
                skip = (None if notifier.accepts(job["severity"])
                        else f"받을 최소 수준({SEVERITY_LABELS[notifier.min_severity]} 이상)보다 낮은 알림") or _stale(job, notifier)
                if skip:
                    await repository.finish_delivery(job, "skipped", skip, tried=0)
                else:
                    ready.append(job)
            if not ready:
                return False
            return await self._send_batch(name, notifier, ready) is not None
        except asyncio.CancelledError:
            raise
        except Exception:
            # 결과를 쓰다가 DB 가 끊기는 등: '보내는 중'으로 남기지 않고 풀어 둔다 (못 풀면 오래된 잡힘 정리가 푼다)
            log.exception("알림 %s → %s 처리 중 오류 — 다시 보낼 차례로 되돌립니다", _ids(jobs), name)
            try:
                for job in jobs:
                    await repository.unclaim_delivery(job)
            except Exception:
                log.exception("되돌리기 실패 (잠시 뒤 오래된 잡힘 정리가 푼다)")
            return True

    async def _send_batch(self, name: str, notifier: Notifier, jobs: list[dict[str, Any]]) -> datetime | None:
        """잡은 행들을 한 통으로. 받는 곳 자체가 안 되면(시간 초과·target_down) 다시 볼 시각을 돌려준다 — 그 줄을 멈춘다.
        묶음을 받는 쪽이 알림 하나 때문에 거절하면(본문 문제 — 400·413·422·SMTP 5xx 554) 반으로 나눠 다시 보낼 차례로 돌린다(시도로 세지
        않음, split_deliveries): 거절된 알림만 혼자 시도를 쓴다. 이 자리에서 나눠 보내면 한 줄이 전송 자리를 오래 쥐었다(검토에서 재현).
        403 은 토큰이 막힌 것일 수도, 방화벽·DLP 가 본문을 막은 것일 수도 있어 여러 건이면 나눈다 — 혼자 보내도 403 이면 받는 곳 문제."""
        try:
            await asyncio.wait_for(notifier.send(_message(jobs)), timeout=SEND_TIMEOUT_SEC)
        except asyncio.CancelledError:
            raise   # 멈출 때: 행은 '보내는 중'으로 남고 다음 시작 때 풀어 다시 보낸다
        except Exception as exc:  # noqa: BLE001 - 어떤 실패든 기록하고 재시도 대상으로
            timed_out = isinstance(exc, TimeoutError)
            down = timed_out or getattr(exc, "target_down", False)
            error = "전송 시간 초과" if timed_out else str(exc)[:1000]
            if len(jobs) > 1 and (not down or getattr(exc, "status", None) == 403):
                await repository.split_deliveries(jobs, error[:900] + SPLIT_NOTE)
                log.warning("알림 %s → %s 묶음 거절 — 하나씩 다시 보냅니다: %s", _ids(jobs), name, error)
                return None
            now = datetime.now(UTC)
            # 묶음은 함께 다시 보내도록 같은 때로 (첫 행의 실패 간격), 다섯 번째 실패한 행만 gave_up
            retry_at = now + RETRY_BACKOFF[min(jobs[0]["attempts"], 3)]
            await repository.finish_deliveries([j for j in jobs if j["attempts"] + 1 >= MAX_ATTEMPTS], "gave_up", error)
            await repository.finish_deliveries([j for j in jobs if j["attempts"] + 1 < MAX_ATTEMPTS], "failed", error,
                                               next_attempt_at=retry_at)
            self.health(name).fail(now, error)
            log.warning("알림 %s → %s 전송 실패: %s", _ids(jobs), name, error)
            if down:
                # 나머지는 시도로 세지 않고 미루기만 — 알림 하나를 받는 곳이 계속 거절해(500) 보지도 않은 다른 알림까지
                # 다섯 번 실패로 버려지던 것을 막는다(검토에서 재현). 미룬 행도 하루가 지나면 만료된다
                await repository.defer_due_deliveries(name, error[:900] + DOWN_NOTE, now, retry_at)
                return retry_at
            return None
        await repository.finish_deliveries(jobs, "sent", None, batch_size=len(jobs))
        self.health(name).ok(datetime.now(UTC))
        return None

    def status(self) -> dict[str, Any]:
        running = self.task is not None and not self.task.done()
        return {"enabled": settings.alert_dispatcher, "progress_at": self.progress_at, "standby": self.standby,
                "running": running,
                "sending": sorted(n for n, t in self._lanes.items() if not t.done()),
                "targets": {n: h.as_dict() for n, h in self.targets.items()}}


def _config() -> AlertConfig:
    from .engine import engine  # 엔진이 이 모듈을 가져온다 — 순환을 피해 부를 때

    return engine.config


async def _group_hold(name: str, jobs: list[dict[str, Any]], config: AlertConfig, now: datetime) -> datetime | None:
    """묶음을 언제까지 미룰까 (B-41, Alertmanager group_wait·group_interval). None = 지금 보낸다.
    - 모으는 시간: 아직 한 번도 보내지 않은 행 중 가장 먼저 들어온 것부터 wait 초 — 그 사이 같은 규칙 알림을 모은다.
    - 묶음 간격: 이 받는 곳에 같은 규칙·종류를 마지막으로 보낸 뒤 interval 초 안이면 그때까지 — '추가 n건' 한 통.
    심각은 바로 보내고 간격도 짧다(group_timing). 재시도 차례인 행(실패한 것)은 모으지 않는다."""
    severity = max((j["severity"] for j in jobs), key=lambda s: SEVERITY_RANK.get(s, 1))
    wait, interval = config.group_timing(severity)
    hold = None
    fresh = [j["queued_at"] for j in jobs if j["attempts"] == 0]
    if wait and fresh:
        hold = min(fresh) + timedelta(seconds=wait)
    if interval:
        last = await repository.last_group_sent(name, jobs[0]["rule"], jobs[0]["action"], now - timedelta(seconds=interval))
        if last is not None:
            hold = max(hold or last, last + timedelta(seconds=interval))
    return hold if hold is not None and hold > now else None


def _message(jobs: list[dict[str, Any]]) -> AlertMessage:
    """잡은 행 → 보낼 메시지. 하나면 예전과 같은 알림, 여럿이면 묶음 알림(AlertMessage.group)."""
    messages = []
    for job in jobs:
        message = AlertMessage.from_dict(job["payload"])
        message.alert_id = job["alert_id"]
        if job.get("action") == "resolve":
            message.event_action, message.resolved_at = "resolve", job["resolved_at"]
            message.started_at = job.get("started_at")
        message.escalation = escalation_from_action(job.get("action") or "") or ""   # B-43: 다시 알림 머리말
        messages.append(message)
    return messages[0] if len(messages) == 1 else AlertMessage.group(messages)


def _ids(jobs: list[dict[str, Any]]) -> str:
    ids = [f"#{j['alert_id']}" for j in jobs[:5]]
    return ", ".join(ids) + (f" 외 {len(jobs) - 5}건" if len(jobs) > 5 else "")


def _stale(job: dict[str, Any], notifier: Notifier) -> str | None:
    """보낼 차례가 왔지만 이제 보내면 안 되는 행의 이유 (B-35 2단계). 넣을 때가 아니라 보낼 때 본다 — 그 사이 바뀐다.
    해소 통지:
    - 그 사이 사람이 다시 열었거나(또는 다시 열었다가 사람이 해결) — 끝나지 않은 문제·자동이 아닌 해결을 '자동 해소'로 알리지 않는다.
    - 같은 대상에 더 새 알림이 있다 — 실패해 재시도를 기다리던 지난 해소가 새 알림 뒤에 나가면 받는 쪽(같은 dedup_key)이
      지금 열린 사고를 닫는다(검토에서 재현).
    - 이번 문제의 알림이 이 곳에 전해지지 않았다 — 넣을 때 '보내는 중'이던 알림이 결국 실패한 경우. 받지 않은 알림의 해소는 혼란이다.
    알림: 자동으로 해결됐다 — 보내다 실패해 다시 보낼 차례가 된 행. 끝난 문제를 뒤늦게 알리지 않는다
    (자동 해결 때 대기 중이던 행은 그때 건너뜀으로 바꾼다. 이것은 그때 보내는 중이던 행)."""
    if job.get("action") == "resolve":
        if job.get("alert_status") != "resolved":
            return "해소 통지를 보내기 전에 알림이 다시 열렸습니다"
        if not job.get("auto_resolved"):
            return "담당자가 해결 처리한 알림이라 자동 해소 통지를 보내지 않습니다"
        if job.get("newer"):
            return "같은 대상에 새 알림이 있어 지난 알림의 해소 통지를 보내지 않습니다 (새 알림을 닫지 않게)"
        if not job.get("delivered"):
            return "이 곳으로 알림이 전해지지 않아 해소 통지도 보내지 않습니다"
        return notifier.accepts_resolve()
    if (job.get("action") or "").startswith(("escalate:", "acktimeout:")):
        # 에스컬레이션 (B-43): 넣을 때가 아니라 보낼 때 본다 — 그 사이 누가 확인·해결했으면 다시 알릴 까닭이 없다.
        # 확인 시간 초과(2단계)는 다시 연 알림이라 그 사이 다시 확인했으면 보내지 않는다
        if job.get("alert_status") == "resolved":
            return "다시 알리기 전에 해결됨"
        if (job["action"].endswith(":acked") or job["action"].startswith("acktimeout:")) and job.get("alert_status") == "acked":
            return "다시 알리기 전에 확인됨"
        return notifier.accepts_escalation()
    if job.get("auto_resolved"):
        return "보내기 전에 조건이 풀려 자동으로 해결됨"
    return None


dispatcher = Dispatcher()
