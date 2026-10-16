"""정한 시각에 보고서를 만들고 저장하고 보낸다 (알림 엔진처럼 앱 안의 백그라운드 작업).

- 1분마다 '지금 만들어야 할 기간'(due_periods)을 계산한다. 일간 = 어제 0~24시, 주간 = 지난주 월~일 (표시 시간대 기준).
- 같은 기간의 정기 보고서는 DB 의 고유 색인으로 한 번만 만들어진다 → 서버를 재시작하거나 여러 대여도 중복 발송이 없다.
- 서버가 꺼져 있어 시각을 놓쳤으면 켜진 뒤 가장 최근 기간만 만든다 (밀린 기간을 몰아서 보내지 않는다).
- 여러 인스턴스가 떠 있어도 PostgreSQL advisory lock 으로 한 곳에서만 돈다.
- 보낼 곳은 보고서를 저장할 때 '보내는 중'으로 같이 적는다. 보내다가 서버가 멈추면 다음 주기에 그곳만 이어서 보낸다
  (하루가 지나면 실패로 바꾼다). 자동 발송 결과는 감사로그(report.deliver)에도 남긴다.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime, time, timedelta, tzinfo
from typing import Any

from .. import db, repository
from ..alerts import targets
from ..alerts.notifiers import NotifierError
from ..config import display_zone
from . import builder, config, render

log = logging.getLogger(__name__)

_LOCK_ID = 727_005
TICK_SEC = 60
SEND_TIMEOUT_SEC = 60
PENDING_RETRY = timedelta(days=1)   # 이보다 오래된 '보내는 중'은 다시 보내지 않고 실패로 남긴다


def _at(day: datetime, hhmm: str) -> datetime:
    h, m = (int(x) for x in hhmm.split(":"))
    return day.replace(hour=h, minute=m)


def due_periods(now: datetime, cfg: dict[str, Any], tz: tzinfo) -> list[tuple[str, datetime, datetime]]:
    """지금(now) 만들 차례인 (종류, 시작, 끝) — 보낼 시각이 지났으면 가장 최근 기간 하나씩. 시각은 UTC 로 돌려준다."""
    local = now.astimezone(tz)
    today = datetime.combine(local.date(), time(0), tzinfo=tz)
    out = []
    if cfg["daily"]["enabled"] and local >= _at(today, cfg["daily"]["time"]):
        out.append(("daily", today - timedelta(days=1), today))
    if cfg["weekly"]["enabled"]:
        monday = today - timedelta(days=local.weekday())
        send_at = _at(monday + timedelta(days=int(cfg["weekly"]["weekday"]) - 1), cfg["weekly"]["time"])
        if local >= send_at:
            out.append(("weekly", monday - timedelta(days=7), monday))
    return [(kind, start.astimezone(UTC), end.astimezone(UTC)) for kind, start, end in out]


def latest_period(kind: str, now: datetime, tz: tzinfo) -> tuple[datetime, datetime]:
    """'지금 만들기'용: 끝난 가장 최근 기간 (일간 = 어제, 주간 = 지난주)."""
    local = now.astimezone(tz)
    today = datetime.combine(local.date(), time(0), tzinfo=tz)
    if kind == "daily":
        start, end = today - timedelta(days=1), today
    else:
        end = today - timedelta(days=local.weekday())
        start = end - timedelta(days=7)
    return start.astimezone(UTC), end.astimezone(UTC)


def payload_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()


async def generate(kind: str, start: datetime, end: datetime, *, scheduled: bool, actor: str,
                   send_to: list[str], now: datetime | None = None, actor_ip: str | None = None) -> int | None:
    """보고서를 만들어 저장하고(감사로그에 내용 해시) 받는 곳에 보낸다. 정기 보고서가 이미 있으면 None."""
    payload = await builder.build(kind, start, end, now)
    summary = render.summary(payload)
    pending = [{"target": name, "status": "pending", "error": None, "at": None} for name in send_to]
    report_id = await repository.insert_report(kind, scheduled, start, end, payload, summary["attention"], actor,
                                               pending)
    if report_id is None:
        return None
    await db.audit(actor, "report.create", f"보고서 #{report_id}", {
        "id": report_id, "kind": kind, "scheduled": scheduled, "period_start": start.isoformat(),
        "period_end": end.isoformat(), "attention": summary["attention"], "sha256": payload_sha256(payload)},
        actor_ip=actor_ip)
    log.info("점검 보고서 #%s %s — %s", report_id, payload["title"], summary["headline"])
    if send_to:
        await _deliver_automatically(report_id, payload, send_to)
    return report_id


async def _deliver_automatically(report_id: int, payload: dict[str, Any], names: list[str]) -> None:
    """자동 발송 + 감사로그 (화면의 다시 보내기는 router 가 report.send 로 남긴다)."""
    results = await deliver(report_id, payload, names)
    await db.audit("system", "report.deliver", f"보고서 #{report_id}", {"id": report_id, "results": results})


def _result(name: str, status: str, error: str | None = None) -> dict[str, Any]:
    return {"target": name, "status": status, "error": error[:500] if error else None, "at": datetime.now(UTC).isoformat()}


async def deliver(report_id: int, payload: dict[str, Any], names: list[str]) -> list[dict[str, Any]]:
    """받는 곳마다 보내고 결과를 보고서 행에 덧붙인다. 무엇이 잘못되어도 결과는 남긴다 — 보고서는 저장되어 있어
    화면에서 다시 보낼 수 있고, '보내지 않음'(받는 곳 없음)과 '보내지 못함'이 구별된다."""
    try:
        notifiers, errors = await targets.load_notifiers()
        notice = render.notice(payload, report_id)
    except Exception as exc:  # 설정·비밀값(키 변경)·렌더링 문제: 받는 곳마다 실패로 남긴다
        log.exception("점검 보고서 #%s 보내기 준비 실패", report_id)
        results = [_result(name, "failed", f"보내기 준비 실패: {exc}") for name in names]
    else:
        results = []
        for name in names:
            notifier = notifiers.get(name)
            try:
                if notifier is None:
                    raise NotifierError(errors.get(name) or f"받는 곳 '{name}' 이 설정에 없습니다")
                await asyncio.wait_for(notifier.send_notice(notice), timeout=SEND_TIMEOUT_SEC)
                results.append(_result(name, "sent"))
            except Exception as exc:  # noqa: BLE001 - 하나가 실패해도 나머지는 보낸다, 사유는 그대로 남긴다
                error = "전송 시간 초과" if isinstance(exc, TimeoutError) else str(exc)
                log.warning("점검 보고서 #%s → %s 전송 실패: %s", report_id, name, error)
                results.append(_result(name, "failed", error))
    await repository.add_report_deliveries(report_id, results)
    return results


class ReportScheduler:
    def __init__(self) -> None:
        self.last_run_at: datetime | None = None
        self.last_error: str | None = None

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
                log.exception("점검 보고서 작업 실패")
            await asyncio.sleep(TICK_SEC)

    async def tick(self, now: datetime | None = None) -> list[int]:
        now = now or datetime.now(UTC)
        cfg = await config.load()
        due = due_periods(now, cfg, display_zone())
        made: list[int] = []
        async with await db.connect_autocommit() as conn:
            cur = await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (_LOCK_ID,))
            if not (await cur.fetchone())["ok"]:
                return made
            try:
                # 보내다가 멈춘 보고서: 하루 안이면 남은 곳으로 이어서, 그보다 오래되었으면 실패로
                await repository.expire_pending_deliveries(now - PENDING_RETRY, "보내는 중에 서버가 멈췄습니다 (하루가 지나 다시 보내지 않음)")
                for row in await repository.reports_pending_delivery(now - PENDING_RETRY):
                    names = [d["target"] for d in row["deliveries"] if d["status"] == "pending"]
                    log.warning("점검 보고서 #%s: 보내다가 멈춘 곳으로 다시 보냅니다 (%s)", row["id"], ", ".join(names))
                    await _deliver_automatically(row["id"], row["payload"], names)
                for kind, start, end in due:
                    if await repository.scheduled_report_exists(kind, start):
                        continue
                    report_id = await generate(kind, start, end, scheduled=True, actor="system",
                                               send_to=cfg["targets"], now=now)
                    if report_id:
                        made.append(report_id)
                self.last_run_at = now
            finally:
                await conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))
        return made


scheduler = ReportScheduler()
