"""수집된 로그(접속기록)의 위·변조 증명 — 시간별 다이제스트 (BACKLOG B-71 2단계, ADR-050 보완).

감사로그는 행마다 해시 체인이 있지만(1단계) events 에는 없어, DB 슈퍼유저가 로그를 고치거나 지워도 드러나지 않았다.
수신 시각(received_at — 서버가 정함, 파티션 키)으로 닫힌 한 시간마다 그 시간의 모든 행을 해시해 감사로그(integrity.events_digest)에
남긴다. 감사로그 체인과 DB 밖 앵커가 이 기록을 지키므로, 나중에 그 시간의 로그를 다시 계산해 다르면 고쳐졌거나 지워졌거나 끼워진 것이다.
- 다이제스트 = SHA-256(행 해시들을 번호(id) 순으로 이은 것). 행 해시 = SHA-256(칸마다 NULL 은 'N', 아니면 '글자 수:값', raw 는 키 정렬 JSON).
  같은 시간 안에서도 동시에 들어온 묶음은 수신 시각과 번호 순서가 다르다 — 보관 파일(수신 시각 순)과 DB 가 같은 값을 내도록 번호로 정렬한다.
  XOR·합처럼 순서와 무관한 결합은 행을 골라 고쳐 서로 상쇄할 수 있어 쓰지 않는다.
- 확인: 매일 검증(최근 24시간), 보관 파일을 만들 때(그 달 전체 — 파티션을 지우기 전 마지막 기회), `cli verify-chain --events 7d`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from . import db, repository
from .config import settings

log = logging.getLogger(__name__)

ACTION = "integrity.events_digest"
MISMATCH_ACTION = "integrity.events_mismatch"
HOUR = timedelta(hours=1)
SETTLE = timedelta(minutes=10)        # 수신 시각은 트랜잭션 시작 시각 — 시간이 끝난 직후 커밋하는 묶음을 기다린다
MAX_HOURS_PER_RUN = 24                # 오래 꺼져 있다 켜져도 한 번의 정리가 끝없이 길어지지 않게 (다음 정기 정리가 이어서)
DIGEST_BATCH = 1000                   # 가져온 행의 jsonb 해석은 이벤트 루프에서 일어난다 — 묶음을 작게(약 35ms) 해 수집·화면을 오래 막지 않게


def recent_window() -> timedelta:
    """매일 검증에서 다시 계산할 기간 (WLM_EVENT_DIGEST_VERIFY_HOURS, 0 = 하지 않음)."""
    return timedelta(hours=max(settings.event_digest_verify_hours, 0))


def _field(value: Any) -> str:
    if value is None:
        return "N"
    text = str(value)
    return f"{len(text)}:{text}"


def _us(value: Any) -> int | None:
    if value is None:
        return None
    at = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return int(at.timestamp() * 1_000_000) if at.tzinfo else None


def row_hash(row: dict[str, Any]) -> bytes:
    """DB 에서 읽은 행(datetime·dict)과 보관 파일의 행(ISO 글·JSON) 모두 같은 값을 낸다. 칸 순서는 archive.COLUMNS."""
    raw = row.get("raw")
    raw_text = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    parts = [str(row["id"]), _field(_us(row.get("received_at"))), _field(_us(row.get("ts"))), _field(row.get("host")),
             _field(row.get("source")), _field(row.get("category")), _field(row.get("channel")), _field(row.get("provider")),
             _field(row.get("event_id")), _field(row.get("level")), _field(row.get("username")), _field(row.get("src_ip")),
             _field(row.get("message")), _field(raw_text)]
    return hashlib.sha256("|".join(parts).encode("utf-8")).digest()


def hour_of(value: Any) -> datetime:
    at = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return at.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _digest(hour: datetime, hashes: Iterable[bytes], rows: int) -> dict[str, Any]:
    h = hashlib.sha256()
    for rh in hashes:
        h.update(rh)
    return {"hour": hour.isoformat(), "rows": rows, "sha256": h.hexdigest()}


class Hours:
    """수신 시각 순으로 오는 행(보관 파일 쓰기)을 시간마다 모아 다이제스트 — 한 번에 한 시간만 메모리에 두고 그 안에서 번호 순 정렬.
    한 달을 통째로 모으면 수천만 행이라 api 컨테이너 메모리(768MB)를 넘는다."""

    def __init__(self) -> None:
        self.done: dict[datetime, dict[str, Any]] = {}
        self._hour: datetime | None = None
        self._items: list[tuple[int, bytes]] = []

    def add(self, row: dict[str, Any]) -> None:
        hour = hour_of(row["received_at"])
        if hour != self._hour:
            self._close()
            self._hour = hour
        self._items.append((int(row["id"]), row_hash(row)))

    def add_many(self, rows: Iterable[dict[str, Any]]) -> None:
        for row in rows:
            self.add(row)

    def _close(self) -> None:
        if self._hour is not None:
            self._items.sort()
            self.done[self._hour] = _digest(self._hour, (rh for _, rh in self._items), len(self._items))
        self._items = []

    def digest(self, hour: datetime) -> dict[str, Any]:
        self._close()
        self._hour = None
        return self.done.get(hour) or _digest(hour, (), 0)


async def compute(start: datetime, end: datetime) -> list[dict[str, Any]]:
    """[start, end) 의 시간마다 지금 DB 에 있는 행으로 다이제스트. 행이 없는 시간도 낸다(빈 시간도 증명).
    시간마다 번호 순으로 읽어 해시를 이어 붙인다 — 메모리는 한 묶음(5천 행)만."""
    out, hour = [], start
    while hour < end:
        h, rows = hashlib.sha256(), 0
        async for batch in repository.events_for_digest(hour, hour + HOUR, DIGEST_BATCH):
            for rh in await asyncio.to_thread(lambda b=batch: [row_hash(r) for r in b]):   # 해시는 스레드에서 — 수집·화면을 막지 않게
                h.update(rh)
            rows += len(batch)
        out.append({"hour": hour.isoformat(), "rows": rows, "sha256": h.hexdigest()})
        hour += HOUR
    return out


async def recorded(start: datetime, end: datetime) -> dict[str, dict[str, Any]]:
    """감사로그에 남긴 다이제스트(시간 ISO → 기록). 같은 시간이 둘이면 먼저 남긴 것(번호 순)."""
    out: dict[str, dict[str, Any]] = {}
    # 그 시간이 끝난 뒤에 남기므로 그 전 기록은 볼 필요가 없다. 위쪽은 열어 둔다 — 오래 꺼졌다 켜지면 며칠 뒤에 따라잡아 남긴다
    for detail in await repository.event_digest_records(start):
        for h in detail.get("hours") or []:
            at = datetime.fromisoformat(h["hour"])
            if start <= at < end:
                out.setdefault(h["hour"], h)
    return out


async def digest_closed_hours(now: datetime | None = None) -> list[dict[str, Any]]:
    """정기 정리(1시간마다)에서: 아직 남기지 않은 닫힌 시간의 다이제스트를 감사로그 한 줄로. 처음에는 직전 시간부터 시작한다
    (그 전의 로그는 증명할 기준이 없다 — 보관 파일의 SHA-256 이 그 몫)."""
    now = now or datetime.now(UTC)
    last_closed = hour_of(now - SETTLE) - HOUR          # 끝난 뒤 SETTLE 이 지난 마지막 시간
    latest = (await repository.latest_audit_by_id([ACTION])).get(ACTION)
    hours = [datetime.fromisoformat(h["hour"]) for h in (latest["detail"].get("hours") or [])] if latest else []
    start = max(hours) + HOUR if hours else last_closed
    if start > last_closed:
        return []
    end = min(last_closed + HOUR, start + MAX_HOURS_PER_RUN * HOUR)
    digests = await compute(start, end)
    await db.audit("system", ACTION, "events", {"hours": digests})
    return digests


async def check(start: datetime, end: datetime) -> list[str]:
    """[start, end) 의 남긴 다이제스트를 지금 DB 로 다시 계산해 다르면 문제. 다이제스트가 없는 시간은 건너뛴다."""
    want = await recorded(start, end)
    if not want:
        return []
    first = min(datetime.fromisoformat(k) for k in want)
    got = {d["hour"]: d for d in await compute(first, end)}
    return [_mismatch(rec, got.get(key)) for key, rec in sorted(want.items()) if _differs(rec, got.get(key))]


def compare(acc: Hours, want: dict[str, dict[str, Any]]) -> list[str]:
    """보관 파일을 만들며 모은 행(acc)과 남긴 다이제스트(want) 비교 — 그 달 전체."""
    return [_mismatch(rec, acc.digest(datetime.fromisoformat(key))) for key, rec in sorted(want.items())
            if _differs(rec, acc.digest(datetime.fromisoformat(key)))]


def _differs(rec: dict[str, Any], got: dict[str, Any] | None) -> bool:
    return got is None or (rec["rows"], rec["sha256"]) != (got["rows"], got["sha256"])


def _mismatch(rec: dict[str, Any], got: dict[str, Any] | None) -> str:
    rows = got["rows"] if got else 0
    change = "지워짐" if rows < rec["rows"] else "끼워짐" if rows > rec["rows"] else "고쳐짐"
    return (f"수집 로그 {datetime.fromisoformat(rec['hour']):%Y-%m-%d %H시}(UTC) 가 다이제스트와 다릅니다 — 기록 {rec['rows']:,}건, "
            f"지금 {rows:,}건 ({change})")


async def check_recent(now: datetime | None = None, window: timedelta | None = None) -> tuple[list[str], int]:
    """매일 검증: 최근 window(기본 설정값) 안의 남긴 다이제스트를 다시 계산 → (문제들, 확인한 시간 수)."""
    now = now or datetime.now(UTC)
    window = recent_window() if window is None else window
    if window <= timedelta(0):
        return [], 0
    end = hour_of(now - SETTLE)
    start = end - window
    want = await recorded(start, end)
    return (await check(start, end) if want else []), len(want)
