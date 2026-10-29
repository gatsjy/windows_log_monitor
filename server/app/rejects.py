"""수집 거절 장부 (B-40): 서버가 거절한 수집 요청을 (보낸 IP, 상태, 사유) 마다 횟수·처음·마지막 시각으로 남긴다.

예전에는 거절이 어디에도 남지 않았다 — API 키를 바꾼 뒤 옛 키로 보내는 PC 는 화면에서 그냥 '오프라인'이었다.
인증 전 요청이라 요청마다 DB 에 쓰지 않는다(키 없이 마구 보내도 DB 가 바빠지지 않게): 메모리에 모았다가 주기적으로 한 번에 쓴다.
워커 1개 전제(ADR-006). TLS 핸드셰이크 실패는 앱까지 오지 않아 여기 남지 않는다.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

log = logging.getLogger(__name__)

FLUSH_SEC = 30
MAX_KEYS = 2000          # 서로 다른 (IP, 상태, 사유, 시간) — 넘치면 새 것은 '그 밖의 IP' 한 줄로 센다
OTHER_IP = "(그 밖의 IP)"

# (client_ip, status, reason, hour) → [count, first_at, last_at]. 시간(정시)으로 나눠야 보고서가 기간의 거절을 센다
_pending: dict[tuple[str, int, str, datetime], list] = {}


def _add(key: tuple[str, int, str, datetime], n: int, first: datetime, last: datetime) -> None:
    if key not in _pending and len(_pending) >= MAX_KEYS:   # 메모리 상한 — DB 가 멈춘 동안에도 (되돌릴 때 포함)
        key = (OTHER_IP, *key[1:])
    row = _pending.get(key)
    if row is None:
        _pending[key] = [n, first, last]
    else:
        row[0] += n
        row[1] = min(row[1], first)
        row[2] = max(row[2], last)


def note(client_ip: str | None, status: int, reason: str, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    _add((client_ip or "-", status, reason[:200], now.replace(minute=0, second=0, microsecond=0)), 1, now, now)


async def flush() -> int:
    """모은 것을 DB 에 더한다. 실패하면 다음에 다시 (모은 것은 버리지 않는다)."""
    from . import repository

    if not _pending:
        return 0
    batch = dict(_pending)
    _pending.clear()
    try:
        await repository.add_ingest_rejections([(ip, status, reason, hour, n, first, last)
                                                for (ip, status, reason, hour), (n, first, last) in batch.items()])
    except BaseException:   # 실패하거나 종료로 취소돼도 되돌려 놓는다 — 그 사이 새로 센 것과 합쳐서 (마지막 기록이 가져간다)
        for key, (n, first, last) in batch.items():
            _add(key, n, first, last)
        raise
    return len(batch)


async def run_forever() -> None:
    while True:
        await asyncio.sleep(FLUSH_SEC)
        try:
            await flush()
        except Exception:
            log.exception("수집 거절 장부 기록 실패 (다음에 다시)")
