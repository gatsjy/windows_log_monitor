"""필드 카탈로그 집계 (ADR-068): 수집한 원본 JSON 의 경로별 수·예시를 메모리에 모았다가 주기적으로 field_stats 에 더한다.

예전에는 수집 요청마다 같은 트랜잭션에서 field_stats 를 upsert 했다. 같은 소스의 요청은 모두 같은 (source, path) 줄을
고치므로 커밋(WAL fsync)까지 줄을 섰다 — 에이전트 1000대 부하에서 수집이 초당 약 300건에서 멈췄고 DB 대기의
대부분이 이 줄 잠금이었다(PERFORMANCE.md §2.12). 필드 탐색 화면의 수·예시일 뿐이라 몇 초 늦거나 비정상 종료 때
마지막 몇 초가 빠져도 되므로, 수집 트랜잭션에서 빼서 rejects 처럼 모아 쓴다. 워커 1개 전제(ADR-006).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

log = logging.getLogger(__name__)

FLUSH_SEC = 10
# 서로 다른 (소스, 경로) 상한 — 원본 키는 보내는 쪽이 정하므로 DB 가 멈춘 동안 메모리가 끝없이 늘지 않게.
# 넘치면 새 경로는 버리고 센다(이미 있는 경로의 수는 계속 센다)
MAX_KEYS = 20000

# (source, path) → [json_type, seen, sample, first_at, last_at]
_pending: dict[tuple[str, str], list] = {}
_dropped = 0


def _add(key: tuple[str, str], json_type: str, n: int, sample: str | None, first: datetime, last: datetime) -> bool:
    row = _pending.get(key)
    if row is None:
        if len(_pending) >= MAX_KEYS:
            return False
        _pending[key] = [json_type, n, sample, first, last]
        return True
    if last >= row[4]:   # 마지막에 본 모양·예시가 이긴다 (예전 upsert 와 같은 뜻)
        row[0], row[2] = json_type, sample
    row[1] += n
    row[3] = min(row[3], first)
    row[4] = max(row[4], last)
    return True


def note(rows: list[tuple[str, str, str, int, str | None]], now: datetime | None = None) -> None:
    """rows = repository.field_stats_rows(저장한 이벤트) — (소스, 경로, json 형, 수, 예시)."""
    global _dropped
    now = now or datetime.now(UTC)
    for source, path, json_type, n, sample in rows:
        if not _add((source, path), json_type, n, sample, now, now):
            _dropped += 1


async def flush() -> int:
    """모은 것을 DB 에 더한다. 실패하거나 종료로 취소되면 되돌려 놓는다 (그 사이 새로 센 것과 합쳐서)."""
    global _dropped
    from . import repository

    if _dropped:
        log.warning("필드 카탈로그: 서로 다른 경로가 %d개를 넘어 새 경로 %d건을 세지 못했습니다", MAX_KEYS, _dropped)
        _dropped = 0
    if not _pending:
        return 0
    batch = dict(_pending)
    _pending.clear()
    try:
        await repository.add_field_stats([(src, path, t, n, sample, first, last)
                                          for (src, path), (t, n, sample, first, last) in batch.items()])
    except BaseException:
        for key, (t, n, sample, first, last) in batch.items():
            _add(key, t, n, sample, first, last)
        raise
    return len(batch)


def forget() -> None:
    """시험: 앞 모듈의 DB 에 쓸 것을 다음 DB 로 넘기지 않는다."""
    global _dropped
    _pending.clear()
    _dropped = 0


async def run_forever() -> None:
    while True:
        await asyncio.sleep(FLUSH_SEC)
        try:
            await flush()
        except Exception:
            log.exception("필드 카탈로그 기록 실패 (다음에 다시)")
