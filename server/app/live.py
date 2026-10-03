"""실시간 스트림(SSE)용 프로세스 내 브로드캐스터 + 수집 속도 측정.

주의: 프로세스 메모리 기반이라 uvicorn 워커 1개를 전제로 한다.
여러 인스턴스로 확장할 때는 PostgreSQL LISTEN/NOTIFY 등으로 교체 (docs/DECISIONS.md ADR-006).
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class Broadcaster:
    def __init__(self, queue_size: int = 200) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._queue_size = queue_size
        self.dropped = 0  # 느린 클라이언트 때문에 버린 배치 수

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def publish(self, items: list[dict]) -> None:
        if not items:
            return
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(items)
            except asyncio.QueueFull:
                self.dropped += 1


class RateMeter:
    """최근 window 초 동안 수신한 이벤트 수 (초 단위 버킷)."""

    def __init__(self, window_sec: int = 300) -> None:
        self.window = window_sec
        self._buckets: deque[list[int]] = deque()  # [epoch_sec, count]

    def add(self, n: int) -> None:
        if n <= 0:
            return
        now = int(time.time())
        if self._buckets and self._buckets[-1][0] == now:
            self._buckets[-1][1] += n
        else:
            self._buckets.append([now, n])
        self._trim(now)

    def _trim(self, now: int) -> None:
        while self._buckets and self._buckets[0][0] <= now - self.window:
            self._buckets.popleft()

    def per_minute(self, last_sec: int = 60) -> float:
        now = int(time.time())
        self._trim(now)
        total = sum(n for t, n in self._buckets if t > now - last_sec)
        return round(total * 60 / last_sec, 1)


broadcaster = Broadcaster()
ingest_rate = RateMeter()
