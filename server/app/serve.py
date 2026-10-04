"""운영 실행 진입점: 한 프로세스에서 두 포트를 연다.

  8000  화면 + 전체 API (호스트 WLM_PORT, 기본 8080)
  8001  에이전트 수집 전용 — /api/ingest, /healthz 만 (호스트 WLM_INGEST_PORT, 기본 6976, main.IngestPortGuard)

워커를 나누지 않고 한 프로세스로 두는 이유: 실시간 스트림이 프로세스 메모리 기반이라(ADR-006)
수집으로 들어온 이벤트가 화면 쪽 구독자에게 바로 보이려면 같은 프로세스여야 한다.

  python -m app.serve           (Dockerfile runtime)
  watchfiles "python -m app.serve" /app/app   (개발: 코드가 바뀌면 재시작)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal

import uvicorn

from .config import settings
from .main import app

WEB_PORT = int(os.environ.get("WLM_LISTEN_PORT", "8000"))


class _Server(uvicorn.Server):
    """신호(SIGTERM/SIGINT)는 아래 main 에서 두 서버에 한꺼번에 전달한다 (서버마다 잡으면 마지막 것만 받는다)."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def main() -> None:
    common = {"host": "0.0.0.0", "proxy_headers": True, "timeout_graceful_shutdown": 5,  # 컨테이너 안이라 모든 주소
              "log_level": settings.log_level.lower()}
    web = _Server(uvicorn.Config(app, port=WEB_PORT, **common))
    # 시작 작업(마이그레이션, 연결 풀, 알림 엔진)은 화면 쪽 서버가 한 번만 한다
    ingest = _Server(uvicorn.Config(app, port=settings.ingest_listen_port, lifespan="off", **common))

    loop = asyncio.get_running_loop()

    def stop() -> None:
        web.should_exit = ingest.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)

    web_task = asyncio.create_task(web.serve())
    # 연결 풀이 열린 뒤에 수집을 받기 시작한다
    while not web.started and not web_task.done():
        await asyncio.sleep(0.05)
    if web_task.done():
        await web_task  # 시작 실패 — 예외를 그대로 올린다
        return
    await asyncio.gather(web_task, ingest.serve())


if __name__ == "__main__":
    asyncio.run(main())
