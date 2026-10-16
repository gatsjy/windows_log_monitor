"""운영 실행 진입점: 한 프로세스에서 여러 리스너를 연다.

  8000  화면 + 전체 API (호스트 WLM_PORT, 기본 8080). WLM_TLS=on 이면 HTTPS 만
  8001  평문 수집 (호스트 WLM_INGEST_PORT, 기본 6976) — WLM_INGEST_PLAIN=off 면 띄우지 않는다(연결 거부)
  8002  TLS 수집 (호스트 WLM_INGEST_TLS_PORT, 기본 6977) — WLM_TLS=on 일 때만
  8003  수집기(collector) 전용 평문 수집, 게시하지 않는다(compose 망 안) — 평문 수집을 닫아도 syslog 는 계속
  수집 리스너 셋은 /api/ingest, /healthz 만 받는다 (main.IngestPortGuard). 배치는 ADR-036.

워커를 나누지 않고 한 프로세스로 두는 이유: 실시간 스트림이 프로세스 메모리 기반이라(ADR-006)
수집으로 들어온 이벤트가 화면 쪽 구독자에게 바로 보이려면 같은 프로세스여야 한다.

  python -m app.serve           (Dockerfile runtime)
  watchfiles "python -m app.serve" /app/app   (개발: 코드가 바뀌면 재시작)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from dataclasses import dataclass
from typing import Any

import uvicorn

from . import tlsutil
from .config import settings

log = logging.getLogger("app.serve")


@dataclass(frozen=True)
class Listener:
    role: str        # web | ingest | ingest-tls | ingest-internal
    port: int
    tls: bool
    lifespan: bool   # 시작 작업(마이그레이션, 연결 풀, 알림 엔진)은 화면 쪽 하나만

    @property
    def label(self) -> str:
        names = {"web": "화면", "ingest": "수집", "ingest-tls": "수집", "ingest-internal": "내부 수집"}
        return f"{names[self.role]} {self.port}({'TLS' if self.tls else '평문'})"


def listener_specs(s: Any) -> list[Listener]:
    specs = [Listener("web", s.web_listen_port, s.tls, True)]
    # TLS 가 꺼져 있으면 평문 수집을 끌 수 없다(받을 곳이 없어진다) — main() 이 오류 로그로 알린다
    if s.ingest_plain or not s.tls:
        specs.append(Listener("ingest", s.ingest_listen_port, False, False))
    if s.tls:
        specs.append(Listener("ingest-tls", s.ingest_tls_listen_port, True, False))
    specs.append(Listener("ingest-internal", s.internal_ingest_listen_port, False, False))
    return specs


def uvicorn_kwargs(s: Any, listener: Listener) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "host": "0.0.0.0", "port": listener.port, "timeout_graceful_shutdown": 5,   # 컨테이너 안이라 모든 주소
        "log_level": s.log_level.lower(),
        # 프록시 헤더는 적어 둔 프록시에서 온 것만 믿는다. 값을 직접 넘겨 환경변수 FORWARDED_ALLOW_IPS(.env 로 들어올 수
        # 있다)가 신뢰 범위를 바꾸지 못하게 한다 — 위조된 X-Forwarded-For 는 로그인 시도 제한·감사로그 IP 를 흔든다
        "proxy_headers": bool(s.trusted_proxies),
        "forwarded_allow_ips": ",".join(s.trusted_proxies) or "127.0.0.1",
    }
    if not listener.lifespan:
        kw["lifespan"] = "off"
    if listener.role != "web":
        kw["timeout_keep_alive"] = s.ingest_keepalive_sec
    if listener.tls:
        kw.update(ssl_certfile=s.tls_cert_file, ssl_keyfile=s.tls_key_file,
                  ssl_context_factory=tlsutil.server_context)
    return kw


class _Server(uvicorn.Server):
    """신호(SIGTERM/SIGINT)는 아래 main 에서 모든 서버에 한꺼번에 전달한다 (서버마다 잡으면 마지막 것만 받는다)."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def main() -> None:
    from .main import app  # 기동 전 점검이 실패하면 앱을 불러오지도 않는다

    specs = listener_specs(settings)
    servers = [(spec, _Server(uvicorn.Config(app, **uvicorn_kwargs(settings, spec)))) for spec in specs]
    web = servers[0][1]

    loop = asyncio.get_running_loop()

    def stop() -> None:
        for _, server in servers:
            server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)

    web_task = asyncio.create_task(web.serve())
    # 연결 풀이 열린 뒤에 수집을 받기 시작한다
    while not web.started and not web_task.done():
        await asyncio.sleep(0.05)
    if web_task.done():
        await web_task  # 시작 실패 — 예외를 그대로 올린다
        return
    line = " · ".join(spec.label for spec, _ in servers)
    st = tlsutil.status(settings)
    if st.not_after:
        line += f" / 인증서 만료 {st.not_after:%Y-%m-%d} (D-{st.days_left})"
    log.info("리스너: %s", line)
    if not settings.ingest_plain and not settings.tls:
        log.error("WLM_INGEST_PLAIN=off 는 WLM_TLS=on 일 때만 됩니다 — 받을 곳이 없어 평문 수집(%s)을 열어 둡니다",
                  settings.ingest_listen_port)
    await asyncio.gather(web_task, *(server.serve() for _, server in servers[1:]))


def run() -> None:
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    errors = tlsutil.preflight(settings)
    if errors:
        # 반쯤 뜬 상태(예: 화면만 평문, 수집 TLS 실패)를 만들지 않는다. 컨테이너는 재시작을 반복하며 로그에 같은 안내를 남긴다
        for text in errors:
            log.error("기동 중단: %s", text)
        sys.exit(2)
    asyncio.run(main())


if __name__ == "__main__":
    run()
