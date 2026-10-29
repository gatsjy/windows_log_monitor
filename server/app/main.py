"""FastAPI 앱 진입점: 라우터 등록, 시작 시 마이그레이션/파티션 준비, 정적 UI 제공."""

from __future__ import annotations

import asyncio
import logging
import mimetypes
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders

from . import __version__, db, partitions, rejects, tlsutil
from .alerts import health as alert_health
from .alerts.dispatcher import dispatcher as alert_dispatcher
from .alerts.engine import engine as alert_engine
from .auth import service as auth_service
from .auth.deps import require_user
from .config import display_zone, settings
from .reports.scheduler import scheduler as report_scheduler
from .routers import agentpkg, alerts, audit, auth, dashboards, ingest, query, reports, users
from .routers import settings as settings_router

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")

MAINTENANCE_INTERVAL_SEC = 3600


def log_tls_problems() -> None:
    """인증서 만료·이름·CA 문제를 로그로 (기동 때, 그리고 하루 한 번). 만료되면 에이전트가 모두 보내지 못한다."""
    for level, text in tlsutil.status(settings).problems:
        (log.error if level == "error" else log.warning)("TLS: %s", text)


async def _maintenance_loop() -> None:
    tls_checked = None
    while True:
        await asyncio.sleep(MAINTENANCE_INTERVAL_SEC)
        try:
            await partitions.run_maintenance()
        except Exception:
            log.exception("파티션 유지보수 실패")
        if settings.tls and tls_checked != (today := datetime.now(UTC).date()):
            tls_checked = today
            log_tls_problems()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await db.migrate()
    await db.open_pool()
    await partitions.run_maintenance()
    await auth_service.bootstrap_admin()
    if not settings.ingest_api_keys:
        log.warning("WLM_INGEST_API_KEYS 가 비어 있어 로그 수집이 거부됩니다")
    if not settings.secret_key:
        log.warning("WLM_SECRET_KEY 가 비어 있어 환경설정에서 비밀번호(SMTP·Oracle 등)를 저장할 수 없습니다")
    if display_zone().key != settings.display_tz:
        log.warning("WLM_DISPLAY_TZ '%s' 를 알 수 없어 UTC 로 표시·계산합니다 (예: Asia/Seoul)", settings.display_tz)
    log_tls_problems()
    task = asyncio.create_task(_maintenance_loop())
    # 전송기를 먼저 — 엔진이 첫 주기에 넣은 알림을 바로 보낸다 (ADR-045). 끄는 것은 시험(conftest)뿐
    dispatch_task = asyncio.create_task(alert_dispatcher.run_forever()) if settings.alert_dispatcher else None
    if not settings.alert_dispatcher:
        log.error("WLM_ALERT_DISPATCHER=off — 알림이 기록만 되고 나가지 않습니다")
    alert_dispatcher.task = dispatch_task
    alert_task = asyncio.create_task(alert_engine.run_forever())
    alert_engine.task = alert_task
    rejects_task = asyncio.create_task(rejects.run_forever())
    report_task = asyncio.create_task(report_scheduler.run_forever()) if settings.report_scheduler else None
    log.info("Log Monitor %s 시작 (보관기간: 로그 %s일 · 알림 %s일 · 감사로그 %s일 · 점검 보고서 %s일)", __version__,
             settings.retention_days, settings.alert_retention_days, settings.audit_retention_days,
             settings.report_retention_days)
    for warning in partitions.retention_warnings():
        log.warning("보관기간 확인 필요: %s", warning)
    try:
        yield
    finally:
        task.cancel()
        alert_task.cancel()   # 알림 기록은 한 트랜잭션이라 중간에 멈춰도 반쪽이 남지 않는다
        if dispatch_task:   # 보내던 알림은 '보내는 중'으로 남고 다음 시작 때 다시 보낸다
            dispatch_task.cancel()
        rejects_task.cancel()
        if report_task:
            report_task.cancel()
        try:   # 모아 둔 수집 거절을 남기고 끝낸다
            await rejects.flush()
        except Exception:
            log.exception("수집 거절 장부 기록 실패")
        await db.close_pool()


INGEST_PORT_PATHS = ("/api/ingest", "/healthz")
# 평문 수집(8001)·TLS 수집(8002)·수집기 전용 내부 수집(8003) — app/serve.py
INGEST_LISTEN_PORTS = (settings.ingest_listen_port, settings.ingest_tls_listen_port, settings.internal_ingest_listen_port)


class IngestPortGuard:
    """수집 전용 포트로 들어온 요청은 수집·상태 확인만 허용한다 (화면·로그인·조회 API 는 404).
    판단 기준은 서버 소켓의 포트(scope["server"])라 요청 헤더로 속일 수 없다."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            port = (scope.get("server") or (None, None))[1]
            if port in INGEST_LISTEN_PORTS and scope.get("path") not in INGEST_PORT_PATHS:
                if scope["type"] == "websocket":
                    return await send({"type": "websocket.close", "code": 1008})
                response = JSONResponse({"detail": "수집 전용 포트입니다. 화면은 WLM_PORT(기본 8080)로 접속하세요"}, 404)
                return await response(scope, receive, send)
        return await self.app(scope, receive, send)


class SecurityHeaders:
    """기본 보안 헤더 (순수 ASGI 미들웨어 — SSE 스트리밍에 영향 없음).
    HSTS 는 https 응답에만, WLM_HSTS_MAX_AGE 를 정했을 때만 — 그 이름의 모든 포트에 걸리고 되돌리기 어려워 기본은 끈다.
    되돌릴 때는 0 으로 두어 'max-age=0' 을 보내야 브라우저가 지운다(헤더를 아예 안 보내면 기억이 남는다).
    includeSubDomains 는 넣지 않는다(같은 도메인의 다른 사내 서비스까지 묶지 않게)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "same-origin")
                if settings.hsts_max_age is not None and scope.get("scheme") == "https":
                    headers.setdefault("Strict-Transport-Security", f"max-age={settings.hsts_max_age}")
            await send(message)

        await self.app(scope, receive, send_with_headers)


# 슬림 이미지에는 글꼴 MIME 정보가 없어 octet-stream 으로 나간다
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("image/svg+xml", ".svg")


class UIStaticFiles(StaticFiles):
    """UI 파일은 브라우저에 캐시하지 않는다(no-store) → 파일 수정 후 새로고침만 하면 반영된다.
    (no-cache 만으로는 일부 브라우저가 메모리 캐시의 CSS/모듈을 재사용했다. 파일이 작아 비용은 미미)"""

    def file_response(self, full_path, *args, **kwargs):
        response = super().file_response(full_path, *args, **kwargs)
        # 글꼴은 크고(2MB) 바뀌지 않는다 → 하루 캐시. 나머지는 수정 즉시 반영되도록 no-store
        is_font = str(full_path).endswith((".woff2", ".woff"))
        response.headers["Cache-Control"] = "public, max-age=86400" if is_font else "no-store"
        return response


app = FastAPI(
    title="Log Monitor API", version=__version__, lifespan=lifespan,
    docs_url="/docs" if settings.api_docs else None, redoc_url=None,
    openapi_url="/openapi.json" if settings.api_docs else None,
)
app.add_middleware(SecurityHeaders)
app.add_middleware(IngestPortGuard)
# 공개: 수집(API 키로 보호), 로그인. 그 외 /api/* 는 로그인 필수, 변경 작업은 엔드포인트에서 관리자 확인
@app.exception_handler(query.QueryRejected)
async def _query_rejected(_: Request, exc: query.QueryRejected) -> JSONResponse:
    return JSONResponse(exc.body(), status_code=400)


def _timeout_message(path: str, exc: db.QueryTimeout) -> str:
    """그 화면에서 할 수 있는 고치는 방법만 안내한다 (수집 PC·규칙 미리보기에는 검색 문장 칸이 없다)."""
    if exc.busy:
        return f"조회가 몰려 {exc.seconds}초 안에 차례가 오지 않았습니다. 잠시 뒤 다시 시도하세요."
    if path.startswith(("/api/events", "/api/stats")):
        return (f"검색이 {exc.seconds}초 안에 끝나지 않아 멈췄습니다. 기간을 줄이거나 PC·이벤트 ID 같은 조건을 더해 보세요."
                " 2글자 이하 단어는 색인을 쓰지 못해 느립니다 — 붙어 있는 말이면 따옴표로 묶으세요.")
    if path.startswith("/api/alerts/rules/preview"):
        return (f"미리보기가 {exc.seconds}초 안에 끝나지 않아 멈췄습니다. 규칙의 조건을 좁혀 보세요"
                " (2글자 이하 단어는 따옴표로 묶기).")
    return f"조회가 {exc.seconds}초 안에 끝나지 않아 멈췄습니다. 기간을 줄여 보세요."


@app.exception_handler(db.QueryTimeout)
async def _query_timeout(request: Request, exc: db.QueryTimeout) -> JSONResponse:
    # 경고 줄은 경로만 — 전체 주소(조건)는 같은 요청의 접근 로그 줄에, 검색 조건은 감사로그(events.search)에도 있다
    log.warning("조회 시간 상한 %s초 %s: %s %s", exc.seconds, "자리 대기 초과" if exc.busy else "초과",
                request.method, request.url.path)
    return JSONResponse({"detail": _timeout_message(request.url.path, exc)}, status_code=503)


@app.exception_handler(db.AuditError)
async def _audit_failed(request: Request, exc: db.AuditError) -> JSONResponse:
    # 개인정보가 보이는 조회·내려받기는 접속기록을 남기지 못하면 결과를 내주지 않는다 (ADR-042)
    log.error("접속기록을 남기지 못해 응답을 거부함: %s %s (%s)", request.method, request.url.path, exc)
    return JSONResponse({"detail": "접속기록을 남기지 못해 조회를 거부했습니다. 잠시 뒤 다시 시도하고, 계속되면 관리자에게 알리세요."},
                        status_code=503)


app.include_router(ingest.router)
app.include_router(auth.router)
app.include_router(query.router, dependencies=[Depends(require_user)])
app.include_router(dashboards.router, dependencies=[Depends(require_user)])
app.include_router(alerts.router, dependencies=[Depends(require_user)])
app.include_router(reports.router, dependencies=[Depends(require_user)])
app.include_router(users.router)
app.include_router(audit.router)
app.include_router(settings_router.router)
app.include_router(agentpkg.router)  # 관리자 전용 (엔드포인트에서 확인)


@app.get("/healthz", tags=["ops"])
async def healthz():
    await db.fetch_one("SELECT 1")
    return {"status": "ok", "version": __version__}


@app.get("/healthz/alerts", tags=["ops"])
async def healthz_alerts(strict: bool = False):
    """알림 기능 상태 — 사내 감시 도구(Zabbix·PRTG·curl -f)용, 로그인 없음 (ADR-045).
    수와 코드만(규칙·받는 곳 이름, 오류 문구 없음), 10초 캐시. down 이면 503, strict 면 warn 도 503.
    수집 포트에서는 열리지 않는다(INGEST_PORT_PATHS 는 정확한 경로만). /healthz 는 DB 만 본다 —
    Docker HEALTHCHECK·install.sh 가 메일 서버 문제로 흔들리지 않게."""
    view = alert_health.public_view(await alert_health.current(), __version__)
    bad = view["status"] == "down" or (strict and view["status"] == "warn")
    return JSONResponse(jsonable_encoder(view), status_code=503 if bad else 200)


# API 라우트를 모두 등록한 뒤 마지막에 마운트해야 /api/* 를 가리지 않는다
app.mount("/", UIStaticFiles(directory=settings.web_dir, html=True), name="ui")
