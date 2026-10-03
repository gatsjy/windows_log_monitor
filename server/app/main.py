"""FastAPI 앱 진입점: 라우터 등록, 시작 시 마이그레이션/파티션 준비, 정적 UI 제공."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders

from . import __version__, db, partitions
from .alerts.engine import engine as alert_engine
from .auth import service as auth_service
from .auth.deps import require_user
from .config import settings
from .routers import alerts, audit, auth, dashboards, ingest, query, users
from .routers import settings as settings_router

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")

MAINTENANCE_INTERVAL_SEC = 3600


async def _maintenance_loop() -> None:
    while True:
        await asyncio.sleep(MAINTENANCE_INTERVAL_SEC)
        try:
            await partitions.run_maintenance()
        except Exception:
            log.exception("파티션 유지보수 실패")


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
    task = asyncio.create_task(_maintenance_loop())
    alert_task = asyncio.create_task(alert_engine.run_forever())
    log.info("Log Monitor %s 시작 (보관기간 %s일)", __version__, settings.retention_days)
    try:
        yield
    finally:
        task.cancel()
        alert_task.cancel()
        await db.close_pool()


class SecurityHeaders:
    """기본 보안 헤더 (순수 ASGI 미들웨어 — SSE 스트리밍에 영향 없음)."""

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
            await send(message)

        await self.app(scope, receive, send_with_headers)


class UIStaticFiles(StaticFiles):
    """UI 파일은 브라우저에 캐시하지 않는다(no-store) → 파일 수정 후 새로고침만 하면 반영된다.
    (no-cache 만으로는 일부 브라우저가 메모리 캐시의 CSS/모듈을 재사용했다. 파일이 작아 비용은 미미)"""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-store"
        return response


app = FastAPI(
    title="Log Monitor API", version=__version__, lifespan=lifespan,
    docs_url="/docs" if settings.api_docs else None, redoc_url=None,
    openapi_url="/openapi.json" if settings.api_docs else None,
)
app.add_middleware(SecurityHeaders)
# 공개: 수집(API 키로 보호), 로그인. 그 외 /api/* 는 로그인 필수, 변경 작업은 엔드포인트에서 관리자 확인
app.include_router(ingest.router)
app.include_router(auth.router)
app.include_router(query.router, dependencies=[Depends(require_user)])
app.include_router(dashboards.router, dependencies=[Depends(require_user)])
app.include_router(alerts.router, dependencies=[Depends(require_user)])
app.include_router(users.router)
app.include_router(audit.router)
app.include_router(settings_router.router)


@app.get("/healthz", tags=["ops"])
async def healthz():
    await db.fetch_one("SELECT 1")
    return {"status": "ok", "version": __version__}


# API 라우트를 모두 등록한 뒤 마지막에 마운트해야 /api/* 를 가리지 않는다
app.mount("/", UIStaticFiles(directory=settings.web_dir, html=True), name="ui")
