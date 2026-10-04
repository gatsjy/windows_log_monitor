"""수집 전용 포트: /api/ingest·/healthz 만 통과, 나머지는 404 (판단은 서버 소켓 포트 기준)."""

from __future__ import annotations

import asyncio

from app.config import settings
from app.main import IngestPortGuard


def call(path: str, port: int) -> int:
    reached = []

    async def inner(scope, receive, send):
        reached.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "path": path, "method": "GET", "headers": [], "server": ("0.0.0.0", port), "query_string": b""}
    asyncio.run(IngestPortGuard(inner)(scope, receive, send))
    return sent[0]["status"]


def test_ingest_port_allows_only_ingest_and_health():
    port = settings.ingest_listen_port
    assert call("/api/ingest", port) == 200
    assert call("/healthz", port) == 200
    assert call("/", port) == 404
    assert call("/api/events", port) == 404
    assert call("/api/auth/login", port) == 404


def test_web_port_is_not_restricted():
    assert call("/api/events", 8000) == 200
    assert call("/", 8000) == 200
