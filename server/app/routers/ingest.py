"""수집 API: 에이전트(Fluent Bit http 출력)가 로그를 보내는 곳.

POST /api/ingest
  헤더   X-API-Key: <WLM_INGEST_API_KEYS 중 하나>
  본문   JSON 배열 | JSON 객체 | NDJSON (gzip 가능: Content-Encoding: gzip)
"""

from __future__ import annotations

import hmac
import json
import logging
import zlib
from datetime import UTC, datetime

from fastapi import APIRouter, Header, HTTPException, Request

from .. import live, repository
from ..config import settings
from ..normalizers import Event, Heartbeat, normalize

log = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])


def _check_key(key: str | None) -> None:
    if not settings.ingest_api_keys:
        raise HTTPException(503, "서버에 WLM_INGEST_API_KEYS 가 설정되지 않았습니다")
    if not key or not any(hmac.compare_digest(key, k) for k in settings.ingest_api_keys):
        raise HTTPException(401, "API 키가 올바르지 않습니다")


async def _read_body(request: Request) -> bytes:
    limit = settings.max_body_mb * 1024 * 1024
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, "요청 본문이 너무 큽니다")
        chunks.append(chunk)
    body = b"".join(chunks)
    if request.headers.get("content-encoding", "").lower() == "gzip" or body[:2] == b"\x1f\x8b":
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            body = decompressor.decompress(body, limit)
        except zlib.error as exc:
            raise HTTPException(400, "gzip 해제 실패") from exc
        if decompressor.unconsumed_tail:
            raise HTTPException(413, "압축 해제 후 본문이 너무 큽니다")
    return body


def _parse_records(body: bytes) -> list[dict]:
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:  # NDJSON (Fluent Bit format: json_lines)
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"JSON 형식 오류: {exc.msg}") from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise HTTPException(400, "JSON 배열 또는 객체를 보내야 합니다")
    return [r for r in data if isinstance(r, dict)]


@router.post("/api/ingest")
async def ingest(request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    _check_key(x_api_key)
    records = _parse_records(await _read_body(request))

    now = datetime.now(UTC)
    events: list[Event] = []
    heartbeats: list[Heartbeat] = []
    for record in records:
        item = normalize(record, now)
        if item is None:  # 저장하지 않는 줄 (IIS 머리줄 등)
            continue
        (heartbeats if isinstance(item, Heartbeat) else events).append(item)

    client_ip = request.client.host if request.client else None
    await repository.insert_batch(events, heartbeats, client_ip)

    live.ingest_rate.add(len(events))
    live.broadcaster.publish([e.to_live(now) for e in events])
    return {"accepted": len(events), "heartbeats": len(heartbeats)}
