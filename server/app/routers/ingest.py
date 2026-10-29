"""수집 API: 에이전트(Fluent Bit http 출력)가 로그를 보내는 곳.

POST /api/ingest
  헤더   X-API-Key: <WLM_INGEST_API_KEYS 중 하나>
  본문   JSON 배열 | JSON 객체 | NDJSON (gzip 가능: Content-Encoding: gzip)
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import zlib
from datetime import UTC, datetime

from fastapi import APIRouter, Header, HTTPException, Request
from starlette.requests import ClientDisconnect

from .. import live, rejects, repository
from ..config import settings
from ..normalizers import Event, Heartbeat, layout_keys, normalize_safely

log = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])


def _check_key(key: str | None) -> None:
    if not settings.ingest_api_keys:
        raise HTTPException(503, "서버에 WLM_INGEST_API_KEYS 가 설정되지 않았습니다")
    if not key:
        raise HTTPException(401, "API 키(X-API-Key)가 없습니다")
    # 바이트로 비교 — 헤더는 latin-1 로 풀려 오는데 compare_digest 는 ASCII 아닌 str 이면 TypeError(→ 500)를 낸다
    # (붙여 넣다 섞인 따옴표·공백 문자 하나로 '키 오류'가 '서버 오류'로 보였다, 검토에서 재현)
    given = key.encode("latin-1", "replace")
    if not any(hmac.compare_digest(given, k.encode()) for k in settings.ingest_api_keys):
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


# JSON 의 \ud800~\udfff 이스케이프. json.loads 는 짝이 맞는 것을 한 글자로 합치므로, 남은 서로게이트는 모두 짝이 없다
_SURROGATE_ESCAPE = re.compile(r"\\u[dD][89a-fA-F]")
_SURROGATE = re.compile("[\ud800-\udfff]")


def _fix_surrogates(root: dict) -> dict:
    """짝 없는 서로게이트는 UTF-8 로 보낼 수 없어(PostgreSQL TEXT·jsonb 모두) 레코드 하나가 요청 전체를 500 으로 만들고,
    에이전트는 그 청크를 끝없이 다시 보낸다(B-40, 재현). U+FFFD 로 바꾼다 — 저장할 수 없는 글자만 바꾸는 것은 NUL 과 같다.
    json.loads 가 막 만든 객체라 제자리에서 고친다. 재귀하지 않는다 — 깊게 겹친 JSON 에서 RecursionError 로 요청 전체가
    실패했다(검토에서 재현)."""
    def fix(text: str) -> str:
        return _SURROGATE.sub("\ufffd", text)

    stack: list = [root]
    while stack:
        obj = stack.pop()
        if isinstance(obj, dict):
            items = list(obj.items())
            obj.clear()
            for key, value in items:
                if isinstance(value, str):
                    value = fix(value)
                elif isinstance(value, (dict, list)):
                    stack.append(value)
                obj[fix(key) if isinstance(key, str) else key] = value
        else:
            for i, value in enumerate(obj):
                if isinstance(value, str):
                    obj[i] = fix(value)
                elif isinstance(value, (dict, list)):
                    stack.append(value)
    return root


def _constant(name: str) -> str:
    """JSON 의 NaN·Infinity 는 PostgreSQL jsonb 가 받지 못한다 — 글자로 둔다 (저장이 실패해 레코드마다 DB 를 두드리지 않게)."""
    return name


def _parse_records(body: bytes) -> list[dict]:
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        data = json.loads(text, parse_constant=_constant)
    except json.JSONDecodeError:
        try:  # NDJSON (Fluent Bit format: json_lines)
            data = [json.loads(line, parse_constant=_constant) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"JSON 형식 오류: {exc.msg}") from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise HTTPException(400, "JSON 배열 또는 객체를 보내야 합니다")
    records = [r for r in data if isinstance(r, dict)]
    # 본문에 서로게이트 이스케이프가 있을 때만 훑는다 (거의 모든 요청은 그냥 지나간다)
    return [_fix_surrogates(r) for r in records] if _SURROGATE_ESCAPE.search(text) else records


@router.post("/api/ingest")
async def ingest(request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    """거절(4xx·5xx)은 수집 거절 장부에 남긴다 (B-40) — 에이전트 쪽 로그는 같은 출력이라 그동안 서버로 오지 못한다."""
    client_ip = request.client.host if request.client else None
    try:
        return await _ingest(request, x_api_key, client_ip)
    except HTTPException as exc:
        rejects.note(client_ip, exc.status_code, str(exc.detail))
        raise
    except ClientDisconnect:   # 보내는 도중 PC 가 꺼지거나 끊김 — 서버가 거절한 것이 아니다 (보고서 '점검 필요'에는 넣지 않음)
        rejects.note(client_ip, 499, "보내는 쪽이 연결을 끊음")
        raise
    except Exception as exc:
        rejects.note(client_ip, 500, f"서버 오류 ({type(exc).__name__})")
        raise


async def _ingest(request: Request, x_api_key: str | None, client_ip: str | None) -> dict:
    _check_key(x_api_key)
    records = _parse_records(await _read_body(request))

    now = datetime.now(UTC)
    # IIS 열 순서: 이 요청에 든 파일들의 저장된 순서를 한 번에 (ADR-037). IIS 가 없으면 DB 에 묻지 않는다
    iis_ctx = await repository.iis_context(layout_keys(records))
    events: list[Event] = []
    heartbeats: list[Heartbeat] = []
    for record in records:
        item = normalize_safely(record, now, iis_ctx)
        if item is None:  # 저장하지 않는 줄 (IIS 머리줄 등)
            continue
        (heartbeats if isinstance(item, Heartbeat) else events).append(item)

    # TLS 리스너(또는 TLS 를 끝낸 신뢰 프록시 — X-Forwarded-Proto)로 왔는지. 하트비트에만 기록된다 (ADR-036).
    # 화면 포트(8080)로 오는 평문은 0.4 이전 설치 묶음이다 — TLS 를 켜면 그 포트가 https 만 받아 끊기므로 따로 표시한다
    if request.url.scheme == "https":
        transport = "tls"
    elif (request.scope.get("server") or (None, None))[1] == settings.web_listen_port:
        transport = "web"
    else:
        transport = "plain"
    try:
        bad = await repository.insert_batch(events, heartbeats, client_ip, transport, iis_ctx.learned)
    except repository.TooManyBadRecords as exc:
        raise HTTPException(400, "저장할 수 없는 값이 든 레코드가 너무 많아 요청을 받지 않았습니다") from exc
    repository.remember_iis_layouts(iis_ctx.learned)
    if bad:   # 격리한 레코드는 저장되지 않았다 — 실시간·수에서도 뺀다 (200 이라 에이전트는 다시 보내지 않는다)
        gone = {id(e) for e in bad}
        events = [e for e in events if id(e) not in gone]

    live.ingest_rate.add(len(events))
    live.broadcaster.publish([e.to_live(now) for e in events])
    return {"accepted": len(events), "heartbeats": len(heartbeats), **({"quarantined": len(bad)} if bad else {})}
