"""심사 대응 API (BACKLOG B-73): ISMS 항목별 탐지·처리 현황과 기간 증적 묶음(zip + MANIFEST).

점검 보고서와 같은 권한(reports.view, 조회 범위가 없는 사용자) — 모든 PC·분류의 알림을 담는다. 묶음은 사유 필수·감사로그 필수
(MANIFEST 의 SHA-256 을 남겨 나중에 받은 파일이 바뀌지 않았는지 대조).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from .. import compliance, db
from ..alerts import coverage
from ..alerts.engine import engine
from ..auth.deps import client_ip
from ..auth.service import User
from ..csvexport import export_reason
from ..filters import FilterError, parse_time
from .query import read_time_limit
from .reports import report_reader

router = APIRouter(tags=["compliance"])
MAX_PERIOD = timedelta(days=400)


def _period(since: str, until: str | None) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    try:
        start, end = parse_time(since, now), parse_time(until, now) if until else now
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    if start is None or start >= end:
        raise HTTPException(400, "기간이 잘못되었습니다")
    if end - start > MAX_PERIOD:
        raise HTTPException(400, "기간은 400일까지 — 나눠서 받으세요")
    return start, end


@router.get("/api/compliance/isms", dependencies=[Depends(read_time_limit)])
async def isms_summary(since: str = "90d", until: str | None = None, user: User = Depends(report_reader)):
    start, end = _period(since, until)
    rules = engine.config.rules
    items = await compliance.summary(rules, await coverage.current(rules), start, end)
    return {"since": start, "until": end, "items": items}


@router.get("/api/compliance/isms/bundle", dependencies=[Depends(read_time_limit)])
async def isms_bundle(request: Request, since: str = "90d", until: str | None = None,
                      reason: str | None = Query(None, max_length=200), user: User = Depends(report_reader)):
    why = export_reason(reason)
    start, end = _period(since, until)
    now = datetime.now(UTC)
    rules = engine.config.rules
    data, manifest_sha, info = await compliance.bundle(rules, await coverage.current(rules), start, end, user.username, why, now)
    # 감사로그를 남기지 못하면 묶음을 주지 않는다 (사람·IP 가 담긴 증적 반출, ADR-042)
    await db.audit(user.username, "compliance.bundle", "isms",
                   {"since": start.isoformat(), "until": end.isoformat(), "reason": why, "manifest_sha256": manifest_sha,
                    "bytes": len(data), **info}, actor_ip=client_ip(request), required=True)
    name = f"isms_evidence_{start:%Y%m%d}_{end:%Y%m%d}.zip"
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "X-WLM-Manifest-SHA256": manifest_sha})
