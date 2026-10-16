"""점검 보고서 API (BACKLOG B-05, ADR-032): 목록·열람·인쇄용 HTML·지금 만들기·점검 확인·다시 보내기.

보기·확인은 관리자 또는 reports.view 권한 그룹. 보고서는 모든 PC·분류를 담으므로 조회 범위가 정해진 사용자는 볼 수 없다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .. import db, repository
from ..auth.deps import client_ip, require_permission
from ..auth.service import User
from ..config import settings
from ..reports import config as report_config
from ..reports import render, scheduler

router = APIRouter(tags=["reports"])


async def report_reader(user: User = Depends(require_permission("reports.view"))) -> User:
    if user.scopes is not None:
        raise HTTPException(403, "조회 범위가 정해진 사용자는 전체 점검 보고서를 볼 수 없습니다")
    return user


async def _report(report_id: int) -> dict:
    row = await repository.get_report(report_id)
    if row is None:
        raise HTTPException(404, "보고서를 찾을 수 없습니다")
    return row


@router.get("/api/reports")
async def list_reports(limit: int = Query(100, ge=1, le=500), user: User = Depends(report_reader)):
    cfg = await report_config.load()
    return {
        "items": await repository.list_reports(limit),
        "unreviewed_30d": await repository.count_unreviewed_reports(datetime.now(UTC) - timedelta(days=30)),
        "schedule": cfg, "tz": settings.display_tz,
        "scheduler": {"last_run_at": scheduler.scheduler.last_run_at, "last_error": scheduler.scheduler.last_error},
    }


@router.get("/api/reports/{report_id}")
async def get_report(report_id: int, user: User = Depends(report_reader)):
    row = await _report(report_id)
    return {**row, "summary": render.summary(row["payload"]), "sha256": scheduler.payload_sha256(row["payload"])}


@router.get("/api/reports/{report_id}/html", response_class=HTMLResponse)
async def report_html(report_id: int, user: User = Depends(report_reader)):
    """화면 iframe·인쇄용. 로그에서 온 값이 들어 있어 스크립트를 막는 CSP 를 걸고, 같은 출처 iframe 만 허용한다."""
    row = await _report(report_id)
    return HTMLResponse(render.page(row["payload"], report_id, row), headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'",
        "X-Frame-Options": "SAMEORIGIN", "Cache-Control": "no-store"})


class CreateBody(BaseModel):
    kind: Literal["daily", "weekly"]


@router.post("/api/reports")
async def create_report(body: CreateBody, request: Request, user: User = Depends(report_reader)):
    """지금 만들기: 끝난 가장 최근 기간(어제·지난주)으로 만든다. 보내지는 않는다 (정기 보고서와 따로 저장)."""
    start, end = scheduler.latest_period(body.kind, datetime.now(UTC), ZoneInfo(settings.display_tz))
    report_id = await scheduler.generate(body.kind, start, end, scheduled=False, actor=user.username, send_to=[])
    return {"ok": True, "id": report_id}


class ReviewBody(BaseModel):
    note: str = Field(default="", max_length=4000)


@router.post("/api/reports/{report_id}/review")
async def review_report(report_id: int, body: ReviewBody, request: Request, user: User = Depends(report_reader)):
    """점검 확인: 누가 언제 보았고 무엇을 조치했는지. 한 번만 남기고 고칠 수 없다."""
    await _report(report_id)
    note = body.note.strip()
    if not await repository.review_report(report_id, user.username, note):
        raise HTTPException(409, "이미 확인한 보고서입니다")
    await db.audit(user.username, "report.review", f"보고서 #{report_id}", {"id": report_id, "note": note},
                   actor_ip=client_ip(request))
    return {"ok": True}


@router.post("/api/reports/{report_id}/send")
async def resend_report(report_id: int, request: Request, user: User = Depends(require_permission("settings.manage"))):
    """지금 설정된 받는 곳으로 다시 보낸다 (전송 실패했거나 '지금 만들기'로 만든 보고서)."""
    row = await _report(report_id)
    targets = (await report_config.load())["targets"]
    if not targets:
        raise HTTPException(422, "받는 곳이 없습니다 — 환경설정 > 점검 보고서에서 수신 그룹·웹훅을 고르세요")
    results = await scheduler.deliver(report_id, row["payload"], targets)
    await db.audit(user.username, "report.send", f"보고서 #{report_id}", {"id": report_id, "results": results},
                   actor_ip=client_ip(request))
    return {"ok": all(r["status"] == "sent" for r in results), "deliveries": results}
