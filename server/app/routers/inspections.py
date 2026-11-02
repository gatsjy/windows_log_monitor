"""접속기록 점검 결과서 API (BACKLOG B-72 3단계, ISMS 2.9.5, ADR-060).

점검 보고서와 같은 권한(reports.view, 조회 범위 없는 사용자) — 점검 담당자를 관리자가 아닌 사람으로도 둘 수 있게. 결재는 서명한 사람과
다른 사람이 승인·반려한다. 모든 동작은 감사로그 inspection.*.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import accesslog, db, inspection
from ..alerts.message import local
from ..auth.deps import client_ip
from ..auth.service import User
from ..config import display_zone, settings
from ..csvexport import csv_response, export_reason
from .reports import report_reader

router = APIRouter(tags=["inspections"])


class StartBody(BaseModel):
    title: str = Field(min_length=2, max_length=100)
    period_start: datetime | None = None   # 비우면 지난달 (표시 시간대)
    period_end: datetime | None = None


class EntryBody(BaseModel):
    kind: str = Field(pattern="^(result|sign|approve|reject)$")
    item: str | None = Field(default=None, max_length=40)
    result: str | None = None
    note: str = Field(default="", max_length=2000)


ACTIONS = {"result": "inspection.result", "sign": "inspection.sign", "approve": "inspection.approve",
           "reject": "inspection.reject"}


def _error(exc: inspection.InspectionError) -> HTTPException:
    return HTTPException(exc.status, exc.message)


@router.get("/api/inspections")
async def list_inspections(user: User = Depends(report_reader)):
    now = datetime.now(UTC)
    start, end = inspection.last_month(now)
    return {"items": await inspection.list_inspections(), "days": settings.access_log_inspection_days,
            "grace_days": inspection.grace_days(settings.access_log_inspection_days),
            "default_period": {"start": start, "end": end, "title": inspection.month_title(start)},
            "results": inspection.RESULTS, "statuses": inspection.STATUS_LABELS}


def _aware(at: datetime) -> datetime:
    # 시간대 없이 온 값은 표시 시간대로 본다 (그대로 두면 지금 시각과 비교하다 500)
    return at if at.tzinfo else at.replace(tzinfo=display_zone())


@router.post("/api/inspections")
async def start_inspection(body: StartBody, request: Request, user: User = Depends(report_reader)):
    now = datetime.now(UTC)
    if (body.period_start is None) != (body.period_end is None):
        raise HTTPException(422, "기간은 시작과 끝을 함께 주세요 (둘 다 비우면 지난달)")
    start, end = (_aware(body.period_start), _aware(body.period_end)) if body.period_start else inspection.last_month(now)
    try:
        inspection_id = await inspection.start(body.title.strip(), start, end, user.username, now)
    except inspection.InspectionError as exc:
        raise _error(exc) from exc
    await db.audit(user.username, "inspection.start", body.title.strip(),
                   {"id": inspection_id, "period_start": start.isoformat(), "period_end": end.isoformat()},
                   actor_ip=client_ip(request))
    return {"id": inspection_id}


@router.get("/api/inspections/{inspection_id}")
async def get_inspection(inspection_id: int, request: Request, user: User = Depends(report_reader)):
    """근거에 계정 이름·로그인 시각·내려받기 사유가 든다 — 접속기록을 남긴다(ADR-042, 같은 CSV 는 사유까지 받는다)."""
    try:
        r = await inspection.get(inspection_id)
    except inspection.InspectionError as exc:
        raise _error(exc) from exc
    await accesslog.record(request, user.username, "inspection.view", str(inspection_id), {"title": r["title"]})
    return r


@router.post("/api/inspections/{inspection_id}/entries")
async def add_entry(inspection_id: int, body: EntryBody, request: Request, user: User = Depends(report_reader)):
    try:
        res = await inspection.add(inspection_id, body.kind, user.username, item=body.item, result=body.result, note=body.note)
    except inspection.InspectionError as exc:
        raise _error(exc) from exc
    entry = res["entry"]
    await db.audit(user.username, ACTIONS[body.kind], res["title"],
                   {"id": inspection_id, "item": entry["item"], "result": entry["result"], "note": entry["note"]},
                   actor_ip=client_ip(request))
    return {"ok": True, "entry": entry}


@router.get("/api/inspections/{inspection_id}/csv")
async def inspection_csv(inspection_id: int, request: Request, reason: str | None = None, user: User = Depends(report_reader)):
    """점검 결과서 (항목·근거 조항·근거 요약·결과·조치·적은 사람, 맨 끝에 서명·승인). 계정 이름이 들어가 사유 필수(ADR-042)."""
    why = export_reason(reason)
    try:
        r = await inspection.get(inspection_id)
    except inspection.InspectionError as exc:
        raise _error(exc) from exc
    await db.audit(user.username, "inspection.export", r["title"], {"id": inspection_id, "rows": len(r["items"]), "reason": why},
                   actor_ip=client_ip(request), required=True)
    rows = [[i["label"], i["basis"], i["summary"], inspection.RESULTS.get((i["result"] or {}).get("result"), ""),
             (i["result"] or {}).get("note", ""), (i["result"] or {}).get("author", ""),
             local((i["result"] or {}).get("at")) if i["result"] else ""] for i in r["items"]]
    for label, e in (("(서명)", r["signed"]), ("(승인)", r["approved"])):
        if e:
            rows.append([label, "", "", "", e["note"], e["author"], local(e["at"])])
    return csv_response(["점검 항목", "근거 조항", "점검 근거 (기간의 숫자)", "결과", "조치·의견", "적은 사람", "시각"], rows,
                        f"access-log-inspection-{inspection_id}.csv")
