"""사용자 관리 API (관리자 전용). 계정 생성·역할·활성 여부·비밀번호 초기화·잠금 해제, 사용자 그룹(권한·조회 범위)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import db
from ..alerts import adminwatch
from ..alerts.message import local
from ..auth import groups, review, service
from ..auth.deps import client_ip, require_admin
from ..auth.service import ROLE_LABELS, AuthError, User
from ..config import settings
from ..csvexport import csv_response, export_reason
from ..normalizers.categories import CATEGORIES

router = APIRouter(tags=["users"], dependencies=[Depends(require_admin)])


class CreateBody(BaseModel):
    username: str = Field(max_length=64)
    display_name: str = Field(default="", max_length=100)
    role: str = "viewer"


class UpdateBody(BaseModel):
    display_name: str | None = Field(default=None, max_length=100)
    role: str | None = None
    is_active: bool | None = None


def _error(exc: AuthError) -> HTTPException:
    return HTTPException(exc.status, exc.message)


@router.get("/api/users")
async def list_users():
    now = datetime.now(UTC)
    items = await service.list_users()
    member_of = await groups.memberships()
    for row in items:
        row["groups"] = member_of.get(row["id"], [])
        user = service.row_to_user(row)
        row["role_label"] = ROLE_LABELS.get(row["role"], row["role"])
        row["locked"] = bool(row["locked_until"] and row["locked_until"] > now)
        row["password_expired"] = user.password_expired
        row["mfa_enabled"] = user.mfa_enabled
    return {"items": items, "roles": ROLE_LABELS}


@router.post("/api/users")
async def create_user(body: CreateBody, request: Request, admin: User = Depends(require_admin)):
    try:
        row, temp = await service.create_user(body.username, body.display_name, body.role, admin.username,
                                              client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    if body.role == "admin":   # 관리 권한 부여는 다른 사람에게도 알린다 (B-36)
        await adminwatch.notify(admin.username, "관리 권한 부여", [f"관리자 계정 '{row['username']}' 을(를) 만들었습니다"])
    # 임시 비밀번호는 이 응답에서 한 번만 보여준다 (저장하지 않음)
    return {"user": row, "temp_password": temp}


@router.patch("/api/users/{user_id}")
async def update_user(user_id: int, body: UpdateBody, request: Request, admin: User = Depends(require_admin)):
    before = await service.user_brief(user_id)
    try:
        await service.update_user(user_id, body.model_dump(exclude_none=True), admin, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    after = await service.user_brief(user_id)
    if before and after and after["role"] == "admin" and after["is_active"] and not (
            before["role"] == "admin" and before["is_active"]):
        await adminwatch.notify(admin.username, "관리 권한 부여",
                                [f"'{after['username']}' 을(를) 관리자로 {'바꿨' if before['role'] != 'admin' else '다시 켰'}습니다"])
    return {"ok": True}


@router.post("/api/users/{user_id}/reset-password")
async def reset_password(user_id: int, request: Request, admin: User = Depends(require_admin)):
    try:
        username, temp = await service.reset_password(user_id, admin.username, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"username": username, "temp_password": temp}


@router.post("/api/users/{user_id}/mfa/reset")
async def reset_mfa(user_id: int, request: Request, admin: User = Depends(require_admin)):
    """인증 앱을 잃은 사람의 2단계 인증 초기화 (B-74) — 그 사람의 세션을 끊고, 필수면 다음 로그인 때 다시 등록한다.
    인증이 약해지는 관리 작업이라 다른 받는 곳에도 알린다 (B-36)."""
    try:
        username = await service.mfa_reset(user_id, admin.username, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    await adminwatch.notify(admin.username, "2단계 인증 초기화", [f"'{username}' 의 2단계 인증을 초기화했습니다"])
    return {"ok": True, "username": username}


@router.post("/api/users/{user_id}/unlock")
async def unlock(user_id: int, request: Request, admin: User = Depends(require_admin)):
    try:
        await service.unlock(user_id, admin.username, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"ok": True}


# ------------------------------------------------------------ 사용자 그룹
class GroupBody(BaseModel):
    name: str = Field(max_length=64)
    description: str = Field(default="", max_length=200)
    permissions: list[str] = Field(default_factory=list, max_length=20)
    scope_categories: list[str] = Field(default_factory=list, max_length=50)
    scope_hosts: list[str] = Field(default_factory=list, max_length=200)
    member_ids: list[int] = Field(default_factory=list, max_length=1000)


@router.get("/api/user-groups")
async def list_user_groups():
    """그룹 목록 + 화면에서 고를 수 있는 권한·분류 목록."""
    return {"items": await groups.list_groups(), "permissions": groups.PERMISSIONS, "categories": CATEGORIES}


async def _save_group(group_id: int | None, body: GroupBody, request: Request, admin: User) -> dict[str, Any]:
    old = next((g for g in await groups.list_groups() if g["id"] == group_id), None) if group_id else None
    try:
        saved = await groups.save(group_id, body.model_dump())
    except groups.GroupError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    await db.audit(admin.username, "user_group.save", saved["name"],
                   {k: saved[k] for k in ("permissions", "scope_categories", "scope_hosts", "member_ids")},
                   actor_ip=client_ip(request))
    await adminwatch.privileged_group(admin.username, saved["name"], old, saved)
    return saved


@router.post("/api/user-groups")
async def create_user_group(body: GroupBody, request: Request, admin: User = Depends(require_admin)):
    return await _save_group(None, body, request, admin)


@router.put("/api/user-groups/{group_id}")
async def update_user_group(group_id: int, body: GroupBody, request: Request, admin: User = Depends(require_admin)):
    return await _save_group(group_id, body, request, admin)


@router.delete("/api/user-groups/{group_id}")
async def delete_user_group(group_id: int, request: Request, admin: User = Depends(require_admin)):
    try:
        name = await groups.delete(group_id)
    except groups.GroupError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    await db.audit(admin.username, "user_group.delete", name, {}, actor_ip=client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------ 분기 권한 검토 (B-72 2단계, ISMS 2.5.6, ADR-058)
class ReviewStart(BaseModel):
    title: str = Field(min_length=2, max_length=100)


class ReviewEntry(BaseModel):
    kind: str = Field(pattern="^(decision|sign|approve|reject)$")
    user_id: int | None = None
    decision: str | None = None
    note: str = Field(default="", max_length=1000)


REVIEW_ACTIONS = {"decision": "access_review.decision", "sign": "access_review.sign", "approve": "access_review.approve",
                  "reject": "access_review.reject"}


@router.get("/api/access-reviews")
async def access_reviews():
    return {"items": await review.list_reviews(), "days": settings.access_review_days,
            "decisions": review.DECISIONS, "statuses": review.STATUS_LABELS}


@router.post("/api/access-reviews")
async def start_access_review(body: ReviewStart, request: Request, admin: User = Depends(require_admin)):
    review_id = await review.start(body.title.strip(), admin.username)
    await db.audit(admin.username, "access_review.start", body.title.strip(), {"id": review_id}, actor_ip=client_ip(request))
    return {"id": review_id}


@router.get("/api/access-reviews/{review_id}")
async def access_review(review_id: int):
    try:
        return await review.get(review_id)
    except review.ReviewError as exc:
        raise HTTPException(exc.status, exc.message) from exc


@router.post("/api/access-reviews/{review_id}/entries")
async def access_review_entry(review_id: int, body: ReviewEntry, request: Request, admin: User = Depends(require_admin)):
    try:
        res = await review.add(review_id, body.kind, admin.username, user_id=body.user_id, decision=body.decision,
                               note=body.note)
    except review.ReviewError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    entry = res["entry"]
    detail = {"id": review_id, "title": res["title"], "note": entry["note"]}
    if body.kind == "decision":
        detail |= {"user": entry["username"], "decision": entry["decision"]}
    await db.audit(admin.username, REVIEW_ACTIONS[body.kind], entry["username"] or res["title"], detail,
                   actor_ip=client_ip(request))
    return {"ok": True, "entry": entry}


@router.get("/api/access-reviews/{review_id}/csv")
async def access_review_csv(review_id: int, request: Request, reason: str | None = None, admin: User = Depends(require_admin)):
    """검토 결과 증적 (계정·역할·그룹·권한·마지막 사용·결정·사유·결정한 사람, 맨 끝에 서명·승인). 사유 필수(ADR-042)."""
    why = export_reason(reason)
    try:
        r = await review.get(review_id)
    except review.ReviewError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    await db.audit(admin.username, "access_review.export", r["title"], {"id": review_id, "rows": len(r["users"]), "reason": why},
                   actor_ip=client_ip(request), required=True)
    rows = [[u["username"], u["display_name"], u["role_label"], "켜짐" if u["is_active"] else "꺼짐", ", ".join(u["groups"]),
             ", ".join(u["permissions"]), "예" if u["scoped"] else "", "예" if u["mfa"] else "", _local(u["last_used"]),
             review.DECISIONS.get((u["decision"] or {}).get("decision"), ""), (u["decision"] or {}).get("note", ""),
             (u["decision"] or {}).get("author", ""), _local((u["decision"] or {}).get("at")),
             {True: "켜짐", False: "꺼짐", None: "지움"}[u["now_active"]]] for u in r["users"]]
    for label, e in (("서명", r["signed"]), ("승인", r["approved"])):
        if e:
            rows.append([f"({label})", e["author"], "", "", "", "", "", "", "", "", e["note"], e["author"], _local(e["at"]), ""])
    return csv_response(["아이디", "이름", "역할", "검토 때 상태", "그룹", "권한", "조회 범위 있음", "2단계 인증", "마지막 사용",
                         "결정", "사유", "결정한 사람", "결정 시각", "지금 상태"], rows, f"access-review-{review_id}.csv")


def _local(value: Any) -> str:
    if not value:
        return ""
    return local(value if isinstance(value, datetime) else datetime.fromisoformat(value))
