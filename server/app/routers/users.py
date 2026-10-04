"""사용자 관리 API (관리자 전용). 계정 생성·역할·활성 여부·비밀번호 초기화·잠금 해제, 사용자 그룹(권한·조회 범위)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import db
from ..auth import groups, service
from ..auth.deps import client_ip, require_admin
from ..auth.service import ROLE_LABELS, AuthError, User
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
    return {"items": items, "roles": ROLE_LABELS}


@router.post("/api/users")
async def create_user(body: CreateBody, request: Request, admin: User = Depends(require_admin)):
    try:
        row, temp = await service.create_user(body.username, body.display_name, body.role, admin.username,
                                              client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    # 임시 비밀번호는 이 응답에서 한 번만 보여준다 (저장하지 않음)
    return {"user": row, "temp_password": temp}


@router.patch("/api/users/{user_id}")
async def update_user(user_id: int, body: UpdateBody, request: Request, admin: User = Depends(require_admin)):
    try:
        await service.update_user(user_id, body.model_dump(exclude_none=True), admin, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"ok": True}


@router.post("/api/users/{user_id}/reset-password")
async def reset_password(user_id: int, request: Request, admin: User = Depends(require_admin)):
    try:
        username, temp = await service.reset_password(user_id, admin.username, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"username": username, "temp_password": temp}


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
    try:
        saved = await groups.save(group_id, body.model_dump())
    except groups.GroupError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    await db.audit(admin.username, "user_group.save", saved["name"],
                   {k: saved[k] for k in ("permissions", "scope_categories", "scope_hosts", "member_ids")},
                   actor_ip=client_ip(request))
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
