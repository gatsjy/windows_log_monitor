"""사용자 관리 API (관리자 전용). 계정 생성·역할·활성 여부·비밀번호 초기화·잠금 해제."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..auth import service
from ..auth.deps import client_ip, require_admin
from ..auth.service import ROLE_LABELS, AuthError, User

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
    for row in items:
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
