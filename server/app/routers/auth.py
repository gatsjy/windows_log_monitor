"""인증 API: 로그인, 로그아웃, 내 정보, 비밀번호 변경, 로그인 화면 안내문."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..auth import service
from ..auth.deps import COOKIE_NAME, check_csrf, client_ip, current_user
from ..auth.service import AuthError, User
from ..config import settings

router = APIRouter(tags=["auth"])


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


def _error(exc: AuthError) -> HTTPException:
    return HTTPException(exc.status, exc.message, headers={"X-WLM-Reason": exc.code})


def _me(user: User) -> dict:
    return {
        **user.public(),
        "session_idle_min": settings.session_idle_min,
        "password_max_age_days": settings.password_max_age_days,
    }


@router.get("/api/auth/info")
async def login_info():
    """로그인 전에도 볼 수 있는 정보 (안내문, 버전)."""
    return {"notice": settings.login_notice, "version": __version__}


@router.post("/api/auth/login")
async def login(body: LoginBody, request: Request, response: Response):
    check_csrf(request)
    try:
        token, user = await service.login(body.username, body.password, client_ip(request),
                                          request.headers.get("user-agent"))
    except AuthError as exc:
        raise _error(exc) from exc
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, samesite="strict", secure=settings.cookie_secure, path="/",
    )
    return _me(user)


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response, user: User = Depends(current_user)):
    await service.logout(request.state.session_token, user, client_ip(request))
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/api/auth/me")
async def me(user: User = Depends(current_user)):
    return _me(user)


@router.post("/api/auth/password")
async def change_password(body: PasswordBody, request: Request, user: User = Depends(current_user)):
    try:
        await service.change_password(user, request.state.session_token, body.current_password,
                                      body.new_password, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"ok": True}
