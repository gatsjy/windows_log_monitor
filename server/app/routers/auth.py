"""인증 API: 로그인, 로그아웃, 내 정보, 비밀번호 변경, 로그인 화면 안내문."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..auth import service
from ..auth.deps import COOKIE_NAME, check_csrf, client_ip, current_user, with_access
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


def _cookie_secure(request: Request) -> bool:
    """https 로 온 요청은 자동으로 Secure (TLS·신뢰 프록시 뒤 모두). WLM_COOKIE_SECURE=true 는 http 에서도 강제."""
    return settings.cookie_secure or request.url.scheme == "https"


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
    if settings.cookie_secure and request.url.scheme != "https":
        # 브라우저는 http 에서 Secure 쿠키를 버린다 — 비밀번호가 맞아도 '로그인이 안 되는' 조용한 실패 대신 바로 안내
        raise HTTPException(400, f"HTTPS 주소로 접속하세요: {settings.public_url}", headers={"X-WLM-Reason": "https_required"})
    try:
        token, user = await service.login(body.username, body.password, client_ip(request),
                                          request.headers.get("user-agent"))
    except AuthError as exc:
        raise _error(exc) from exc
    await with_access(user)
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, samesite="strict", secure=_cookie_secure(request), path="/",
    )
    return _me(user)


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response, user: User = Depends(current_user)):
    await service.logout(request.state.session_token, user, client_ip(request))
    # 지울 때도 같은 속성으로 (Secure 쿠키를 속성이 다른 Set-Cookie 로 지우면 브라우저가 무시할 수 있다)
    response.delete_cookie(COOKIE_NAME, path="/", secure=_cookie_secure(request), httponly=True, samesite="strict")
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
