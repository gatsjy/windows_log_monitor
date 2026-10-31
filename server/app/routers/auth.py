"""인증 API: 로그인, 2단계 인증(B-74), 로그아웃, 내 정보, 비밀번호 변경, 로그인 화면 안내문."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..auth import service
from ..auth.deps import COOKIE_NAME, check_csrf, client_ip, current_user, session_user, with_access
from ..auth.service import AuthError, User
from ..config import settings

router = APIRouter(tags=["auth"])


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class CodeBody(BaseModel):
    code: str = Field(max_length=64)


def _error(exc: AuthError) -> HTTPException:
    return HTTPException(exc.status, exc.message, headers={"X-WLM-Reason": exc.code})


def _cookie_secure(request: Request) -> bool:
    """https 로 온 요청은 자동으로 Secure (TLS·신뢰 프록시 뒤 모두). WLM_COOKIE_SECURE=true 는 http 에서도 강제."""
    return settings.cookie_secure or request.url.scheme == "https"


def _me(user: User) -> dict:
    if not user.mfa_ok:
        # 비밀번호까지만 맞은 세션 — 코드 화면에 필요한 것만 (마지막 로그인 IP·권한·범위를 비밀번호만 아는 사람에게 보이지 않게, 검토)
        return {"username": user.username, "display_name": user.display_name, "mfa_pending": True, "mfa_setup_required": False}
    return {
        **user.public(),
        "session_idle_min": settings.session_idle_min,
        "password_max_age_days": settings.password_max_age_days,
        # 비밀번호까지만 맞았다 — 화면이 인증 코드 입력으로 (B-74)
        "mfa_pending": not user.mfa_ok,
        "mfa_setup_required": user.mfa_ok and user.needs_mfa_setup,
    }


def _set_cookie(request: Request, response: Response, token: str) -> None:
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict", secure=_cookie_secure(request), path="/")


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
    _set_cookie(request, response, token)
    return _me(user)


# ------------------------------------------------------------------ 2단계 인증 (B-74)

@router.post("/api/auth/mfa/verify")
async def mfa_verify(body: CodeBody, request: Request, response: Response, user: User = Depends(session_user)):
    """비밀번호까지 맞은 세션 + 인증 코드(또는 복구 코드) → 정식 세션. 쿠키 토큰을 새로 준다."""
    if user.mfa_ok:
        return _me(user)
    try:
        token, done = await service.mfa_verify(request.state.session_token, user.username, body.code, client_ip(request),
                                               request.headers.get("user-agent"))
    except AuthError as exc:
        raise _error(exc) from exc
    await with_access(done)
    _set_cookie(request, response, token)
    return _me(done)


@router.get("/api/auth/mfa")
async def mfa_status(user: User = Depends(current_user)):
    return {**user.public()["mfa"], "recovery_left": await service.recovery_left(user.id) if user.mfa_enabled else 0}


@router.post("/api/auth/mfa/setup")
async def mfa_setup(request: Request, user: User = Depends(current_user)):
    """등록 시작 — 인증 앱에 넣을 비밀값(이 응답에서만 보인다)."""
    try:
        return await service.mfa_setup(user, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc


@router.post("/api/auth/mfa/enroll")
async def mfa_enroll(body: CodeBody, request: Request, user: User = Depends(current_user)):
    """등록 마침 — 복구 코드는 이 응답에서 한 번만 보인다."""
    try:
        codes = await service.mfa_enroll(user, request.state.session_token, body.code, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"recovery_codes": codes}


@router.post("/api/auth/mfa/recovery")
async def mfa_recovery(body: CodeBody, request: Request, user: User = Depends(current_user)):
    try:
        return {"recovery_codes": await service.mfa_regenerate(user, body.code, client_ip(request))}
    except AuthError as exc:
        raise _error(exc) from exc


@router.post("/api/auth/mfa/reenroll")
async def mfa_reenroll(body: CodeBody, request: Request, user: User = Depends(current_user)):
    """휴대폰을 바꿨거나 잃었을 때 — 지금 코드나 남은 복구 코드 하나로 지우고 다시 등록한다."""
    try:
        await service.mfa_reenroll(user, request.state.session_token, body.code, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"ok": True}


@router.post("/api/auth/mfa/disable")
async def mfa_disable(body: CodeBody, request: Request, user: User = Depends(current_user)):
    try:
        await service.mfa_disable(user, body.code, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"ok": True}


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response, user: User = Depends(session_user)):
    await service.logout(request.state.session_token, user, client_ip(request))
    # 지울 때도 같은 속성으로 (Secure 쿠키를 속성이 다른 Set-Cookie 로 지우면 브라우저가 무시할 수 있다)
    response.delete_cookie(COOKIE_NAME, path="/", secure=_cookie_secure(request), httponly=True, samesite="strict")
    return {"ok": True}


@router.get("/api/auth/me")
async def me(user: User = Depends(session_user)):
    return _me(user)


@router.post("/api/auth/password")
async def change_password(body: PasswordBody, request: Request, user: User = Depends(current_user)):
    try:
        await service.change_password(user, request.state.session_token, body.current_password,
                                      body.new_password, client_ip(request))
    except AuthError as exc:
        raise _error(exc) from exc
    return {"ok": True}
