"""FastAPI 의존성: 로그인 확인, 관리자 확인, CSRF 확인.

라우터에 붙이는 방법 (main.py):
    app.include_router(query.router, dependencies=[Depends(require_user)])
엔드포인트에서 사용자 정보가 필요하면:
    async def handler(user: User = Depends(require_user)): ...   (같은 요청 안에서는 한 번만 조회된다)
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from . import groups, service
from .service import User

COOKIE_NAME = "wlm_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "X-WLM-CSRF"
IDLE_HEADER = "X-WLM-Idle-Sec"
PASSWORD_CHANGE_REASON = "password_change_required"


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def check_csrf(request: Request) -> None:
    """상태를 바꾸는 요청은 사용자 지정 헤더가 있어야 한다.
    다른 사이트의 폼/이미지 요청은 이 헤더를 붙일 수 없고, 스크립트 요청은 CORS 에서 막힌다."""
    if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(403, "요청 검증에 실패했습니다 (CSRF 헤더 없음)")


async def current_user(request: Request) -> User:
    """로그인만 확인 (비밀번호 변경이 필요한 사용자도 통과). 인증 API 에서 사용."""
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    token = request.cookies.get(COOKIE_NAME, "")
    idle = request.headers.get(IDLE_HEADER)
    try:
        idle_sec = float(idle) if idle is not None else None
    except ValueError:
        idle_sec = None
    # 실시간 스트림 재연결은 사용자 조작이 아니므로 세션을 연장하지 않는다
    user = await service.resolve(token, idle_sec, touch=request.url.path != "/api/live")
    if user is None:
        raise HTTPException(401, "로그인이 필요합니다", headers={"X-WLM-Reason": "login_required"})
    check_csrf(request)
    await with_access(user)
    request.state.user = user
    request.state.session_token = token
    return user


async def require_user(user: User = Depends(current_user)) -> User:
    """일반 API: 로그인 + 비밀번호 변경이 끝난 사용자."""
    if user.needs_password_change:
        raise HTTPException(403, "비밀번호를 변경해야 합니다", headers={"X-WLM-Reason": PASSWORD_CHANGE_REASON})
    return user


async def require_admin(user: User = Depends(require_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "관리자만 할 수 있는 작업입니다")
    return user


async def with_access(user: User) -> User:
    """사용자 그룹의 권한·조회 범위를 채운다. 관리자는 범위 제한이 없다."""
    perms, scopes, names = await groups.access_for(user.id)
    user.permissions, user.groups = perms, names
    user.scopes = None if user.is_admin else scopes
    return user


def require_permission(permission: str):
    """기능 권한이 있어야 하는 API (관리자 또는 그 권한을 가진 그룹의 구성원)."""

    async def dependency(user: User = Depends(require_user)) -> User:
        if not user.can(permission):
            raise HTTPException(403, f"권한이 없습니다 ({groups.PERMISSIONS.get(permission, permission)})")
        return user

    return dependency
