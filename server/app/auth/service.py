"""인증 서비스: 로그인·잠금, 세션, 비밀번호 변경, 사용자 관리, 초기 관리자 생성.

모든 보안 관련 행위는 audit_log 에 남긴다 (ISMS 2.5 인증·권한, 2.9.4 접속기록).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import db
from ..config import settings
from .passwords import check_policy, dummy_verify, generate_password, hash_password, needs_rehash, verify_password

log = logging.getLogger(__name__)

ROLES = ("admin", "viewer")
ROLE_LABELS = {"admin": "관리자", "viewer": "조회자"}
GENERIC_LOGIN_ERROR = "아이디 또는 비밀번호가 올바르지 않습니다"


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "error"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


@dataclass
class User:
    id: int
    username: str
    display_name: str
    role: str
    must_change_password: bool
    password_changed_at: datetime
    last_login_at: datetime | None = None
    last_login_ip: str | None = None
    # 사용자 그룹에서 온 권한·조회 범위 (deps.current_user 가 요청마다 채운다, auth/groups.py)
    permissions: frozenset[str] = frozenset()
    scopes: tuple | None = None   # tuple[filters.Scope, ...] — None 이면 모든 로그
    groups: tuple[str, ...] = ()

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def can(self, permission: str) -> bool:
        """기능 권한. 관리자는 전부."""
        return self.is_admin or permission in self.permissions

    @property
    def password_expired(self) -> bool:
        if settings.password_max_age_days <= 0:
            return False
        return datetime.now(UTC) - self.password_changed_at > timedelta(days=settings.password_max_age_days)

    @property
    def needs_password_change(self) -> bool:
        return self.must_change_password or self.password_expired

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id, "username": self.username, "display_name": self.display_name,
            "role": self.role, "role_label": ROLE_LABELS.get(self.role, self.role),
            "must_change_password": self.must_change_password, "password_expired": self.password_expired,
            "password_changed_at": self.password_changed_at, "last_login_at": self.last_login_at,
            "last_login_ip": self.last_login_ip,
            "groups": list(self.groups),
            "permissions": sorted(self.permissions),
            # 관리자는 범위 제한 없음. 조회 범위가 있으면 화면에 '볼 수 있는 범위' 로 보여 준다
            "scope": None if self.is_admin or self.scopes is None
            else [{"categories": list(sc.categories), "hosts": list(sc.hosts)} for sc in self.scopes],
        }


_USER_COLUMNS = ("id, username, display_name, role, must_change_password, password_changed_at,"
                 " last_login_at, last_login_ip")


def row_to_user(row: dict) -> User:
    return User(**{k: row[k] for k in User.__dataclass_fields__ if k in row})


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def normalize_username(username: str) -> str:
    return (username or "").strip().lower()


# --------------------------------------------------- IP 단위 실패 제한

_ip_failures: dict[str, deque[float]] = defaultdict(deque)
IP_WINDOW_SEC, IP_MAX_FAILURES = 600, 30


def _ip_blocked(ip: str | None) -> bool:
    if not ip:
        return False
    q = _ip_failures[ip]
    while q and q[0] < time.monotonic() - IP_WINDOW_SEC:
        q.popleft()
    return len(q) >= IP_MAX_FAILURES


def _ip_fail(ip: str | None) -> None:
    if ip:
        _ip_failures[ip].append(time.monotonic())


# ------------------------------------------------------------ 로그인

async def login(username: str, password: str, ip: str | None, user_agent: str | None) -> tuple[str, User]:
    """성공하면 (세션 토큰, 사용자). 실패하면 AuthError."""
    name = normalize_username(username)
    if _ip_blocked(ip):
        await db.audit(name or "-", "auth.login_failed", name, {"reason": "ip_rate_limited"}, actor_ip=ip)
        raise AuthError("로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요", 429, "rate_limited")

    row = await db.fetch_one(
        f"SELECT {_USER_COLUMNS}, password_hash, is_active, failed_count, locked_until FROM users WHERE username = %s",
        (name,),
    )
    now = datetime.now(UTC)

    async def fail(reason: str, detail: dict | None = None, message: str = GENERIC_LOGIN_ERROR,
                   status: int = 401, code: str = "invalid") -> None:
        _ip_fail(ip)
        await db.audit(name or "-", "auth.login_failed", name, {"reason": reason, **(detail or {}),
                                                               "user_agent": (user_agent or "")[:200]}, actor_ip=ip)
        raise AuthError(message, status, code)

    if row is None:
        await asyncio.to_thread(dummy_verify, password)
        await fail("unknown_user")
    if row["locked_until"] and row["locked_until"] > now:
        minutes = max(1, int((row["locked_until"] - now).total_seconds() // 60) + 1)
        await fail("locked", message=f"로그인 실패가 반복되어 계정이 잠겼습니다. {minutes}분 후 다시 시도하거나 관리자에게 문의하세요",
                   status=423, code="locked")
    ok = await asyncio.to_thread(verify_password, password, row["password_hash"])
    if not row["is_active"]:
        await fail("disabled")
    if not ok:
        failures = row["failed_count"] + 1
        lock = failures >= settings.login_max_failures
        await db.fetch_one(
            "UPDATE users SET failed_count = %s, locked_until = %s WHERE id = %s RETURNING id",
            (0 if lock else failures, now + timedelta(minutes=settings.login_lockout_min) if lock else None, row["id"]),
        )
        if lock:
            await db.audit("system", "auth.account_locked", name,
                           {"failures": failures, "minutes": settings.login_lockout_min}, actor_ip=ip)
            await fail("bad_password", {"failures": failures},
                       message=f"비밀번호를 {failures}회 틀려 계정이 {settings.login_lockout_min}분 동안 잠겼습니다",
                       status=423, code="locked")
        # 남은 횟수를 알려주면 '있는 아이디'라는 사실이 드러나므로 일반 문구만 보낸다
        await fail("bad_password", {"failures": failures})

    updates = "failed_count = 0, locked_until = NULL, last_login_at = now(), last_login_ip = %s"
    params: list[Any] = [ip]
    if needs_rehash(row["password_hash"]):
        updates += ", password_hash = %s"
        params.append(await asyncio.to_thread(hash_password, password))
    await db.fetch_one(f"UPDATE users SET {updates} WHERE id = %s RETURNING id", (*params, row["id"]))

    token = secrets.token_urlsafe(32)
    await db.fetch_one(
        "INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent) VALUES (%s, %s, %s, %s, %s)"
        " RETURNING token_hash",
        (_token_hash(token), row["id"], now + timedelta(hours=settings.session_max_hours), ip, (user_agent or "")[:300]),
    )
    user = row_to_user({**row, "last_login_at": now, "last_login_ip": ip})
    await db.audit(user.username, "auth.login", user.username, {"role": user.role, "user_agent": (user_agent or "")[:200]},
                   actor_ip=ip)
    return token, user


async def logout(token: str, user: User, ip: str | None, reason: str = "user") -> None:
    await db.fetch_all("DELETE FROM sessions WHERE token_hash = %s RETURNING token_hash", (_token_hash(token),))
    await db.audit(user.username, "auth.logout", user.username, {"reason": reason}, actor_ip=ip)


async def resolve(token: str, idle_sec: float | None, touch: bool = True) -> User | None:
    """쿠키 토큰 → 사용자. 만료/유휴 초과/비활성 계정이면 None (세션도 지운다).

    idle_sec: 브라우저가 알려주는 '마지막 사용자 조작 후 경과 초' (X-WLM-Idle-Sec).
    자동 새로고침 요청은 이 값이 커서 세션을 연장하지 않는다 → 화면을 켜 두기만 해도 유휴 시간이 흐른다.
    """
    if not token:
        return None
    row = await db.fetch_one(
        f"SELECT s.token_hash, s.last_activity_at, s.expires_at, u.is_active,"
        f" {', '.join('u.' + c.strip() for c in _USER_COLUMNS.split(','))}"
        " FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s",
        (_token_hash(token),),
    )
    if row is None:
        return None
    now = datetime.now(UTC)
    idle_limit = timedelta(minutes=settings.session_idle_min)
    if not row["is_active"] or row["expires_at"] <= now or now - row["last_activity_at"] > idle_limit:
        await db.fetch_all("DELETE FROM sessions WHERE token_hash = %s RETURNING token_hash", (row["token_hash"],))
        if row["is_active"]:
            reason = "max_age" if row["expires_at"] <= now else "idle"
            await db.audit(row["username"], "auth.session_expired", row["username"], {"reason": reason})
        return None
    if touch:
        activity = now - timedelta(seconds=min(max(idle_sec, 0), 86400)) if idle_sec is not None else now
        # 30초 이상 차이 날 때만 기록 (요청마다 쓰지 않도록)
        if activity - row["last_activity_at"] > timedelta(seconds=30):
            await db.fetch_one("UPDATE sessions SET last_activity_at = %s WHERE token_hash = %s RETURNING token_hash",
                               (activity, row["token_hash"]))
    return row_to_user(row)


async def session_alive(token: str) -> bool:
    row = await db.fetch_one(
        "SELECT 1 AS ok FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s"
        " AND u.is_active AND s.expires_at > now() AND s.last_activity_at > now() - make_interval(mins => %s)",
        (_token_hash(token), settings.session_idle_min),
    )
    return row is not None


async def purge_sessions() -> None:
    await db.fetch_all(
        "DELETE FROM sessions WHERE expires_at <= now() OR last_activity_at <= now() - make_interval(mins => %s)"
        " RETURNING token_hash", (settings.session_idle_min,),
    )


# -------------------------------------------------------- 비밀번호 변경

async def change_password(user: User, token: str, current: str, new: str, ip: str | None) -> None:
    row = await db.fetch_one("SELECT password_hash FROM users WHERE id = %s", (user.id,))
    if not await asyncio.to_thread(verify_password, current, row["password_hash"]):
        await db.audit(user.username, "auth.password_change_failed", user.username, {"reason": "bad_current"}, actor_ip=ip)
        raise AuthError("현재 비밀번호가 올바르지 않습니다", 400, "bad_current")
    problem = check_policy(new, user.username)
    if problem:
        raise AuthError(problem, 400, "policy")
    if current == new:
        raise AuthError("이전과 다른 비밀번호를 사용하세요", 400, "policy")
    encoded = await asyncio.to_thread(hash_password, new)
    await db.fetch_one(
        "UPDATE users SET password_hash = %s, must_change_password = false, password_changed_at = now()"
        " WHERE id = %s RETURNING id", (encoded, user.id),
    )
    # 다른 곳에 열려 있던 세션은 끊는다 (지금 세션만 유지)
    await db.fetch_all("DELETE FROM sessions WHERE user_id = %s AND token_hash <> %s RETURNING token_hash",
                       (user.id, _token_hash(token)))
    await db.audit(user.username, "auth.password_change", user.username, {}, actor_ip=ip)


# ---------------------------------------------------------- 사용자 관리

async def list_users() -> list[dict]:
    return await db.fetch_all(
        f"SELECT {_USER_COLUMNS}, is_active, failed_count, locked_until, created_at, created_by,"
        " (SELECT count(*) FROM sessions s WHERE s.user_id = users.id AND s.expires_at > now()"
        "   AND s.last_activity_at > now() - make_interval(mins => %s)) AS sessions"
        " FROM users ORDER BY username", (settings.session_idle_min,),
    )


async def create_user(username: str, display_name: str, role: str, actor: str, ip: str | None,
                      password: str | None = None, check_policy_: bool = True) -> tuple[dict, str]:
    name = normalize_username(username)
    if not name or not all(c.isalnum() or c in "._-" for c in name) or len(name) > 64:
        raise AuthError("아이디는 영문/숫자/._- 로 64자 이내", 400, "invalid_username")
    if role not in ROLES:
        raise AuthError(f"역할은 {ROLES} 중 하나", 400, "invalid_role")
    temp = password or generate_password()
    if password and check_policy_ and (problem := check_policy(password, name)):
        raise AuthError(problem, 400, "policy")
    encoded = await asyncio.to_thread(hash_password, temp)
    try:
        row = await db.fetch_one(
            "INSERT INTO users (username, display_name, role, password_hash, must_change_password, created_by)"
            " VALUES (%s, %s, %s, %s, true, %s) RETURNING id, username",
            (name, display_name.strip()[:100], role, encoded, actor),
        )
    except Exception as exc:
        if "users_username_key" in str(exc):
            raise AuthError("이미 있는 아이디입니다", 409, "duplicate") from exc
        raise
    await db.audit(actor, "user.create", name, {"role": role, "display_name": display_name}, actor_ip=ip)
    return row, temp


async def _active_admins(exclude_id: int | None = None) -> int:
    row = await db.fetch_one("SELECT count(*) AS n FROM users WHERE role = 'admin' AND is_active AND id <> %s",
                             (exclude_id or 0,))
    return row["n"]


async def update_user(user_id: int, changes: dict[str, Any], actor: User, ip: str | None) -> None:
    row = await db.fetch_one("SELECT id, username, role, is_active, display_name FROM users WHERE id = %s", (user_id,))
    if row is None:
        raise AuthError("사용자가 없습니다", 404, "not_found")
    allowed = {k: v for k, v in changes.items() if k in ("display_name", "role", "is_active")}
    if "role" in allowed and allowed["role"] not in ROLES:
        raise AuthError(f"역할은 {ROLES} 중 하나", 400, "invalid_role")
    if user_id == actor.id and (allowed.get("role", row["role"]) != row["role"] or allowed.get("is_active") is False):
        raise AuthError("자기 자신의 역할을 바꾸거나 비활성화할 수 없습니다", 400, "self")
    demoting = row["role"] == "admin" and (allowed.get("role") == "viewer" or allowed.get("is_active") is False)
    if demoting and await _active_admins(exclude_id=user_id) == 0:
        raise AuthError("마지막 관리자는 바꿀 수 없습니다", 400, "last_admin")
    diff = {k: {"from": row[k], "to": v} for k, v in allowed.items() if row[k] != v}
    if not diff:
        return
    sets = ", ".join(f"{k} = %s" for k in diff)
    await db.fetch_one(f"UPDATE users SET {sets} WHERE id = %s RETURNING id", (*[d["to"] for d in diff.values()], user_id))
    if allowed.get("is_active") is False:
        await db.fetch_all("DELETE FROM sessions WHERE user_id = %s RETURNING token_hash", (user_id,))
    await db.audit(actor.username, "user.update", row["username"], diff, actor_ip=ip)


async def reset_password(user_id: int, actor: str, ip: str | None) -> tuple[str, str]:
    row = await db.fetch_one("SELECT username FROM users WHERE id = %s", (user_id,))
    if row is None:
        raise AuthError("사용자가 없습니다", 404, "not_found")
    temp = generate_password()
    encoded = await asyncio.to_thread(hash_password, temp)
    await db.fetch_one(
        "UPDATE users SET password_hash = %s, must_change_password = true, failed_count = 0, locked_until = NULL,"
        " password_changed_at = now() WHERE id = %s RETURNING id", (encoded, user_id),
    )
    await db.fetch_all("DELETE FROM sessions WHERE user_id = %s RETURNING token_hash", (user_id,))
    await db.audit(actor, "user.reset_password", row["username"], {}, actor_ip=ip)
    return row["username"], temp


async def unlock(user_id: int, actor: str, ip: str | None) -> None:
    row = await db.fetch_one(
        "UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = %s RETURNING username", (user_id,)
    )
    if row is None:
        raise AuthError("사용자가 없습니다", 404, "not_found")
    await db.audit(actor, "user.unlock", row["username"], {}, actor_ip=ip)


async def bootstrap_admin() -> None:
    """사용자가 한 명도 없으면 admin 계정을 만든다 (첫 로그인 때 비밀번호 변경 강제)."""
    row = await db.fetch_one("SELECT count(*) AS n FROM users")
    if row["n"]:
        return
    given = settings.admin_initial_password
    if given.startswith("#"):
        # 'KEY=    # 설명' 형태의 .env 줄은 compose 가 설명문을 값으로 넘긴다 → 공개된 문구가 비밀번호가 되지 않게 무시
        log.error("WLM_ADMIN_INITIAL_PASSWORD 가 주석문으로 읽혔습니다 (.env 확인). 무시하고 무작위 비밀번호를 만듭니다")
        given = ""
    _, password = await create_user("admin", "관리자", "admin", "system", None, password=given or None,
                                    check_policy_=False)
    if given:
        log.warning("초기 관리자 계정 admin 생성 (WLM_ADMIN_INITIAL_PASSWORD, 첫 로그인 때 변경 필요)")
        return
    log.warning("=" * 60)
    log.warning("초기 관리자 계정을 만들었습니다: 아이디 admin / 임시 비밀번호 %s", password)
    log.warning("첫 로그인 때 비밀번호를 바꿔야 합니다. 이 로그는 다시 출력되지 않습니다.")
    log.warning("=" * 60)
