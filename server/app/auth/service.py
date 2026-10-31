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
from .. import secrets as secret_store
from ..config import settings
from . import totp
from .groups import PRIVILEGED
from .passwords import check_policy, dummy_verify, generate_password, hash_password, needs_rehash, verify_password

log = logging.getLogger(__name__)

ROLES = ("admin", "viewer")
ROLE_LABELS = {"admin": "관리자", "viewer": "조회자"}
GENERIC_LOGIN_ERROR = "아이디 또는 비밀번호가 올바르지 않습니다"
MFA_PENDING_MIN = 5   # 비밀번호까지 맞은 세션이 2단계 코드를 기다리는 시간
MFA_ERROR = "인증 코드가 올바르지 않습니다"


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
    mfa_enabled_at: datetime | None = None
    mfa_ok: bool = True          # 이 세션이 2단계 코드까지 맞았나 (B-74). 2단계를 쓰지 않는 사용자는 늘 True
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

    @property
    def mfa_enabled(self) -> bool:
        return self.mfa_enabled_at is not None

    @property
    def mfa_required(self) -> bool:
        """이 사람에게 2단계 인증이 필수인가 (권한은 with_access 가 채운 뒤에 본다)."""
        if not settings.secret_key or settings.mfa_required == "off":
            return False
        if settings.mfa_required == "all":
            return True
        return self.is_admin or bool(self.permissions & PRIVILEGED)

    @property
    def needs_mfa_setup(self) -> bool:
        return self.mfa_required and not self.mfa_enabled

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id, "username": self.username, "display_name": self.display_name,
            "role": self.role, "role_label": ROLE_LABELS.get(self.role, self.role),
            "must_change_password": self.must_change_password, "password_expired": self.password_expired,
            "password_changed_at": self.password_changed_at, "last_login_at": self.last_login_at,
            "last_login_ip": self.last_login_ip,
            "mfa": {"enabled": self.mfa_enabled, "required": self.mfa_required, "enabled_at": self.mfa_enabled_at},
            "groups": list(self.groups),
            "permissions": sorted(self.permissions),
            # 관리자는 범위 제한 없음. 조회 범위가 있으면 화면에 '볼 수 있는 범위' 로 보여 준다
            "scope": None if self.is_admin or self.scopes is None
            else [{"categories": list(sc.categories), "hosts": list(sc.hosts)} for sc in self.scopes],
        }


_USER_COLUMNS = ("id, username, display_name, role, must_change_password, password_changed_at,"
                 " last_login_at, last_login_ip, mfa_enabled_at")


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
    # 시도를 먼저 센다(원자적으로) — 확인한 뒤에 세면 동시에 보낸 요청이 모두 잠금 검사를 지나 잠금이 듣지 않았다(B-74 검토에서 재현)
    attempt = await _reserve_attempt(row["id"])
    if attempt is None:
        locked = await db.fetch_one("SELECT locked_until FROM users WHERE id = %s", (row["id"],))
        minutes = max(1, int(((locked["locked_until"] or now) - now).total_seconds() // 60) + 1)
        await fail("locked", message=f"로그인 실패가 반복되어 계정이 잠겼습니다. {minutes}분 후 다시 시도하거나 관리자에게 문의하세요",
                   status=423, code="locked")
    ok = await asyncio.to_thread(verify_password, password, row["password_hash"])
    if not row["is_active"]:
        await fail("disabled")
    if not ok:
        failures = attempt["failed_count"]
        if attempt["locked_until"] is not None:
            await db.audit("system", "auth.account_locked", name,
                           {"failures": failures, "minutes": settings.login_lockout_min}, actor_ip=ip)
            await fail("bad_password", {"failures": failures},
                       message=f"비밀번호를 {failures}회 틀려 계정이 {settings.login_lockout_min}분 동안 잠겼습니다",
                       status=423, code="locked")
        # 남은 횟수를 알려주면 '있는 아이디'라는 사실이 드러나므로 일반 문구만 보낸다
        await fail("bad_password", {"failures": failures})

    if needs_rehash(row["password_hash"]):
        await db.fetch_one("UPDATE users SET password_hash = %s WHERE id = %s RETURNING id",
                           (await asyncio.to_thread(hash_password, password), row["id"]))
    if row["mfa_enabled_at"] is not None:
        if not settings.secret_key:
            # 키가 없으면 비밀값을 풀 수 없다 — 비밀번호만으로 들여보내지 않는다(닫힌 쪽으로). 비상: cli reset-mfa
            await fail("mfa_no_secret_key", message="서버에 WLM_SECRET_KEY 가 없어 2단계 인증을 확인할 수 없습니다 — 서버 관리자에게 문의하세요",
                       status=503, code="mfa_unavailable")
        # 2단계 인증을 쓰는 사람: 코드를 기다리는 세션만 (5분, 인증 API 일부만). 실패 횟수는 여기서 지우지 않는다 —
        # 비밀번호를 아는 사람이 다시 로그인할 때마다 지워지면 코드를 끝없이 맞혀 볼 수 있다. 이 로그인도 시도 하나로 남는다
        token = await _new_session(row["id"], now + timedelta(minutes=MFA_PENDING_MIN), ip, user_agent, mfa_ok=False)
        await db.audit(row["username"], "auth.login_password_ok", row["username"],
                       {"mfa": "pending", "user_agent": (user_agent or "")[:200]}, actor_ip=ip)
        return token, row_to_user({**row, "mfa_ok": False})
    return await _complete_login(row, ip, user_agent, now)


async def _reserve_attempt(user_id: int) -> dict | None:
    """로그인 시도 하나를 원자적으로 센다 — 잠겨 있으면 None. 이 시도로 기준(WLM_LOGIN_MAX_FAILURES)에 닿으면 바로 잠근다.
    끝난 잠금 뒤에는 1부터 다시. 행 잠금으로 줄을 서므로 동시에 몇 개를 보내도 잠금 기간마다 기준 수까지만 확인된다.
    성공하면 _complete_login(또는 코드 확인 성공)이 0 으로 되돌린다."""
    return await db.fetch_one(
        "UPDATE users SET failed_count = (CASE WHEN locked_until IS NULL THEN failed_count ELSE 0 END) + 1,"
        " locked_until = CASE WHEN (CASE WHEN locked_until IS NULL THEN failed_count ELSE 0 END) + 1 >= %(max)s"
        "   THEN now() + make_interval(mins => %(min)s) END"
        " WHERE id = %(id)s AND (locked_until IS NULL OR locked_until <= now()) RETURNING failed_count, locked_until",
        {"max": settings.login_max_failures, "min": settings.login_lockout_min, "id": user_id})


async def _new_session(user_id: int, expires_at: datetime, ip: str | None, user_agent: str | None, mfa_ok: bool) -> str:
    token = secrets.token_urlsafe(32)
    await db.fetch_one(
        "INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent, mfa_ok) VALUES (%s, %s, %s, %s, %s, %s)"
        " RETURNING token_hash", (_token_hash(token), user_id, expires_at, ip, (user_agent or "")[:300], mfa_ok))
    return token


async def _complete_login(row: dict, ip: str | None, user_agent: str | None, now: datetime,
                          detail: dict | None = None) -> tuple[str, User]:
    """로그인 끝 (비밀번호만 쓰는 사람은 비밀번호 뒤, 2단계를 쓰는 사람은 코드 뒤): 실패 횟수를 지우고 정식 세션."""
    await db.fetch_one("UPDATE users SET failed_count = 0, locked_until = NULL, last_login_at = now(), last_login_ip = %s"
                       " WHERE id = %s RETURNING id", (ip, row["id"]))
    token = await _new_session(row["id"], now + timedelta(hours=settings.session_max_hours), ip, user_agent, mfa_ok=True)
    user = row_to_user({**row, "last_login_at": now, "last_login_ip": ip})
    await db.audit(user.username, "auth.login", user.username,
                   {"role": user.role, "user_agent": (user_agent or "")[:200], **(detail or {})}, actor_ip=ip)
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
        f"SELECT s.token_hash, s.last_activity_at, s.expires_at, s.mfa_ok, u.is_active,"
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


# ------------------------------------------------------ 2단계 인증 (B-74)
_U_COLUMNS = ", ".join("u." + c.strip() for c in _USER_COLUMNS.split(","))
KEY_CHANGED = ("서버 키(WLM_SECRET_KEY)가 바뀌어 2단계 인증을 확인할 수 없습니다 — 서버 관리자가 키를 되돌리거나"
               " python -m app.cli reset-mfa 로 다시 등록하게 하세요")


def _secret_of(encrypted: str | None) -> str:
    try:
        return str(secret_store.decrypt(encrypted).get("secret") or "")
    except secret_store.SecretError as exc:
        raise AuthError(KEY_CHANGED, 503, "mfa_unavailable") from exc


async def _check_code(user_id: int, encrypted: str | None, last_step: int, code: str, *, recovery: bool) -> str | None:
    """맞으면 'totp' 또는 'recovery', 아니면 None. 시간 칸·복구 코드는 조건부 UPDATE 로 한 번만 — 같은 코드를 동시에 두 번 보내도
    한쪽만 통과한다."""
    secret = _secret_of(encrypted)
    step = totp.verify(secret, code, datetime.now(UTC), last_step) if secret else None
    if step is not None:
        row = await db.fetch_one("UPDATE users SET mfa_last_step = %s WHERE id = %s AND mfa_last_step < %s RETURNING id",
                                 (step, user_id, step))
        if row is not None:
            return "totp"
    if recovery and settings.secret_key and len(totp.normalize_recovery(code)) == 10:
        row = await db.fetch_one(
            "UPDATE mfa_recovery_codes SET used_at = now() WHERE id = (SELECT id FROM mfa_recovery_codes"
            " WHERE user_id = %s AND code_hash = %s AND used_at IS NULL LIMIT 1) AND used_at IS NULL RETURNING id",
            (user_id, totp.recovery_hash(code, settings.secret_key)))
        if row is not None:
            return "recovery"
    return None


async def recovery_left(user_id: int) -> int:
    row = await db.fetch_one("SELECT count(*) AS n FROM mfa_recovery_codes WHERE user_id = %s AND used_at IS NULL", (user_id,))
    return row["n"]


def _start_attempt(ip: str | None) -> None:
    """IP 단위 제한: 확인하기 전에, await 없이 센다(워커 1개라 원자적) — 실패 뒤에 세면 동시에 보낸 요청이 모두 검사를 지났다."""
    if _ip_blocked(ip):
        raise AuthError("시도가 너무 많습니다. 잠시 후 다시 시도하세요", 429, "rate_limited")
    _ip_fail(ip)


async def mfa_verify(token: str, username: str, code: str, ip: str | None, user_agent: str | None) -> tuple[str, User]:
    """비밀번호까지 맞은 세션 + 인증 코드(또는 복구 코드) → 정식 세션(새 토큰). 비밀번호와 같은 잠금 정책 —
    시도는 확인 전에 원자적으로 센다(동시에 수천 개를 보내 잠금을 피하던 것, 검토에서 재현)."""
    try:
        _start_attempt(ip)
    except AuthError:
        await db.audit(username, "auth.mfa.failed", username, {"reason": "ip_rate_limited"}, actor_ip=ip)
        raise
    row = await db.fetch_one(
        f"SELECT {_U_COLUMNS}, u.is_active, u.mfa_secret_enc, u.mfa_last_step"
        " FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash = %s AND NOT s.mfa_ok AND s.expires_at > now()", (_token_hash(token),))
    if row is None or not row["is_active"]:
        await db.audit(username, "auth.mfa.failed", username, {"reason": "expired_pending"}, actor_ip=ip)
        raise AuthError("인증 시간이 지났습니다. 다시 로그인하세요", 401, "login_required")
    attempt = await _reserve_attempt(row["id"])
    if attempt is None:
        await _drop_pending(row["id"])
        await db.audit(row["username"], "auth.mfa.failed", row["username"], {"reason": "locked"}, actor_ip=ip)
        raise AuthError("로그인 실패가 반복되어 계정이 잠겼습니다. 잠시 후 다시 시도하거나 관리자에게 문의하세요", 423, "locked")
    method = await _check_code(row["id"], row["mfa_secret_enc"], row["mfa_last_step"], code, recovery=True)
    if method is None:
        failures = attempt["failed_count"]
        await db.audit(row["username"], "auth.mfa.failed", row["username"], {"failures": failures}, actor_ip=ip)
        if attempt["locked_until"] is not None:
            await _drop_pending(row["id"])
            await db.audit("system", "auth.account_locked", row["username"],
                           {"failures": failures, "minutes": settings.login_lockout_min, "stage": "mfa"}, actor_ip=ip)
            raise AuthError(f"인증 코드를 {failures}회 틀려 계정이 {settings.login_lockout_min}분 동안 잠겼습니다", 423, "locked")
        # 400 — 401 이면 화면이 '세션 만료'로 보고 로그인 화면으로 돌아갔다(검토)
        raise AuthError(MFA_ERROR, 400, "mfa_invalid")
    # 코드를 기다리던 토큰은 버리고 새 토큰으로 — 비밀번호 단계의 토큰이 새어도 정식 세션이 되지 않게
    await db.fetch_all("DELETE FROM sessions WHERE token_hash = %s RETURNING token_hash", (_token_hash(token),))
    result = await _complete_login(row, ip, user_agent, datetime.now(UTC), {"mfa": method})
    if method == "recovery":
        await db.audit(row["username"], "auth.mfa.recovery_used", row["username"], {"left": await recovery_left(row["id"])},
                       actor_ip=ip)
    return result


async def _drop_pending(user_id: int) -> None:
    await db.fetch_all("DELETE FROM sessions WHERE user_id = %s AND NOT mfa_ok RETURNING token_hash", (user_id,))


async def mfa_setup(user: User, ip: str | None) -> dict[str, str]:
    """등록 시작: 새 비밀값(아직 쓰지 않음). 인증 앱에 넣고 enroll 로 코드를 맞히면 켜진다. 다시 부르면 새 비밀값."""
    if user.mfa_enabled:
        raise AuthError("이미 2단계 인증을 쓰고 있습니다", 409, "mfa_enabled")
    if not settings.secret_key:
        raise AuthError("서버에 WLM_SECRET_KEY 가 없어 2단계 인증을 켤 수 없습니다 (.env 확인)", 409, "no_secret_key")
    secret = totp.new_secret()
    await db.fetch_one("UPDATE users SET mfa_secret_enc = %s, mfa_last_step = 0 WHERE id = %s AND mfa_enabled_at IS NULL"
                       " RETURNING id", (secret_store.encrypt({"secret": secret}), user.id))
    await db.audit(user.username, "auth.mfa.setup", user.username, {}, actor_ip=ip)
    return {"secret": secret, "uri": totp.otpauth_uri(secret, user.username)}


async def _store_recovery_codes(conn: Any, user_id: int) -> list[str]:
    """복구 코드 새로 — 호출하는 쪽이 그 사용자 행을 잠근 트랜잭션 안에서 (동시에 두 번 눌러도 한 벌만 남게, 검토)."""
    codes = totp.new_recovery_codes()
    await conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id = %s", (user_id,))
    async with conn.cursor() as cur:
        await cur.executemany("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (%s, %s)",
                              [(user_id, totp.recovery_hash(c, settings.secret_key)) for c in codes])
    return codes


async def mfa_enroll(user: User, token: str, code: str, ip: str | None) -> list[str]:
    """등록 마침: 앱이 보인 코드가 맞으면 켜고 복구 코드(한 번만 보여 줌)를 돌려준다. 다른 곳에 열린 세션은 끊는다 —
    2단계 없이 열린 세션이 남지 않게. 사용자 행을 잠근 한 트랜잭션 — 두 번 눌러도 한 번만 켜고 복구 코드도 한 벌."""
    async with db.pool().connection() as conn, conn.transaction():
        cur = await conn.execute("SELECT mfa_secret_enc, mfa_enabled_at FROM users WHERE id = %s FOR UPDATE", (user.id,))
        row = await cur.fetchone()
        if row["mfa_enabled_at"] is not None:
            raise AuthError("이미 2단계 인증을 쓰고 있습니다", 409, "mfa_enabled")
        if not row["mfa_secret_enc"]:
            raise AuthError("먼저 등록을 시작하세요", 409, "mfa_not_started")
        step = totp.verify(_secret_of(row["mfa_secret_enc"]), code, datetime.now(UTC), 0)
        if step is None:
            enroll_failed = True
        else:
            enroll_failed = False
            await conn.execute("UPDATE users SET mfa_enabled_at = now(), mfa_last_step = %s WHERE id = %s", (step, user.id))
            codes = await _store_recovery_codes(conn, user.id)
    if enroll_failed:
        await db.audit(user.username, "auth.mfa.enroll_failed", user.username, {}, actor_ip=ip)
        raise AuthError(MFA_ERROR + " — 휴대폰 시계가 맞는지, 키를 바르게 넣었는지 확인하세요", 400, "mfa_invalid")
    await db.fetch_all("DELETE FROM sessions WHERE user_id = %s AND token_hash <> %s RETURNING token_hash",
                       (user.id, _token_hash(token)))
    await db.audit(user.username, "auth.mfa.enroll", user.username, {"recovery_codes": len(codes)}, actor_ip=ip)
    return codes


async def _require_code(user: User, code: str, ip: str | None, action: str, *, recovery: bool = False) -> str:
    """로그인한 사람이 2단계 설정을 바꿀 때 지금 코드를 다시 확인 — 로그인과 같은 잠금(시도를 먼저 센다). 기준에 닿으면 그 사람의
    모든 세션을 끊는다: 가로챈 세션으로 코드를 끝없이 맞혀 보지 못하게(검토)."""
    _start_attempt(ip)
    row = await db.fetch_one("SELECT mfa_secret_enc, mfa_enabled_at, mfa_last_step FROM users WHERE id = %s", (user.id,))
    if row["mfa_enabled_at"] is None:
        raise AuthError("2단계 인증을 쓰고 있지 않습니다", 409, "mfa_disabled")
    attempt = await _reserve_attempt(user.id)
    if attempt is None:
        await db.fetch_all("DELETE FROM sessions WHERE user_id = %s RETURNING token_hash", (user.id,))
        raise AuthError("시도가 반복되어 계정이 잠겼습니다. 잠시 후 다시 로그인하세요", 423, "locked")
    method = await _check_code(user.id, row["mfa_secret_enc"], row["mfa_last_step"], code, recovery=recovery)
    if method is None:
        await db.audit(user.username, "auth.mfa.failed", user.username, {"for": action, "failures": attempt["failed_count"]},
                       actor_ip=ip)
        if attempt["locked_until"] is not None:
            await db.fetch_all("DELETE FROM sessions WHERE user_id = %s RETURNING token_hash", (user.id,))
            await db.audit("system", "auth.account_locked", user.username,
                           {"failures": attempt["failed_count"], "minutes": settings.login_lockout_min, "stage": action},
                           actor_ip=ip)
            raise AuthError("인증 코드를 여러 번 틀려 계정이 잠겼습니다. 잠시 후 다시 로그인하세요", 423, "locked")
        raise AuthError(MFA_ERROR, 400, "mfa_invalid")
    await db.fetch_one("UPDATE users SET failed_count = 0 WHERE id = %s RETURNING id", (user.id,))
    return method


async def mfa_regenerate(user: User, code: str, ip: str | None) -> list[str]:
    """복구 코드 새로 (예전 것은 모두 무효). 지금 코드가 필요하다."""
    await _require_code(user, code, ip, "recovery")
    async with db.pool().connection() as conn, conn.transaction():
        await conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user.id,))
        codes = await _store_recovery_codes(conn, user.id)
    await db.audit(user.username, "auth.mfa.recovery_regenerated", user.username, {"recovery_codes": len(codes)}, actor_ip=ip)
    return codes


async def _clear_mfa(user_id: int) -> None:
    async with db.pool().connection() as conn, conn.transaction():
        await conn.execute("UPDATE users SET mfa_secret_enc = NULL, mfa_enabled_at = NULL, mfa_last_step = 0 WHERE id = %s",
                           (user_id,))
        await conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id = %s", (user_id,))


async def mfa_reenroll(user: User, token: str, code: str, ip: str | None) -> None:
    """휴대폰을 바꿨거나 잃었을 때 스스로 다시 등록 — 지금 코드나 남은 복구 코드 하나로 지운다. 다른 세션은 끊는다.
    필수면 화면이 바로 등록으로 간다(require_user 가 mfa_setup_required)."""
    method = await _require_code(user, code, ip, "reenroll", recovery=True)
    await _clear_mfa(user.id)
    await db.fetch_all("DELETE FROM sessions WHERE user_id = %s AND token_hash <> %s RETURNING token_hash",
                       (user.id, _token_hash(token)))
    await db.audit(user.username, "auth.mfa.reenroll", user.username, {"with": method}, actor_ip=ip)


async def mfa_disable(user: User, code: str, ip: str | None) -> None:
    """스스로 끄기 — 필수인 사람은 못 끈다(다시 등록은 mfa_reenroll)."""
    if user.mfa_required:
        raise AuthError("2단계 인증이 필수라 끌 수 없습니다 — 휴대폰을 바꿨으면 '다시 등록'을 쓰세요", 403, "mfa_mandatory")
    await _require_code(user, code, ip, "disable")
    await _clear_mfa(user.id)
    await db.audit(user.username, "auth.mfa.disable", user.username, {}, actor_ip=ip)


async def mfa_reset(user_id: int, actor: str, ip: str | None, reason: str = "") -> str:
    """관리자(또는 비상 명령)가 초기화: 비밀값·복구 코드를 지우고 그 사람의 세션을 끊는다 — 휴대폰을 잃은 경우.
    다음 로그인 때 필수면 다시 등록한다. 실패 횟수·잠금도 푼다(잃은 사람이 코드를 틀려 잠겼을 수 있다)."""
    row = await db.fetch_one("SELECT username FROM users WHERE id = %s", (user_id,))
    if row is None:
        raise AuthError("사용자가 없습니다", 404, "not_found")
    await _clear_mfa(user_id)
    await db.fetch_one("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = %s RETURNING id", (user_id,))
    await db.fetch_all("DELETE FROM sessions WHERE user_id = %s RETURNING token_hash", (user_id,))
    await db.audit(actor, "auth.mfa.reset", row["username"], {"reason": reason[:200]} if reason else {}, actor_ip=ip)
    return row["username"]


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


async def user_brief(user_id: int) -> dict | None:
    """역할·활성 여부 (관리 권한 부여를 알릴지 판단, B-36)."""
    return await db.fetch_one("SELECT id, username, role, is_active FROM users WHERE id = %s", (user_id,))


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
