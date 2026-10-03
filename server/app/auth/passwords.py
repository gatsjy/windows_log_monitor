"""비밀번호 해시(scrypt, 표준 라이브러리)와 비밀번호 정책.

저장 형식: scrypt$N$r$p$<salt base64>$<hash base64>
  - N=2^17, r=8, p=1 은 OWASP 권고 최소값. 변수를 형식 안에 저장하므로 나중에 올려도 기존 해시는 검증된다.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import string

from ..config import settings

_R, _P, _DKLEN = 8, 1, 32
_MAXMEM = 512 * 1024 * 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, n: int | None = None) -> str:
    n = n or settings.password_hash_n
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=_R, p=_P, maxmem=_MAXMEM, dklen=_DKLEN)
    return f"scrypt${n}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = encoded.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r),
                                p=int(p), maxmem=_MAXMEM, dklen=len(base64.b64decode(expected)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, base64.b64decode(expected))


def needs_rehash(encoded: str) -> bool:
    """해시 비용을 올렸으면 다음 로그인 때 새 비용으로 다시 저장."""
    try:
        return int(encoded.split("$")[1]) != settings.password_hash_n
    except (IndexError, ValueError):
        return True


_dummy: str | None = None


def dummy_verify(password: str) -> None:
    """없는 아이디로 로그인할 때도 같은 시간이 걸리게 해서 아이디 존재 여부를 숨긴다."""
    global _dummy
    _dummy = _dummy or hash_password("dummy-password-for-timing")
    verify_password(password, _dummy)


# -------------------------------------------------------------- 정책

_CLASSES = (string.ascii_lowercase, string.ascii_uppercase, string.digits)


def _class_count(password: str) -> int:
    count = sum(any(c in chars for c in password) for chars in _CLASSES)
    return count + (1 if any(not c.isalnum() for c in password) else 0)


def check_policy(password: str, username: str = "") -> str | None:
    """정책 위반이면 사용자에게 보여줄 문구, 통과하면 None.

    영문 대문자·소문자·숫자·특수문자 중 3종 이상이면 8자 이상, 2종이면 10자 이상
    (개인정보 안전성 확보조치 기준 해설서의 일반적 해석). 아이디 포함·같은 문자 4번 반복 금지.
    """
    if len(password) > 128:
        return "비밀번호는 128자 이하여야 합니다"
    classes = _class_count(password)
    if not ((classes >= 3 and len(password) >= 8) or (classes >= 2 and len(password) >= 10)):
        return "영문 대·소문자, 숫자, 특수문자 중 3종류 이상이면 8자 이상, 2종류면 10자 이상이어야 합니다"
    if username and len(username) >= 3 and username.lower() in password.lower():
        return "비밀번호에 아이디를 포함할 수 없습니다"
    if re.search(r"(.)\1{3,}", password):
        return "같은 문자를 4번 이상 연속해서 쓸 수 없습니다"
    return None


def generate_password(length: int = 14) -> str:
    """정책을 만족하는 임시 비밀번호 (헷갈리는 문자 0 O l 1 I 제외)."""
    lower, upper, digits, special = "abcdefghjkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^*-_"
    while True:
        chars = [secrets.choice(s) for s in (lower, upper, digits, special)]
        chars += [secrets.choice(lower + upper + digits) for _ in range(length - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        candidate = "".join(chars)
        if check_policy(candidate) is None:
            return candidate
