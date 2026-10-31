"""2단계 인증 코드 (TOTP, RFC 6238 — HMAC-SHA1, 30초, 6자리). 표준 라이브러리만 (새 의존성 없음).

인증 앱(Google Authenticator·Microsoft Authenticator 등)이 같은 계산을 한다. 폐쇄망에서도 휴대폰 시계만 맞으면 된다.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from urllib.parse import quote

STEP_SEC = 30
DIGITS = 6
WINDOW = 1            # 앞뒤 한 칸(±30초)까지 — 휴대폰 시계가 조금 어긋나도 받는다
RECOVERY_COUNT = 10
ISSUER = "Log Monitor"


def new_secret() -> str:
    """160비트 비밀값을 base32 로 (인증 앱에 직접 입력할 수 있게 '=' 없이)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    text = secret_b32.replace(" ", "").upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def code_at(secret_b32: str, step: int) -> str:
    digest = hmac.new(_key(secret_b32), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def step_of(now: datetime) -> int:
    return int(now.timestamp()) // STEP_SEC


def verify(secret_b32: str, code: str, now: datetime, last_step: int) -> int | None:
    """맞으면 그 시간 칸 번호, 아니면 None. last_step 이하의 칸은 받지 않는다 — 같은 코드를 두 번(가로챈 코드를 다시) 쓰지 못하게."""
    # ASCII 숫자만 — str.isdigit 은 전각·아라비아 숫자도 참이라 compare_digest 가 TypeError(500)를 냈다(검토)
    code = "".join(ch for ch in (code or "") if ch in "0123456789")
    if len(code) != DIGITS:
        return None
    current = step_of(now)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if step > last_step and hmac.compare_digest(code_at(secret_b32, step), code):
            return step
    return None


def otpauth_uri(secret_b32: str, account: str) -> str:
    """인증 앱 등록용 주소 (QR 대신 앱의 '키 직접 입력'에 비밀값을 넣어도 된다)."""
    label = quote(f"{ISSUER}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(ISSUER)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SEC}")


def new_recovery_codes() -> list[str]:
    """휴대폰을 잃었을 때 한 번씩 쓰는 코드 — 'abcd-efgh-jk' (헷갈리는 글자 0/o·1/l 없음, 약 52비트)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    out = []
    for _ in range(RECOVERY_COUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        out.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return out


def normalize_recovery(code: str) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())


def recovery_hash(code: str, server_key: str) -> str:
    """서버 키(WLM_SECRET_KEY)로 HMAC — DB 만 새도 코드를 되찾을 수 없다. 느린 해시가 필요 없을 만큼 코드가 길다."""
    return hmac.new(server_key.encode(), normalize_recovery(code).encode(), hashlib.sha256).hexdigest()
