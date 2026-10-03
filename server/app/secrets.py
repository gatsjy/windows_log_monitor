"""화면에서 입력한 비밀값(SMTP·Oracle 비밀번호, 웹훅 토큰) 암호화.

- Fernet (AES-128-CBC + HMAC-SHA256, cryptography 라이브러리 / Apache-2.0·BSD)
- 키 = WLM_SECRET_KEY 를 SHA-256 으로 늘린 값. 이 값을 잃어버리면 저장된 비밀값을 복호화할 수 없다
  → 다시 입력해야 한다 (백업 대상에 .env 포함, ISMS 2.7.2 암호키 관리)
- 화면/API 로는 비밀값을 절대 돌려주지 않는다 (설정 여부만 표시)
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


class SecretError(Exception):
    pass


def _fernet() -> Fernet:
    if not settings.secret_key:
        raise SecretError("서버에 WLM_SECRET_KEY 가 설정되지 않아 비밀번호를 저장할 수 없습니다 (.env 확인)")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest()))


def encrypt(values: dict[str, Any]) -> str:
    return _fernet().encrypt(json.dumps(values, ensure_ascii=False).encode()).decode()


def decrypt(token: str | None) -> dict[str, Any]:
    if not token:
        return {}
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except InvalidToken as exc:
        raise SecretError("저장된 비밀값을 복호화할 수 없습니다 (WLM_SECRET_KEY 가 바뀌었는지 확인, 다시 입력 필요)") from exc


def merge(old_token: str | None, updates: dict[str, Any]) -> str | None:
    """화면에서 비워 둔 비밀 항목은 기존 값을 유지한다. None 을 보내면 삭제."""
    current = decrypt(old_token) if old_token else {}
    for key, value in updates.items():
        if value is None:
            current.pop(key, None)
        elif value != "":
            current[key] = value
    return encrypt(current) if current else None
