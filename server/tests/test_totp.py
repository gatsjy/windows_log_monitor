"""2단계 인증 코드 계산 (RFC 6238, B-74) — DB 없는 단위 시험."""

from __future__ import annotations

from datetime import UTC, datetime

from app.auth import totp

# RFC 6238 부록 B 의 SHA1 시험 값 (비밀값 '12345678901234567890', 8자리) — 6자리는 끝 6자리
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
VECTORS = [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924"), (2000000000, "279037")]


def test_rfc6238_vectors():
    for t, code in VECTORS:
        assert totp.code_at(RFC_SECRET, t // 30) == code


def test_window_and_replay():
    now = datetime.fromtimestamp(1234567890, UTC)
    step = totp.step_of(now)
    assert totp.verify(RFC_SECRET, "005924", now, 0) == step
    assert totp.verify(RFC_SECRET, " 005 924 ", now, 0) == step          # 띄어쓰기는 무시
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), now, 0) == step - 1   # 30초 앞까지
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 2), now, 0) is None      # 60초 뒤는 아님
    assert totp.verify(RFC_SECRET, "005924", now, step) is None          # 이미 쓴 칸 — 같은 코드를 두 번 쓰지 못한다
    assert totp.verify(RFC_SECRET, "00592", now, 0) is None
    assert totp.verify(RFC_SECRET, "", now, 0) is None


def test_new_secret_and_uri():
    secret = totp.new_secret()
    assert len(secret) == 32 and "=" not in secret and totp.code_at(secret, 1).isdigit()
    uri = totp.otpauth_uri(secret, "kim.minsu")
    assert uri.startswith("otpauth://totp/Log%20Monitor%3Akim.minsu?secret=") and "period=30" in uri


def test_recovery_codes_are_unique_and_hash_ignores_format():
    codes = totp.new_recovery_codes()
    assert len(set(codes)) == 10 and all(len(c) == 12 and c.count("-") == 2 for c in codes)
    assert totp.recovery_hash("ABCD-efgh-jk", "k") == totp.recovery_hash(" abcdefghjk ", "k")
    assert totp.recovery_hash("abcd-efgh-jk", "k") != totp.recovery_hash("abcd-efgh-jk", "other-key")
