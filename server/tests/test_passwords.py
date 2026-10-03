import pytest

from app.auth.passwords import check_policy, generate_password, hash_password, needs_rehash, verify_password


def test_hash_and_verify():
    encoded = hash_password("Correct#Horse9")
    assert encoded.startswith("scrypt$")
    assert verify_password("Correct#Horse9", encoded)
    assert not verify_password("correct#horse9", encoded)
    assert not verify_password("x", "garbage")


def test_salt_makes_hashes_differ():
    assert hash_password("Same#Pass99") != hash_password("Same#Pass99")


def test_needs_rehash_when_cost_changes():
    assert not needs_rehash(hash_password("A#b1cdefgh"))
    assert needs_rehash(hash_password("A#b1cdefgh", n=2**10))


@pytest.mark.parametrize("password, ok", [
    ("Abcdef1!", True),        # 4종 8자
    ("abcdef12!", True),       # 3종 9자
    ("abcdefgh12", True),      # 2종 10자
    ("abcdefg1", False),       # 2종 8자
    ("abcdefghij", False),     # 1종
    ("Ab1!", False),           # 짧음
    ("Aaaaa1!xyz", False),     # 같은 문자 4번 연속
])
def test_policy(password, ok):
    assert (check_policy(password) is None) is ok


def test_policy_rejects_username():
    assert "아이디" in check_policy("Kim.Minsu#2026", "kim.minsu")


def test_generated_passwords_meet_policy():
    for _ in range(50):
        assert check_policy(generate_password()) is None


def test_bootstrap_ignores_initial_password_read_from_comment(monkeypatch):
    """'.env' 의 'WLM_ADMIN_INITIAL_PASSWORD=    # 설명' 은 compose 가 설명문을 값으로 넘긴다 → 공개 문구를 비밀번호로 쓰지 않음."""
    import asyncio
    import dataclasses

    from app.auth import service

    created = {}

    async def fetch_one(*_args, **_kwargs):
        return {"n": 0}

    async def create_user(*_args, password=None, **_kwargs):
        created["password"] = password
        return {}, "random-temp"

    monkeypatch.setattr(service.db, "fetch_one", fetch_one)
    monkeypatch.setattr(service, "create_user", create_user)
    monkeypatch.setattr(service, "settings", dataclasses.replace(service.settings, admin_initial_password="# 비우면 무작위"))
    asyncio.run(service.bootstrap_admin())
    assert created["password"] is None
