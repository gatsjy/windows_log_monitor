import dataclasses

import pytest

from app import secrets


def test_round_trip_and_ciphertext_hides_value():
    token = secrets.encrypt({"password": "Tiger#2026"})
    assert "Tiger" not in token
    assert secrets.decrypt(token) == {"password": "Tiger#2026"}


def test_merge_keeps_existing_when_blank_and_deletes_on_none():
    token = secrets.encrypt({"password": "a", "url": "https://x"})
    kept = secrets.merge(token, {"password": ""})
    assert secrets.decrypt(kept) == {"password": "a", "url": "https://x"}
    changed = secrets.merge(token, {"password": "b", "url": None})
    assert secrets.decrypt(changed) == {"password": "b"}
    assert secrets.merge(None, {}) is None


def test_wrong_key_is_reported(monkeypatch):
    token = secrets.encrypt({"password": "a"})
    monkeypatch.setattr(secrets, "settings", dataclasses.replace(secrets.settings, secret_key="another-key"))
    with pytest.raises(secrets.SecretError, match="복호화"):
        secrets.decrypt(token)
