"""관리자 2단계 인증 (TOTP, BACKLOG B-74) — 통합 시험.

회귀: 병원 전체의 보안 로그·감사 증적을 쥔 서버가 비밀번호 하나로 열렸다. 비밀번호만 아는 사람이 코드를 끝없이 맞혀 보거나,
코드 확인 전에 비밀번호를 바꾸거나, 가로챈 코드를 다시 쓰지 못해야 한다.
"""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime

import psycopg
import pytest

from app.auth import totp

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PASSWORD = "Root#Changed2026"


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _code(secret, ahead=0):
    return totp.code_at(secret, totp.step_of(datetime.now(UTC)) + ahead)


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.auth import service
    from app.main import app

    service._ip_failures.clear()
    original = service.settings
    service.settings = replace(original, mfa_required="privileged")
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": PASSWORD}, headers=CSRF)
            yield {"c": c, "state": {}}
    finally:
        service.settings = original


def _login(c, username="admin", password=PASSWORD):
    return c.post("/api/auth/login", json={"username": username, "password": password}, headers=CSRF)


def test_admin_must_enroll_before_using_the_app(ctx):
    c = ctx["c"]
    r = c.get("/api/alerts", headers=CSRF)
    assert r.status_code == 403 and r.headers["X-WLM-Reason"] == "mfa_setup_required"
    assert c.get("/api/auth/me").json()["mfa_setup_required"] is True
    setup = c.post("/api/auth/mfa/setup", headers=CSRF).json()
    assert setup["uri"].startswith("otpauth://totp/") and len(setup["secret"]) == 32
    assert c.post("/api/auth/mfa/enroll", json={"code": "000000"}, headers=CSRF).status_code == 400
    r = c.post("/api/auth/mfa/enroll", json={"code": _code(setup["secret"])}, headers=CSRF)
    assert r.status_code == 200, r.text
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10 and c.get("/api/alerts", headers=CSRF).status_code == 200
    # 비밀값은 암호화, 복구 코드는 HMAC 만 저장
    [(enc,)] = sql("SELECT mfa_secret_enc FROM users WHERE username = 'admin'")
    assert setup["secret"] not in enc
    assert not sql("SELECT 1 FROM mfa_recovery_codes WHERE code_hash = %s", (codes[0],))
    ctx["state"].update(secret=setup["secret"], codes=codes)


def test_password_alone_opens_only_a_pending_session(ctx):
    c = ctx["c"]
    c.post("/api/auth/logout", headers=CSRF)
    r = _login(c)
    assert r.status_code == 200 and r.json()["mfa_pending"] is True
    for method, path, body in (("get", "/api/alerts", None), ("post", "/api/auth/password",
                                                                {"current_password": PASSWORD, "new_password": "Other#Pass2026"}),
                               ("post", "/api/auth/mfa/setup", None), ("post", "/api/auth/mfa/reenroll", {"code": "000000"})):
        res = getattr(c, method)(path, json=body, headers=CSRF) if body else getattr(c, method)(path, headers=CSRF)
        assert res.status_code == 403 and res.headers["X-WLM-Reason"] == "mfa_required", path
    me = c.get("/api/auth/me").json()
    # 비밀번호만 아는 사람에게 마지막 로그인 IP·권한·범위를 보이지 않는다
    assert me == {"username": "admin", "display_name": me["display_name"], "mfa_pending": True, "mfa_setup_required": False}


def test_code_is_single_use_and_the_session_token_changes(ctx):
    c, secret = ctx["c"], ctx["state"]["secret"]
    pending = c.cookies.get("wlm_session")
    # 등록 때 쓴 칸의 코드는 다시 쓰지 못한다 (가로챈 코드 재사용) — 틀린 코드는 400 (화면이 로그인으로 튕기지 않게)
    used = sql("SELECT mfa_last_step FROM users WHERE username = 'admin'")[0][0]
    r = c.post("/api/auth/mfa/verify", json={"code": totp.code_at(secret, used)}, headers=CSRF)
    assert r.status_code == 400 and r.headers["X-WLM-Reason"] == "mfa_invalid"
    assert c.post("/api/auth/mfa/verify", json={"code": "１２３４５６"}, headers=CSRF).status_code == 400   # 전각 숫자도 500 이 아니다
    r = c.post("/api/auth/mfa/verify", json={"code": _code(secret, 1)}, headers=CSRF)
    assert r.status_code == 200 and r.json()["mfa_pending"] is False and "last_login_ip" in r.json()
    assert c.cookies.get("wlm_session") != pending and c.get("/api/alerts", headers=CSRF).status_code == 200
    assert sql("SELECT count(*) FROM sessions WHERE NOT mfa_ok")[0][0] == 0
    assert sql("SELECT failed_count FROM users WHERE username = 'admin'") == [(0,)]


def test_recovery_code_works_once(ctx):
    c, code = ctx["c"], ctx["state"]["codes"][0]
    c.post("/api/auth/logout", headers=CSRF)
    _login(c)
    assert c.post("/api/auth/mfa/verify", json={"code": code.upper()}, headers=CSRF).status_code == 200
    assert c.get("/api/auth/mfa").json()["recovery_left"] == 9
    c.post("/api/auth/logout", headers=CSRF)
    _login(c)
    assert c.post("/api/auth/mfa/verify", json={"code": code}, headers=CSRF).status_code == 400


def test_wrong_codes_lock_the_account_and_password_logins_do_not_reset_the_count(ctx):
    c = ctx["c"]
    sql("UPDATE users SET failed_count = 0 WHERE username = 'admin'")
    for _ in range(2):
        assert c.post("/api/auth/mfa/verify", json={"code": "123456"}, headers=CSRF).status_code == 400
    _login(c)   # 비밀번호를 아는 사람이 다시 로그인해도 실패 수는 지워지지 않는다 — 이 로그인도 시도 하나
    assert sql("SELECT failed_count FROM users WHERE username = 'admin'") == [(3,)]
    statuses = [c.post("/api/auth/mfa/verify", json={"code": "123456"}, headers=CSRF).status_code for _ in range(2)]
    assert statuses == [400, 423]
    assert _login(c).status_code == 423
    actions = [a for (a,) in sql("SELECT action FROM audit_log WHERE action LIKE 'auth.%%' ORDER BY id")]
    assert "auth.mfa.failed" in actions and actions.count("auth.account_locked") == 1
    sql("UPDATE users SET locked_until = NULL, failed_count = 0 WHERE username = 'admin'")


def test_a_burst_of_concurrent_guesses_is_still_capped(ctx):
    """동시에 보낸 코드 수백 개가 모두 잠금 검사를 지나던 것 (검토에서 재현) — 잠금 기간마다 기준 수까지만 확인된다."""
    import asyncio

    import httpx

    from app.auth import service
    from app.main import app

    c = ctx["c"]
    service._ip_failures.clear()
    _login(c)
    cookies = {"wlm_session": c.cookies.get("wlm_session")}

    async def burst():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", cookies=cookies) as client:
            return await asyncio.gather(*[client.post("/api/auth/mfa/verify", json={"code": "123456"}, headers=CSRF)
                                          for _ in range(25)])

    responses = c.portal.call(burst)
    checked = [r for r in responses if r.status_code == 400 or (r.status_code == 423 and "회 틀려" in r.text)]
    assert len(checked) <= 5 and sql("SELECT locked_until IS NOT NULL FROM users WHERE username = 'admin'") == [(True,)]
    sql("UPDATE users SET locked_until = NULL, failed_count = 0 WHERE username = 'admin'")
    service._ip_failures.clear()


def test_pending_session_expires(ctx):
    c = ctx["c"]
    _login(c)
    sql("UPDATE sessions SET expires_at = now() - interval '1 second' WHERE NOT mfa_ok")
    r = c.post("/api/auth/mfa/verify", json={"code": _code(ctx["state"]["secret"], 1)}, headers=CSRF)
    assert r.status_code == 401 and r.headers["X-WLM-Reason"] == "login_required"


def _full_login(c, secret):
    _login(c)
    sql("UPDATE users SET mfa_last_step = 0, failed_count = 0 WHERE username = 'admin'")   # 시간이 흐른 것처럼
    assert c.post("/api/auth/mfa/verify", json={"code": _code(secret)}, headers=CSRF).status_code == 200


def test_viewers_are_not_forced_but_privileged_groups_are(ctx):
    c = ctx["c"]
    _full_login(c, ctx["state"]["secret"])
    viewer = c.post("/api/users", json={"username": "watcher", "role": "viewer"}, headers=CSRF).json()
    ops = c.post("/api/users", json={"username": "ops", "role": "viewer"}, headers=CSRF).json()
    assert c.post("/api/user-groups", json={"name": "운영", "permissions": ["alerts.manage"], "member_ids": [ops["user"]["id"]]},
                  headers=CSRF).status_code == 200
    from fastapi.testclient import TestClient

    from app.main import app

    for name, temp, forced in (("watcher", viewer["temp_password"], False), ("ops", ops["temp_password"], True)):
        other = TestClient(app)
        other.post("/api/auth/login", json={"username": name, "password": temp}, headers=CSRF)
        other.post("/api/auth/password", json={"current_password": temp, "new_password": "Viewer#Pass2026"}, headers=CSRF)
        r = other.get("/api/events", params={"since": "1h"}, headers=CSRF)
        assert (r.status_code == 403 and r.headers.get("X-WLM-Reason") == "mfa_setup_required") is forced, name
    ctx["state"]["ops_id"] = ops["user"]["id"]


def test_step_up_checks_share_the_lockout(ctx):
    """복구 코드 새로 받기·끄기의 코드 확인도 같은 잠금 — 가로챈 세션으로 코드를 끝없이 맞혀 보지 못하고 세션이 끊긴다 (검토)."""
    from app.auth import service

    c = ctx["c"]
    service._ip_failures.clear()
    statuses = [c.post("/api/auth/mfa/recovery", json={"code": "123456"}, headers=CSRF).status_code for _ in range(5)]
    assert statuses == [400, 400, 400, 400, 423]
    assert c.get("/api/auth/me").status_code == 401   # 세션이 끊겼다
    sql("UPDATE users SET locked_until = NULL, failed_count = 0 WHERE username = 'admin'")
    service._ip_failures.clear()


def test_lost_phone_reenrolls_with_a_recovery_code(ctx):
    c = ctx["c"]
    _full_login(c, ctx["state"]["secret"])
    r = c.post("/api/auth/mfa/reenroll", json={"code": ctx["state"]["codes"][1]}, headers=CSRF)
    assert r.status_code == 200, r.text
    r = c.get("/api/alerts", headers=CSRF)
    assert r.status_code == 403 and r.headers["X-WLM-Reason"] == "mfa_setup_required"   # 필수라 바로 다시 등록
    setup = c.post("/api/auth/mfa/setup", headers=CSRF).json()
    assert c.post("/api/auth/mfa/enroll", json={"code": _code(setup["secret"])}, headers=CSRF).status_code == 200
    ctx["state"]["secret"] = setup["secret"]
    assert [a for (a,) in sql("SELECT action FROM audit_log WHERE action = 'auth.mfa.reenroll'")] == ["auth.mfa.reenroll"]


def test_admin_reset_and_self_disable(ctx):
    c = ctx["c"]
    other_id = ctx["state"]["ops_id"]
    sql("UPDATE users SET mfa_enabled_at = now(), mfa_secret_enc = 'x', locked_until = now() + interval '5 minutes'"
        " WHERE id = %s", (other_id,))
    r = c.post(f"/api/users/{other_id}/mfa/reset", headers=CSRF)
    assert r.status_code == 200 and r.json()["username"] == "ops"
    assert sql("SELECT mfa_enabled_at, mfa_secret_enc, locked_until FROM users WHERE id = %s", (other_id,)) == [(None, None, None)]
    assert sql("SELECT count(*) FROM sessions WHERE user_id = %s", (other_id,)) == [(0,)]
    [(text,)] = sql("SELECT payload->>'description' FROM alerts WHERE rule = '관리 작업 알림' ORDER BY id DESC LIMIT 1")
    assert "'ops' 의 2단계 인증을 초기화했습니다" in text
    # 필수인 사람은 스스로 끌 수 없다 (코드 대기 세션과 다른 이유 코드)
    r = c.post("/api/auth/mfa/disable", json={"code": _code(ctx["state"]["secret"])}, headers=CSRF)
    assert r.status_code == 403 and r.headers["X-WLM-Reason"] == "mfa_mandatory"


def test_missing_secret_key_fails_closed(ctx):
    """키가 없으면 비밀값을 풀 수 없다 — 비밀번호만으로 들여보내지 않는다 (검토)."""
    from app.auth import service

    c = ctx["c"]
    c.post("/api/auth/logout", headers=CSRF)
    current = service.settings
    service.settings = replace(current, secret_key="")
    try:
        r = _login(c)
        assert r.status_code == 503 and r.headers["X-WLM-Reason"] == "mfa_unavailable"
    finally:
        service.settings = current
