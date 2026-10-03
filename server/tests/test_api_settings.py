"""환경설정 통합 테스트 — 수신자·그룹·외부 연동·메일 서버, Oracle(TNS/SID/서비스) 실제 접속.

Oracle 부분은 시험용 Oracle 컨테이너(wlm-oracle-test, gvenzl/oracle-free)가 같은 docker 네트워크에 있을 때만 실행된다:
  docker run -d --name wlm-oracle-test --network log-monitor_default -e ORACLE_PASSWORD=TestSys_2026 \\
    -e APP_USER=LOGMON -e APP_USER_PASSWORD=LogmonTest_2026 gvenzl/oracle-free:23-slim-faststart
"""

from __future__ import annotations

import os
import socket

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
ORACLE_HOST = os.environ.get("WLM_TEST_ORACLE_HOST", "wlm-oracle-test")
APP_USER, APP_PASSWORD = "LOGMON", "LogmonTest_2026"
SYS_PASSWORD = "TestSys_2026"


def _oracle_up() -> bool:
    try:
        with socket.create_connection((ORACLE_HOST, 1521), timeout=1):
            return True
    except OSError:
        return False


needs_oracle = pytest.mark.skipif(not _oracle_up(), reason="시험용 Oracle 컨테이너 없음")


@pytest.fixture(scope="module")
def client():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        r = c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"},
                   headers=CSRF)
        assert r.status_code == 200, r.text
        yield c


def test_default_group_exists(client):
    names = [g["name"] for g in client.get("/api/settings/groups").json()["items"]]
    assert names == ["운영팀"]


def test_contacts_and_groups(client):
    r = client.post("/api/settings/contacts", json={"name": "김민수", "email": "kim@example.com", "department": "인프라"},
                    headers=CSRF)
    assert r.status_code == 200, r.text
    kim = r.json()["id"]
    lee = client.post("/api/settings/contacts", json={"name": "이지영", "email": "lee@example.com"}, headers=CSRF).json()["id"]
    assert client.post("/api/settings/contacts", json={"name": "x", "email": "not-an-email"},
                       headers=CSRF).status_code == 400

    r = client.post("/api/settings/groups", json={"name": "보안팀", "member_ids": [kim, lee], "min_severity": "error"},
                    headers=CSRF)
    assert r.status_code == 200, r.text
    groups = {g["name"]: g for g in client.get("/api/settings/groups").json()["items"]}
    assert groups["보안팀"]["members"] == 2 and groups["보안팀"]["deliverable"] == 2
    assert groups["보안팀"]["min_severity"] == "error"

    # 비활성 수신자는 메일 대상에서 빠진다
    client.put(f"/api/settings/contacts/{lee}", json={"name": "이지영", "email": "lee@example.com", "is_active": False},
               headers=CSRF)
    groups = {g["name"]: g for g in client.get("/api/settings/groups").json()["items"]}
    assert groups["보안팀"]["deliverable"] == 1


def test_rules_must_reference_existing_targets(client):
    bad = "rules:\n  - name: r1\n    match: {level: '1'}\n    notify: [없는그룹]\n"
    r = client.put("/api/alerts/config", content=bad, headers={**CSRF, "Content-Type": "text/plain"})
    assert r.status_code == 422 and "없는그룹" in r.json()["detail"]
    good = "rules:\n  - name: r1\n    match: {level: '1'}\n    notify: [보안팀]\n"
    r = client.put("/api/alerts/config", content=good, headers={**CSRF, "Content-Type": "text/plain"})
    assert r.status_code == 200, r.text


def test_group_in_use_cannot_be_deleted_or_renamed(client):
    group = next(g for g in client.get("/api/settings/groups").json()["items"] if g["name"] == "보안팀")
    assert group["used_by"] == ["r1"]
    assert client.delete(f"/api/settings/groups/{group['id']}", headers=CSRF).status_code == 400
    r = client.put(f"/api/settings/groups/{group['id']}", json={"name": "보안2팀"}, headers=CSRF)
    assert r.status_code == 400


def test_names_shared_between_groups_and_channels(client):
    r = client.post("/api/settings/channels", json={"name": "보안팀", "type": "webhook", "url": "https://h/x"},
                    headers=CSRF)
    assert r.status_code == 400


def test_webhook_secrets_are_never_returned(client):
    r = client.post("/api/settings/channels", json={
        "name": "메신저", "type": "webhook", "url": "https://hooks.example.com/T000/SECRET-PATH",
        "headers": {"Authorization": "Bearer very-secret"}, "config": {"format": "text"}}, headers=CSRF)
    assert r.status_code == 200, r.text
    body = client.get("/api/settings/channels").text
    assert "SECRET-PATH" not in body and "very-secret" not in body
    channel = client.get("/api/settings/channels").json()["items"][0]
    assert channel["has_secret"] and channel["target"] == "https://hooks.example.com/…"
    stored = psycopg.connect(os.environ["WLM_DATABASE_URL"]).execute("SELECT secret_enc FROM channels").fetchone()[0]
    assert "very-secret" not in stored  # DB 에도 암호화되어 저장


def test_smtp_settings_hide_password(client):
    r = client.put("/api/settings/smtp", json={"host": "smtp.example.com", "port": 587, "security": "starttls",
                                               "user": "logmon", "sender": "logmon@example.com",
                                               "password": "Mail#Pass2026"}, headers=CSRF)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["source"] == "db" and data["has_password"] and "Mail#Pass2026" not in r.text
    # 비밀번호를 비워 저장하면 기존 비밀번호 유지
    data = client.put("/api/settings/smtp", json={"host": "smtp.example.com", "password": ""}, headers=CSRF).json()
    assert data["has_password"]


def test_viewer_cannot_open_settings(client):
    temp = client.post("/api/users", json={"username": "viewer2", "role": "viewer"}, headers=CSRF).json()["temp_password"]
    from fastapi.testclient import TestClient

    from app.main import app

    other = TestClient(app)
    other.post("/api/auth/login", json={"username": "viewer2", "password": temp}, headers=CSRF)
    other.post("/api/auth/password", json={"current_password": temp, "new_password": "Viewer#Pass2026"}, headers=CSRF)
    assert other.get("/api/settings/contacts").status_code == 403


# ------------------------------------------------------------------ Oracle

def _oracle_channel(client, name, config, password):
    r = client.post("/api/settings/channels", json={"name": name, "type": "oracle", "config": config,
                                                     "password": password}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()["id"]


@needs_oracle
def test_oracle_service_name_connection_and_alert_insert(client):
    import oracledb

    with oracledb.connect(user=APP_USER, password=APP_PASSWORD, dsn=f"{ORACLE_HOST}:1521/FREEPDB1") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM user_tables WHERE table_name = 'LOGMON_ALERTS'")
            if not cur.fetchone()[0]:
                # docs/oracle_alerts.sql 과 같은 구조
                cur.execute("CREATE TABLE LOGMON_ALERTS (ALERT_ID NUMBER(19) PRIMARY KEY, RULE_NAME VARCHAR2(200) NOT NULL,"
                            " SEVERITY VARCHAR2(20) NOT NULL, HOST VARCHAR2(255), EVENT_COUNT NUMBER(19),"
                            " WINDOW_SEC NUMBER(10), FIRST_EVENT_AT TIMESTAMP, LAST_EVENT_AT TIMESTAMP,"
                            " FIRED_AT TIMESTAMP NOT NULL, TITLE VARCHAR2(500), MESSAGE VARCHAR2(4000),"
                            " LINK VARCHAR2(1000), DETAIL_JSON CLOB, CREATED_AT TIMESTAMP DEFAULT SYSTIMESTAMP)")
            cur.execute("DELETE FROM LOGMON_ALERTS")
        conn.commit()

    cid = _oracle_channel(client, "erp-service", {"mode": "service", "host": ORACLE_HOST, "port": 1521,
                                                   "service_name": "FREEPDB1", "user": APP_USER}, APP_PASSWORD)
    r = client.post(f"/api/settings/channels/{cid}/test", headers=CSRF)
    assert r.status_code == 200, r.text
    assert r.json()["result"]["schema"] == APP_USER

    # 시험 실행 (롤백) → 행이 남지 않는다
    r = client.post(f"/api/settings/channels/{cid}/oracle/dry-run", json={"commit": False}, headers=CSRF)
    assert r.status_code == 200 and r.json()["rowcount"] == 1, r.text
    q = {"sql": "SELECT count(*) AS N FROM LOGMON_ALERTS"}
    r = client.post(f"/api/settings/channels/{cid}/oracle/query", json=q, headers=CSRF)
    assert r.status_code == 200, r.text
    assert r.json()["rows"] == [[0]]
    # 실제 저장
    r = client.post(f"/api/settings/channels/{cid}/oracle/dry-run", json={"commit": True}, headers=CSRF)
    assert r.status_code == 200, r.text
    result = client.post(f"/api/settings/channels/{cid}/oracle/query",
                         json={"sql": "SELECT RULE_NAME, HOST, DETAIL_JSON FROM LOGMON_ALERTS"}, headers=CSRF).json()
    assert result["columns"] == ["RULE_NAME", "HOST", "DETAIL_JSON"]
    assert result["rows"][0][:2] == ["테스트 알림", "TEST-PC"] and '"rule": "테스트 알림"' in result["rows"][0][2]  # CLOB


@needs_oracle
def test_oracle_query_runner_is_read_only(client):
    cid = next(c["id"] for c in client.get("/api/settings/channels").json()["items"] if c["name"] == "erp-service")
    for sql in ("DELETE FROM LOGMON_ALERTS", "SELECT 1 FROM DUAL; DROP TABLE X", "UPDATE LOGMON_ALERTS SET HOST = 'x'"):
        r = client.post(f"/api/settings/channels/{cid}/oracle/query", json={"sql": sql}, headers=CSRF)
        assert r.status_code == 400, sql
    # SELECT 로 위장한 DML 도 읽기 전용 트랜잭션에서 막힌다 (FOR UPDATE 잠금 시도 → ORA 오류)
    r = client.post(f"/api/settings/channels/{cid}/oracle/query",
                    json={"sql": "SELECT * FROM LOGMON_ALERTS FOR UPDATE"}, headers=CSRF)
    assert r.status_code == 400
    audit = psycopg.connect(os.environ["WLM_DATABASE_URL"]).execute(
        "SELECT count(*) FROM audit_log WHERE action = 'settings.oracle.query'").fetchone()[0]
    assert audit >= 5


@needs_oracle
def test_oracle_sid_connection(client):
    # SID 방식: CDB(FREE)에 공통 사용자 SYSTEM 으로
    r = client.post("/api/settings/oracle/test-connection", json={
        "config": {"mode": "sid", "host": ORACLE_HOST, "port": 1521, "sid": "FREE", "user": "SYSTEM"},
        "password": SYS_PASSWORD}, headers=CSRF)
    assert r.status_code == 200, r.text
    assert r.json()["db_name"] == "FREE"


@needs_oracle
def test_oracle_tns_alias_connection(client):
    tns = (f"ERP_TEST =\n  (DESCRIPTION =\n    (ADDRESS = (PROTOCOL = TCP)(HOST = {ORACLE_HOST})(PORT = 1521))\n"
           "    (CONNECT_DATA = (SERVICE_NAME = FREEPDB1)))\n")
    r = client.put("/api/settings/oracle/tnsnames", json={"text": tns}, headers=CSRF)
    assert r.status_code == 200 and r.json()["aliases"] == ["ERP_TEST"], r.text
    cid = _oracle_channel(client, "erp-tns", {"mode": "tns", "tns_alias": "ERP_TEST", "user": APP_USER}, APP_PASSWORD)
    r = client.post(f"/api/settings/channels/{cid}/test", headers=CSRF)
    assert r.status_code == 200, r.text
    # 없는 별칭은 저장 단계에서 거부되지 않지만 접속 시 친절한 오류
    r = client.post("/api/settings/oracle/test-connection", json={
        "config": {"mode": "tns", "tns_alias": "NOPE", "user": APP_USER}, "password": APP_PASSWORD}, headers=CSRF)
    assert r.status_code == 502 and "NOPE" in r.json()["detail"]


@needs_oracle
def test_wrong_oracle_password_reports_error(client):
    r = client.post("/api/settings/oracle/test-connection", json={
        "config": {"mode": "service", "host": ORACLE_HOST, "service_name": "FREEPDB1", "user": APP_USER},
        "password": "wrong"}, headers=CSRF)
    assert r.status_code == 502 and "ORA-01017" in r.json()["detail"]
