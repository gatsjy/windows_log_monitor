"""에이전트 설치 묶음: 설정(주소·포트·키)과 Fluent Bit 설치 파일이 들어간 zip, 입력 검증, 감사 기록."""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
INSTALLERS = Path(os.environ["WLM_AGENT_INSTALLERS_DIR"])


@pytest.fixture(scope="module")
def client():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from app.config import settings

    if not (Path(settings.agent_dir) / "windows" / "install.ps1").exists():
        pytest.skip(f"에이전트 파일 없음: {settings.agent_dir} (컨테이너 밖이면 WLM_AGENT_DIR 지정)")
    INSTALLERS.mkdir(parents=True, exist_ok=True)
    (INSTALLERS / "fluent-bit-4.0.14-win64.zip").write_bytes(b"PK fake")
    (INSTALLERS / "fluent-bit-4.0.1-win64.zip").write_bytes(b"PK old")   # 같은 종류는 최신 하나만
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        yield c


def unzip(response):
    assert response.status_code == 200, response.text
    return zipfile.ZipFile(io.BytesIO(response.content))


def test_info(client):
    info = client.get("/api/agents/package/info", headers=CSRF).json()
    assert info["port"] == 6976 and info["installers"]["windows"] == ["fluent-bit-4.0.14-win64.zip"] and info["has_key"]


def test_windows_package(client):
    z = unzip(client.get("/api/agents/package", params={"server": "logmon.corp.local", "iis": "true"}, headers=CSRF))
    names = set(z.namelist())
    prefix = "log-monitor-agent-windows/"
    assert {f"{prefix}install.cmd", f"{prefix}install.ps1", f"{prefix}fluent-bit.yaml", f"{prefix}settings.json",
            f"{prefix}fluent-bit/fluent-bit-4.0.14-win64.zip", f"{prefix}설치방법.txt"} <= names
    assert f"{prefix}fluent-bit/fluent-bit-4.0.1-win64.zip" not in names
    conf = json.loads(z.read(f"{prefix}settings.json"))
    assert conf == {"ServerHost": "logmon.corp.local", "ServerPort": 6976, "ApiKey": "test-key", "Iis": True, "MssqlErrorlog": False}


def test_linux_package_quotes_values(client):
    z = unzip(client.get("/api/agents/package", params={"os": "linux", "server": "10.0.0.10", "port": 7000}, headers=CSRF))
    script = z.read("log-monitor-agent-linux/install-configured.sh").decode()
    assert "exec ./install.sh 10.0.0.10 7000 test-key" in script
    assert z.getinfo("log-monitor-agent-linux/install-configured.sh").external_attr >> 16 == 0o755


def test_rejects_bad_server_and_records_audit(client):
    assert client.get("/api/agents/package", params={"server": "x; rm -rf /"}, headers=CSRF).status_code == 422
    assert client.get("/api/agents/package", params={"server": "a.b", "os": "mac"}, headers=CSRF).status_code == 422
    items = client.get("/api/audit", params={"since": "1h", "action": "agents.package.download"}, headers=CSRF).json()["items"]
    assert items and "test-key" not in json.dumps(items)
