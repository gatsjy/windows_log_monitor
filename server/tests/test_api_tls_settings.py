"""보안 연결 화면·CA 내려받기·점검 보고서 경고 (BACKLOG B-31 1단계) — 통합 시험."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


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
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        for host, transport in (("PC-OLD", "plain"), ("PC-NEW", "tls"), ("PC-WEB", "web")):
            sql("INSERT INTO agents (host, last_seen, last_transport) VALUES (%s, now(), %s)", (host, transport))
        yield c


@pytest.fixture
def tls_on(tmp_path, monkeypatch):
    from app import tlsutil
    from app.config import settings
    from app.reports import builder
    from app.routers import settings as settings_router

    def make(days=400):
        ca_key, ca = tlsutil.issue_ca(["logmon.corp.local"], [])
        key, cert = tlsutil.issue_server(ca_key, ca, ["logmon.corp.local"], [], days=days)
        (tmp_path / "server.crt").write_bytes(tlsutil.cert_pem(cert) + tlsutil.cert_pem(ca))
        (tmp_path / "server.key").write_bytes(tlsutil.key_pem(key))
        (tmp_path / "server.key").chmod(0o600)
        (tmp_path / "ca.crt").write_bytes(tlsutil.cert_pem(ca) + tlsutil.key_pem(ca_key))   # 개인키가 섞인 파일도
        on = replace(settings, tls_mode="on", tls_cert_file=str(tmp_path / "server.crt"), tls_key_file=str(tmp_path / "server.key"),
                     tls_ca_file=str(tmp_path / "ca.crt"), public_url="https://logmon.corp.local:8080")
        monkeypatch.setattr(settings_router, "settings", on)
        monkeypatch.setattr(builder, "settings", on)
        return ca
    return make


def test_tls_off_overview_and_no_ca(client):
    t = client.get("/api/settings/tls").json()
    assert t["enabled"] is False and t["listeners"]["web"] == "http" and t["ca_download"] is False
    assert t["plain_pcs"] == ["PC-OLD", "PC-WEB"] and t["pcs"] == 3
    assert client.get("/api/settings/tls/ca.crt").status_code == 404


def test_tls_on_overview_ca_download_and_report(client, tls_on):
    from app import tlsutil

    ca = tls_on()
    t = client.get("/api/settings/tls").json()
    assert t["enabled"] and t["listeners"]["web"] == "https" and t["ca_ok"] and t["ca_download"]
    assert "logmon.corp.local" in t["dns_names"] and t["days_left"] > 300
    r = client.get("/api/settings/tls/ca.crt")
    assert r.status_code == 200 and b"PRIVATE KEY" not in r.content          # 개인키는 새지 않는다
    assert r.content == tlsutil.cert_pem(ca)
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'settings.tls.ca_download'")
    assert detail["ca_sha256"] == t["ca_sha256"]

    from app.reports import builder, render

    now = datetime.now(UTC)
    payload = client.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    texts = [a["text"] for a in payload["attention"]]
    assert any("평문으로 보내는 PC 2대" in x for x in texts) and not any("만료됩니다" in x for x in texts)
    assert render.html({k: v for k, v in payload.items() if k != "tls"}, 1)   # B-31 이전 보고서도 그린다


def test_report_warns_before_certificate_expiry(client, tls_on):
    tls_on(days=10)
    from app.reports import builder

    now = datetime.now(UTC)
    payload = client.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    warn = [a for a in payload["attention"] if "만료됩니다" in a["text"]]
    assert warn and warn[0]["level"] == "warn" and payload["tls"]["days_left"] <= 10
