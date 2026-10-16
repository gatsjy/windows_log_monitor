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


def test_delete_agent(client):
    # 1. 하트비트로 에이전트 등록
    res = client.post("/api/ingest", json=[{"type": "heartbeat", "agent_host": "TEST-AGENT-DEL"}],
                      headers={"X-API-Key": "test-key"})
    assert res.status_code == 200
    agents = client.get("/api/agents", headers=CSRF).json()["items"]
    assert any(a["host"] == "TEST-AGENT-DEL" for a in agents)

    # 2. CSRF 헤더 누락 시 거부
    assert client.delete("/api/agents/TEST-AGENT-DEL").status_code == 403

    # 3. 정상 삭제
    del_res = client.delete("/api/agents/TEST-AGENT-DEL", headers=CSRF)
    assert del_res.status_code == 200 and del_res.json()["deleted"] == ["TEST-AGENT-DEL"]

    # 4. 목록에서 제거되었는지 확인
    agents_after = client.get("/api/agents", headers=CSRF).json()["items"]
    assert not any(a["host"] == "TEST-AGENT-DEL" for a in agents_after)

    # 5. 이미 삭제된 호스트 삭제 시 404
    assert client.delete("/api/agents/TEST-AGENT-DEL", headers=CSRF).status_code == 404

    # 6. 감사 로그 확인
    audits = client.get("/api/audit", params={"since": "1h", "action": "agent.delete"}, headers=CSRF).json()["items"]
    assert any(a["target"] == "TEST-AGENT-DEL" for a in audits)

    # 7. 감사로그에 지운 PC 의 요약(무엇을 지웠는지)이 남는다
    entry = next(a for a in audits if a["target"] == "TEST-AGENT-DEL")
    assert "events_total" in entry["detail"] and "last_seen" in entry["detail"]


def test_delete_agents_bulk(client):
    hosts = ["BULK-A", "BULK-B", "BULK/C"]  # '/' 가 든 syslog 장비 이름도 지울 수 있어야 한다
    res = client.post("/api/ingest", json=[{"type": "heartbeat", "agent_host": h} for h in hosts],
                      headers={"X-API-Key": "test-key"})
    assert res.status_code == 200

    assert client.post("/api/agents/delete", json={"hosts": ["BULK-A"]}).status_code == 403  # CSRF
    assert client.post("/api/agents/delete", json={"hosts": []}, headers=CSRF).status_code == 422

    res = client.post("/api/agents/delete", json={"hosts": ["BULK-A", "BULK-B", "NO-SUCH-PC"]}, headers=CSRF)
    assert res.status_code == 200
    body = res.json()
    assert body["deleted"] == ["BULK-A", "BULK-B"] and body["missing"] == ["NO-SUCH-PC"]
    # 방금 하트비트를 보낸 PC 는 곧 다시 등록되므로 화면에 알릴 수 있게 돌려준다
    assert body["still_online"] == ["BULK-A", "BULK-B"]

    assert client.delete("/api/agents/BULK%2FC", headers=CSRF).status_code == 200
    left = {a["host"] for a in client.get("/api/agents", headers=CSRF).json()["items"]}
    assert not left & set(hosts)

    audits = client.get("/api/audit", params={"since": "1h", "action": "agent.delete"}, headers=CSRF).json()["items"]
    assert {"BULK-A", "BULK-B", "BULK/C"} <= {a["target"] for a in audits}


@pytest.fixture
def tls_on(tmp_path, monkeypatch):
    """TLS 를 켠 서버 흉내: 자체 CA + 서버 인증서(logmon.corp.local, 10.0.0.10), 에이전트 폴더에 실수로 든 개인키."""
    import shutil
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta

    from app import tlsutil
    from app.config import settings
    from app.routers import agentpkg

    def make(name="logmon.corp.local", now=None, other_ca=False):
        ca_key, ca = tlsutil.issue_ca([name], ["10.0.0.10"], now=now)
        key, cert = tlsutil.issue_server(ca_key, ca, [name], ["10.0.0.10"], now=now)
        d = tmp_path / f"tls-{name}-{bool(now)}-{other_ca}"
        d.mkdir()
        (d / "server.crt").write_bytes(tlsutil.cert_pem(cert) + tlsutil.cert_pem(ca))
        (d / "server.key").write_bytes(tlsutil.key_pem(key))
        (d / "server.key").chmod(0o640)
        shown_ca = tlsutil.issue_ca([name], [])[1] if other_ca else ca
        (d / "ca.crt").write_bytes(tlsutil.cert_pem(shown_ca))
        agent = tmp_path / "agent"
        if not agent.exists():
            shutil.copytree(settings.agent_dir, agent)
            (agent / "windows" / "leak.key").write_text("-----BEGIN PRIVATE KEY-----")
        monkeypatch.setattr(agentpkg, "settings", replace(
            settings, tls_mode="on", tls_cert_file=str(d / "server.crt"), tls_key_file=str(d / "server.key"),
            tls_ca_file=str(d / "ca.crt"), public_url=f"https://{name}:8080", agent_dir=str(agent)))
        return d, shown_ca

    make.past = datetime.now(UTC) - timedelta(days=800)
    return make


def test_tls_windows_package(client, tls_on):
    import hashlib

    from cryptography.hazmat.primitives import serialization

    d, ca = tls_on()
    info = client.get("/api/agents/package/info", headers=CSRF).json()
    der = ca.public_bytes(serialization.Encoding.DER)
    assert info["port"] == 6977 and info["tls"]["enabled"] and info["tls"]["server_names"] == ["logmon.corp.local"]
    assert info["tls"]["ca_sha256"] == hashlib.sha256(der).hexdigest() and info["tls"]["problems"] == []
    # 서버 주소가 IP 여도 에이전트는 인증서의 DNS 이름으로 확인한다
    z = unzip(client.get("/api/agents/package", params={"server": "10.0.0.10"}, headers=CSRF))
    prefix = "log-monitor-agent-windows/"
    conf = json.loads(z.read(f"{prefix}settings.json"))
    assert conf == {"ServerHost": "10.0.0.10", "ServerPort": 6977, "ApiKey": "test-key", "Iis": False,
                    "MssqlErrorlog": False, "CaFile": "ca.crt", "TlsServerName": "logmon.corp.local",
                    "CaSha256": hashlib.sha256(der).hexdigest()}
    assert z.read(f"{prefix}ca.crt") == (d / "ca.crt").read_bytes()
    assert not [n for n in z.namelist() if n.endswith(".key")]   # 에이전트 폴더의 개인키는 묶음에 넣지 않는다
    guide = z.read(f"{prefix}설치방법.txt").decode("utf-8-sig")
    assert "10.0.0.10:6977" in guide and "TLS" in guide and "logmon.corp.local" in guide
    audit = client.get("/api/audit", params={"since": "1h", "action": "agents.package.download"},
                       headers=CSRF).json()["items"][0]["detail"]
    assert audit["tls"] is True and audit["server_name"] == "logmon.corp.local"
    assert audit["ca_sha256"] == conf["CaSha256"] and "test-key" not in json.dumps(audit)


def test_tls_names_and_linux(client, tls_on):
    tls_on()
    get = lambda **p: client.get("/api/agents/package", params={"server": "logmon.corp.local", **p}, headers=CSRF)
    r = get(name="other.corp.local")
    assert r.status_code == 422 and "가능한 이름: logmon.corp.local" in r.json()["detail"]
    assert get(name="10.0.0.10").status_code == 422
    z = unzip(get(os="linux", name="LogMon.corp.local."))
    script = z.read("log-monitor-agent-linux/install-configured.sh").decode()
    assert 'TLS_CA_FILE="$PWD/ca.crt" TLS_SERVER_NAME=logmon.corp.local exec ./install.sh logmon.corp.local 6977 test-key' \
        in script
    assert "log-monitor-agent-linux/ca.crt" in z.namelist()


def test_tls_refuses_bundles_agents_cannot_verify(client, tls_on):
    d, _ = tls_on()
    (d / "ca.crt").unlink()
    r = client.get("/api/agents/package", params={"server": "logmon.corp.local"}, headers=CSRF)
    assert r.status_code == 409 and "CA 인증서" in r.json()["detail"]
    tls_on(other_ca=True)
    r = client.get("/api/agents/package", params={"server": "logmon.corp.local"}, headers=CSRF)
    assert r.status_code == 409 and "다른 CA" in r.json()["detail"]
    tls_on(now=tls_on.past)
    r = client.get("/api/agents/package", params={"server": "logmon.corp.local"}, headers=CSRF)
    assert r.status_code == 409 and "만료" in r.json()["detail"]


def test_tls_bundle_carries_only_certificates(client, tls_on):
    """사내 PKI 의 full.pem 처럼 CA 파일에 개인키가 섞여 있으면 묶음을 만들지 않고, 묶음에는 늘 인증서만 들어간다."""
    from app import tlsutil

    d, _ = tls_on()
    pem = (d / "ca.crt").read_bytes()
    (d / "ca.crt").write_bytes(pem + tlsutil.key_pem(tlsutil.load_key(str(d / "server.key"))))
    r = client.get("/api/agents/package", params={"server": "logmon.corp.local"}, headers=CSRF)
    assert r.status_code == 409 and "개인키" in r.json()["detail"]
    assert b"PRIVATE KEY" not in tlsutil.ca_bundle_pem(str(d / "ca.crt"))


def test_tls_wildcard_certificate_and_name_checks(client, tls_on, monkeypatch):
    """와일드카드(*.corp.local)뿐인 사내 인증서: 서버 주소가 그 아래 이름이면 그것으로, IP 면 이름을 지정하게.
    이름은 DNS 모양만 받는다 (설정 파일·스크립트에 그대로 들어가므로)."""
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    from app import tlsutil
    from app.routers import agentpkg

    d, _ = tls_on()
    root_key, root = tlsutil.issue_ca(["corp.local"], [])
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "corp")]))
            .issuer_name(root.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=300))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.corp.local")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
            .sign(root_key, hashes.SHA256()))
    (d / "server.crt").write_bytes(tlsutil.cert_pem(leaf))
    (d / "server.key").write_bytes(tlsutil.key_pem(key))
    (d / "ca.crt").write_bytes(tlsutil.cert_pem(root))
    monkeypatch.setattr(agentpkg, "settings", replace(agentpkg.settings, public_url="https://logmon.corp.local"))
    info = client.get("/api/agents/package/info", headers=CSRF).json()["tls"]
    assert info["server_names"] == [] and info["wildcards"] == ["*.corp.local"] and info["ca_ok"]
    get = lambda **p: client.get("/api/agents/package", params=p, headers=CSRF)
    conf = json.loads(unzip(get(server="logmon.corp.local")).read("log-monitor-agent-windows/settings.json"))
    assert conf["TlsServerName"] == "logmon.corp.local"
    r = get(server="10.0.0.10")
    assert r.status_code == 409 and "와일드카드" in r.json()["detail"]
    conf = json.loads(unzip(get(server="10.0.0.10", name="LogMon.corp.local.")).read(
        "log-monitor-agent-windows/settings.json"))
    assert conf["TlsServerName"] == "logmon.corp.local"
    for bad in ("*.corp.local", "a b.corp.local", "x\n tls: off\n#.corp.local", "$(id).corp.local"):
        r = get(server="10.0.0.10", name=bad)
        assert r.status_code == 422 and "DNS 이름" in r.json()["detail"], bad


def test_tls_unreadable_server_cert_names_the_real_cause(client, tls_on):
    d, _ = tls_on()
    (d / "server.crt").write_bytes(b"")
    r = client.get("/api/agents/package", params={"server": "logmon.corp.local"}, headers=CSRF)
    assert r.status_code == 409 and "서버 인증서" in r.json()["detail"] and "CA 인증서" not in r.json()["detail"]
