"""운영 HTTPS·에이전트 TLS (B-06, ADR-036) — 인증서 발급·TLS 설정·기동 전 점검·인증서 상태. DB 없음."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import tlsutil

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def _write(tmp_path, name, data: bytes, mode=0o600):
    path = tmp_path / name
    path.write_bytes(data)
    path.chmod(mode)
    return str(path)


def _files(tmp_path, names=("logmon.corp.local",), ips=("10.0.0.10",), *, now=None, days=tlsutil.SERVER_DAYS):
    """자체 CA + 서버 인증서를 tmp 에 쓰고 설정 흉내를 돌려준다."""
    ca_key, ca = tlsutil.issue_ca(list(names), list(ips), now=now)
    key, cert = tlsutil.issue_server(ca_key, ca, list(names), list(ips), days=days, now=now)
    s = SimpleNamespace(
        tls_mode="on", trusted_proxies=(), public_url=f"https://{names[0]}:8080",
        tls_cert_file=_write(tmp_path, "server.crt", tlsutil.cert_pem(cert) + tlsutil.cert_pem(ca)),
        tls_key_file=_write(tmp_path, "server.key", tlsutil.key_pem(key), 0o640),
        tls_ca_file=_write(tmp_path, "ca.crt", tlsutil.cert_pem(ca), 0o644),
    )
    return s, ca_key, ca, cert


def _ext(cert, cls):
    return cert.extensions.get_extension_for_class(cls)


def test_issued_certificates(tmp_path):
    ca_key, ca = tlsutil.issue_ca(["logmon.corp.local", "localhost"], ["10.0.0.10"], now=NOW)
    bc = _ext(ca, x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = _ext(ca, x509.KeyUsage)
    assert ku.critical and ku.value.key_cert_sign and ku.value.crl_sign
    nc = _ext(ca, x509.NameConstraints)
    assert nc.critical
    assert {g.value for g in nc.value.permitted_subtrees} == {"logmon.corp.local", "localhost",
                                                               ipaddress.ip_network("10.0.0.10/32")}
    assert ca.not_valid_after_utc - NOW == timedelta(days=tlsutil.CA_DAYS)

    key, cert = tlsutil.issue_server(ca_key, ca, ["LogMon.corp.local."], ["10.0.0.10"], now=NOW)
    assert tlsutil.san_names(cert) == (["logmon.corp.local"], ["10.0.0.10"])
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "logmon.corp.local"
    assert _ext(cert, x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    assert not _ext(cert, x509.BasicConstraints).value.ca
    assert _ext(cert, x509.KeyUsage).value.digital_signature
    # AKI = CA 의 SKI (없으면 Python 3.13 엄격 검증이 거부)
    assert (_ext(cert, x509.AuthorityKeyIdentifier).value.key_identifier
            == _ext(ca, x509.SubjectKeyIdentifier).value.digest)
    assert NOW - cert.not_valid_before_utc == timedelta(days=1)   # PC 시계가 조금 늦어도
    assert cert.not_valid_after_utc - NOW == timedelta(days=tlsutil.SERVER_DAYS)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    # CA 보다 오래 살 수 없다
    _, long = tlsutil.issue_server(ca_key, ca, ["logmon.corp.local"], [], days=99999, now=NOW)
    assert long.not_valid_after_utc == ca.not_valid_after_utc


def test_names_are_checked():
    with pytest.raises(tlsutil.TlsError, match="--ip"):
        tlsutil.check_names(["10.0.0.1"], [])
    with pytest.raises(tlsutil.TlsError, match="DNS 이름 형식"):
        tlsutil.check_names(["*.corp.local"], [])
    with pytest.raises(tlsutil.TlsError, match="DNS 이름 형식"):
        tlsutil.check_names(["log mon"], [])
    with pytest.raises(tlsutil.TlsError, match="하나 이상"):
        tlsutil.check_names([], ["10.0.0.1"])
    with pytest.raises(tlsutil.TlsError, match="IP 주소가 아닙니다"):
        tlsutil.check_names(["a.local"], ["10.0.0.300"])
    assert tlsutil.check_names(["A.local", "a.local"], ["10.0.0.1", "10.0.0.1"])[0] == ["a.local"]


def test_name_constraints_limit_renewal():
    ca_key, ca = tlsutil.issue_ca(["logmon.corp.local"], ["10.0.0.10"], now=NOW)
    # 허용 이름의 하위 도메인은 된다(RFC 5280)
    tlsutil.issue_server(ca_key, ca, ["web.logmon.corp.local"], ["10.0.0.10"], now=NOW)
    with pytest.raises(tlsutil.TlsError, match="이름 제한 밖"):
        tlsutil.issue_server(ca_key, ca, ["other.corp.local"], [], now=NOW)
    with pytest.raises(tlsutil.TlsError, match="10.0.0.11"):
        tlsutil.issue_server(ca_key, ca, ["logmon.corp.local"], ["10.0.0.11"], now=NOW)


def _handshake(server_ctx, client_ctx, server_name):
    """localhost 에서 한 번 TLS 핸드셰이크. (클라이언트 결과 버전, 서버 쪽 예외)"""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    errors = []

    def serve():
        conn, _ = listener.accept()
        try:
            with server_ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError) as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
                client_ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            version = tls.version()
            tls.sendall(b"x")
    finally:
        thread.join(5)
        listener.close()
    return version, errors


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1:DeprecationWarning")   # 일부러 옛 버전 클라이언트를 만든다
def test_server_context_and_handshake(tmp_path):
    s, *_ = _files(tmp_path)

    def default_factory():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(s.tls_cert_file, s.tls_key_file)
        return ctx

    ctx = tlsutil.server_context(None, default_factory)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.options & ssl.OP_NO_RENEGOTIATION
    tls12 = [c["name"] for c in ctx.get_ciphers() if c["protocol"] == "TLSv1.2"]
    assert tls12 and all(n.startswith("ECDHE-") and ("GCM" in n or "CHACHA20" in n) for n in tls12), tls12

    # Python 3.13 기본 클라이언트(엄격 검증 + 이름 확인)가 믿는다
    client = ssl.create_default_context(cafile=s.tls_ca_file)
    version, errors = _handshake(ctx, client, "logmon.corp.local")
    assert version in ("TLSv1.2", "TLSv1.3") and not errors

    # 다른 이름은 거부 (에이전트의 tls.verify_hostname 과 같은 판단)
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(ctx, ssl.create_default_context(cafile=s.tls_ca_file), "other.corp.local")

    # TLS 1.1 클라이언트는 서버가 거부 (클라이언트 쪽 보안 수준은 0 으로 낮춰 서버 판단만 본다)
    old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    old.check_hostname, old.verify_mode = False, ssl.CERT_NONE
    old.set_ciphers("DEFAULT:@SECLEVEL=0")
    old.minimum_version, old.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
    with pytest.raises((ssl.SSLError, OSError)):
        _handshake(ctx, old, "logmon.corp.local")

    # TLS 1.2 의 CBC 암호만 쓰는 클라이언트도 거부
    cbc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cbc.check_hostname, cbc.verify_mode = False, ssl.CERT_NONE
    cbc.maximum_version = ssl.TLSVersion.TLSv1_2
    cbc.set_ciphers("ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA")
    with pytest.raises((ssl.SSLError, OSError)):
        _handshake(ctx, cbc, "logmon.corp.local")


def test_preflight(tmp_path):
    s, *_ = _files(tmp_path)
    assert tlsutil.preflight(s) == []
    assert tlsutil.preflight(SimpleNamespace(tls_mode="off", trusted_proxies=("10.0.0.5", "10.0.0.0/24", "fd00::/8"))) == []
    bad = tlsutil.preflight(SimpleNamespace(tls_mode="yes", trusted_proxies=("*", "0.0.0.0/0", "::/0", "abc")))
    assert len(bad) == 5 and "off 또는 on" in bad[0] and "'*'" in bad[1] and "모든 주소" in bad[2] and "모든 주소" in bad[3]
    assert "IP 나 CIDR" in bad[4]
    missing = SimpleNamespace(**{**vars(s), "tls_cert_file": str(tmp_path / "없음.crt")})
    assert "tls-init" in tlsutil.preflight(missing)[0]
    other_key = _write(tmp_path, "other.key", tlsutil.key_pem(ec.generate_private_key(ec.SECP256R1())))
    assert "짝이 맞지 않거나" in tlsutil.preflight(SimpleNamespace(**{**vars(s), "tls_key_file": other_key}))[0]
    # 끈 상태에서는 인증서를 보지 않는다
    assert tlsutil.preflight(SimpleNamespace(**{**vars(missing), "tls_mode": "off"})) == []


def _levels(st):
    return [(lv, text.split(" ")[0]) for lv, text in st.problems]


def test_status_ok_and_cached(tmp_path):
    s, _, ca, cert = _files(tmp_path)
    st = tlsutil.status(s, now=NOW)
    assert st.enabled and st.ca_ok and st.problems == ()
    assert st.dns_names == ("logmon.corp.local",) and st.ip_names == ("10.0.0.10",)
    assert st.days_left == tlsutil.SERVER_DAYS - 1 or st.days_left == tlsutil.SERVER_DAYS
    assert st.ca_sha256 == ca.fingerprint(hashes.SHA256()).hex()
    assert st.cert_sha256 == cert.fingerprint(hashes.SHA256()).hex()
    assert tlsutil.status(s, now=NOW) is st   # 같은 파일·같은 날이면 다시 읽지 않는다
    assert tlsutil.status(SimpleNamespace(tls_mode="off")) == tlsutil.TlsStatus(enabled=False)
    d = st.as_dict()
    assert d["server_names"] == ["logmon.corp.local"] and d["problems"] == [] and d["ca_ok"]


def test_status_problems(tmp_path):
    # 곧 만료 + 공개 주소가 http + 키를 누구나 읽음
    a = tmp_path / "a"
    a.mkdir()
    s, *_ = _files(a, days=10, now=NOW)
    (a / "server.key").chmod(0o644)
    s.public_url = "http://logmon.corp.local:8080"
    st = tlsutil.status(s, now=NOW)
    texts = " ".join(t for _, t in st.problems)
    assert "10일 뒤" in texts and "https 가 아닙니다" in texts and "누구나 읽을 수" in texts
    assert all(lv == "warn" for lv, _ in st.problems) and st.ca_ok

    # 만료 → error, 다른 호스트 이름
    b = tmp_path / "b"
    b.mkdir()
    s, *_ = _files(b, now=NOW - timedelta(days=800))
    s.public_url = "https://monitor.corp.local"
    st = tlsutil.status(s, now=NOW)
    assert st.problems[0][0] == "error" and "만료됐습니다" in st.problems[0][1]
    assert any("인증서 이름에 없습니다" in t for _, t in st.problems)
    assert st.ca_ok   # 만료돼도 연쇄는 이어진다 (만료는 따로 error)

    # CA 파일 없음 / 다른 CA
    c = tmp_path / "c"
    c.mkdir()
    s, *_ = _files(c)
    (c / "ca.crt").unlink()
    st = tlsutil.status(s)
    assert not st.ca_ok and st.ca_sha256 is None and any("CA 인증서" in t and "없습니다" in t for _, t in st.problems)
    _, other = tlsutil.issue_ca(["logmon.corp.local"], [])
    (c / "ca.crt").write_bytes(tlsutil.cert_pem(other))
    st = tlsutil.status(s)
    assert not st.ca_ok and any(lv == "error" and "다른 CA" in t for lv, t in st.problems)


def _manual_root():
    """이름 제한·pathlen 없는 사내 루트 CA 흉내 (중간 CA 를 둘 수 있게)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Root")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=2)).not_valid_after(NOW + timedelta(days=3000))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _manual_intermediate(root_key, root):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Issuing CA")]))
            .issuer_name(root.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=2)).not_valid_after(NOW + timedelta(days=2000))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
            .sign(root_key, hashes.SHA256()))
    return key, cert


def test_status_corporate_chain_and_wildcard(tmp_path):
    """사내 PKI: 서버 인증서(와일드카드 + 이름) + 중간 CA, ca.crt 는 루트만."""
    root_key, root = _manual_root()
    mid_key, mid = _manual_intermediate(root_key, root)
    key, leaf = tlsutil.issue_server(mid_key, mid, ["logmon.corp.local"], [], now=NOW)
    s = SimpleNamespace(tls_mode="on", trusted_proxies=(), public_url="https://logmon.corp.local",
                        tls_cert_file=_write(tmp_path, "server.crt", tlsutil.cert_pem(leaf) + tlsutil.cert_pem(mid)),
                        tls_key_file=_write(tmp_path, "server.key", tlsutil.key_pem(key), 0o640),
                        tls_ca_file=_write(tmp_path, "ca.crt", tlsutil.cert_pem(root)))
    st = tlsutil.status(s, now=NOW)
    assert st.ca_ok and st.problems == ()
    # 중간 CA 를 빠뜨리면 이어지지 않는다
    _write(tmp_path, "server.crt", tlsutil.cert_pem(leaf))
    assert not tlsutil.status(s, now=NOW).ca_ok


def test_pick_server_name():
    st = tlsutil.TlsStatus(enabled=True, dns_names=("logmon.corp.local", "*.corp.local"), ip_names=("10.0.0.10",))
    assert tlsutil.pick_server_name(st, "logmon.corp.local") == "logmon.corp.local"
    assert tlsutil.pick_server_name(st, "web.corp.local") == "web.corp.local"   # 와일드카드 한 단계
    assert tlsutil.pick_server_name(st, "a.b.corp.local") == "logmon.corp.local"
    assert tlsutil.pick_server_name(st, "10.0.0.10") == "logmon.corp.local"
    assert tlsutil.pick_server_name(st, None) == "logmon.corp.local"
    only_wild = tlsutil.TlsStatus(enabled=True, dns_names=("*.corp.local",))
    assert tlsutil.pick_server_name(only_wild, "10.0.0.10") is None
    assert tlsutil.name_matches("*.corp.local", "LOGMON.corp.local.") and not tlsutil.name_matches("*.corp.local", "corp.local")
