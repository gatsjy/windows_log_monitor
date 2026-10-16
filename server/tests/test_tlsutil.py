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
    # DNS·IP 는 준 것만, 메일 주소는 예약 도메인만(= 못 만듦). CA 용도는 서버 인증만
    assert {g.value for g in nc.value.permitted_subtrees} == {"logmon.corp.local", "localhost",
                                                               ipaddress.ip_network("10.0.0.10/32"), "invalid"}
    assert nc.value.excluded_subtrees is None
    assert _ext(ca, x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    assert ca.not_valid_after_utc - NOW == timedelta(days=tlsutil.CA_DAYS)
    # IP 를 주지 않은 CA 는 모든 IP 를 막는다 (키가 새도 IP 로 접속하는 다른 사내 서버를 사칭하지 못하게)
    _, dns_only = tlsutil.issue_ca(["logmon.corp.local"], [], now=NOW)
    assert {g.value for g in _ext(dns_only, x509.NameConstraints).value.excluded_subtrees} == {
        ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")}

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
    dns_key, dns_only = tlsutil.issue_ca(["logmon.corp.local"], [], now=NOW)
    with pytest.raises(tlsutil.TlsError, match="10.0.0.10"):
        tlsutil.issue_server(dns_key, dns_only, ["logmon.corp.local"], ["10.0.0.10"], now=NOW)


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
    # uvicorn 은 호스트 비트가 있는 대역·IPv4 매핑 주소를 조용히 무시한다 — 여기서 막고 바른 값을 알려 준다
    bad = tlsutil.preflight(SimpleNamespace(tls_mode="off", trusted_proxies=("10.0.0.5/24", "::ffff:10.0.0.5")))
    assert "10.0.0.0/24 또는 10.0.0.5" in bad[0] and "IPv4 주소로" in bad[1] and "10.0.0.5" in bad[1]
    # 어느 파일이 문제인지 정확히
    missing_key = SimpleNamespace(**{**vars(s), "tls_key_file": str(tmp_path / "없음.key")})
    text = tlsutil.preflight(missing_key)[0]
    assert "없음.key" in text and "server.crt" not in text and "tls-init" in text
    as_dir = SimpleNamespace(**{**vars(s), "tls_cert_file": str(tmp_path)})
    assert "폴더입니다" in tlsutil.preflight(as_dir)[0]
    other_key = _write(tmp_path, "other.key", tlsutil.key_pem(ec.generate_private_key(ec.SECP256R1())))
    assert "짝이 맞지 않습니다" in tlsutil.preflight(SimpleNamespace(**{**vars(s), "tls_key_file": other_key}))[0]
    # 암호 걸린 키: 묻지 않고(컨테이너엔 터미널이 없다) 고치는 방법과 함께 멈춘다
    from cryptography.hazmat.primitives import serialization
    key = tlsutil.load_key(s.tls_key_file)
    enc = _write(tmp_path, "enc.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.BestAvailableEncryption(b"secret")))
    assert "암호가 걸려" in tlsutil.preflight(SimpleNamespace(**{**vars(s), "tls_key_file": enc}))[0]
    # 끈 상태에서는 인증서를 보지 않는다
    assert tlsutil.preflight(SimpleNamespace(**{**vars(missing_key), "tls_mode": "off"})) == []


def test_status_ok_and_cached(tmp_path):
    s, _, ca, cert = _files(tmp_path)
    now = datetime.now(UTC)
    st = tlsutil.status(s, now=now)
    assert st.enabled and st.ca_ok and st.problems == ()
    assert st.dns_names == ("logmon.corp.local",) and st.ip_names == ("10.0.0.10",)
    assert st.days_left in (tlsutil.SERVER_DAYS - 1, tlsutil.SERVER_DAYS)
    assert st.ca_sha256 == ca.fingerprint(hashes.SHA256()).hex()
    assert st.cert_sha256 == cert.fingerprint(hashes.SHA256()).hex()
    assert tlsutil.status(s, now=now) is st   # 같은 파일·같은 10분이면 다시 보지 않는다
    assert tlsutil.status(s, now=now + timedelta(minutes=11)) is not st   # 하루 중간의 만료도 늦지 않게
    assert tlsutil.status(SimpleNamespace(tls_mode="off")) == tlsutil.TlsStatus(enabled=False)
    d = st.as_dict()
    assert d["server_names"] == ["logmon.corp.local"] and d["wildcards"] == [] and d["problems"] == [] and d["ca_ok"]


def test_status_problems(tmp_path):
    # 곧 만료 + 공개 주소가 http + 키를 누구나 읽음
    a = tmp_path / "a"
    a.mkdir()
    s, *_ = _files(a, days=10)
    (a / "server.key").chmod(0o644)
    s.public_url = "http://logmon.corp.local:8080"
    st = tlsutil.status(s)
    texts = " ".join(t for _, t in st.problems)
    assert ("9일 뒤" in texts or "10일 뒤" in texts) and "https 가 아닙니다" in texts and "누구나 읽을 수" in texts
    assert all(lv == "warn" for lv, _ in st.problems) and st.ca_ok

    # 만료 → error 두 개(만료, 에이전트가 믿지 않음 code 10), 다른 호스트 이름
    b = tmp_path / "b"
    b.mkdir()
    s, *_ = _files(b, now=datetime.now(UTC) - timedelta(days=800))
    s.public_url = "https://monitor.corp.local"
    st = tlsutil.status(s)
    assert st.problems[0][0] == "error" and "만료됐습니다" in st.problems[0][1]
    assert any("인증서 이름에 없습니다" in t for _, t in st.problems)
    assert not st.ca_ok and any(lv == "error" and "X509 code 10" in t for lv, t in st.problems)

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
    assert not st.ca_ok and any(lv == "error" and "다른 CA" in t and "X509 code" in t for lv, t in st.problems)


def test_status_ca_file_hygiene(tmp_path):
    """사내 PKI 의 full.pem 처럼 개인키가 섞인 CA 파일, 서버 인증서를 CA 자리에 둔 경우."""
    s, ca_key, ca, cert = _files(tmp_path)
    with open(s.tls_ca_file, "ab") as fh:
        fh.write(tlsutil.key_pem(ca_key))
    st = tlsutil.status(s)
    assert any(lv == "error" and "개인키" in t for lv, t in st.problems)
    assert b"PRIVATE KEY" not in tlsutil.ca_bundle_pem(s.tls_ca_file)   # 묶음에는 인증서만
    assert tlsutil.load_certs(s.tls_ca_file)[0] == ca
    _write(tmp_path, "ca.crt", tlsutil.cert_pem(cert) + tlsutil.cert_pem(ca))
    st = tlsutil.status(s)
    assert any(lv == "error" and "첫 인증서가 CA 가 아닙니다" in t for lv, t in st.problems)


def test_status_key_unreadable_or_mismatched(tmp_path):
    """tls-status·설치 묶음이 키를 실제로 써 본다 — 짝이 아니거나 못 읽는 키를 켜기 전에 잡는다."""
    s, *_ = _files(tmp_path)
    _write(tmp_path, "server.key", tlsutil.key_pem(ec.generate_private_key(ec.SECP256R1())))
    st = tlsutil.status(s)
    assert not st.ca_ok and any(lv == "error" and "짝" in t for lv, t in st.problems)


def test_status_remembers_served_certificate(tmp_path, monkeypatch):
    """파일만 바꾸고 api 를 다시 시작하지 않으면 옛 인증서를 내보낸다 — 매일 점검이 알린다."""
    s, ca_key, ca, _ = _files(tmp_path, days=5)
    monkeypatch.setattr(tlsutil, "_served", None)   # 끝나면 None 으로 되돌린다 (다른 시험에 새지 않게)
    tlsutil.remember_served(s)
    assert not [t for _, t in tlsutil.status(s).problems if "다시 시작하지 않아" in t]
    key, cert = tlsutil.issue_server(ca_key, ca, ["logmon.corp.local"], ["10.0.0.10"])
    _write(tmp_path, "server.key", tlsutil.key_pem(key), 0o640)
    _write(tmp_path, "server.crt", tlsutil.cert_pem(cert) + tlsutil.cert_pem(ca))
    st = tlsutil.status(s)
    warn = [(lv, t) for lv, t in st.problems if "다시 시작하지 않아" in t]
    assert warn and warn[0][0] == "warn" and "restart api" in warn[0][1]
    st = tlsutil.status(s, now=datetime.now(UTC) + timedelta(days=6))   # 옛 인증서가 만료된 뒤
    assert any(lv == "error" and "다시 시작하지 않아" in t for lv, t in st.problems)


def _root(*, ca=True, path_length=None, days=3000, names=None, eku=None):
    """사내 루트 CA 흉내 (이름 제한·용도는 선택)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Root")])
    now = datetime.now(UTC)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if names:
        b = b.add_extension(x509.NameConstraints([x509.DNSName(n) for n in names], None), critical=True)
    return key, b.sign(key, hashes.SHA256())


def _issued(issuer_key, issuer, *, names=("logmon.corp.local",), ca=False, eku=ExtendedKeyUsageOID.SERVER_AUTH,
            start=None, days=700):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Issuing CA" if ca else names[0])]))
         .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start or now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
             issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    return key, b.sign(issuer_key, hashes.SHA256())


def _corp(tmp_path, chain, key, ca_certs):
    return SimpleNamespace(tls_mode="on", trusted_proxies=(), public_url="https://logmon.corp.local",
                           tls_cert_file=_write(tmp_path, "server.crt", b"".join(tlsutil.cert_pem(c) for c in chain)),
                           tls_key_file=_write(tmp_path, "server.key", tlsutil.key_pem(key), 0o640),
                           tls_ca_file=_write(tmp_path, "ca.crt", b"".join(tlsutil.cert_pem(c) for c in ca_certs)))


def test_status_corporate_chain(tmp_path):
    """사내 PKI: 서버 인증서 + 중간 CA, ca.crt 는 루트만 — 에이전트(OpenSSL)와 같은 판단."""
    root_key, root = _root()
    mid_key, mid = _issued(root_key, root, ca=True)
    key, leaf = _issued(mid_key, mid)
    s = _corp(tmp_path, [leaf, mid], key, [root])
    st = tlsutil.status(s)
    assert st.ca_ok and st.problems == ()
    # 중간 CA 를 빠뜨림 → code 20
    _write(tmp_path, "server.crt", tlsutil.cert_pem(leaf))
    st = tlsutil.status(s)
    assert not st.ca_ok and any("X509 code 20" in t for _, t in st.problems)
    # 중간(발급) CA 를 루트로 착각해 ca.crt 에 → OpenSSL 은 자체 서명 루트까지 잇지 못한다(code 2)
    s = _corp(tmp_path, [leaf, mid], key, [mid])
    st = tlsutil.status(s)
    assert not st.ca_ok and any("X509 code 2)" in t and "중간(발급) CA" in t for _, t in st.problems)


@pytest.mark.parametrize("case, code", [
    ("expired_ca", 10), ("client_auth_only", 26), ("not_yet_valid", 9), ("non_ca_intermediate", 79),
    ("name_constraint", 47), ("wildcard_first_expired_ca", 10)])
def test_status_rejects_what_agents_reject(tmp_path, case, code):
    """검토에서 찾은 사례: 서명만 이어지면 통과시키던 때와 달리, 에이전트(OpenSSL)가 거부하면 error — 묶음도 만들지 않는다."""
    if case in ("expired_ca", "wildcard_first_expired_ca"):
        root_key, root = _root(days=-1)
        names = ("*.corp.local", "logmon.corp.local") if case.startswith("wildcard") else ("logmon.corp.local",)
        key, leaf = _issued(root_key, root, names=names)
        chain, cas = [leaf], [root]
    elif case == "client_auth_only":
        root_key, root = _root()
        key, leaf = _issued(root_key, root, eku=x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
        chain, cas = [leaf], [root]
    elif case == "not_yet_valid":
        root_key, root = _root()
        key, leaf = _issued(root_key, root, start=datetime.now(UTC) + timedelta(days=3))
        chain, cas = [leaf], [root]
    elif case == "non_ca_intermediate":
        root_key, root = _root()
        mid_key, mid = _issued(root_key, root, names=("mid.corp.local",))   # CA:FALSE 인 '중간'
        key, leaf = _issued(mid_key, mid)
        chain, cas = [leaf, mid], [root]
    else:   # name_constraint
        root_key, root = _root(names=["other.corp.local"])
        key, leaf = _issued(root_key, root)
        chain, cas = [leaf], [root]
    st = tlsutil.status(_corp(tmp_path, chain, key, cas))
    assert not st.ca_ok, st.problems
    assert any(lv == "error" and f"X509 code {code})" in t for lv, t in st.problems), st.problems


def test_status_wildcard_only(tmp_path):
    root_key, root = _root()
    key, leaf = _issued(root_key, root, names=("*.corp.local",))
    st = tlsutil.status(_corp(tmp_path, [leaf], key, [root]))
    # 와일드카드 아래 아무 이름으로 확인해 본다 — 에이전트는 그 아래 이름을 tls.vhost 로 쓴다
    assert st.ca_ok and st.usable_names == () and st.wildcards == ("*.corp.local",)
    assert not any("DNS 이름이 없습니다" in t for _, t in st.problems)


def test_pick_server_name():
    st = tlsutil.TlsStatus(enabled=True, dns_names=("logmon.corp.local", "*.corp.local"), ip_names=("10.0.0.10",))
    assert tlsutil.pick_server_name(st, "logmon.corp.local") == "logmon.corp.local"
    assert tlsutil.pick_server_name(st, "web.corp.local") == "web.corp.local"   # 와일드카드 한 단계
    assert tlsutil.pick_server_name(st, "Web.corp.local.") == "web.corp.local"  # 끝의 점·대문자
    assert tlsutil.pick_server_name(st, "a.b.corp.local") == "logmon.corp.local"
    assert tlsutil.pick_server_name(st, "10.0.0.10") == "logmon.corp.local"
    assert tlsutil.pick_server_name(st, None) == "logmon.corp.local"
    only_wild = tlsutil.TlsStatus(enabled=True, dns_names=("*.corp.local",))
    assert tlsutil.pick_server_name(only_wild, "10.0.0.10") is None
    assert tlsutil.pick_server_name(only_wild, "logmon.corp.local") == "logmon.corp.local"
    assert tlsutil.name_matches("*.corp.local", "LOGMON.corp.local.") and not tlsutil.name_matches("*.corp.local", "corp.local")
    assert tlsutil.is_dns_name("logmon.corp.local") and not tlsutil.is_dns_name("*.corp.local")
    assert not tlsutil.is_dns_name("a b.corp.local") and not tlsutil.is_dns_name("10.0.0.1")
