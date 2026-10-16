"""운영 HTTPS·에이전트 TLS (BACKLOG B-06, ADR-036).

- uvicorn 의 TLS 설정(`server_context`): TLS 1.2 이상, TLS 1.2 는 ECDHE + AEAD 암호만, 재협상 끔.
- 기동 전 점검(`preflight`): 틀린 설정으로 반쯤 뜨지 않게, 고칠 방법을 적은 한국어 오류.
- 인증서 상태(`status`): 만료·이름·CA 일치 — 기동 로그, 매일 점검, 에이전트 설치 묶음이 쓴다.
- 자체 CA·서버 인증서 발급(`issue_ca`·`issue_server`): `python -m app.cli tls-init / tls-renew`.

cryptography(이미 의존성 — secrets.py 의 Fernet)만 쓴다. 호스트의 openssl 버전에 기대지 않고 pytest 로 시험하기 위해서다.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import ssl
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger(__name__)

TLS_MODES = ("off", "on")
# TLS 1.2 는 순방향 비밀성(ECDHE) + AEAD 만. 파이썬 기본 목록에는 CBC·DHE 가 남는다. TLS 1.3 은 OpenSSL 기본 세 개(모두 AEAD)
CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"
CA_DAYS = 3650
# 사설 CA 의 서버 인증서 — Apple 기기의 사설 인증서 상한(825일) 안. CA 는 길게 두어 에이전트 재배포를 피한다
SERVER_DAYS = 730
WARN_DAYS = 30
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_RE = re.compile(rf"^(?=.{{1,253}}$){_DNS_LABEL}(?:\.{_DNS_LABEL})*$")


class TlsError(ValueError):
    """인증서를 만들거나 고칠 수 없음 (한국어 문장)."""


# ---- uvicorn ----

def server_context(config: Any, default_factory) -> ssl.SSLContext:
    """uvicorn `ssl_context_factory`: 인증서·키 읽기는 uvicorn 기본 그대로 두고 프로토콜·암호만 좁힌다."""
    ctx = default_factory()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_RENEGOTIATION
    return ctx


def preflight(s: Any) -> list[str]:
    """기동을 멈춰야 하는 설정 오류. 비어 있으면 그대로 띄운다."""
    errors: list[str] = []
    if s.tls_mode not in TLS_MODES:
        errors.append(f"WLM_TLS 는 off 또는 on 이어야 합니다 (지금: {s.tls_mode!r}).")
    for item in s.trusted_proxies:
        # '*' 나 /0 을 믿으면 누구나 X-Forwarded-For 로 IP 를 속인다 — 로그인 시도 제한·감사로그 IP·PC 마지막 IP 가 흔들린다
        if item == "*":
            errors.append("WLM_TRUSTED_PROXIES 에 '*' 를 쓸 수 없습니다. 리버스 프록시의 IP 나 대역만 적으세요.")
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            errors.append(f"WLM_TRUSTED_PROXIES 의 {item!r} 은 IP 나 CIDR 이 아닙니다.")
            continue
        if net.prefixlen == 0:
            errors.append(f"WLM_TRUSTED_PROXIES 에 모든 주소({item})를 넣을 수 없습니다. 리버스 프록시의 IP 나 대역만 적으세요.")
    if s.tls_mode == "on":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(s.tls_cert_file, s.tls_key_file)
        except FileNotFoundError as exc:
            errors.append(f"WLM_TLS=on 인데 인증서·키 파일이 없습니다: {exc.filename or s.tls_cert_file}. "
                          "python -m app.cli tls-init 으로 만들거나 사내 인증서를 tls/ 에 두세요 (docs/AIRGAP.md §7.5).")
        except PermissionError as exc:
            errors.append(f"인증서·키 파일을 읽을 수 없습니다(권한): {exc.filename}. 키는 0640 root:10001 로 두세요.")
        except ssl.SSLError as exc:
            errors.append(f"인증서와 키가 짝이 맞지 않거나 PEM 형식이 아닙니다 ({exc.reason or exc}): "
                          f"{s.tls_cert_file}, {s.tls_key_file}")
    return errors


# ---- 인증서 상태 ----

@dataclass(frozen=True)
class TlsStatus:
    enabled: bool
    dns_names: tuple[str, ...] = ()
    ip_names: tuple[str, ...] = ()
    not_after: datetime | None = None
    days_left: int | None = None
    cert_sha256: str | None = None
    ca_sha256: str | None = None
    ca_ok: bool = False
    problems: tuple[tuple[str, str], ...] = ()   # (error|warn, 문장)

    @property
    def usable_names(self) -> tuple[str, ...]:
        """에이전트가 이름 확인(tls.vhost)에 쓸 수 있는 DNS 이름 — 와일드카드는 그대로 쓸 수 없다."""
        return tuple(n for n in self.dns_names if not n.startswith("*."))

    def as_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "server_names": list(self.usable_names), "dns_names": list(self.dns_names),
                "ip_names": list(self.ip_names), "not_after": self.not_after.isoformat() if self.not_after else None,
                "days_left": self.days_left, "ca_sha256": self.ca_sha256, "ca_ok": self.ca_ok,
                "problems": [{"level": lv, "text": t} for lv, t in self.problems]}


_status_cache: dict[tuple, TlsStatus] = {}


def _file_key(path: str) -> tuple:
    try:
        st = os.stat(path)
    except OSError:
        return (path, None)
    return (path, st.st_mtime_ns, st.st_size, st.st_mode)


def status(s: Any, now: datetime | None = None) -> TlsStatus:
    """지금 설정의 인증서 상태. 파일이 바뀌거나 날짜가 바뀔 때만 다시 읽는다."""
    if s.tls_mode != "on":
        return TlsStatus(enabled=False)
    now = now or datetime.now(UTC)
    key = (_file_key(s.tls_cert_file), _file_key(s.tls_key_file), _file_key(s.tls_ca_file), s.public_url, now.date())
    cached = _status_cache.get(key)
    if cached is None:
        cached = _status_cache[key] = _read_status(s, now)
        if len(_status_cache) > 16:   # 날짜가 지난 항목
            _status_cache.pop(next(iter(_status_cache)))
    return cached


def load_certs(path: str) -> list[x509.Certificate]:
    with open(path, "rb") as fh:
        return x509.load_pem_x509_certificates(fh.read())


def san_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    return ([n.lower() for n in san.get_values_for_type(x509.DNSName)],
            [str(ip) for ip in san.get_values_for_type(x509.IPAddress)])


def name_matches(pattern: str, host: str) -> bool:
    """인증서 이름(와일드카드는 왼쪽 한 단계만)과 호스트가 맞는지."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, rest = host.partition(".")
        return bool(head) and rest == pattern[2:]
    return pattern == host


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _read_status(s: Any, now: datetime) -> TlsStatus:
    problems: list[tuple[str, str]] = []
    try:
        chain = load_certs(s.tls_cert_file)
    except (OSError, ValueError) as exc:
        return TlsStatus(enabled=True, problems=(("error", f"서버 인증서를 읽을 수 없습니다: {exc}"),))
    if not chain:
        return TlsStatus(enabled=True, problems=(("error", "서버 인증서 파일에 인증서가 없습니다."),))
    leaf = chain[0]
    dns, ips = san_names(leaf)
    not_after = leaf.not_valid_after_utc
    days_left = (not_after - now).days
    if not_after <= now:
        problems.append(("error", (f"서버 인증서가 만료됐습니다 ({not_after:%Y-%m-%d}). 에이전트가 로그를 보내지 못합니다 — "
                                  "python -m app.cli tls-renew 후 api 를 다시 시작하세요.")))
    elif days_left <= WARN_DAYS:
        problems.append(("warn", f"서버 인증서가 {days_left}일 뒤({not_after:%Y-%m-%d}) 만료됩니다 — tls-renew 로 갱신하세요."))
    if not [n for n in dns if not n.startswith("*.")]:
        problems.append(("warn", ("서버 인증서에 DNS 이름이 없습니다. 에이전트가 서버 이름을 확인할 수 없어 설치 묶음을 만들 수 없습니다 "
                                 "(DNS 에 등록하지 않은 이름이어도 됩니다).")))
    url = urlsplit(s.public_url)
    if url.scheme != "https":
        problems.append(("warn", "WLM_PUBLIC_URL 이 https 가 아닙니다. 알림·보고서의 링크가 열리지 않습니다."))
    elif url.hostname and not (any(name_matches(n, url.hostname) for n in dns) or url.hostname in ips):
        problems.append(("warn", f"WLM_PUBLIC_URL 의 호스트({url.hostname})가 인증서 이름에 없습니다. 브라우저가 경고합니다."))
    try:
        mode = os.stat(s.tls_key_file).st_mode
        if mode & stat.S_IROTH:
            problems.append(("warn", "서버 키 파일을 누구나 읽을 수 있습니다. 0640 root:10001 로 두세요."))
    except OSError:
        pass

    ca_sha256, ca_ok = None, False
    try:
        cas = load_certs(s.tls_ca_file)
    except FileNotFoundError:
        cas = []
        problems.append(("warn", f"CA 인증서({s.tls_ca_file})가 없습니다. 에이전트 설치 묶음을 만들 수 없습니다."))
    except (OSError, ValueError) as exc:
        cas = []
        problems.append(("warn", f"CA 인증서를 읽을 수 없습니다: {exc}"))
    if cas:
        ca_sha256 = cas[0].fingerprint(hashes.SHA256()).hex()
        ca_ok, note = verify_chain(leaf, chain[1:], cas, dns[0] if dns else None, now)
        if not ca_ok:
            problems.append(("error", (f"CA 인증서로 서버 인증서를 확인할 수 없습니다 — 다른 CA 입니다 ({note}). "
                                      "에이전트가 서버를 믿지 않습니다.")))
        elif note:
            problems.append(("warn", f"CA 와 서버 인증서는 이어지지만 엄격한 확인은 실패했습니다: {note}"))
    return TlsStatus(enabled=True, dns_names=tuple(dns), ip_names=tuple(ips), not_after=not_after, days_left=days_left,
                     cert_sha256=leaf.fingerprint(hashes.SHA256()).hex(), ca_sha256=ca_sha256, ca_ok=ca_ok,
                     problems=tuple(problems))


def verify_chain(leaf: x509.Certificate, intermediates: list[x509.Certificate], cas: list[x509.Certificate],
                 dns_name: str | None, now: datetime) -> tuple[bool, str]:
    """(이어지는가, 메모). 먼저 RFC 5280 엄격 검증, 실패하면 서명 연쇄만 다시 본다(메모에 엄격 검증 실패 사유).

    엄격 검증만 쓰면 AKI 가 없는 옛 사내 인증서 등이 '다른 CA' 로 잘못 보이고, 연쇄만 보면 이름 제한·만료를 놓친다."""
    intermediates = [c for c in intermediates if c not in cas]
    strict_error = ""
    if dns_name and not dns_name.startswith("*.") and leaf.not_valid_after_utc > now:
        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

        try:
            verifier = PolicyBuilder().store(Store(cas)).time(now).build_server_verifier(x509.DNSName(dns_name))
            verifier.verify(leaf, intermediates)
            return True, ""
        except (VerificationError, ValueError) as exc:
            strict_error = str(exc)
    cert, pool = leaf, list(intermediates)
    for _ in range(6):
        if any(_issued_by(cert, ca) for ca in cas):
            return True, strict_error
        issuer = next((c for c in pool if _issued_by(cert, c)), None)
        if issuer is None:
            return False, strict_error or "서명 연쇄가 끊김"
        pool.remove(issuer)
        cert = issuer
    return False, strict_error or "연쇄가 너무 깊음"


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):   # 이름 불일치 · 지원하지 않는 키 · 서명 틀림
        return False
    return True


def pick_server_name(st: TlsStatus, host: str | None) -> str | None:
    """에이전트의 tls.vhost: 접속 주소가 인증서 이름이면 그것, 아니면(IP 등) 인증서의 첫 DNS 이름."""
    if host and not _is_ip(host) and any(name_matches(n, host) for n in st.dns_names):
        return host.lower()
    return st.usable_names[0] if st.usable_names else None


# ---- 발급 (tls-init / tls-renew) ----

def check_names(names: list[str], ips: list[str]) -> tuple[list[str], list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    clean: list[str] = []
    for raw in names:
        name = raw.strip().lower().rstrip(".")
        if _is_ip(name):
            raise TlsError(f"{raw!r} 은 IP 입니다. IP 는 --ip 로 주세요(에이전트는 DNS 이름으로 서버를 확인합니다).")
        if not _DNS_RE.match(name) or not re.search(r"[a-z]", name):
            raise TlsError(f"{raw!r} 은 DNS 이름 형식이 아닙니다 (영문자·숫자·하이픈과 점, 와일드카드 없이).")
        if name not in clean:
            clean.append(name)
    if not clean:
        raise TlsError("DNS 이름이 하나 이상 필요합니다 (--name). DNS 에 등록하지 않은 이름(예: logmon.internal)이어도 됩니다.")
    addrs = []
    for raw in ips:
        try:
            addr = ipaddress.ip_address(raw.strip())
        except ValueError as exc:
            raise TlsError(f"{raw!r} 은 IP 주소가 아닙니다.") from exc
        if addr not in addrs:
            addrs.append(addr)
    return clean, addrs


def issue_ca(names: list[str], ips: list[str], days: int = CA_DAYS, now: datetime | None = None):
    """사설 CA. 이름 제한(NameConstraints)으로 이 이름·IP 밖의 인증서는 만들어도 에이전트가 믿지 않는다
    (CA 키가 새도 피해 범위를 좁힘). 이름을 나중에 바꾸려면 새 CA 가 필요하다."""
    dns, addrs = check_names(names, ips)
    now = now or datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Log Monitor"),
                         x509.NameAttribute(NameOID.COMMON_NAME, "Log Monitor Private CA")])
    permitted: list[x509.GeneralName] = [x509.DNSName(n) for n in dns]
    permitted += [x509.IPAddress(ipaddress.ip_network(f"{a}/{a.max_prefixlen}")) for a in addrs]
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def ca_allows(ca_cert: x509.Certificate, dns: list[str], addrs: list) -> list[str]:
    """CA 이름 제한 밖의 이름 목록 (비면 모두 허용)."""
    try:
        nc = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return []
    allowed_dns = [g.value.lower() for g in nc.permitted_subtrees or [] if isinstance(g, x509.DNSName)]
    allowed_ip = [g.value for g in nc.permitted_subtrees or [] if isinstance(g, x509.IPAddress)]
    outside = []
    if allowed_dns:
        outside += [n for n in dns if not any(n == a or n.endswith("." + a) for a in allowed_dns)]
    if allowed_ip:
        outside += [str(a) for a in addrs if not any(a in net for net in allowed_ip)]
    return outside


def issue_server(ca_key, ca_cert: x509.Certificate, names: list[str], ips: list[str], days: int = SERVER_DAYS,
                 now: datetime | None = None):
    dns, addrs = check_names(names, ips)
    outside = ca_allows(ca_cert, dns, addrs)
    if outside:
        raise TlsError(f"CA 의 이름 제한 밖입니다: {', '.join(outside)}. 이 이름을 쓰려면 새 CA(tls-init --force)와 "
                       "전체 에이전트 재배포가 필요합니다.")
    now = now or datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    not_after = min(now + timedelta(days=days), ca_cert.not_valid_after_utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns[0])]))
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # 하루 앞당김: PC 시계가 조금 늦어도 '아직 유효하지 않음(X509 code 9)' 으로 끊기지 않게
        .not_valid_before(now - timedelta(days=1)).not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([*(x509.DNSName(n) for n in dns),
                                                    *(x509.IPAddress(a) for a in addrs)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        # AKI 가 없으면 Python 3.13 의 엄격 검증(VERIFY_X509_STRICT)이 거부한다
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_key(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)
