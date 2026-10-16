"""운영 HTTPS·에이전트 TLS (BACKLOG B-06, ADR-036).

- uvicorn 의 TLS 설정(`server_context`): TLS 1.2 이상, TLS 1.2 는 ECDHE + AEAD 암호만, 재협상 끔.
- 기동 전 점검(`preflight`): 틀린 설정으로 반쯤 뜨지 않게, 고칠 방법을 적은 한국어 오류.
- 인증서 상태(`status`): 만료·이름·키 짝·**에이전트가 믿는가** — 기동 로그, 매일 점검, 설치 묶음, tls-status 가 쓴다.
  에이전트(Fluent Bit = OpenSSL)와 같은 조건으로 메모리 안에서 실제 핸드셰이크를 해 본다(`agent_handshake`).
  다른 검증기로 흉내 내면 만료된 CA·용도(EKU)·이름 제한·중간 CA 를 루트로 둔 경우를 놓치거나 반대로 지나치게 막는다.
- 자체 CA·서버 인증서 발급(`issue_ca`·`issue_server`): `python -m app.cli tls-init / tls-renew`.

cryptography(이미 의존성 — secrets.py 의 Fernet)와 표준 ssl 만 쓴다. 호스트의 openssl 버전에 기대지 않고 pytest 로 시험한다.
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
# 메일 주소 이름 제한에 쓰는 예약 도메인 (RFC 2606) — 이 CA 로는 메일(S/MIME) 인증서를 만들 수 없게
_NO_EMAIL_DOMAIN = "invalid"


class TlsError(ValueError):
    """인증서를 만들거나 고칠 수 없음 (한국어 문장)."""


def _no_password() -> bytes:
    # 암호 걸린 키면 터미널에서 묻지 않고 바로 실패하게 (컨테이너에는 묻을 곳이 없어 멈추거나 알 수 없는 오류가 난다)
    return b""


# ---- uvicorn ----

def server_context(config: Any, default_factory) -> ssl.SSLContext:
    """uvicorn `ssl_context_factory`: 인증서·키 읽기는 uvicorn 기본 그대로 두고 프로토콜·암호만 좁힌다."""
    ctx = default_factory()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_RENEGOTIATION
    return ctx


def _unreadable(path: str) -> str | None:
    """파일을 못 읽는 이유 (읽을 수 있으면 None)."""
    try:
        with open(path, "rb"):
            return None
    except FileNotFoundError:
        return "없습니다"
    except IsADirectoryError:
        return "폴더입니다(파일 경로를 적으세요)"
    except PermissionError:
        return "권한이 없어 읽을 수 없습니다 (소유자 uid 10001(api), 권한 0600 으로)"
    except OSError as exc:
        return f"읽을 수 없습니다 ({exc.strerror or exc})"


def _encrypted(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"ENCRYPTED" in fh.read(4096)   # 'BEGIN ENCRYPTED PRIVATE KEY' 또는 'Proc-Type: 4,ENCRYPTED'
    except OSError:
        return False


def _key_load_error(exc: ssl.SSLError, key_file: str = "") -> str:
    text = f"{exc.reason or ''} {exc}".upper()
    # OpenSSL 은 암호 걸린 키를 'PEM lib' 로만 알리기도 해서 파일 머리도 본다
    if (key_file and _encrypted(key_file)) or "DECRYPT" in text or "PASSWORD" in text or "PASS PHRASE" in text:
        return ("키에 암호가 걸려 있습니다. 암호 없는 키로 바꾸세요 (예: openssl pkey -in 암호키.key -out server.key) — "
                "api 는 기동할 때 암호를 물을 곳이 없습니다.")
    if "MISMATCH" in text:
        return "인증서와 키가 짝이 맞지 않습니다 — 그 인증서를 만들 때 쓴 키를 두세요."
    return f"인증서나 키가 PEM 형식이 아니거나 읽을 수 없습니다 ({exc.reason or exc})."


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
            # uvicorn 과 같은 해석(strict). 호스트 비트가 있는 대역(10.0.0.5/24)은 uvicorn 이 오류 없이 무시해
            # 프록시 헤더가 조용히 꺼진다 — Secure 쿠키·HSTS·접속 IP 가 틀어지므로 여기서 막는다
            net = ipaddress.ip_network(item)
        except ValueError:
            try:
                loose = ipaddress.ip_network(item, strict=False)
            except ValueError:
                errors.append(f"WLM_TRUSTED_PROXIES 의 {item!r} 은 IP 나 CIDR 이 아닙니다.")
                continue
            errors.append(f"WLM_TRUSTED_PROXIES 의 {item!r} 은 대역 표기가 틀렸습니다(호스트 비트). "
                          f"{loose} 또는 {item.split('/')[0]} 로 적으세요.")
            continue
        if net.prefixlen == 0:
            errors.append(f"WLM_TRUSTED_PROXIES 에 모든 주소({item})를 넣을 수 없습니다. 리버스 프록시의 IP 나 대역만 적으세요.")
        elif net.version == 6 and net.network_address.ipv4_mapped:
            errors.append(f"WLM_TRUSTED_PROXIES 의 {item!r} 는 IPv4 주소로 적으세요 ({net.network_address.ipv4_mapped}) — "
                          "접속 주소는 IPv4 로 비교됩니다.")
    if s.tls_mode == "on":
        missing = [f"{label} {path} 이(가) {why}" for label, path in (("인증서", s.tls_cert_file), ("키", s.tls_key_file))
                   if (why := _unreadable(path))]
        if missing:
            errors.append(f"WLM_TLS=on 인데 {'; '.join(missing)}. python -m app.cli tls-init 으로 만들거나 "
                          "사내 인증서를 tls/ 에 두세요 (docs/AIRGAP.md §7.5).")
        else:
            try:
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(s.tls_cert_file, s.tls_key_file,
                                                                        password=_no_password)
            except ssl.SSLError as exc:
                errors.append(_key_load_error(exc, s.tls_key_file))
            except OSError as exc:
                errors.append(f"인증서·키를 읽을 수 없습니다: {exc}")
    return errors


# ---- 에이전트와 같은 조건의 확인 ----

# OpenSSL 의 확인 오류 번호 → 고치는 방법 (에이전트 로그의 'X509 code' 와 같은 번호)
_VERIFY_HINTS = {
    2: "ca.crt 에 루트 CA 가 아니라 중간(발급) CA 를 넣었습니다 — 자체 서명된 루트 CA 를 넣으세요",
    9: "인증서가 아직 유효하지 않습니다 — 서버·PC 시계(NTP)나 인증서의 시작 시각을 확인하세요",
    10: "인증서(서버 또는 CA)가 만료됐습니다 — tls-renew 로 갱신하세요",
    18: "서버 인증서가 자체 서명입니다 — CA 가 발급한 인증서를 쓰세요(tls-init)",
    19: "ca.crt 가 서버 인증서를 발급한 CA 가 아닙니다 — 다른 CA 입니다",
    20: "ca.crt 가 서버 인증서를 발급한 CA 가 아니거나, server.crt 에 중간 CA 가 빠졌습니다",
    21: "ca.crt 가 서버 인증서를 발급한 CA 가 아닙니다",
    24: "연쇄 안의 인증서가 CA 가 아닙니다(basicConstraints)",
    26: "서버 인증용(EKU serverAuth) 인증서가 아닙니다",
    47: "서버 인증서의 이름이 CA 의 이름 제한 밖입니다 — 그 이름을 허용하는 CA 가 필요합니다",
    62: "인증서 이름이 맞지 않습니다",
    79: "연쇄 안의 중간 인증서가 CA 가 아닙니다(basicConstraints)",
}


def agent_handshake(cert_file: str, key_file: str, ca_file: str, name: str) -> tuple[bool, int | None, str]:
    """(믿는가, X509 오류 번호, OpenSSL 문구). 에이전트(Fluent Bit — OpenSSL 기본 확인: 연쇄·용도·이름 제한·만료,
    tls.verify_hostname)와 같은 조건으로 메모리 안에서 핸드셰이크한다. 서버 쪽은 키를 실제로 쓰므로 키 짝·읽기도 함께 본다.
    키를 못 읽으면 OSError·ssl.SSLError 를 그대로 올린다."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_file, key_file, password=_no_password)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)   # 연쇄·이름 확인 켜짐. 파이썬 3.13 의 STRICT·PARTIAL_CHAIN 은 없다
    client.verify_flags &= ~(ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN)   # Fluent Bit 과 같게
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    client.load_verify_locations(cafile=ca_file)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    cli = client.wrap_bio(c_in, c_out, server_hostname=name)
    srv = server.wrap_bio(s_in, s_out, server_side=True)
    cli_done = srv_done = False
    try:
        for _ in range(50):
            if not cli_done:
                try:
                    cli.do_handshake()
                    cli_done = True
                except ssl.SSLWantReadError:
                    pass
            if c_out.pending:
                s_in.write(c_out.read())
            if not srv_done:
                try:
                    srv.do_handshake()
                    srv_done = True
                except ssl.SSLWantReadError:
                    pass
            if s_out.pending:
                c_in.write(s_out.read())
            if cli_done and srv_done:
                return True, None, ""
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_code, exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        return False, None, str(exc.reason or exc)
    return False, None, "핸드셰이크가 끝나지 않았습니다"


def trust_problem(code: int | None, message: str) -> str:
    hint = _VERIFY_HINTS.get(code or -1, "")
    detail = f"OpenSSL: {message}" + (f", X509 code {code}" if code is not None else "")
    return (f"에이전트가 서버 인증서를 믿지 않습니다{' — ' + hint if hint else ''} ({detail}). "
            "이대로면 설치 묶음을 만들지 않습니다.")


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
    ca_ok: bool = False          # 에이전트(OpenSSL)가 이 CA·이름으로 서버를 믿는가 (agent_handshake)
    problems: tuple[tuple[str, str], ...] = ()   # (error|warn, 문장)

    @property
    def usable_names(self) -> tuple[str, ...]:
        """에이전트가 이름 확인(tls.vhost)에 그대로 쓸 수 있는 DNS 이름 — 와일드카드는 그 아래 이름을 따로 정해야 한다."""
        return tuple(n for n in self.dns_names if not n.startswith("*."))

    @property
    def wildcards(self) -> tuple[str, ...]:
        return tuple(n for n in self.dns_names if n.startswith("*."))

    def as_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "server_names": list(self.usable_names), "wildcards": list(self.wildcards),
                "dns_names": list(self.dns_names), "ip_names": list(self.ip_names),
                "not_after": self.not_after.isoformat() if self.not_after else None,
                "days_left": self.days_left, "ca_sha256": self.ca_sha256, "ca_ok": self.ca_ok,
                "problems": [{"level": lv, "text": t} for lv, t in self.problems]}


_status_cache: dict[tuple, TlsStatus] = {}
# 기동 때 실제로 읽어 내보내는 인증서 (serve.main → remember_served). 파일만 바꾸고 재시작을 빠뜨리면 이것과 달라진다
_served: dict[str, Any] | None = None


def _file_key(path: str) -> tuple:
    try:
        st = os.stat(path)
    except OSError:
        return (path, None)
    return (path, st.st_mtime_ns, st.st_size, st.st_mode)


def remember_served(s: Any) -> None:
    """기동할 때 내보내는 인증서를 기억한다 — 나중에 파일이 바뀌어도 재시작 전까지는 이것을 내보낸다."""
    global _served
    try:
        leaf = load_certs(s.tls_cert_file)[0]
    except (OSError, ValueError, IndexError):
        _served = None
        return
    _served = {"sha256": leaf.fingerprint(hashes.SHA256()).hex(), "not_after": leaf.not_valid_after_utc}


def status(s: Any, now: datetime | None = None) -> TlsStatus:
    """지금 설정의 인증서 상태. 파일이 바뀌거나 10분이 지나면 다시 본다(만료 시각이 하루 중간이어도 늦지 않게)."""
    if s.tls_mode != "on":
        return TlsStatus(enabled=False)
    now = now or datetime.now(UTC)
    key = (_file_key(s.tls_cert_file), _file_key(s.tls_key_file), _file_key(s.tls_ca_file), s.public_url,
           _served and _served["sha256"], int(now.timestamp() // 600))
    cached = _status_cache.get(key)
    if cached is None:
        cached = _status_cache[key] = _read_status(s, now)
        while len(_status_cache) > 16:   # 지난 10분 칸
            _status_cache.pop(next(iter(_status_cache)))
    return cached


def load_certs(path: str) -> list[x509.Certificate]:
    with open(path, "rb") as fh:
        return x509.load_pem_x509_certificates(fh.read())


def ca_bundle_pem(path: str) -> bytes:
    """설치 묶음에 넣을 CA — 파일의 인증서만 다시 써서 넣는다. 사내 PKI 의 full.pem 처럼 개인키가 섞여 있어도
    수백 대의 PC 로 퍼지지 않게 (status 는 그런 파일을 오류로 알린다)."""
    return b"".join(cert_pem(c) for c in load_certs(path))


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


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def is_dns_name(text: str) -> bool:
    """에이전트 tls.vhost 로 쓸 수 있는 DNS 이름 (와일드카드·공백·IP 아님, 영문자 하나 이상)."""
    return bool(_DNS_RE.match(text)) and bool(re.search(r"[a-z]", text)) and not is_ip(text)


def _check_name(dns: list[str]) -> str | None:
    """핸드셰이크 확인에 쓸 이름: 첫 일반 이름, 와일드카드뿐이면 그 아래 아무 이름."""
    plain = [n for n in dns if not n.startswith("*.")]
    if plain:
        return plain[0]
    return f"agent-check.{dns[0][2:]}" if dns else None


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
    if _served and _served["sha256"] != leaf.fingerprint(hashes.SHA256()).hex():
        served_end = _served["not_after"]
        level = "error" if served_end <= now else "warn"
        problems.append((level, (f"인증서 파일이 바뀌었지만 api 를 다시 시작하지 않아 옛 인증서(만료 {served_end:%Y-%m-%d}, "
                                 f"D-{(served_end - now).days})를 내보내고 있습니다 — "
                                 "docker compose -f docker-compose.yml restart api")))
    if not dns:
        problems.append(("warn", ("서버 인증서에 DNS 이름이 없습니다. 에이전트가 서버 이름을 확인할 수 없어 설치 묶음을 만들 수 없습니다 "
                                 "(DNS 에 등록하지 않은 이름이어도 됩니다).")))
    url = urlsplit(s.public_url)
    if url.scheme != "https":
        problems.append(("warn", "WLM_PUBLIC_URL 이 https 가 아닙니다. 알림·보고서의 링크가 열리지 않습니다."))
    elif url.hostname and not (any(name_matches(n, url.hostname) for n in dns) or url.hostname in ips):
        problems.append(("warn", f"WLM_PUBLIC_URL 의 호스트({url.hostname})가 인증서 이름에 없습니다. 브라우저가 경고합니다."))
    try:
        if os.stat(s.tls_key_file).st_mode & stat.S_IROTH:
            problems.append(("warn", "서버 키 파일을 누구나 읽을 수 있습니다. 소유자 api 계정(uid 10001), 권한 0600 으로 두세요."))
    except OSError:
        pass

    ca_sha256, ca_ok = None, False
    try:
        with open(s.tls_ca_file, "rb") as fh:
            ca_raw = fh.read()
        cas = x509.load_pem_x509_certificates(ca_raw)
    except FileNotFoundError:
        cas = []
        problems.append(("warn", f"CA 인증서({s.tls_ca_file})가 없습니다. 에이전트 설치 묶음을 만들 수 없습니다."))
    except (OSError, ValueError) as exc:
        cas = []
        problems.append(("error", f"CA 인증서를 읽을 수 없습니다: {exc}"))
    if cas:
        ca_sha256 = cas[0].fingerprint(hashes.SHA256()).hex()
        if b"PRIVATE KEY" in ca_raw:
            problems.append(("error", (f"CA 파일({s.tls_ca_file})에 개인키가 들어 있습니다. 인증서(BEGIN CERTIFICATE)만 남기세요 — "
                                      "설치 묶음에는 인증서만 넣지만 파일이 공개값으로 다뤄집니다.")))
        try:
            is_ca = cas[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            problems.append(("error", ("CA 파일의 첫 인증서가 CA 가 아닙니다(서버 인증서를 넣었나요?). 설치 스크립트가 지문으로 대조하는 "
                                      "인증서라 루트 CA 를 맨 앞에 두세요.")))
        name = _check_name(dns)
        if name:
            try:
                ca_ok, code, message = agent_handshake(s.tls_cert_file, s.tls_key_file, s.tls_ca_file, name)
            except (OSError, ssl.SSLError) as exc:
                problems.append(("error", "서버 키를 읽을 수 없거나 인증서와 짝이 아닙니다 — "
                                          + (_key_load_error(exc, s.tls_key_file) if isinstance(exc, ssl.SSLError)
                                             else str(exc))))
            else:
                if not ca_ok:
                    problems.append(("error", trust_problem(code, message)))
    return TlsStatus(enabled=True, dns_names=tuple(dns), ip_names=tuple(ips), not_after=not_after, days_left=days_left,
                     cert_sha256=leaf.fingerprint(hashes.SHA256()).hex(), ca_sha256=ca_sha256, ca_ok=ca_ok,
                     problems=tuple(problems))


def pick_server_name(st: TlsStatus, host: str | None) -> str | None:
    """에이전트의 tls.vhost: 접속 주소가 인증서 이름(와일드카드 포함)에 맞으면 그것, 아니면(IP 등) 인증서의 첫 DNS 이름."""
    host = (host or "").lower().rstrip(".")
    if host and is_dns_name(host) and any(name_matches(n, host) for n in st.dns_names):
        return host
    return st.usable_names[0] if st.usable_names else None


# ---- 발급 (tls-init / tls-renew) ----

def check_names(names: list[str], ips: list[str]) -> tuple[list[str], list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    clean: list[str] = []
    for raw in names:
        name = raw.strip().lower().rstrip(".")
        if is_ip(name):
            raise TlsError(f"{raw!r} 은 IP 입니다. IP 는 --ip 로 주세요(에이전트는 DNS 이름으로 서버를 확인합니다).")
        if not is_dns_name(name):
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
    """사설 CA. 이 CA 로는 주어진 이름·IP(와 그 하위 도메인)의 서버 인증서만 만들 수 있게 이름 제한을 건다 —
    DNS 이름, IP(주지 않았으면 모든 IP 를 막음), 메일 주소(모두 막음)와 용도(서버 인증만, EKU).
    GPO 로 루트에 배포된 CA 의 키가 새도 다른 서버·메일·코드 서명 용도로 쓰지 못하게 피해 범위를 좁힌다.
    이름을 나중에 바꾸려면 새 CA 가 필요하다."""
    dns, addrs = check_names(names, ips)
    now = now or datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Log Monitor"),
                         x509.NameAttribute(NameOID.COMMON_NAME, "Log Monitor Private CA")])
    permitted: list[x509.GeneralName] = [x509.DNSName(n) for n in dns]
    permitted += [x509.IPAddress(ipaddress.ip_network(f"{a}/{a.max_prefixlen}")) for a in addrs]
    permitted.append(x509.RFC822Name(_NO_EMAIL_DOMAIN))
    excluded = None if addrs else [x509.IPAddress(ipaddress.ip_network("0.0.0.0/0")),
                                   x509.IPAddress(ipaddress.ip_network("::/0"))]
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
        .add_extension(x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
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
    excluded_ip = [g.value for g in nc.excluded_subtrees or [] if isinstance(g, x509.IPAddress)]
    outside = []
    if allowed_dns:
        outside += [n for n in dns if not any(n == a or n.endswith("." + a) for a in allowed_dns)]
    for a in addrs:
        if (allowed_ip and not any(a in net for net in allowed_ip)) or any(a in net for net in excluded_ip):
            outside.append(str(a))
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
