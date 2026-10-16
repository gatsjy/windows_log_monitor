"""운영 실행의 리스너 배치·uvicorn 설정·보안 헤더·상태 확인 (B-06, ADR-036). DB 없음."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import uvicorn

from app import healthcheck, main, serve, tlsutil
from app.config import settings


def _s(**kw):
    base = {"web_listen_port": 8000, "ingest_listen_port": 8001, "ingest_tls_listen_port": 8002,
            "internal_ingest_listen_port": 8003, "tls_mode": "off", "ingest_plain": True, "ingest_keepalive_sec": 75,
            "trusted_proxies": (), "log_level": "INFO", "tls_cert_file": "/app/tls/server.crt",
            "tls_key_file": "/app/tls/server.key"}
    base.update(kw)
    ns = SimpleNamespace(**base)
    ns.tls = ns.tls_mode == "on"
    return ns


def _layout(s):
    return [(spec.role, spec.port, spec.tls, spec.lifespan) for spec in serve.listener_specs(s)]


def test_listener_layout():
    assert _layout(_s()) == [("web", 8000, False, True), ("ingest", 8001, False, False),
                             ("ingest-internal", 8003, False, False)]
    assert _layout(_s(tls_mode="on")) == [("web", 8000, True, True), ("ingest", 8001, False, False),
                                          ("ingest-tls", 8002, True, False), ("ingest-internal", 8003, False, False)]
    # 평문 닫기: 리스너를 띄우지 않는다(연결 거부). 수집기 전용 내부 리스너는 그대로
    assert [r for r, *_ in _layout(_s(tls_mode="on", ingest_plain=False))] == ["web", "ingest-tls", "ingest-internal"]
    # TLS 없이 평문을 닫으면 받을 곳이 없어진다 → 열어 둔다
    assert [r for r, *_ in _layout(_s(ingest_plain=False))] == ["web", "ingest", "ingest-internal"]
    assert serve.Listener("ingest-tls", 8002, True, False).label == "수집 8002(TLS)"


def test_uvicorn_kwargs(monkeypatch):
    s = _s(tls_mode="on")
    specs = {spec.role: spec for spec in serve.listener_specs(s)}
    web = serve.uvicorn_kwargs(s, specs["web"])
    assert web["ssl_context_factory"] is tlsutil.server_context and web["ssl_certfile"] == s.tls_cert_file
    assert "timeout_keep_alive" not in web and "lifespan" not in web
    tls_ingest = serve.uvicorn_kwargs(s, specs["ingest-tls"])
    assert tls_ingest["timeout_keep_alive"] == 75 and tls_ingest["lifespan"] == "off" and "ssl_keyfile" in tls_ingest
    assert "ssl_certfile" not in serve.uvicorn_kwargs(s, specs["ingest"])
    # 프록시 헤더: 적어 둔 프록시만. 비우면 끔 — .env 로 들어온 FORWARDED_ALLOW_IPS='*' 가 신뢰 범위를 바꾸지 못한다
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    plain = serve.uvicorn_kwargs(s, specs["ingest"])
    assert plain["proxy_headers"] is False
    assert uvicorn.Config(main.app, **plain).forwarded_allow_ips == "127.0.0.1"
    proxied = serve.uvicorn_kwargs(_s(trusted_proxies=("10.0.0.5", "10.1.0.0/24")), specs["web"])
    assert proxied["proxy_headers"] is True and proxied["forwarded_allow_ips"] == "10.0.0.5,10.1.0.0/24"


def _headers(scope_extra, monkeypatch, **cfg):
    monkeypatch.setattr(main, "settings", replace(settings, **cfg))
    sent = []

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "path": "/", "method": "GET", "headers": [], "query_string": b"", **scope_extra}
    asyncio.run(main.SecurityHeaders(inner)(scope, None, send))
    return {k.decode().lower(): v.decode() for k, v in sent[0]["headers"]}


def test_hsts_only_on_https_when_enabled(monkeypatch):
    h = _headers({"scheme": "https"}, monkeypatch, hsts_max_age=15552000)
    assert h["strict-transport-security"] == "max-age=15552000"   # includeSubDomains 없음
    assert "strict-transport-security" not in _headers({"scheme": "http"}, monkeypatch, hsts_max_age=15552000)
    assert "strict-transport-security" not in _headers({"scheme": "https"}, monkeypatch, hsts_max_age=None)   # 기본
    # 되돌릴 때: 0 이면 'max-age=0' 을 보내 브라우저가 기억을 지운다 (아예 안 보내면 기억이 남는다)
    assert _headers({"scheme": "https"}, monkeypatch, hsts_max_age=0)["strict-transport-security"] == "max-age=0"
    assert h["x-frame-options"] == "DENY"


def test_healthcheck_follows_tls(monkeypatch):
    seen = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(url, timeout, context):
        seen.update(url=url, context=context)
        return Resp()

    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(healthcheck, "settings", replace(settings, tls_mode="off"))
    assert healthcheck.main() == 0 and seen["url"] == "http://127.0.0.1:8000/healthz" and seen["context"] is None
    monkeypatch.setattr(healthcheck, "settings", replace(settings, tls_mode="on"))
    assert healthcheck.main() == 0 and seen["url"] == "https://127.0.0.1:8000/healthz"
    assert seen["context"].verify_mode.name == "CERT_NONE"   # 자기 자신(루프백)이라 이름 확인 불가

    def fail(*_a, **_k):
        raise OSError("connection refused")

    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", fail)
    assert healthcheck.main() == 1


def test_preflight_stops_start(monkeypatch, caplog):
    monkeypatch.setattr(serve, "settings", replace(settings, tls_mode="maybe"))
    try:
        serve.run()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("기동해서는 안 된다")
    assert any("off 또는 on" in r.getMessage() for r in caplog.records)
