"""IIS 열 순서 캐시(repository.iis_context) — DB 없이 db.fetch_all 을 흉내 내 캐시 규칙만 본다 (ADR-037, 검토 반영)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from app import db, repository
from app.normalizers import IisContext, iis, normalize
from app.normalizers.iis import plausible_guess

A = ("WEB-1", "C:/logs/W3SVC1/u_ex261019.log", "C:/logs/W3SVC1")
B = ("WEB-1", "C:/logs/W3SVC2/u_ex261019.log", "C:/logs/W3SVC2")
C = ("WEB-2", "C:/logs/W3SVC1/u_ex261019.log", "C:/logs/W3SVC1")
FIELDS = ("date", "time", "c-ip", "sc-status")


@pytest.fixture(autouse=True)
def _clean_cache():
    repository.forget_iis_layouts()
    yield
    repository.forget_iis_layouts()


def _fake_db(monkeypatch, table: dict[tuple[str, str, str], tuple[str, ...]], before=None):
    """table = {(host, file, dir): fields} — 'DB' 의 내용. 물어본 키를 기록한다."""
    asked: list[list[tuple[str, str, str]]] = []

    async def fetch_all(_query, params):
        keys = list(zip(*params, strict=True))
        asked.append(keys)
        if before:
            before()
        rows = [{"kind": "file", "host": h, "name": f, "fields": " ".join(table[(h, f, d)])}
                for h, f, d in keys if (h, f, d) in table]
        rows += [{"kind": "site", "host": h, "name": d, "fields": " ".join(fl)}
                 for (h, f, d), fl in table.items() if (h, d) in {(k[0], k[2]) for k in keys}]
        return rows

    monkeypatch.setattr(db, "fetch_all", fetch_all)
    return asked


def test_lookup_once_then_cached_including_absence(monkeypatch):
    asked = _fake_db(monkeypatch, {A: FIELDS})
    ctx = asyncio.run(repository.iis_context({A, B}))
    assert ctx.stored == {A[:2]: FIELDS} and ctx.site == {(A[0], A[2]): FIELDS}
    asyncio.run(repository.iis_context({A, B}))
    assert len(asked) == 1  # 없음(B)도 기억해 다시 묻지 않는다


def test_commit_during_lookup_is_not_overwritten_by_none(monkeypatch):
    # 조회하는 사이 다른 요청이 같은 파일의 머리줄을 커밋했다 — 이 조회의 '없음'으로 덮으면 다음 머리줄까지 원문이 된다
    _fake_db(monkeypatch, {}, before=lambda: repository.remember_iis_layouts({A[:2]: (A[2], FIELDS)}))
    ctx = asyncio.run(repository.iis_context({A}))
    assert ctx.stored == {A[:2]: FIELDS} and ctx.site == {(A[0], A[2]): FIELDS}


def test_overflow_clear_keeps_this_requests_layouts(monkeypatch):
    # 검토에서 재현: 캐시가 넘쳐 비울 때, 이미 캐시에 있던 이 요청의 열 순서가 사라져 그 줄들이 원문이 되었다
    monkeypatch.setattr(repository, "_IIS_CACHE_MAX", 1)
    repository.remember_iis_layouts({A[:2]: (A[2], FIELDS), C[:2]: (C[2], FIELDS)})
    _fake_db(monkeypatch, {A: FIELDS, C: FIELDS})
    ctx = asyncio.run(repository.iis_context({A, B}))
    assert ctx.stored.get(A[:2]) == FIELDS


def test_remember_updates_the_folder_layout_too(monkeypatch):
    _fake_db(monkeypatch, {})
    asyncio.run(repository.iis_context({A}))  # 폴더에 아무것도 없음 → None 으로 기억
    repository.remember_iis_layouts({A[:2]: (A[2], FIELDS)})  # 같은 폴더의 다른 파일 머리줄이 커밋됨
    new_file = (A[0], A[1].replace("261019", "261020"), A[2])
    ctx = asyncio.run(repository.iis_context({new_file}))
    assert ctx.site == {(A[0], A[2]): FIELDS}


@pytest.mark.parametrize(("field", "value", "ok"), [
    ("cs-method", "GET", True), ("cs-method", "VERSION-CONTROL", True), ("cs-method", "/x", False),
    ("cs-method", "1.2.3.4", False), ("cs-method", "get", False),
    ("cs-uri-stem", "/a/b.aspx", True), ("cs-uri-stem", "*", True), ("cs-uri-stem", "id=7", False),
    ("cs-version", "HTTP/1.1", True), ("cs-version", "HTTP/2", True), ("cs-version", "443", False),
    ("cs-username", "CORP\\kim", True), ("cs-username", "203.0.113.5", False), ("cs-username", "443", False),
    ("cs(User-Agent)", "Mozilla/5.0", True), ("cs(User-Agent)", "198.51.100.77", False),
    ("cs(Referer)", "https://example.com/", True), ("cs(Referer)", "500", False),
    ("cs-uri-query", "id=7", True), ("cs-uri-query", "7", False),
])
def test_guess_request_shapes(field, value, ok):
    # 추정한 순서에만 쓰는 요청 쪽 모양 — 칸이 밀리면 서버 값(숫자·IP)이 요청자 칸으로, 요청 값이 서버 칸으로 간다
    base = {"date": "2026-10-04", "time": "01:02:03", "c-ip": "203.0.113.5", "sc-status": "200"}
    fields = (*base, field)
    assert plausible_guess({**base, field: value}, fields) is ok


# ------------------------------------------------- 규칙마다 '그것만으로' 실패하는 시험 (2차 검토: 18개 규칙이 시험 없이 빠질 수 있었다)


NOW = datetime(2026, 10, 4, 3, 0, 0, tzinfo=UTC)
# IIS 가 쓸 수 있는 표준 필드 전부를 IIS 순서대로 — 규칙 목록에 새 이름을 넣으면 여기에도 넣어야 시험이 돈다
FULL = ("date", "time", "s-sitename", "s-computername", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port",
        "cs-username", "c-ip", "cs-version", "cs(User-Agent)", "cs(Cookie)", "cs(Referer)", "cs-host", "sc-status",
        "sc-substatus", "sc-win32-status", "sc-bytes", "cs-bytes", "time-taken")
GOOD = {"date": "2026-10-04", "time": "01:02:03", "s-sitename": "W3SVC1", "s-computername": "WEB01", "s-ip": "10.0.0.10",
        "cs-method": "GET", "cs-uri-stem": "/a", "cs-uri-query": "id=7", "s-port": "443", "cs-username": "CORP\\kim",
        "c-ip": "203.0.113.5", "cs-version": "HTTP/1.1", "cs(User-Agent)": "Mozilla/5.0", "cs(Cookie)": "sid=1",
        "cs(Referer)": "https://x/", "cs-host": "shop.example", "sc-status": "401", "sc-substatus": "1",
        "sc-win32-status": "0", "sc-bytes": "512", "cs-bytes": "300", "time-taken": "15"}
FILE, DIR = "C:\\logs\\W3SVC1\\u_ex261004.log", "C:/logs/W3SVC1"


def _read(**changes):
    """(같은 폴더 순서로 추정했을 때 해석했나, 그 파일의 순서일 때 해석했나)"""
    line = " ".join({**GOOD, **changes}[name] for name in FULL)
    rec = {"log": line, "file": FILE, "agent_host": "WEB-X", "log_source": "iis"}
    guess = normalize(rec, NOW, IisContext(site={("WEB-X", DIR): FULL}))
    own = normalize(rec, NOW, IisContext(stored={("WEB-X", FILE): FULL}))
    return "iis" in guess.raw, "iis" in own.raw


def test_full_layout_baseline():
    assert _read() == (True, True)


# 기대 목록은 시험에 적는다 — 모듈의 목록으로 매개변수를 만들면 항목을 빼는 순간 그 시험도 사라진다
ALWAYS = ("date", "time", "s-sitename", "s-computername", "s-ip", "s-port", "c-ip", "sc-status", "sc-substatus",
          "sc-win32-status", "sc-bytes", "cs-bytes", "time-taken")
SHAPES = ("date", "time", "s-ip", "c-ip", "s-port", "sc-status", "sc-substatus", "sc-win32-status", "sc-bytes",
          "cs-bytes", "time-taken")
REQUESTER_TEXT = ("cs-username", "cs(User-Agent)", "cs(Referer)", "cs-uri-query", "cs(Cookie)")


def test_rule_lists_match_the_pinned_lists():
    assert set(iis._ALWAYS) == set(ALWAYS) and set(iis._SHAPES) == set(SHAPES)
    assert set(iis._REQUESTER_TEXT) == set(REQUESTER_TEXT)
    assert set(iis._REQUEST_SHAPES) == {"cs-method", "cs-uri-stem", "cs-version"}


@pytest.mark.parametrize("name", ALWAYS)
def test_always_present_field_missing_rejects_only_a_guess(name):
    assert _read(**{name: "-"}) == (False, True)


@pytest.mark.parametrize("name", SHAPES)
def test_server_shape_rejects_every_layout(name):
    assert _read(**{name: "x"}) == (False, False)


@pytest.mark.parametrize("value", ["500", "198.51.100.7", "HTTP/1.1"])
@pytest.mark.parametrize("name", REQUESTER_TEXT)
def test_requester_text_that_looks_like_a_server_value_rejects_only_a_guess(name, value):
    assert _read(**{name: value}) == (False, True)


@pytest.mark.parametrize(("value", "guessed"), [("500", False), ("HTTP/1.1", False), ("10.0.0.10", True)])
def test_host_header(value, guessed):
    assert _read(**{"cs-host": value}) == (guessed, True)  # Host 가 IP 인 것은 흔하다


@pytest.mark.parametrize(("name", "bad"), [("cs-method", "get"), ("cs-uri-stem", "id=7"), ("cs-version", "HTTP1")])
def test_request_shape_rejects_only_a_guess(name, bad):
    assert _read(**{name: bad}) == (False, True)


DEFAULT_LINE_FIELDS = iis.DEFAULT_FIELDS


def test_round2_cs_version_layout_cannot_choose_status():
    # 실제 구성: 기본 - time-taken + cs-version (15칸). Referer 를 200 으로 보낸 401 요청 → 기본으로 읽으면 상태가 200 이 되었다
    line = "2026-10-04 01:02:03 10.0.0.10 POST /login - 443 - 203.0.113.5 HTTP/1.1 Mozilla/5.0 200 401 1 1326"
    e = normalize({"log": line, "file": FILE, "agent_host": "WEB-X", "log_source": "iis"}, NOW, IisContext())
    assert (e.event_id, "iis" in e.raw) == (None, False)


def test_round2_host_slot_cannot_carry_status():
    # 같은 폴더 순서 = 기본 - sc-substatus + cs-host, 실제 = 기본 - sc-substatus + sc-bytes → 상태 200 이 Host 칸에, 995 가 상태로
    site = tuple(f for f in DEFAULT_LINE_FIELDS if f != "sc-substatus")
    site = site[:site.index("sc-status")] + ("cs-host",) + site[site.index("sc-status"):]
    line = "2026-10-04 01:02:03 10.0.0.10 GET /a - 443 - 203.0.113.5 Mozilla/5.0+(Windows+NT+10.0) https://intra/ 200 995 0 31"
    e = normalize({"log": line, "file": FILE, "agent_host": "WEB-X", "log_source": "iis"}, NOW,
                  IisContext(site={("WEB-X", DIR): site}))
    assert (e.event_id, e.raw["iis"]["_layout"]) == (200, "default")  # Host 칸에 숫자 → 폴더 순서 거절, 기본 순서가 맞다


def test_ip_cache_does_not_keep_long_values():
    iis._is_ip_cached.cache_clear()
    assert not iis._is_ip("1" * 1_000_000) and not iis._is_ip("Mozilla/5.0 " * 10)
    assert iis._is_ip_cached.cache_info().currsize == 0
    assert iis._is_ip("fe80::1%12") and iis._is_ip_cached.cache_info().currsize == 1


def test_custom_field_named_like_a_standard_one_does_not_override_it():
    # 사용자 지정 필드 'Client-IP'(요청 헤더 값)가 실제 c-ip 를, 'Status' 가 상태 코드를 덮지 않는다
    ctx = IisContext()
    normalize({"log": "#Fields: " + " ".join(iis.DEFAULT_FIELDS + ("Client-IP", "Status")), "file": FILE,
               "agent_host": "WEB-X", "log_source": "iis"}, NOW, ctx)
    line = "2026-10-04 01:02:03 10.0.0.10 POST /login - 443 - 203.0.113.5 Mozilla/5.0 - 401 1 1326 15 198.51.100.77 200"
    e = normalize({"log": line, "file": FILE, "agent_host": "WEB-X", "log_source": "iis"}, NOW, ctx)
    assert (e.src_ip, e.event_id, e.level) == ("203.0.113.5", 401, 3)
    assert (e.raw["iis"]["client_ip"], e.raw["iis"]["x_client_ip"], e.raw["iis"]["x_status"]) == \
        ("203.0.113.5", "198.51.100.77", "200")
