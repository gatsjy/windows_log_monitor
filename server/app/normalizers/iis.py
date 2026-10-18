"""IIS 웹 접속 로그 (W3C 확장 형식, C:\\inetpub\\logs\\LogFiles\\W3SVC*\\u_ex*.log).

에이전트(Fluent Bit tail)는 줄을 그대로 보낸다: {"log": "...", "file": "...", "log_source": "iis", "agent_host": ...}
해석은 서버에서 한다 (파이썬이라 고치기 쉽고 테스트할 수 있다):
  - '#Fields: date time s-ip ...' 머리줄 = 그 파일의 열 순서 (사이트마다 필드 구성이 다를 수 있음).
    DB 표 iis_layouts 에 저장한다(ADR-037) — tail 은 재시작 뒤 머리줄을 다시 보내지 않으므로 메모리로는 부족하다.
  - 줄을 읽을 열 순서 후보: 같은 요청의 머리줄 → 그 파일의 저장된 열 순서 → 같은 폴더(W3SVC<n>)의 최신 열 순서 → 기본 순서.
    어느 후보든 칸 수와 값 모양(plausible)이 맞아야 쓴다. 맞는 것이 없으면 원문으로 저장한다 — 틀리게 읽지 않는다.
    추정한 순서(같은 폴더·기본)로 읽었으면 raw.iis._layout 에 'site'|'default' 를 남긴다.
  - 해석한 값은 원본(log)을 건드리지 않고 raw.iis.* 에 덧붙인다

공통 필드: event_id = HTTP 상태 코드, username = cs-username, src_ip = c-ip
수준: 5xx → 오류, 401·403·429 → 경고, 그 외 → 정보
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from urllib.parse import unquote_plus

from .base import ERROR, INFO, WARNING, Event, clean_ip, clean_text, clean_user, pick_host, to_int

SOURCE = "iis"

DEFAULT_FIELDS = (
    "date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "cs-username", "c-ip",
    "cs(User-Agent)", "cs(Referer)", "sc-status", "sc-substatus", "sc-win32-status", "time-taken",
)

Layout = tuple[str, ...]
# 머리줄을 저장할 때의 상한 — 수집 키만 있으면 누구나 보낼 수 있어 표가 쓰레기로 커지지 않게 (IIS 필드는 30여 개).
# 필드 이름은 사용자 지정 필드(IIS 8.5+, 관리자가 정한 이름 — 한글도 됨)까지 받되 공백·제어 문자는 받지 않는다
# (공백 하나로 이어 저장하고 split() 으로 되읽는다)
_MAX_FILE_BYTES = 1024
_MAX_FIELDS = 100
_MAX_FIELD_NAME = 256


def _field_name(name: str) -> bool:
    return 0 < len(name) <= _MAX_FIELD_NAME and name.isprintable() and not any(c.isspace() for c in name)


@dataclass
class IisContext:
    """한 수집 요청 동안의 열 순서 문맥. stored·site 는 repository.iis_context 가 DB(캐시)에서 미리 채운다."""

    stored: dict[tuple[str, str], Layout] = field(default_factory=dict)  # (host, file) → 그 파일의 열 순서
    site: dict[tuple[str, str], Layout] = field(default_factory=dict)    # (host, dir) → 그 폴더의 최신 열 순서
    learned: dict[tuple[str, str], tuple[str, Layout]] = field(default_factory=dict)  # 이 요청의 머리줄 (host, file) → (dir, 열)


def site_dir(file: str) -> str:
    """파일의 폴더 (…\\W3SVC1). IIS 파일 이름(u_exYYMMDD.log)은 사이트마다 같아서 폴더로 사이트를 가린다."""
    return file.replace("\\", "/").rpartition("/")[0]


def is_header(line: str) -> bool:
    return line.startswith("#")


def _line(record: dict) -> str:
    return str(record.get("log") or record.get("message") or "").rstrip("\r\n")


def _storable(host: str, file: str) -> bool:
    # PostgreSQL 이 받지 못하는 값(NUL, 짝 없는 서러게이트)이나 색인 한 줄 상한(약 2.7KB)을 넘는 값 때문에
    # 조회·저장 SQL 자체가 실패해 요청 전체(다른 이벤트까지)가 거절되지 않게
    try:
        size = len(file.encode("utf-8")) + len(host.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return size <= _MAX_FILE_BYTES and "\x00" not in file and "\x00" not in host


def layout_keys(records: Iterable[dict]) -> set[tuple[str, str, str]]:
    """DB 에서 열 순서를 찾아야 하는 (host, file, dir) — IIS 의 머리줄이 아닌 줄이 있는 파일만, 파일 단위로."""
    keys = set()
    for record in records:
        if str(record.get("log_source") or "") == SOURCE and not is_header(_line(record)):
            host, file = pick_host(record, "host", "hostname"), str(record.get("file") or "")
            if _storable(host, file):
                keys.add((host, file, site_dir(file)))
    return keys


def _learn(ctx: IisContext, host: str, file: str, line: str) -> None:
    if not line.startswith("#Fields:") or not _storable(host, file):
        return  # #Software·#Version·#Date 는 열 순서와 무관
    fields = tuple(line[len("#Fields:"):].split())
    if not fields or len(fields) > _MAX_FIELDS or not all(_field_name(name) for name in fields):
        return
    directory = site_dir(file)
    ctx.learned[(host, file)] = (directory, fields)
    ctx.site[(host, directory)] = fields  # 같은 요청 안의 같은 폴더 다른 파일도 이것을 '같은 폴더의 최신'으로


def parse_line(line: str, fields: Layout) -> dict[str, str] | None:
    parts = line.split(" ")
    if len(parts) != len(fields):
        return None
    return {name: value for name, value in zip(fields, parts, strict=True) if value != "-"}


_IPV4 = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})").fullmatch


def _is_ip(value: str) -> bool:
    # 캐시에는 주소 길이의 값만 — UA·Referer 처럼 요청자가 정하는 긴 값(수 MB)이 캐시에 남아 메모리를 채우지 않게(검토에서 재현).
    # IPv6 + 영역 표시도 64자 안쪽
    return len(value) <= 64 and _is_ip_cached(value)


@lru_cache(maxsize=8192)  # 줄마다 두 번(s-ip·c-ip) — 같은 주소가 되풀이되고 ipaddress 는 느리다 (수집 처리량)
def _is_ip_cached(value: str) -> bool:
    if m := _IPV4(value):
        return all(int(octet) <= 255 for octet in m.groups())
    if ":" not in value:
        return False
    try:
        ipaddress.ip_address(value.split("%", 1)[0])  # fe80::1%12 (IPv6 영역 표시)
    except ValueError:
        return False
    return True


_INT = re.compile(r"\d{1,19}").fullmatch
# 값 모양 ① 모든 후보: 서버(IIS)가 만드는 필드만 본다. 그 파일의 머리줄로 확인한 순서라면 요청자가 정하는 값
# (method·URI·UA·Referer·username)이 무엇이든 해석이 깨지지 않게 — 해석 실패를 일부러 일으켜 규칙을 피하지 못하게.
# 상태 코드는 HTTP.sys 가 받는 100–999 (응용 프로그램이 6xx 를 돌려줄 수 있다)
_SHAPES = {
    "date": re.compile(r"\d{4}-\d{2}-\d{2}").fullmatch,
    "time": re.compile(r"\d{2}:\d{2}:\d{2}").fullmatch,
    "sc-status": re.compile(r"[1-9]\d\d").fullmatch,
    "s-port": _INT, "sc-substatus": _INT, "sc-win32-status": _INT, "time-taken": _INT, "sc-bytes": _INT, "cs-bytes": _INT,
    "c-ip": _is_ip, "s-ip": _is_ip,
}
# 값 모양 ② 추정한 순서(같은 폴더·기본)에만 더한다. 열 구성이 다르면 칸이 밀리는데, 요청자 값('-'·IP 모양 UA)이
# 서버 칸에 들어가 ①을 통과할 수 있다(검토에서 재현: 공격자가 정한 IP 가 src_ip 로, 실제 IP 가 username 으로).
# IIS 의 열 순서는 정해져 있어(포함·제외만 고름) 칸이 밀리면 서버 값(IP·숫자)이 요청자 칸으로도 가므로 아래로 잡힌다.
# 대가: 추정하는 동안(그 파일의 머리줄을 아직 못 받음) 요청자가 자기 줄을 원문으로 남길 수 있다 — 틀린 IP 보다 낫다
_ALWAYS = frozenset({"date", "time", "s-ip", "s-port", "c-ip", "sc-status", "sc-substatus", "sc-win32-status",
                     "time-taken", "sc-bytes", "cs-bytes", "s-sitename", "s-computername"})  # IIS 가 늘 쓴다 ('-' 없음)
_REQUEST_SHAPES = {
    "cs-method": re.compile(r"[A-Z][A-Z_-]*").fullmatch,
    "cs-uri-stem": re.compile(r"[/*]\S*").fullmatch,
    "cs-version": re.compile(r"HTTP/\d(\.\d)?").fullmatch,
}
_REQUESTER_TEXT = ("cs-username", "cs(User-Agent)", "cs(Referer)", "cs-uri-query", "cs(Cookie)")
_BARE_NUMBER = re.compile(r"\d+").fullmatch
# 요청자 칸에 HTTP 버전·숫자만 있는 Host 도 칸이 밀린 표시다 (2차 검토: cs-version 을 더한 구성, cs-host 칸에 상태 코드)
_VERSION = _REQUEST_SHAPES["cs-version"]


def plausible(parsed: dict[str, str]) -> bool:
    """이 열 순서로 읽은 값들이 IIS 가 쓰는 모양인가 (①). '-'(값 없음)는 parse_line 이 이미 뺐다."""
    return all(ok(parsed[name]) for name, ok in _SHAPES.items() if name in parsed)


def plausible_guess(parsed: dict[str, str], fields: Layout) -> bool:
    """추정한 순서로 읽어도 되는가 (① + ②) — 맞지 않으면 원문으로 남긴다."""
    return (plausible(parsed)
            and all(name in parsed for name in fields if name in _ALWAYS)
            and all(ok(parsed[name]) for name, ok in _REQUEST_SHAPES.items() if name in parsed)
            and not any(_BARE_NUMBER(parsed[name]) or _is_ip(parsed[name]) or _VERSION(parsed[name])
                        for name in _REQUESTER_TEXT if name in parsed)
            and not ("cs-host" in parsed and (_BARE_NUMBER(parsed["cs-host"]) or _VERSION(parsed["cs-host"]))))


def _parse(line: str, host: str, file: str, ctx: IisContext) -> tuple[dict[str, str], str | None] | None:
    """(해석값, 추정 표시) — 추정 표시는 같은 폴더(site)·기본(default) 순서로 읽었을 때만."""
    learned = ctx.learned.get((host, file))
    own = learned[1] if learned else ctx.stored.get((host, file))
    if own is not None:  # 흔한 경우를 먼저 — 그 파일의 순서 (수집 처리량)
        parsed = parse_line(line, own)
        if parsed is not None and plausible(parsed):
            return parsed, None
    tried = {own}
    stored = ctx.stored.get((host, file)) if learned else None
    if stored is not None and stored not in tried:  # 같은 요청의 머리줄이 저장된 것과 다를 때
        tried.add(stored)
        parsed = parse_line(line, stored)
        if parsed is not None and plausible(parsed):
            return parsed, None
    for fields, mark in ((ctx.site.get((host, site_dir(file))), "site"), (DEFAULT_FIELDS, "default")):
        if fields is None or fields in tried:
            continue
        tried.add(fields)
        parsed = parse_line(line, fields)
        if parsed is not None and plausible_guess(parsed, fields):
            return parsed, mark
    return None


# W3C 필드 이름 → raw.iis 에 쓸 이름 (검색하기 쉽게)
FIELD_NAMES = {
    "date": "date", "time": "time", "s-sitename": "site", "s-computername": "server", "s-ip": "server_ip",
    "cs-method": "method", "cs-uri-stem": "uri_stem", "cs-uri-query": "uri_query", "s-port": "port",
    "cs-username": "username", "c-ip": "client_ip", "cs-version": "http_version", "cs(User-Agent)": "user_agent",
    "cs(Cookie)": "cookie", "cs(Referer)": "referer", "cs-host": "host_header", "sc-status": "status",
    "sc-substatus": "substatus", "sc-win32-status": "win32_status", "sc-bytes": "bytes_sent",
    "cs-bytes": "bytes_received", "time-taken": "time_taken",
}


_STANDARD_KEYS = frozenset(FIELD_NAMES.values())


def _key(name: str) -> str:
    return FIELD_NAMES.get(name) or "".join(c if c.isalnum() else "_" for c in name).strip("_").lower()


def level_for(status: int | None) -> int:
    if status is None:
        return INFO
    if status >= 500:
        return ERROR
    if status in (401, 403, 429):
        return WARNING
    return INFO


def normalize(record: dict, now: datetime, ctx: IisContext | None = None) -> Event | None:
    """ctx 가 없으면(단위 시험·다른 경로) 빈 문맥 — 같은 레코드 안의 정보만으로 기본 순서를 모양 검사와 함께 쓴다."""
    ctx = ctx if ctx is not None else IisContext()
    line = _line(record)
    host = pick_host(record, "host", "hostname")
    file = str(record.get("file") or "")
    if is_header(line):
        _learn(ctx, host, file, line)
        return None  # 머리줄은 이벤트로 저장하지 않는다

    found = _parse(line, host, file, ctx)
    if found is None:
        # 맞는 열 순서가 없으면 버리지 않고 원문 그대로 저장한다 (틀린 자리의 값으로 사용자·IP 를 채우지 않는다)
        return Event(ts=now, host=host, source=SOURCE, level=INFO, message=clean_text(line), raw=record,
                     channel="IIS", provider=file or None)

    parsed, mark = found
    # 표준 필드가 먼저 이름을 갖는다 — 사용자 지정 필드 이름이 겹치면('Client-IP' → client_ip) x_ 를 붙여, 요청 헤더 값이
    # 실제 c-ip·상태 코드를 덮지 않게 (2차 검토)
    iis: dict[str, str] = {_key(k): v for k, v in parsed.items() if k in FIELD_NAMES}
    for k, v in parsed.items():
        if k not in FIELD_NAMES:
            key = _key(k)
            iis["x_" + key if key in iis or key in _STANDARD_KEYS else key] = v
    if mark:
        iis["_layout"] = mark
    status = to_int(iis.get("status"))
    try:  # W3C 로그 시각은 UTC
        ts = datetime.strptime(f"{iis['date']} {iis['time']}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except (KeyError, ValueError):
        ts = now
    url = iis.get("uri_stem", "")
    if iis.get("uri_query"):
        url += "?" + iis["uri_query"]
    agent = unquote_plus(iis.get("user_agent", ""))
    message = f"{iis.get('method', '')} {url} → {iis.get('status', '?')}"
    if iis.get("time_taken"):
        message += f" ({iis['time_taken']}ms)"
    if agent:
        message += f" · {agent[:200]}"
    site = file.replace("\\", "/").split("/")[-2] if "/" in file.replace("\\", "/") else "IIS"
    return Event(
        ts=ts,
        host=host,
        source=SOURCE,
        channel=f"IIS/{site}" if site.upper().startswith("W3SVC") else "IIS",
        provider="IIS",
        event_id=status,
        level=level_for(status),
        message=clean_text(message),
        raw={**record, "iis": iis},
        username=clean_user(iis.get("username")),
        src_ip=clean_ip(iis.get("client_ip")),
    )
