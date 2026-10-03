"""IIS 웹 접속 로그 (W3C 확장 형식, C:\\inetpub\\logs\\LogFiles\\W3SVC*\\u_ex*.log).

에이전트(Fluent Bit tail)는 줄을 그대로 보낸다: {"log": "...", "file": "...", "log_source": "iis", "agent_host": ...}
해석은 서버에서 한다 (파이썬이라 고치기 쉽고 테스트할 수 있다):
  - '#Fields: date time s-ip ...' 머리줄을 만나면 그 파일의 필드 순서를 기억한다 (사이트마다 필드 구성이 다를 수 있음)
  - 머리줄을 아직 못 봤으면 IIS 기본 필드 순서로 해석한다
  - 해석한 값은 원본(log)을 건드리지 않고 raw.iis.* 에 덧붙인다

공통 필드: event_id = HTTP 상태 코드, username = cs-username, src_ip = c-ip
수준: 5xx → 오류, 401·403·429 → 경고, 그 외 → 정보
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import unquote_plus

from .base import ERROR, INFO, WARNING, Event, clean_ip, clean_text, clean_user, pick_host, to_int

SOURCE = "iis"

DEFAULT_FIELDS = (
    "date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "cs-username", "c-ip",
    "cs(User-Agent)", "cs(Referer)", "sc-status", "sc-substatus", "sc-win32-status", "time-taken",
)

# (host, 파일 경로) → 필드 목록. 서버를 재시작하면 다음 머리줄까지 기본 순서를 쓴다
_layouts: dict[tuple[str, str], tuple[str, ...]] = {}
_MAX_LAYOUTS = 5000


def is_header(line: str) -> bool:
    return line.startswith("#")


def remember_header(host: str, file: str, line: str) -> None:
    if line.startswith("#Fields:"):
        if len(_layouts) > _MAX_LAYOUTS:
            _layouts.clear()
        _layouts[(host, file)] = tuple(line[len("#Fields:"):].split())


def parse_line(line: str, fields: tuple[str, ...]) -> dict[str, str] | None:
    parts = line.split(" ")
    if len(parts) != len(fields):
        return None
    return {name: value for name, value in zip(fields, parts, strict=True) if value != "-"}


# W3C 필드 이름 → raw.iis 에 쓸 이름 (검색하기 쉽게)
FIELD_NAMES = {
    "date": "date", "time": "time", "s-sitename": "site", "s-computername": "server", "s-ip": "server_ip",
    "cs-method": "method", "cs-uri-stem": "uri_stem", "cs-uri-query": "uri_query", "s-port": "port",
    "cs-username": "username", "c-ip": "client_ip", "cs-version": "http_version", "cs(User-Agent)": "user_agent",
    "cs(Cookie)": "cookie", "cs(Referer)": "referer", "cs-host": "host_header", "sc-status": "status",
    "sc-substatus": "substatus", "sc-win32-status": "win32_status", "sc-bytes": "bytes_sent",
    "cs-bytes": "bytes_received", "time-taken": "time_taken",
}


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


def normalize(record: dict, now: datetime) -> Event | None:
    line = str(record.get("log") or record.get("message") or "").rstrip("\r\n")
    host = pick_host(record, "host", "hostname")
    file = str(record.get("file") or "")
    if is_header(line):
        remember_header(host, file, line)
        return None  # 머리줄은 이벤트로 저장하지 않는다

    fields = _layouts.get((host, file), DEFAULT_FIELDS)
    parsed = parse_line(line, fields) or (parse_line(line, DEFAULT_FIELDS) if fields != DEFAULT_FIELDS else None)
    if parsed is None:
        # 해석 실패해도 버리지 않는다 (원문 그대로 저장)
        return Event(ts=now, host=host, source=SOURCE, level=INFO, message=clean_text(line), raw=record,
                     channel="IIS", provider=file or None)

    iis = {_key(k): v for k, v in parsed.items()}
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
