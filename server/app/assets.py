"""수집 대상 대조 (BACKLOG B-55): 로그를 보내야 할 시스템 목록과 실제로 보내는 PC 를 맞춰 본다.

수집 PC 화면은 한 번이라도 보낸 PC 만 보여, 아예 설치되지 않은 중요 서버는 어디에도 나타나지 않았다(B-37 은 보내는 PC 의 빠진 채널,
B-11 은 묶음을 받은 PC 만 본다). 목록은 CSV(Get-ADComputer 내보내기 등)나 이름 목록을 붙여 넣어 통째로 바꾼다.
비교는 짧은 이름(FQDN 의 첫 마디, 소문자) — 에이전트는 PC 이름을 짧게도 FQDN 으로도 보내고, AD 내보내기의 컴퓨터 계정은 끝에 $ 가 붙는다.
화면·점검 보고서·운영 준비도가 coverage() 하나를 같이 쓴다.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from . import repository

MAX_ROWS = 5000
COLLECTING = timedelta(days=7)          # 이 안에 받았으면 '수집 중' — 주말·휴가로 꺼진 PC 까지 빠졌다고 하지 않게
SHOWN = 200                             # 화면·보고서에 이름을 늘어놓는 상한 (수는 다 센다)
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
HOST_COLUMNS = ("name", "host", "hostname", "computer", "computername", "dnshostname", "컴퓨터", "컴퓨터 이름", "호스트", "서버", "pc")
GRADE_COLUMNS = ("grade", "등급", "중요도", "criticality", "importance")
NOTE_COLUMNS = ("description", "note", "비고", "설명", "operatingsystem", "os", "용도")
CRITICAL = {"중요", "critical", "high", "상", "핵심", "1", "y", "yes", "true", "o"}


def short_name(name: str) -> str:
    """비교용 이름: 끝의 $(컴퓨터 계정)·점을 떼고 첫 마디만, 소문자."""
    return name.strip().rstrip("$").split(".")[0].lower()


def _pick(row: dict[str, str], names: tuple[str, ...]) -> str:
    lowered = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
    return next((lowered[n] for n in names if lowered.get(n)), "")


def parse(text: str) -> tuple[list[dict[str, str]], list[str]]:
    """붙여 넣은 목록 → (자산들, 문제들). 머리줄에 아는 이름(Name·DNSHostName·호스트 …)이 있으면 CSV, 아니면 한 줄에 하나
    ('이름' 또는 '이름,중요'). 같은 이름이 여러 번이면 하나로(중요가 이긴다)."""
    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return [], ["목록이 비어 있습니다"]
    problems: list[str] = []
    try:
        dialect: Any = csv.Sniffer().sniff(lines[0], delimiters=",\t;")
    except csv.Error:
        dialect = csv.excel
    header = [c.strip().lower() for c in next(csv.reader([lines[0]], dialect))]
    if any(c in HOST_COLUMNS for c in header):
        rows = [(_pick(r, HOST_COLUMNS), _pick(r, GRADE_COLUMNS), _pick(r, NOTE_COLUMNS))
                for r in csv.DictReader(io.StringIO("\n".join(lines)), dialect=dialect)]
        first = 2
    else:
        rows = [(cells + ["", "", ""])[:3] for cells in csv.reader(lines, dialect)]
        rows = [(name.strip(), grade.strip(), note.strip()) for name, grade, note in rows]
        first = 1
    out: dict[str, dict[str, str]] = {}
    for n, (name, grade, note) in enumerate(rows, start=first):
        name = name.strip().strip('"').rstrip("$")
        if not name:
            continue
        if not _NAME.match(name):
            if len(problems) < 20:
                problems.append(f"{n}번째 줄: 이름 '{name[:40]}' 을(를) 알 수 없습니다")
            continue
        host = short_name(name)
        critical = grade.strip().lower() in CRITICAL
        if host in out:
            out[host]["grade"] = "critical" if critical or out[host]["grade"] == "critical" else "normal"
            continue
        out[host] = {"host": host, "name": name, "grade": "critical" if critical else "normal", "note": note[:200]}
        if len(out) > MAX_ROWS:
            return [], [f"목록이 너무 깁니다 (최대 {MAX_ROWS:,}대)"]
    if not out and not problems:
        problems.append("이름을 찾지 못했습니다 — 한 줄에 하나씩, 또는 Name 열이 있는 CSV")
    return list(out.values()), problems


async def coverage(now: datetime | None = None) -> dict[str, Any]:
    """목록의 시스템마다 수집 상태: collecting(7일 안에 받음)·silent(받은 적은 있으나 7일 넘음)·never(한 번도 없음).
    unexpected = 보내는데 목록에 없는 PC 수(목록이 낡았는지 보는 데 씀)."""
    now = now or datetime.now(UTC)
    listed = await repository.list_assets()
    seen: dict[str, datetime] = {}
    for a in await repository.agent_hosts():
        key = short_name(a["host"])
        if key not in seen or a["last_seen"] > seen[key]:
            seen[key] = a["last_seen"]
    items = []
    for a in listed:
        last = seen.get(a["host"])
        status = "never" if last is None else "collecting" if now - last <= COLLECTING else "silent"
        items.append({**a, "last_seen": last, "status": status})
    missing = [i for i in items if i["status"] != "collecting"]
    missing.sort(key=lambda i: (i["grade"] != "critical", i["status"] != "never", i["host"]))
    total = len(items)
    collecting = total - len(missing)
    names = {a["host"] for a in listed}
    return {
        "total": total, "collecting": collecting, "percent": round(collecting * 100 / total, 1) if total else None,
        "missing_total": len(missing), "critical_missing": sum(1 for i in missing if i["grade"] == "critical"),
        "missing": missing[:SHOWN], "items": items,
        "unexpected": sum(1 for host in seen if host not in names),
        "updated_at": max((a["updated_at"] for a in listed), default=None),
    }
