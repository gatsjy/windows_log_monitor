"""보고서 내용(payload) 만들기: 기간 [start, end) 의 로그·알림과, 만드는 시각의 수집 PC·보관·백업 상태.

payload 는 그대로 DB 에 저장되고(고칠 수 없음) 메일·화면이 모두 이것으로 그린다 — 같은 보고서는 어디서 봐도 같다.
시각은 모두 ISO 문자열(UTC)로 넣는다. 화면·메일은 표시 시간대(WLM_DISPLAY_TZ)로 바꿔 보여 준다.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from .. import archive, backups, db, partitions, repository
from ..config import settings
from ..filters import EventFilter

PAYLOAD_VERSION = 1
KIND_LABELS = {"daily": "일간", "weekly": "주간"}
LEVEL_KEYS = {1: "critical", 2: "error", 3: "warning", 4: "info", 5: "verbose"}
WEEKDAY_KO = "월화수목금토일"

# 보안 점검 항목 — 이벤트 이름은 화면의 web/js/catalog.js 와 같게. attention: 1건이라도 있으면 '점검 필요'(bad/warn)
SECURITY_ITEMS: list[dict[str, Any]] = [
    {"key": "logon_failed", "label": "로그온 실패", "ids": [4625]},
    {"key": "locked_out", "label": "계정 잠금", "ids": [4740]},
    {"key": "account_changed", "label": "계정 생성·삭제·변경", "ids": [4720, 4722, 4723, 4724, 4725, 4726, 4738]},
    {"key": "group_member_added", "label": "보안 그룹 구성원 추가", "ids": [4728, 4732, 4756], "attention": "warn"},
    {"key": "log_cleared", "label": "감사·시스템 로그 삭제", "ids": [1102, 104],
     "providers": ["Microsoft-Windows-Eventlog"], "attention": "bad"},
    {"key": "audit_policy_changed", "label": "감사 정책 변경", "ids": [4719], "attention": "warn"},
    {"key": "service_installed", "label": "서비스 설치", "ids": [7045, 4697]},
    {"key": "task_created", "label": "예약 작업 생성", "ids": [4698]},
    {"key": "sql_login_failed", "label": "SQL Server 로그인 실패", "ids": [18456]},
]


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def period_label(kind: str, start: datetime, end: datetime) -> str:
    tz = ZoneInfo(settings.display_tz)
    s, e = start.astimezone(tz), (end - timedelta(seconds=1)).astimezone(tz)
    if kind == "daily":
        return f"{s:%Y-%m-%d} ({WEEKDAY_KO[s.weekday()]})"
    return f"{s:%Y-%m-%d} ({WEEKDAY_KO[s.weekday()]}) ~ {e:%m-%d} ({WEEKDAY_KO[e.weekday()]})"


def report_title(kind: str, start: datetime, end: datetime) -> str:
    return f"{KIND_LABELS[kind]} 점검 보고서 · {period_label(kind, start, end)}"


async def _events(start: datetime, end: datetime) -> dict[str, Any]:
    base = EventFilter(since=start, until=end)
    totals = await repository.count(base, compare=True)
    by_level = {LEVEL_KEYS.get(int(r["value"]), str(r["value"])): r["n"]
                for r in await repository.top(base, "level", 10) if r["value"] is not None}
    # 추이: 일간은 1시간, 주간은 하루 단위 — 시간대 경계에 맞추려고 기간 시작을 기준점으로
    step = timedelta(hours=1) if end - start <= timedelta(days=1) else timedelta(days=1)
    buckets = [start + step * i for i in range(int((end - start) / step))]
    rows = await repository.timeseries(base, step, start, "level")
    index = {b: i for i, b in enumerate(buckets)}
    total = [0] * len(buckets)
    errors = [0] * len(buckets)
    for r in rows:
        i = index.get(r["bucket"])
        if i is None:
            continue
        total[i] += r["n"]
        if str(r["key"]) in ("1", "2"):
            errors[i] += r["n"]
    return {
        "total": totals["current"], "previous": totals["previous"], "by_level": by_level,
        "trend": {"step_sec": int(step.total_seconds()), "buckets": [_iso(b) for b in buckets], "total": total,
                  "errors": errors},
        "top_error_hosts": await repository.top(replace(base, levels=[1, 2]), "host", 10),
        "by_category": await repository.top(base, "category", 10),
    }


async def _security(start: datetime, end: datetime) -> dict[str, Any]:
    base = EventFilter(since=start, until=end)
    items = []
    for item in SECURITY_ITEMS:
        f = replace(base, event_ids=item["ids"], providers=item.get("providers", []))
        n = (await repository.count(f))["current"]
        items.append({"key": item["key"], "label": item["label"], "event_ids": item["ids"], "n": n,
                      "attention": item.get("attention") if n else None})
    failed = replace(base, event_ids=[4625])
    return {"items": items, "logon_failed_users": await repository.top(failed, "user", 5),
            "logon_failed_ips": await repository.top(failed, "ip", 5)}


async def _alerts(start: datetime, end: datetime) -> dict[str, Any]:
    data = await repository.report_alert_summary(start, end)
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {"open": 0, "acked": 0, "resolved": 0}
    for r in data["fired"]:
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + r["n"]
        by_status[r["status"]] = by_status.get(r["status"], 0) + r["n"]
    median = data["median_resolve_sec"]
    return {
        "fired": sum(by_severity.values()), "by_severity": by_severity, "by_status": by_status,
        "unresolved_by_severity": {r["severity"]: r["n"] for r in data["open_by_severity"]},
        "unresolved_oldest": [{**r, "fired_at": _iso(r["fired_at"])} for r in data["oldest_unresolved"]],
        "resolved_in_period": data["resolved_in_period"],
        "median_resolve_min": round(float(median) / 60, 1) if median is not None else None,
    }


async def _agents(now: datetime) -> dict[str, Any]:
    rows = await repository.agents(now - timedelta(days=1))
    online = stale = 0
    silent = []
    for r in rows:
        if r["silent_sec"] <= settings.heartbeat_online_sec:
            online += 1
        elif r["silent_sec"] <= settings.heartbeat_stale_sec:
            stale += 1
        else:
            silent.append({"host": r["host"], "last_seen": _iso(r["last_seen"]), "last_ip": r["last_ip"]})
    silent.sort(key=lambda a: a["last_seen"] or "")
    return {"total": len(rows), "online": online, "stale": stale, "offline": len(silent), "silent": silent[:20]}


async def _retention() -> dict[str, Any]:
    async with await db.connect_autocommit() as conn:
        parts = await partitions.list_partitions(conn)
    files = archive.list_archives()
    check = (await repository.latest_audit(["retention.verify_archives"])).get("retention.verify_archives")
    return {
        "db_retention_days": settings.db_retention_days, "retention_days": settings.retention_days,
        "partitions": len(parts), "rows_estimate": sum(p["rows_estimate"] for p in parts),
        "oldest_partition": _iso(min((p["from"] for p in parts), default=None)),
        "archives": len(files), "archives_missing": sum(1 for f in files if not f["exists"]),
        "last_integrity_check": {"at": _iso(check["at"]), "detail": check["detail"]} if check else None,
    }


def _attention(p: dict[str, Any]) -> list[dict[str, str]]:
    """'점검 필요' — 사람이 들여다봐야 할 것만, 심각한 것부터. 없으면 빈 목록(= 특이 사항 없음)."""
    out: list[dict[str, str]] = []
    ev = p["events"]
    if ev["total"] == 0:
        out.append({"level": "bad", "text": "이 기간에 들어온 로그가 없습니다 — 수집이 멈췄을 수 있습니다"})
    elif ev["previous"] and ev["total"] < ev["previous"] * 0.5:
        drop = round((1 - ev["total"] / ev["previous"]) * 100)
        out.append({"level": "warn", "text": f"로그 수가 직전 기간보다 {drop}% 줄었습니다 — 수집 PC 상태를 확인하세요"})
    for problem in p["backup"]["problems"]:
        out.append({"level": "bad", "text": f"백업: {problem}"})
    for item in p["security"]["items"]:
        if item["attention"]:
            out.append({"level": item["attention"], "text": f"{item['label']} {item['n']:,}건"})
    unresolved = p["alerts"]["unresolved_by_severity"]
    serious = unresolved.get("critical", 0) + unresolved.get("error", 0)
    if serious:
        out.append({"level": "bad" if unresolved.get("critical") else "warn",
                    "text": f"해결 안 된 심각·오류 알림 {serious:,}건"})
    if p["agents"]["offline"]:
        out.append({"level": "warn", "text": f"연락이 끊긴 PC {p['agents']['offline']:,}대"})
    if p["retention"]["archives_missing"]:
        out.append({"level": "bad", "text": f"보관 파일 {p['retention']['archives_missing']}개가 없습니다 (목록에는 있음)"})
    check = p["retention"]["last_integrity_check"]
    bad = (check or {}).get("detail", {}).get("bad") or []   # 문제 파일 이름 목록 (routers/settings.retention_verify)
    if bad:
        count = len(bad) if isinstance(bad, list) else int(bad)
        out.append({"level": "bad", "text": f"마지막 보관 파일 무결성 확인에서 문제 {count}건"})
    return sorted(out, key=lambda a: a["level"] != "bad")


async def build(kind: str, start: datetime, end: datetime, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    backup = await backups.backup_status(now)
    payload: dict[str, Any] = {
        "version": PAYLOAD_VERSION, "kind": kind, "title": report_title(kind, start, end),
        "period": {"start": _iso(start), "end": _iso(end), "label": period_label(kind, start, end),
                   "tz": settings.display_tz},
        "generated_at": _iso(now),
        "events": await _events(start, end),
        "security": await _security(start, end),
        "alerts": await _alerts(start, end),
        "agents": await _agents(now),
        "retention": await _retention(),
        "backup": {"problems": backup["problems"],
                   "last_backup": _jsonable(backup["last_backup"]), "last_verify": _jsonable(backup["last_verify"]),
                   "last_verify_ok_at": _iso(backup["last_verify_ok_at"])},
    }
    payload["attention"] = _attention(payload)
    return payload


def _jsonable(row: dict | None) -> dict | None:
    return None if row is None else {k: _iso(v) if isinstance(v, datetime) else v for k, v in row.items()}
