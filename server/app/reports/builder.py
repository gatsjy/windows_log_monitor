"""보고서 내용(payload) 만들기: 기간 [start, end) 의 로그·알림과, 만드는 시각의 수집 PC·보관·백업 상태.

payload 는 그대로 DB 에 저장되고(고칠 수 없음) 메일·화면이 모두 이것으로 그린다 — 같은 보고서는 어디서 봐도 같다.
시각은 모두 ISO 문자열(UTC)로 넣는다. 화면·메일은 표시 시간대(WLM_DISPLAY_TZ)로 바꿔 보여 준다.
"""

from __future__ import annotations

import math
from bisect import bisect_right
from dataclasses import replace
from datetime import UTC, datetime, time, timedelta, tzinfo
from typing import Any

from .. import archive, backups, db, partitions, repository
from ..alerts import health
from ..alerts.builtin import ADMIN_RULE
from ..alerts.engine import engine
from ..config import display_zone, settings
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


CONFIG_ROWS = 20    # 보고서에 싣는 설정 변경·넓은 무음 (최근 것부터 이만큼, 수는 전체)
CONFIG_LINES = 8


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def period_label(kind: str, start: datetime, end: datetime) -> str:
    tz = display_zone()
    s, e = start.astimezone(tz), (end - timedelta(seconds=1)).astimezone(tz)
    if kind == "daily":
        return f"{s:%Y-%m-%d} ({WEEKDAY_KO[s.weekday()]})"
    return f"{s:%Y-%m-%d} ({WEEKDAY_KO[s.weekday()]}) ~ {e:%m-%d} ({WEEKDAY_KO[e.weekday()]})"


def report_title(kind: str, start: datetime, end: datetime) -> str:
    return f"{KIND_LABELS[kind]} 점검 보고서 · {period_label(kind, start, end)}"


def trend_buckets(kind: str, start: datetime, end: datetime, tz: tzinfo) -> list[datetime]:
    """추이 칸의 시작 시각(UTC). 일간 = 1시간, 주간 = 하루(표시 시간대의 자정).
    서머타임이 있는 시간대에서는 하루가 23·25시간이라 고정 길이로 나누면 칸이 빠지거나 하나로 뭉친다 →
    일간은 실제 시간으로 1시간씩(23·25칸), 주간은 달력 날짜의 자정으로 나눈다."""
    if kind == "daily":
        return [start + timedelta(hours=i) for i in range(math.ceil((end - start) / timedelta(hours=1)))]
    day = datetime.combine(start.astimezone(tz).date(), time(0), tzinfo=tz)
    out = []
    while (at := day.astimezone(UTC)) < end:
        out.append(max(at, start))
        day += timedelta(days=1)   # 시간대가 붙은 datetime 의 날짜 더하기는 벽시계 기준 → 다음 날 자정
    return out


def previous_window(start: datetime, end: datetime, tz: tzinfo) -> tuple[datetime, datetime]:
    """비교 기간 = 일주일 전 같은 시간 (일간 = 지난주 같은 요일, 주간 = 지난주).
    일간을 바로 전날과 비교하면 PC 를 끄는 주말·휴일 다음 보고서마다 '로그가 줄었다'는 거짓 경고가 난다."""
    week = timedelta(days=7)
    return (start.astimezone(tz) - week).astimezone(UTC), (end.astimezone(tz) - week).astimezone(UTC)


async def _events(kind: str, start: datetime, end: datetime) -> dict[str, Any]:
    tz = display_zone()
    base = EventFilter(since=start, until=end)
    total_n = (await repository.count(base))["current"]
    prev_start, prev_end = previous_window(start, end, tz)
    previous = (await repository.count(replace(base, since=prev_start, until=prev_end)))["current"]
    by_level = {LEVEL_KEYS.get(int(r["value"]), str(r["value"])): r["n"]
                for r in await repository.top(base, "level", 10) if r["value"] is not None}
    # 추이: 1시간 단위로 세어 칸(일간 1시간·주간 하루)에 나눠 담는다 — 서머타임 날에도 칸 경계가 시간 단위라 맞는다
    buckets = trend_buckets(kind, start, end, tz)
    rows = await repository.timeseries(base, timedelta(hours=1), start, "level")
    total = [0] * len(buckets)
    errors = [0] * len(buckets)
    for r in rows:
        i = bisect_right(buckets, r["bucket"]) - 1
        if i < 0:
            continue
        total[i] += r["n"]
        if str(r["key"]) in ("1", "2"):
            errors[i] += r["n"]
    step = timedelta(hours=1) if kind == "daily" else timedelta(days=1)
    return {
        "total": total_n, "previous": previous,
        "previous_label": "지난주 같은 요일" if kind == "daily" else "지난주", "by_level": by_level,
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
    # 탐지를 바꾼 관리 작업 (ADR-043) — 알림 설정 판본과 넓은 무음
    versions = await repository.report_config_changes(start, end)
    silences = await repository.report_wide_silences(start, end)
    return {
        "fired": sum(by_severity.values()), "by_severity": by_severity, "by_status": by_status,
        "unresolved_by_severity": {r["severity"]: r["n"] for r in data["open_by_severity"]},
        "unresolved_oldest": [{**r, "fired_at": _iso(r["fired_at"])} for r in data["oldest_unresolved"]],
        "resolved_in_period": data["resolved_in_period"],
        "median_resolve_min": round(float(median) / 60, 1) if median is not None else None,
        "config_changes": [
            {"version": v["id"], "at": _iso(v["applied_at"]), "source": v["source"], "actor": v["actor"],
             "weakened": v["weakened"], "n": len(v["changes"]),
             # 약해지는 변경부터 몇 줄만 (나머지는 감사로그·판본에)
             "changes": [c["text"] for c in sorted(v["changes"], key=lambda c: not c.get("weakens"))][:CONFIG_LINES]}
            for v in versions[-CONFIG_ROWS:]],
        "config_changes_total": len(versions),
        "config_changes_weakened": sum(1 for v in versions if v["weakened"]),
        "config_changes_direct": sum(1 for v in versions if v["source"] != "ui"),
        "wide_silences": [{"id": r["id"], "rule": r["rule"], "group_key": r["group_key"], "starts_at": _iso(r["starts_at"]),
                           "ends_at": _iso(r["ends_at"]), "reason": r["reason"], "created_by": r["created_by"]}
                          for r in silences[-CONFIG_ROWS:]],
        "wide_silences_total": len(silences),
        "config_error": engine.config_error,
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
    # PC 는 보내는데 늘 오던 채널만 끊긴 것 (B-37) — GPO 변경으로 Security 수집만 멈춘 DC 같은 경우
    streams = await repository.silent_streams(now)
    return {"total": len(rows), "online": online, "stale": stale, "offline": len(silent), "silent": silent[:20],
            "silent_streams": [{"host": r["host"], "source": r["source"], "channel": r["channel"],
                                "last_at": _iso(r["last_at"]), "per_day": round(r["n7"] / max(r["days"], 1))}
                               for r in streams[:30]],
            "silent_streams_total": len(streams)}


async def _retention() -> dict[str, Any]:
    async with await db.connect_autocommit() as conn:
        parts = await partitions.list_partitions(conn)
    files = archive.list_archives()
    check = (await repository.latest_audit(["retention.verify_archives"])).get("retention.verify_archives")
    return {
        "db_retention_days": settings.db_retention_days, "retention_days": settings.retention_days,
        "audit_retention_days": settings.audit_retention_days, "warnings": partitions.retention_warnings(),
        "partitions": len(parts), "rows_estimate": sum(p["rows_estimate"] for p in parts),
        "oldest_partition": _iso(min((p["from"] for p in parts), default=None)),
        "archives": len(files), "archives_missing": sum(1 for f in files if not f["exists"]),
        "last_integrity_check": {"at": _iso(check["at"]), "detail": check["detail"],
                                 "bad_count": integrity_bad_count(check)} if check else None,
    }


def integrity_bad_count(check: dict[str, Any] | None) -> int:
    """마지막 보관 파일 무결성 확인의 문제 수. 화면 확인은 문제 파일 이름 목록을, 예전 CLI 는 개수를 남겼다 — 둘 다 받는다
    (예전 형식으로 만든 보고서도 그릴 수 있어야 한다: 보고서는 고칠 수 없다)."""
    if not check:
        return 0
    if isinstance(check.get("bad_count"), int):
        return check["bad_count"]
    bad = (check.get("detail") or {}).get("bad")
    if isinstance(bad, list):
        return len(bad)
    try:
        return int(bad or 0)
    except (TypeError, ValueError):
        return 0


# 관리 작업 요약의 묶음: (이름, 감사로그 동작 앞부분들). 수가 0 인 묶음도 보인다 — '없었음'도 점검 결과다
ADMIN_GROUPS = (
    ("권한·계정", ("user.", "user_group.")),
    ("알림 규칙·무음", ("alerts.config.save", "alerts.config.apply", "alerts.rule.", "alerts.silence.")),
    ("알림 받는 곳", ("settings.group.", "settings.channel.save", "settings.channel.delete", "settings.contact.", "settings.smtp.save")),
    ("보관·복원", ("retention.restore_archive", "retention.rotate_now", "retention.delete_archive")),
    ("내려받기", ("audit.export", "alerts.export", "agents.package.download")),
)


async def _admin(start: datetime, end: datetime) -> dict[str, Any]:
    counts = await repository.audit_action_counts(start, end)
    groups = [{"label": label, "n": sum(n for action, n in counts.items() if action.startswith(prefixes))}
              for label, prefixes in ADMIN_GROUPS]
    return {"groups": groups, "alerts": await repository.count_alerts_of_rule(ADMIN_RULE, start, end)}


async def _alerting() -> dict[str, Any]:
    state = await health.current(fresh=True)
    # 전송기를 끈 것(WLM_ALERT_DISPATCHER=off)은 시험용 설정이라 보고서에 싣지 않는다 — 화면·/healthz/alerts 에는 나온다
    problems = [{"level": p["level"], "code": p["code"], "text": p["text"]} for p in state["problems"]
                if p["code"] != "dispatcher_off"]
    return {"problems": problems}


def _attention(p: dict[str, Any]) -> list[dict[str, str]]:
    """'점검 필요' — 사람이 들여다봐야 할 것만, 심각한 것부터. 없으면 빈 목록(= 특이 사항 없음)."""
    out: list[dict[str, str]] = []
    ev = p["events"]
    if ev["total"] == 0:
        out.append({"level": "bad", "text": "이 기간에 들어온 로그가 없습니다 — 수집이 멈췄을 수 있습니다"})
    elif ev["previous"] and ev["total"] < ev["previous"] * 0.5:
        drop = round((1 - ev["total"] / ev["previous"]) * 100)
        out.append({"level": "warn",
                    "text": f"로그 수가 {ev.get('previous_label', '직전 기간')}보다 {drop}% 줄었습니다 — 수집 PC 상태를 확인하세요"})
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
    for problem in (p.get("alerting") or {}).get("problems", []):   # ADR-045 이전 보고서에는 없다
        out.append({"level": problem["level"], "text": f"알림 기능: {problem['text']}"})
    al = p["alerts"]
    if al.get("config_error"):
        out.append({"level": "bad", "text": f"알림 설정 파일 오류: {al['config_error'][:200]}"})
    if al.get("config_changes_weakened"):
        out.append({"level": "warn", "text": f"탐지를 약하게 하는 알림 설정 변경 {al['config_changes_weakened']:,}건"
                                             " — 누가 왜 바꿨는지 확인하세요"})
    if al.get("config_changes_direct"):
        out.append({"level": "warn", "text": f"화면을 거치지 않고 서버에서 고친 알림 설정 {al['config_changes_direct']:,}건"})
    if al.get("wide_silences_total"):
        out.append({"level": "warn", "text": f"넓은 무음 {al['wide_silences_total']:,}건 (모든 규칙·모든 대상이거나 24시간 넘음)"})
    ingest = p.get("ingest") or {}
    if ingest.get("quarantined"):
        out.append({"level": "warn", "text": f"저장하지 못해 격리한 수집 레코드 {ingest['quarantined']:,}건 — 수집 PC 화면에서 확인하세요"})
    for r in ingest.get("rejected") or []:
        if r["status"] == 499:   # 보내는 쪽이 끊음(PC 끄기 등) — 서버가 거절한 것이 아니다
            continue
        reason = "API 키가 틀리거나 없어" if r["status"] == 401 else f"{r['status']}"
        out.append({"level": "warn", "text": f"{reason} 거절된 수집 요청 {r['n']:,}건 (보낸 곳 {r['ips']:,}곳)"
                                             + (" — 키를 바꾼 뒤 옛 설치 묶음으로 보내는 PC" if r["status"] == 401 else "")})
    if p["agents"].get("silent_streams_total"):
        first = p["agents"]["silent_streams"][:3]
        names = ", ".join(f"{s['host']} {s['channel'] or s['source']}" for s in first)
        more = p["agents"]["silent_streams_total"] - len(first)
        out.append({"level": "warn", "text": f"늘 오던 로그가 끊긴 채널 {p['agents']['silent_streams_total']:,}개: {names}"
                                             + (f" 외 {more:,}개" if more > 0 else "") + " — 감사 정책·에이전트 설정을 확인하세요"})
    if p["agents"]["offline"]:
        out.append({"level": "warn", "text": f"연락이 끊긴 PC {p['agents']['offline']:,}대"})
    if p["retention"]["archives_missing"]:
        out.append({"level": "bad", "text": f"보관 파일 {p['retention']['archives_missing']}개가 없습니다 (목록에는 있음)"})
    for warning in p["retention"].get("warnings") or []:
        out.append({"level": "warn", "text": f"보관기간: {warning}"})
    bad = integrity_bad_count(p["retention"]["last_integrity_check"])
    if bad:
        out.append({"level": "bad", "text": f"마지막 보관 파일 무결성 확인에서 문제 {bad}건"})
    return sorted(out, key=lambda a: a["level"] != "bad")


async def build(kind: str, start: datetime, end: datetime, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    backup = await backups.backup_status(now)
    payload: dict[str, Any] = {
        "version": PAYLOAD_VERSION, "kind": kind, "title": report_title(kind, start, end),
        "period": {"start": _iso(start), "end": _iso(end), "label": period_label(kind, start, end),
                   "tz": display_zone().key},
        "generated_at": _iso(now),
        "events": await _events(kind, start, end),
        "security": await _security(start, end),
        "alerts": await _alerts(start, end),
        "agents": await _agents(now),
        # 수집 거절·격리 (B-40) — 에이전트 쪽 로그는 같은 출력이라 서버로 오지 못하니 여기서만 보인다
        "ingest": await repository.ingest_problem_counts(start, end),
        # 알림 기능 자체 (ADR-045) — 보고서를 만든 시각 기준. 평가·전송이 멈췄으면 그 사이 알림은 오지 않았다
        "alerting": await _alerting(),
        # 관리 작업 요약 (B-36) — 관리자 행위 점검(ISMS 2.9.5)
        "admin": await _admin(start, end),
        "retention": await _retention(),
        "backup": {"problems": backup["problems"],
                   "last_backup": _jsonable(backup["last_backup"]), "last_verify": _jsonable(backup["last_verify"]),
                   "last_verify_ok_at": _iso(backup["last_verify_ok_at"])},
    }
    payload["attention"] = _attention(payload)
    return payload


def _jsonable(row: dict | None) -> dict | None:
    return None if row is None else {k: _iso(v) if isinstance(v, datetime) else v for k, v in row.items()}
