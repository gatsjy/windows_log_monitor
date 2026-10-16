"""점검 보고서 일정·받는 곳 (환경설정 화면 '점검 보고서'). app_settings 의 'report' 키에 저장한다."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from .. import db

DEFAULTS: dict[str, Any] = {
    # 받는 곳이 없어도 만들어서 저장한다 — 보고서 자체가 점검 증적이다
    "daily": {"enabled": True, "time": "09:00"},
    "weekly": {"enabled": True, "weekday": 1, "time": "09:00"},   # 1=월 … 7=일
    "targets": [],                                                 # 수신 그룹·웹훅 연동 이름
}
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class ReportConfigError(ValueError):
    pass


def _merged(value: dict[str, Any] | None) -> dict[str, Any]:
    cfg = deepcopy(DEFAULTS)
    for key in ("daily", "weekly"):
        cfg[key].update((value or {}).get(key) or {})
    cfg["targets"] = list((value or {}).get("targets") or [])
    return cfg


async def load() -> dict[str, Any]:
    row = await db.fetch_one("SELECT value FROM app_settings WHERE key = 'report'")
    return _merged(row["value"] if row else None)


def clean(body: dict[str, Any], known_targets: set[str]) -> dict[str, Any]:
    cfg = _merged(body)
    for key in ("daily", "weekly"):
        part = cfg[key]
        part["enabled"] = bool(part.get("enabled"))
        if not _TIME.match(str(part.get("time", ""))):
            raise ReportConfigError(f"{'일간' if key == 'daily' else '주간'} 보고서 시각은 HH:MM 입니다 (예: 09:00)")
    try:
        weekday = int(cfg["weekly"].get("weekday", 1))
    except (TypeError, ValueError) as exc:
        raise ReportConfigError("주간 보고서 요일은 1(월)~7(일)입니다") from exc
    if not 1 <= weekday <= 7:
        raise ReportConfigError("주간 보고서 요일은 1(월)~7(일)입니다")
    cfg["weekly"]["weekday"] = weekday
    names = sorted({str(t).strip() for t in cfg["targets"] if str(t).strip()})
    unknown = [n for n in names if n not in known_targets]
    if unknown:
        raise ReportConfigError(f"없는 받는 곳: {', '.join(unknown)} — 환경설정의 수신 그룹·웹훅 이름을 고르세요")
    cfg["targets"] = names
    return {"daily": {k: cfg["daily"][k] for k in ("enabled", "time")},
            "weekly": {k: cfg["weekly"][k] for k in ("enabled", "weekday", "time")}, "targets": names}


async def save(cfg: dict[str, Any], actor: str) -> None:
    await db.fetch_one(
        "INSERT INTO app_settings (key, value, updated_at, updated_by) VALUES ('report', %s::jsonb, now(), %s)"
        " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"
        " RETURNING key",
        (json.dumps(cfg, ensure_ascii=False), actor),
    )


async def report_targets() -> list[str]:
    """보고서를 받을 수 있는 이름: 수신 그룹(메일) + 웹훅 연동 (Oracle 은 알림 표용이라 뺀다)."""
    rows = await db.fetch_all(
        "SELECT name FROM contact_groups UNION SELECT name FROM channels WHERE type = 'webhook' ORDER BY name"
    )
    return [r["name"] for r in rows]
