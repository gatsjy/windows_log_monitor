"""DB 백업·복구 시험 상태 (ADR-031). 백업은 compose 의 backup 서비스(deploy/backup/backup.sh)가 하고 결과를 audit_log 에 남긴다.
여기서는 그 기록으로 상태와 '점검 필요' 문제 목록을 만든다 — 환경설정 '로그 보관' 화면과 점검 보고서(ADR-032)가 함께 쓴다.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from . import repository
from .config import settings

BACKUP_STALE = timedelta(hours=36)   # 매일 백업 + 여유 (하루를 건너뛰면 경고)
VERIFY_STALE = timedelta(days=8)     # 주 1회 복구 시험 + 여유
WEEKDAYS = {1: "월", 2: "화", 3: "수", 4: "목", 5: "금", 6: "토", 7: "일"}


async def backup_status(now: datetime | None = None) -> dict[str, Any]:
    """DB 백업·복구 시험 상태와 문제 목록 (ISMS 2.9.3)."""
    now = now or datetime.now(UTC)
    data = await repository.backup_audit()
    latest = data["latest"]
    created, failed, verify = latest.get("backup.create"), latest.get("backup.failed"), latest.get("backup.verify")
    problems = []
    if created is None:
        problems.append("백업 기록이 없습니다. backup 서비스가 떠 있는지 확인하세요 (docker compose ps backup)")
    elif now - created["at"] > BACKUP_STALE:
        hours = int((now - created["at"]).total_seconds() // 3600)
        problems.append(f"마지막 백업이 {hours}시간 전입니다. 매일 {settings.backup_time} 에 돌아야 합니다 — backup 서비스 로그를 확인하세요")
    if failed and (created is None or failed["at"] > created["at"]):
        problems.append(f"마지막 백업이 실패했습니다: {str(failed['detail'].get('error', ''))[:300]}")
    if verify and not verify["detail"].get("ok"):
        problems.append(f"마지막 복구 시험이 실패했습니다: {str(verify['detail'].get('reason', ''))[:300]}")
    # 백업을 시작한 지 8일이 넘었는데 성공한 복구 시험이 없으면 (처음 설치 직후에는 경고하지 않는다)
    if (settings.backup_verify_weekday and data["first_backup_at"] and now - data["first_backup_at"] > VERIFY_STALE
            and (data["verify_ok"] is None or now - data["verify_ok"]["at"] > VERIFY_STALE)):
        problems.append("최근 8일 안에 성공한 복구 시험이 없습니다")

    def row(r: dict | None, keys: tuple[str, ...]) -> dict | None:
        return None if r is None else {"at": r["at"], "file": r["target"], **{k: r["detail"].get(k) for k in keys}}

    return {
        "schedule": {"time": settings.backup_time, "keep": settings.backup_keep, "tz": settings.display_tz,
                     "verify_weekday": settings.backup_verify_weekday,
                     "verify_day": WEEKDAYS.get(settings.backup_verify_weekday)},
        "last_backup": row(created, ("bytes", "seconds", "sha256", "counts", "migration")),
        "last_verify": row(verify, ("ok", "reason", "seconds", "counts")),
        "last_verify_ok_at": data["verify_ok"]["at"] if data["verify_ok"] else None,
        "problems": problems,
    }
