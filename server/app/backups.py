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
REPLICA_STALE = timedelta(hours=36)  # 매일 백업 뒤 복제 + 여유
WEEKDAYS = {1: "월", 2: "화", 3: "수", 4: "목", 5: "금", 6: "토", 7: "일"}


async def backup_status(now: datetime | None = None) -> dict[str, Any]:
    """DB 백업·복구 시험 상태와 문제 목록 (ISMS 2.9.3)."""
    now = now or datetime.now(UTC)
    data = await repository.backup_audit()
    latest = data["latest"]
    created, failed, restored = latest.get("backup.create"), latest.get("backup.failed"), latest.get("backup.restore")
    verify = latest.get("backup.verify")
    problems = []
    # 백업으로 복원하면 감사로그도 그 백업 시점으로 돌아가 '마지막 백업'이 예전 것이 된다 → 복원 뒤로는 복원 시각부터 잰다
    after_restore = restored is not None and (created is None or restored["at"] > created["at"])
    since = restored["at"] if after_restore else created["at"] if created else None
    if since is None:
        problems.append("백업 기록이 없습니다. backup 서비스가 떠 있는지 확인하세요 (docker compose ps backup)")
    elif now - since > BACKUP_STALE:
        hours = int((now - since).total_seconds() // 3600)
        what = f"백업으로 복원한 뒤 {hours}시간 동안 새 백업이 없습니다" if after_restore else f"마지막 백업이 {hours}시간 전입니다"
        problems.append(f"{what}. 매일 {settings.backup_time} 에 돌아야 합니다 — backup 서비스 로그를 확인하세요")
    if failed and (created is None or failed["at"] > created["at"]):
        problems.append(f"마지막 백업이 실패했습니다: {str(failed['detail'].get('error', ''))[:300]}")
    # 실패한 복구 시험: 더 새 백업의 성공으로 풀리기 전까지 경고. 자동 복구 시험을 끈 뒤에는 8일이 지나면 경고에서 뺀다
    # (끄고 나면 새 시험이 없어 옛 실패가 영영 남는다)
    vf = data["verify_failed"]
    if vf and not data["verify_failed_superseded"] and (settings.backup_verify_weekday or now - vf["at"] <= VERIFY_STALE):
        file = f" ({vf['target']})" if str(vf["target"]).endswith(".dump") else ""
        problems.append(f"복구 시험이 실패했습니다{file}: {str(vf['detail'].get('reason', ''))[:300]}")
    # 백업을 시작한 지 8일이 넘었는데 성공한 복구 시험이 없으면 (처음 설치 직후에는 경고하지 않는다)
    if (settings.backup_verify_weekday and data["first_backup_at"] and now - data["first_backup_at"] > VERIFY_STALE
            and (data["verify_ok"] is None or now - data["verify_ok"]["at"] > VERIFY_STALE)):
        problems.append("최근 8일 안에 성공한 복구 시험이 없습니다")

    # 외부 저장소 복제 (B-17): 켜 두었으면 밀리거나 실패한 것, 원본이 만료 전에 사라진 것(사고일 수 있다)을 알린다
    replicate = latest.get("backup.replicate")
    if settings.replica:
        if replicate is None:
            problems.append("외부 저장소 복제 기록이 없습니다 — WLM_REPLICA_DIR 마운트와 backup 서비스 로그를 확인하세요")
        elif now - replicate["at"] > REPLICA_STALE:
            problems.append(f"마지막 외부 저장소 복제가 {int((now - replicate['at']).total_seconds() // 3600)}시간 전입니다")
        elif not replicate["detail"].get("ok"):
            problems.append(f"외부 저장소 복제가 실패했습니다: {replicate['detail'].get('error') or str(replicate['detail'].get('failed')) + '개 파일'}")
        if replicate is not None and replicate["detail"].get("missing_locally"):
            problems.append(f"복제본에는 있는데 이 서버에서 만료 전에 사라진 보관 파일 {replicate['detail']['missing_locally']}개 — "
                            "삭제·사고 여부를 확인하세요 (복제본은 지우지 않았습니다)")

    def row(r: dict | None, keys: tuple[str, ...]) -> dict | None:
        return None if r is None else {"at": r["at"], "file": r["target"], **{k: r["detail"].get(k) for k in keys}}

    return {
        "schedule": {"time": settings.backup_time, "keep": settings.backup_keep, "tz": settings.display_tz,
                     "verify_weekday": settings.backup_verify_weekday,
                     "verify_day": WEEKDAYS.get(settings.backup_verify_weekday)},
        "last_backup": row(created, ("bytes", "seconds", "sha256", "counts", "migration")),
        "last_verify": row(verify, ("ok", "reason", "seconds", "counts")),
        "last_verify_ok_at": data["verify_ok"]["at"] if data["verify_ok"] else None,
        "last_restore": row(restored, ("safety_dump",)) if after_restore else None,
        "replica": {"enabled": settings.replica,
                    "last": row(replicate, ("ok", "copied", "failed", "deleted", "missing_locally", "files", "error"))},
        "problems": problems,
    }
