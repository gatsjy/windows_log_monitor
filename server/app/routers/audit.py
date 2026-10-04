"""감사로그 조회 API (관리자 전용). CSV 내려받기는 ISMS 심사 증적 제출용."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from .. import db, repository
from ..auth.deps import client_ip, require_permission
from ..auth.service import User
from ..filters import FilterError, parse_time

router = APIRouter(tags=["audit"], dependencies=[Depends(require_permission("audit.view"))])

ACTION_LABELS = {
    "auth.login": "로그인",
    "auth.login_failed": "로그인 실패",
    "auth.account_locked": "계정 잠금",
    "auth.logout": "로그아웃",
    "auth.session_expired": "세션 만료",
    "auth.password_change": "비밀번호 변경",
    "auth.password_change_failed": "비밀번호 변경 실패",
    "user.create": "사용자 생성",
    "user.update": "사용자 변경",
    "user.reset_password": "비밀번호 초기화",
    "user.delete": "사용자 삭제",
    "user.unlock": "잠금 해제",
    "events.search": "이벤트 검색",
    "events.view": "이벤트 상세 조회",
    "dashboard.save": "대시보드 저장",
    "alerts.config.save": "알림 규칙 파일 저장",
    "alerts.rule.save": "알림 규칙 저장",
    "alerts.rule.delete": "알림 규칙 삭제",
    "alerts.rule.toggle": "알림 규칙 켜기/끄기",
    "agents.package.download": "에이전트 설치 묶음 내려받기",
    "user_group.save": "사용자 그룹 저장",
    "user_group.delete": "사용자 그룹 삭제",
    "alerts.test": "알림 테스트 발송",
    "settings.smtp.save": "메일 서버 설정",
    "settings.smtp.test": "메일 서버 테스트",
    "settings.contact.save": "수신자 저장",
    "settings.contact.delete": "수신자 삭제",
    "settings.group.save": "수신 그룹 저장",
    "settings.group.delete": "수신 그룹 삭제",
    "settings.channel.save": "외부 연동 저장",
    "settings.channel.delete": "외부 연동 삭제",
    "settings.channel.test": "외부 연동 테스트",
    "settings.oracle.test": "Oracle 연결 시험",
    "settings.oracle.dry_run": "Oracle 알림 SQL 시험",
    "settings.oracle.query": "Oracle 쿼리 실행",
    "settings.oracle.tnsnames.save": "tnsnames.ora 저장",
    "audit.export": "감사로그 내려받기",
    "retention.drop_partition": "보관기간 만료 로그 삭제",
    "retention.purge_alerts": "보관기간 만료 알림 삭제",
    "retention.purge_audit": "보관기간 만료 감사로그 삭제",
    "retention.archive_partition": "로그 보관 파일로 이동",
    "retention.archive_failed": "로그 보관 파일 만들기 실패",
    "retention.delete_archive": "보관기간 만료 보관 파일 삭제",
    "retention.restore_archive": "보관 파일 복원",
    "retention.verify_archives": "보관 파일 무결성 확인",
    "retention.rotate_now": "로그 로테이션 즉시 실행",
}


@router.get("/api/audit")
async def list_audit(
    request: Request,
    since: str = "7d",
    actor: str | None = None,
    action: str | None = None,
    q: str | None = None,
    limit: int = Query(500, ge=1, le=10000),
    format: str = Query("json", pattern="^(json|csv)$"),
    admin: User = Depends(require_permission("audit.view")),
):
    try:
        start = parse_time(since, datetime.now(UTC))
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    rows = await repository.list_audit(start, limit, actor=actor, action=action, q=q)
    if format == "json":
        return {"items": rows, "labels": ACTION_LABELS, "actions": await repository.audit_actions()}

    await db.audit(admin.username, "audit.export", "audit_log",
                   {"since": since, "actor": actor, "action": action, "q": q, "rows": len(rows)},
                   actor_ip=client_ip(request))
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["번호", "일시(UTC)", "사용자", "접속 IP", "행위 코드", "행위", "대상", "상세"])
    for r in rows:
        writer.writerow([r["id"], r["at"].isoformat(), r["actor"], r["actor_ip"] or "", r["action"],
                         ACTION_LABELS.get(r["action"], ""), r["target"] or "",
                         json.dumps(r["detail"], ensure_ascii=False, default=str)])
    filename = f"audit_log_{datetime.now(UTC):%Y%m%d_%H%M%S}.csv"
    # UTF-8 BOM: 엑셀에서 한글이 깨지지 않게
    return Response("﻿" + buffer.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
