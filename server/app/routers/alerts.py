"""알림 API: 이력 조회, 규칙/알림 대상 현황, 설정 파일 편집, 테스트 발송."""

from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .. import db, repository
from ..alerts import targets
from ..alerts.engine import engine
from ..alerts.notifiers import NotifierError
from ..alerts.rules import ConfigError, parse_text
from ..auth.deps import client_ip, require_admin, require_user
from ..auth.service import User
from ..filters import FilterError, parse_time

router = APIRouter(tags=["alerts"])


def _since(text: str) -> datetime:
    try:
        return parse_time(text, datetime.now(UTC))
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc


def _seconds(delta: timedelta) -> int:
    return int(delta.total_seconds())


@router.get("/api/alerts")
async def list_alerts(
    since: str = "7d",
    rule: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
):
    items = await repository.list_alerts(_since(since), limit, rule=rule, severity=severity, group_key=host)
    return {"items": items}


@router.get("/api/alerts/config")
async def alert_config(since: str = "24h", user: User = Depends(require_user)):
    """화면용: 엔진 상태 + 규칙 목록(최근 발생 포함) + 알림 대상(비밀값 제외) + 원본 YAML(관리자만)."""
    engine.reload()
    stats = await repository.alert_stats(_since(since))
    known = await targets.target_names()
    rules = []
    for r in engine.config.rules:
        recent = stats["by_rule"].get(r.name, {})
        rules.append({
            "name": r.name, "kind": r.kind, "enabled": r.enabled, "severity": r.severity,
            "description": r.description, "notify": list(r.notify), "match": r.match,
            "window_sec": _seconds(r.window), "threshold": r.threshold, "group_by": r.group_by,
            "cooldown_sec": _seconds(r.cooldown), "silent_for_sec": _seconds(r.silent_for), "hosts": list(r.hosts),
            "fired": recent.get("n", 0), "last_fired_at": stats["last_fired"].get(r.name),
            "unknown_notify": [n for n in r.notify if n not in known],
            "tags": list(r.tags),
        })
    # 알림 대상 = 환경설정의 수신 그룹 + 외부 연동
    await engine.load_targets()
    used = engine.config.used_targets()
    notifiers = [
        {"name": name, "type": n.type, "target": n.target(), "error": None, "used_by": used.get(name, [])}
        for name, n in sorted(engine.notifiers.items())
    ] + [
        {"name": name, "type": "-", "target": "", "error": err, "used_by": used.get(name, [])}
        for name, err in sorted(engine.notifier_errors.items())
    ]
    path = engine.path
    return {
        **engine.status(),
        "rules": rules,
        "notifiers": notifiers,
        "by_severity": stats["by_severity"],
        "yaml": path.read_text(encoding="utf-8") if user.is_admin and path.exists() else None,
    }


@router.put("/api/alerts/config")
async def save_alert_config(request: Request, admin: User = Depends(require_admin)):
    """본문 = YAML 텍스트. 검증에 실패하면 422 와 오류 내용을 돌려주고 파일은 바꾸지 않는다."""
    text = (await request.body()).decode("utf-8", errors="replace")
    try:
        config = parse_text(text)
    except ConfigError as exc:
        raise HTTPException(422, str(exc)) from exc
    known = await targets.target_names()
    unknown = sorted({n for r in config.rules for n in r.notify if n not in known})
    if unknown:
        raise HTTPException(422, f"없는 알림 대상: {', '.join(unknown)} — 환경설정에서 수신 그룹·외부 연동을 먼저 만드세요")
    path = engine.path
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        os.replace(tmp, path)
    except OSError as exc:
        Path(tmp).unlink(missing_ok=True)
        raise HTTPException(500, f"저장 실패: {exc}") from exc
    engine.reload(force=True)
    await db.audit(
        admin.username,
        "alerts.config.save", path.name,
        {"rules": len(config.rules), "sha256": hashlib.sha256(text.encode()).hexdigest()},
        actor_ip=client_ip(request),
    )
    return {"ok": True, "rules": len(config.rules)}


@router.post("/api/alerts/test/{name}")
async def test_notifier(name: str, request: Request, admin: User = Depends(require_admin)):
    try:
        await engine.send_test(name)
        ok, error = True, None
    except (NotifierError, TimeoutError) as exc:
        ok, error = False, str(exc) or "전송 시간 초과"
    await db.audit(admin.username, "alerts.test", name, {"ok": ok, "error": error}, actor_ip=client_ip(request))
    if not ok:
        raise HTTPException(502, error)
    return {"ok": True}


@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: int):
    row = await repository.get_alert(alert_id)
    if row is None:
        raise HTTPException(404, "알림을 찾을 수 없습니다")
    return row
