"""알림 API: 이력 조회, 규칙/알림 대상 현황, 규칙 관리(규칙 한 개 추가·수정·삭제·켜기/끄기·미리보기),
설정 파일 직접 편집, 테스트 발송."""

from __future__ import annotations

import hashlib
import math
import os
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import db, repository
from ..alerts import ruleedit, targets
from ..alerts.engine import engine
from ..alerts.notifiers import NotifierError
from ..alerts.rules import AlertConfig, ConfigError, Rule, parse, parse_text
from ..auth.deps import client_ip, require_permission, require_user
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


def _rule_categories(rule_name: str) -> set[str]:
    rule = next((r for r in engine.config.rules if r.name == rule_name), None)
    return set(rule.match.get("category", "").split(",")) - {""} if rule else set()


def _alert_visible(user: User, alert: dict) -> bool:
    """조회 범위가 있는 사용자: 그 범위의 분류를 감시하는 규칙이거나, 대상(PC)이 범위의 PC 패턴에 맞는 알림만."""
    if user.scopes is None:
        return True
    cats = _rule_categories(alert["rule"])
    for scope in user.scopes:
        cat_ok = not scope.categories or bool(cats & set(scope.categories))
        host_ok = scope.allows_host(alert["group_key"])
        if cat_ok and host_ok:
            return True
    return False


@router.get("/api/alerts")
async def list_alerts(
    request: Request,
    since: str = "7d",
    rule: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
):
    items = await repository.list_alerts(_since(since), limit, rule=rule, severity=severity, group_key=host)
    user = request.state.user
    return {"items": [a for a in items if _alert_visible(user, a)]}


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
            "tags": list(r.tags), "sid": r.sid, "group": r.group,
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
        "yaml": path.read_text(encoding="utf-8") if user.can("alerts.manage") and path.exists() else None,
    }


# ------------------------------------------------------------ 저장 공통
async def _validate(text: str) -> AlertConfig:
    try:
        config = parse_text(text)
    except ConfigError as exc:
        raise HTTPException(422, str(exc)) from exc
    known = await targets.target_names()
    unknown = sorted({n for r in config.rules for n in r.notify if n not in known})
    if unknown:
        raise HTTPException(422, f"없는 알림 대상: {', '.join(unknown)} — 환경설정에서 수신 그룹·외부 연동을 먼저 만드세요")
    return config


async def _store(text: str, admin: User, request: Request, action: str, detail: dict[str, Any]) -> None:
    """검증된 YAML 을 원자적으로 저장하고 엔진에 바로 반영, 감사로그(내용 해시 포함)."""
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
    await db.audit(admin.username, action, path.name,
                   {**detail, "sha256": hashlib.sha256(text.encode()).hexdigest()}, actor_ip=client_ip(request))


def _current_text() -> str:
    path = engine.path
    return path.read_text(encoding="utf-8") if path.exists() else "settings:\n  interval_sec: 30\n\nrules:\n"


@router.put("/api/alerts/config")
async def save_alert_config(request: Request, admin: User = Depends(require_permission("alerts.manage"))):
    """본문 = YAML 텍스트(고급 편집). 검증에 실패하면 422 와 오류 내용을 돌려주고 파일은 바꾸지 않는다."""
    text = (await request.body()).decode("utf-8", errors="replace")
    config = await _validate(text)
    await _store(text, admin, request, "alerts.config.save", {"rules": len(config.rules)})
    return {"ok": True, "rules": len(config.rules)}


# ------------------------------------------------------------ 규칙 관리 (화면 편집기)
def _duration_text(seconds: Any, field: str) -> str:
    try:
        sec = int(seconds)
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, f"{field}: 숫자(초)여야 합니다") from exc
    if sec <= 0:
        raise HTTPException(422, f"{field}: 0보다 커야 합니다")
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if sec % size == 0:
            return f"{sec // size}{unit}"
    return f"{sec}s"


def _clean_rule(raw: dict[str, Any]) -> dict[str, Any]:
    """화면에서 온 규칙(JSON) → 파일에 쓸 dict. 기본값과 같은 항목은 빼서 파일을 짧게 유지한다."""
    def text(key: str) -> str:
        return str(raw.get(key) or "").strip()

    def str_list(key: str) -> list[str]:
        value = raw.get(key) or []
        if isinstance(value, str):
            value = value.split(",")
        return [str(v).strip() for v in value if str(v).strip()]

    rule: dict[str, Any] = {"name": text("name")}
    if not rule["name"]:
        raise HTTPException(422, "규칙 이름을 입력하세요")
    if raw.get("sid") not in (None, ""):
        try:
            rule["sid"] = int(raw["sid"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, "규칙 번호(sid)는 숫자여야 합니다") from exc
    if text("group"):
        rule["group"] = text("group")
    if text("description"):
        rule["description"] = text("description")
    kind = text("kind") or "count"
    if kind != "count":
        rule["kind"] = kind
    if raw.get("enabled") is False:
        rule["enabled"] = False
    if kind == "agent_silent":
        rule["silent_for"] = _duration_text(raw.get("silent_for_sec", 600), "끊김 판정 시간")
        if str_list("hosts"):
            rule["hosts"] = str_list("hosts")
    else:
        match = {str(k).strip(): str(v).strip() for k, v in (raw.get("match") or {}).items()
                 if str(k).strip() and str(v).strip()}
        rule["match"] = match
        group_by = text("group_by") or "host"
        if group_by != "host":
            rule["group_by"] = group_by
        rule["window"] = _duration_text(raw.get("window_sec", 300), "집계 기간")
        try:
            rule["threshold"] = int(raw.get("threshold", 1))
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, "건수는 숫자여야 합니다") from exc
        rule["cooldown"] = _duration_text(raw.get("cooldown_sec", 1800), "재알림 간격")
    rule["severity"] = text("severity") or "warning"
    if str_list("tags"):
        rule["tags"] = str_list("tags")
    rule["notify"] = str_list("notify")
    return rule


def _check_one(rule: dict[str, Any], *, need_notify: bool = True) -> Rule:
    probe = rule if need_notify or rule.get("notify") else {**rule, "notify": ["(미리보기)"]}
    try:
        return parse({"rules": [probe]}).rules[0]
    except ConfigError as exc:
        raise HTTPException(422, str(exc).replace("rules[0] ", "")) from exc


class RuleBody(BaseModel):
    original: str | None = Field(default=None, max_length=200)  # 수정할 규칙의 원래 이름 (새 규칙이면 없음)
    rule: dict[str, Any]


class ToggleBody(BaseModel):
    names: list[str] = Field(min_length=1, max_length=500)
    enabled: bool


class PreviewBody(BaseModel):
    rule: dict[str, Any]
    hours: int = Field(default=24, ge=1, le=168)


@router.put("/api/alerts/rules")
async def save_rule(body: RuleBody, request: Request, admin: User = Depends(require_permission("alerts.manage"))):
    """규칙 한 개 추가·수정. 파일에서 그 규칙 블록만 바꾸고(다른 규칙·주석 유지), 전체를 검증한 뒤 저장."""
    text = _current_text()
    rule = _clean_rule(body.rule)
    _check_one(rule)
    try:
        existing = ruleedit.names(text)
        if rule["name"] != body.original and rule["name"] in existing:
            raise HTTPException(409, f"같은 이름의 규칙이 이미 있습니다: {rule['name']}")
        if "sid" not in rule:
            rule["sid"] = ruleedit.next_sid(text)
        new_text = ruleedit.replace(text, body.original, rule) if body.original else ruleedit.append(text, rule)
    except ruleedit.EditError as exc:
        raise HTTPException(422, str(exc)) from exc
    await _validate(new_text)
    await _store(new_text, admin, request, "alerts.rule.save",
                 {"rule": rule["name"], "sid": rule["sid"], "original": body.original})
    return {"ok": True, "name": rule["name"], "sid": rule["sid"]}


@router.delete("/api/alerts/rules/{name:path}")
async def delete_rule(name: str, request: Request, admin: User = Depends(require_permission("alerts.manage"))):
    try:
        new_text = ruleedit.delete(_current_text(), name)
    except ruleedit.EditError as exc:
        raise HTTPException(404, str(exc)) from exc
    await _validate(new_text)
    await _store(new_text, admin, request, "alerts.rule.delete", {"rule": name})
    return {"ok": True}


@router.post("/api/alerts/rules/enabled")
async def toggle_rules(body: ToggleBody, request: Request, admin: User = Depends(require_permission("alerts.manage"))):
    """규칙(여러 개 가능 — 묶음 단위 켜기/끄기) 사용 여부만 바꾼다. 블록 안 주석도 그대로."""
    text = _current_text()
    try:
        for name in body.names:
            text = ruleedit.set_enabled(text, name, body.enabled)
    except ruleedit.EditError as exc:
        raise HTTPException(404, str(exc)) from exc
    await _validate(text)
    await _store(text, admin, request, "alerts.rule.toggle", {"rules": body.names, "enabled": body.enabled})
    return {"ok": True, "count": len(body.names)}


@router.post("/api/alerts/rules/preview")
async def preview_rule(body: PreviewBody, admin: User = Depends(require_permission("alerts.manage"))):
    """최근 N시간 데이터에 이 규칙을 적용했다면: 맞는 이벤트 수, 알림 횟수(재알림 간격 반영, 근사), 대상별."""
    rule = _check_one(_clean_rule({**body.rule, "name": body.rule.get("name") or "(미리보기)"}), need_notify=False)
    now = datetime.now(UTC)
    if rule.kind == "agent_silent":
        rows = await repository.silent_agents(now - rule.silent_for, rule.hosts)
        return {"kind": rule.kind, "silent": [{"host": r["host"], "last_seen": r["last_seen"]} for r in rows]}
    base = replace(rule.event_filter(), received_since=now - timedelta(hours=body.hours))
    window_sec = max(1, _seconds(rule.window))
    matched = (await repository.count(base))["current"]
    rows = await repository.rule_preview(base, rule.group_by, window_sec, rule.threshold)
    step = max(1, math.ceil(_seconds(rule.cooldown) / window_sec))
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:  # 구간 순서대로 — 재알림 간격 안의 구간은 알림 1번으로 친다
        key = "" if row["key"] is None else str(row["key"])
        g = groups.setdefault(key, {"key": key, "fires": 0, "max": 0, "last": None})
        if g["last"] is None or row["bucket"] - g["last"] >= step:
            g["fires"] += 1
            g["last"] = row["bucket"]
        g["max"] = max(g["max"], row["n"])
    ranked = sorted(groups.values(), key=lambda g: (-g["fires"], -g["max"]))
    return {
        "kind": rule.kind, "hours": body.hours, "matched": matched,
        "fires": sum(g["fires"] for g in ranked), "targets": len(ranked),
        "groups": [{"key": g["key"], "fires": g["fires"], "max": g["max"]} for g in ranked[:10]],
    }


@router.post("/api/alerts/test/{name}")
async def test_notifier(name: str, request: Request, admin: User = Depends(require_permission("alerts.manage"))):
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
async def get_alert(alert_id: int, request: Request):
    row = await repository.get_alert(alert_id)
    if row is None or not _alert_visible(request.state.user, row):
        raise HTTPException(404, "알림을 찾을 수 없습니다")
    return row
