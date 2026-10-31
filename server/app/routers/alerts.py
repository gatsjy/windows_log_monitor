"""알림 API: 이력 조회(CSV), 처리(확인·해결·다시 열기·메모), 무음, 규칙/알림 대상 현황,
규칙 관리(규칙 한 개 추가·수정·삭제·켜기/끄기·미리보기), 설정 파일 직접 편집, 테스트 발송."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .. import db, repository
from ..alerts import configdiff, coverage, health, ruleedit, targets
from ..alerts.builtin import SYSTEM_RULES
from ..alerts.dispatcher import dispatcher
from ..alerts.engine import _with_group, engine, stream_label  # _with_group: 엔진과 같은 묶음 조건 (알림 뒤 이벤트 수)
from ..alerts.health import RULE_LABELS
from ..alerts.message import local
from ..alerts.notifiers import SEVERITY_LABELS, NotifierError
from ..alerts.rules import SILENT_KINDS, AlertConfig, ConfigError, Rule, parse, parse_text
from ..alerts.visibility import alert_visible, count_by_status, scrub_silence, silence_visible
from ..auth import groups
from ..auth.deps import client_ip, require_permission, require_user
from ..auth.service import User
from ..csvexport import csv_response, export_reason
from ..filters import FilterError, parse_time, scopes_allow
from .query import read_time_limit

log = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])


def _since(text: str) -> datetime:
    try:
        return parse_time(text, datetime.now(UTC))
    except FilterError as exc:
        raise HTTPException(400, str(exc)) from exc


def _seconds(delta: timedelta) -> int:
    return int(delta.total_seconds())


STATUS_LABELS = {"open": "처리 안 됨", "acked": "확인함", "resolved": "해결됨"}
NOTE_LABELS = {"note": "메모", "ack": "확인", "resolve": "해결", "reopen": "다시 열기", "auto_resolve": "자동 해결"}
STATUS_PATTERN = "^(open|acked|resolved|unresolved)$"


@router.get("/api/alerts")
async def list_alerts(
    request: Request,
    since: str = "7d",
    rule: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    status: str | None = Query(None, pattern=STATUS_PATTERN),
    limit: int = Query(200, ge=1, le=1000),
    format: str = Query("json", pattern="^(json|csv)$"),
    reason: str | None = Query(None, max_length=200),
):
    """알림 이력. counts = 기간 안의 처리 상태별 수(필터와 무관, 조회 범위 반영). format=csv 는 처리 기록 포함 증적."""
    start, user = _since(since), request.state.user
    groups = await repository.alert_group_counts(start)
    # 조회 범위가 있으면 보이는 (규칙, 대상)만 SQL 에서 거른다 — LIMIT 뒤에 거르면 오래된 내 알림이 목록에서 빠진다
    pairs = None if user.scopes is None else sorted({(g["rule"], g["group_key"]) for g in groups if alert_visible(user, g)})
    filters = {"rule": rule, "severity": severity, "group_key": host, "status": status}
    if format == "csv":
        return await _alerts_csv(request, user, start, since, pairs, filters, export_reason(reason))
    items = await repository.list_alerts(start, limit, pairs=pairs, **filters)
    return {"items": items, "counts": count_by_status(user, groups)}


CSV_LIMIT = 10000


async def _alerts_csv(request: Request, user: User, start: datetime, since: str,
                      pairs: list[tuple[str, str]] | None, filters: dict[str, str | None], reason: str) -> Response:
    rows = await repository.list_alerts(start, CSV_LIMIT + 1, pairs=pairs, **filters)
    truncated = len(rows) > CSV_LIMIT  # 잘렸다는 사실을 파일·응답 머리글·감사로그에 모두 남긴다 (증적이 몰래 빠지지 않게)
    rows = rows[:CSV_LIMIT]
    notes = await repository.alert_notes_for([a["id"] for a in rows])
    await db.audit(user.username, "alerts.export", "alerts",
                   {"since": since, **filters, "rows": len(rows), "truncated": truncated, "reason": reason},
                   actor_ip=client_ip(request), required=True)

    def lines():
        for a in rows:
            history = " / ".join(
                f"{local(n['at'])} {n['author']} [{NOTE_LABELS[n['action']]}]{' ' + n['text'] if n['text'] else ''}"
                for n in notes.get(a["id"], []))
            yield [
                a["id"], local(a["fired_at"]), SEVERITY_LABELS.get(a["severity"], a["severity"]), a["rule"], a["group_key"],
                a["event_count"], STATUS_LABELS[a["status"]] + (" (자동)" if a["auto_resolved"] else ""), a["acked_by"] or "",
                local(a["acked_at"]) if a["acked_at"] else "", a["resolved_by"] or "",
                local(a["resolved_at"]) if a["resolved_at"] else "", f"#{a['silence_id']}" if a["silence_id"] else "",
                "; ".join(f"{d['notifier']}{' 해소' if d.get('action') == 'resolve' else ''}:{d['status']}"
                          for d in a["deliveries"]), history,
            ]
        if truncated:
            yield [f"(최근 {CSV_LIMIT:,}건까지만 내보냈습니다. 기간을 나눠 다시 내려받으세요)"]

    return csv_response(
        ["번호", "발생 시각", "심각도", "규칙", "대상", "건수", "처리 상태", "확인한 사람", "확인 시각",
         "해결한 사람", "해결 시각", "무음", "전송", "처리 기록"],
        lines(), f"alerts_{datetime.now(UTC):%Y%m%d_%H%M%S}.csv",
        headers={"X-WLM-Truncated": "1"} if truncated else None)


@router.get("/api/alerts/config")
async def alert_config(since: str = "24h", user: User = Depends(require_user)):
    """화면용: 엔진 상태 + 규칙 목록(최근 발생 포함) + 알림 대상(비밀값 제외) + 원본 YAML(관리자만)."""
    # 파일을 다시 읽어 적용하면 판본도 바로 — 적용만 하고 기록이 늦으면 그 사이 되돌린 변경이 흔적 없이 지나간다(검토에서 재현)
    await _record_versions()
    stats = await repository.alert_stats(_since(since))
    known = await targets.target_names()
    # 규칙별 데이터 유무 (B-37 2단계) — 빠진 PC 이름이 들어 있어 조회 범위가 없는 사용자에게만
    data = await coverage.current(engine.config.rules) if user.scopes is None else {}
    state = await health.current()
    rules = []
    for r in engine.config.rules:
        recent = stats["by_rule"].get(r.name, {})
        run = engine.runs.get(r.name)
        rule_state = state["rules"].get(r.name) or ("off" if not r.enabled else "never")
        rules.append({
            "name": r.name, "kind": r.kind, "enabled": r.enabled, "severity": r.severity,
            "description": r.description, "notify": list(r.notify), "match": r.match,
            "window_sec": _seconds(r.window), "threshold": r.threshold, "group_by": r.group_by,
            "cooldown_sec": _seconds(r.cooldown), "silent_for_sec": _seconds(r.silent_for), "hosts": list(r.hosts),
            "fired": recent.get("n", 0), "last_fired_at": stats["last_fired"].get(r.name),
            "unknown_notify": [n for n in r.notify if n not in known],
            "tags": list(r.tags), "sid": r.sid, "group": r.group,
            "distinct": {"field": r.distinct_field, "min": r.distinct_min} if r.distinct_field else None,
            "resolve": r.resolve, "channels": list(r.channels), "coverage": coverage.public(data.get(r.name)),
            # 마지막 평가 (ADR-045): 상태 칩·오류 줄
            "run": {**(run.as_dict() if run else {}), "state": rule_state, "label": RULE_LABELS[rule_state]},
        })
    # 알림 대상 = 환경설정의 수신 그룹 + 외부 연동 (엔진 상태를 건드리지 않게 따로 읽는다)
    loaded, load_errors = await targets.load_notifiers()
    used = engine.config.used_targets()
    queue = {q["notifier"]: q for q in state.get("queue", [])}

    def target_health(name: str, error: str | None) -> dict[str, Any]:
        t = dispatcher.targets.get(name)
        q = queue.get(name, {})
        status = "error" if error else "failing" if t and t.failing_since else "ok" if t and t.last_ok_at else "idle"
        return {"state": status, **(t.as_dict() if t else {}), "due": q.get("due", 0), "sending": q.get("sending", 0),
                "queued": q.get("queued", 0), "next_at": q.get("next_at")}

    notifiers = [
        {"name": name, "type": n.type, "target": n.target(), "error": None, "used_by": used.get(name, []),
         "health": target_health(name, None)}
        for name, n in sorted(loaded.items())
    ] + [
        {"name": name, "type": "-", "target": "", "error": err, "used_by": used.get(name, []), "health": target_health(name, err)}
        for name, err in sorted(load_errors.items())
    ]
    path = engine.path
    return {
        **engine.status(),
        "health": {"status": state["status"], "problems": state["problems"], "checked_at": state["checked_at"]},
        "silences_active": sum(silence_visible(user, r) for r in await repository.active_silence_refs(datetime.now(UTC))),
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
    unknown = sorted({n for r in config.rules for n in r.notify if n not in known}
                     | {n for n in config.fallback_notify if n not in known})
    if unknown:
        raise HTTPException(422, f"없는 알림 대상: {', '.join(unknown)} — 환경설정에서 수신 그룹·외부 연동을 먼저 만드세요")
    return config


async def _store(text: str, admin: User, request: Request, action: str, detail: dict[str, Any]) -> None:
    """검증된 YAML 을 원자적으로 저장하고 엔진에 바로 반영, 감사로그(내용 해시 포함).
    판본(ADR-043)은 쓰기 전에 아직 기록하지 않은 파일 직접 수정부터 남기고, 쓴 뒤에 화면 저장으로 남긴다 —
    그래야 서버에서 고친 것이 이 사용자가 저장한 것으로 섞이지 않는다."""
    await _record_versions(strict=True)
    path = engine.path
    path.parent.mkdir(parents=True, exist_ok=True)
    written = text if text.endswith("\n") else text + "\n"   # 해시도 쓴 내용으로 — 판본(alert_config_versions)과 같게
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(written)
        os.replace(tmp, path)
    except OSError as exc:
        Path(tmp).unlink(missing_ok=True)
        raise HTTPException(500, f"저장 실패: {exc}") from exc
    engine.reload(force=True, source="ui", actor=admin.username)
    await db.audit(admin.username, action, path.name,
                   {**detail, "sha256": hashlib.sha256(written.encode()).hexdigest()}, actor_ip=client_ip(request))
    await _record_versions()


async def _record_versions(*, strict: bool = False) -> None:
    """strict = 쓰기 전: 서버에서 고친 것을 남기지 못했으면 저장을 거절한다(덮어쓰면 그 변경이 이 사용자 이름으로 기록된다)."""
    engine.reload()
    try:
        await engine.record()
    except Exception as exc:   # 저장 뒤라면 저장은 끝났다 — 판본 기록은 엔진의 다음 주기가 다시 한다
        log.exception("알림 설정 판본 기록 실패")
        if strict and engine.unrecorded_file_change():
            raise HTTPException(503, "서버에서 고친 알림 설정을 아직 기록하지 못했습니다 — 잠시 뒤 다시 저장하세요") from exc


def _require_readable_file() -> None:
    """파일이 깨졌거나 없으면 규칙 하나만 고치는 저장을 막는다 — 빈 틀에 규칙 하나를 더해 쓰면 나머지 규칙이 모두 사라진다
    (검토에서 재현). '고급 편집'의 전체 저장으로 파일부터 고친다."""
    if engine.config_error:
        raise HTTPException(409, f"알림 설정 파일을 쓸 수 없는 상태입니다: {engine.config_error[:300]} — "
                                 "'고급 편집'에서 설정 전체를 저장해 먼저 고치세요")


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
    # 해결 방식은 종류의 기본값과 다를 때만 적는다 (화면에서 저장해도 파일이 불필요하게 바뀌지 않게)
    resolve = text("resolve")
    if resolve and resolve != ("auto" if kind in SILENT_KINDS else "manual"):
        rule["resolve"] = resolve
    if kind == "agent_silent":
        rule["silent_for"] = _duration_text(raw.get("silent_for_sec", 600), "끊김 판정 시간")
        if str_list("hosts"):
            rule["hosts"] = str_list("hosts")
    elif kind == "stream_silent":
        for key in ("hosts", "channels"):
            if str_list(key):
                rule[key] = str_list(key)
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
        distinct = raw.get("distinct") or {}
        if isinstance(distinct, dict) and str(distinct.get("field") or "").strip():
            try:
                rule["distinct"] = {"field": str(distinct["field"]).strip(), "min": int(distinct.get("min") or 0)}
            except (TypeError, ValueError) as exc:
                raise HTTPException(422, "서로 다른 값 수는 숫자여야 합니다") from exc
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
    _require_readable_file()
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
    _require_readable_file()
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
    _require_readable_file()
    text = _current_text()
    try:
        for name in body.names:
            text = ruleedit.set_enabled(text, name, body.enabled)
    except ruleedit.EditError as exc:
        raise HTTPException(404, str(exc)) from exc
    await _validate(text)
    await _store(text, admin, request, "alerts.rule.toggle", {"rules": body.names, "enabled": body.enabled})
    return {"ok": True, "count": len(body.names)}


@router.post("/api/alerts/rules/preview", dependencies=[Depends(read_time_limit)])
async def preview_rule(body: PreviewBody, admin: User = Depends(require_permission("alerts.manage"))):
    """최근 N시간 데이터에 이 규칙을 적용했다면: 맞는 이벤트 수, 알림 횟수(재알림 간격 반영, 근사), 대상별."""
    rule = _check_one(_clean_rule({**body.rule, "name": body.rule.get("name") or "(미리보기)"}), need_notify=False)
    now = datetime.now(UTC)
    if rule.kind == "agent_silent":
        rows = await repository.silent_agents(now - rule.silent_for, rule.hosts)
        return {"kind": rule.kind, "silent": [{"host": r["host"], "last_seen": r["last_seen"]} for r in rows]}
    if rule.kind == "stream_silent":
        wanted = {c.casefold() for c in rule.channels}
        rows = [r for r in await repository.silent_streams(now, list(rule.hosts) or None)
                if (not wanted or (r["channel"] or r["source"]).casefold() in wanted)
                and scopes_allow(admin.scopes, None, r["host"])]
        return {"kind": rule.kind, "silent": [{"host": r["host"], "channel": stream_label(r["source"], r["channel"]),
                                               "last_seen": r["last_at"]} for r in rows]}
    # 미리보기도 이벤트 수·대상 이름을 돌려주므로 사용자 그룹의 조회 범위를 붙인다 (ADR-025)
    base = replace(rule.event_filter(), received_since=now - timedelta(hours=body.hours), scopes=admin.scopes)
    window_sec = max(1, _seconds(rule.window))
    matched = (await repository.count(base))["current"]
    rows = await repository.rule_preview(base, rule.group_by, window_sec, rule.threshold,
                                         rule.distinct_field, rule.distinct_min)
    step = max(1, math.ceil(_seconds(rule.cooldown) / window_sec))
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:  # 구간 순서대로 — 재알림 간격 안의 구간은 알림 1번으로 친다
        key = "" if row["key"] is None else str(row["key"])
        g = groups.setdefault(key, {"key": key, "fires": 0, "max": 0, "last": None})
        if g["last"] is None or row["bucket"] - g["last"] >= step:
            g["fires"] += 1
            g["last"] = row["bucket"]
        g["max"] = max(g["max"], row["dn"] if rule.distinct_field else row["n"])
    ranked = sorted(groups.values(), key=lambda g: (-g["fires"], -g["max"]))
    return {
        "kind": rule.kind, "hours": body.hours, "matched": matched, "distinct": rule.distinct_field,
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


# ------------------------------------------------------------ 처리 (확인·해결·다시 열기·메모) — ADR-029
# 동작별로 필요한 권한. None = 그 알림을 볼 수 있으면 누구나 (인지 기록은 넓게, 종료는 담당자만)
HANDLE_PERMISSION = {"ack": None, "resolve": "alerts.handle", "reopen": "alerts.handle"}


class HandleBody(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=1000)
    action: Literal["ack", "resolve", "reopen"]
    note: str = Field(default="", max_length=2000)
    with_related: bool = False  # 같은 규칙·대상의 다른 알림도 함께 (상세에서 '함께 해결')


class NoteBody(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


def _ids_text(ids: list[int]) -> str:
    return f"#{ids[0]}" if len(ids) == 1 else f"#{ids[0]} 외 {len(ids) - 1}건"


@router.post("/api/alerts/handle")
async def handle_alerts(body: HandleBody, request: Request, user: User = Depends(require_user)):
    """알림 여러 개를 한 번에 확인·해결·다시 열기. 이미 그 상태인 알림은 건너뛴다(unchanged)."""
    permission = HANDLE_PERMISSION[body.action]
    if permission and not user.can(permission):
        raise HTTPException(403, f"권한이 없습니다 ({groups.PERMISSIONS[permission]})")
    ids = sorted(set(body.ids))
    visible = [r["id"] for r in await repository.alert_refs(ids) if alert_visible(user, r)]
    if not visible:
        raise HTTPException(404, "알림을 찾을 수 없습니다")
    note = body.note.strip()
    # 같은 규칙·대상의 알림은 보이는지 여부도 같다 → 보이는 알림에서 넓혀도 범위를 벗어나지 않는다
    changed = await repository.handle_alerts(visible, body.action, user.username, note, with_related=body.with_related)
    unchanged = [i for i in visible if i not in changed]
    if changed:
        await db.audit(user.username, f"alerts.{body.action}", _ids_text(changed),
                       {"ids": changed, "unchanged": unchanged, "note": note, "with_related": body.with_related},
                       actor_ip=client_ip(request))
    return {"ok": True, "changed": changed, "unchanged": unchanged, "missing": [i for i in ids if i not in visible]}


@router.post("/api/alerts/{alert_id}/notes")
async def add_note(alert_id: int, body: NoteBody, request: Request, user: User = Depends(require_user)):
    """메모: 조사·조치 내용. 수정·삭제할 수 없다 (alert_notes 트리거)."""
    refs = await repository.alert_refs([alert_id])
    if not refs or not alert_visible(user, refs[0]):
        raise HTTPException(404, "알림을 찾을 수 없습니다")
    text = body.text.strip()
    if not text:
        raise HTTPException(422, "메모 내용을 입력하세요")
    note = await repository.add_alert_note(alert_id, user.username, text)
    await db.audit(user.username, "alerts.note", f"#{alert_id}", {"text": text}, actor_ip=client_ip(request))
    return note


# ------------------------------------------------------------ 무음 (silence) — ADR-029
MAX_SILENCE = timedelta(days=30)  # 더 길게 끌 일이면 규칙을 끄는 것이 맞다 (규칙 관리 권한, 이력도 남음)


class SilenceBody(BaseModel):
    rule: str | None = Field(default=None, max_length=200)          # 없으면 모든 규칙
    group_key: str | None = Field(default=None, max_length=500)     # 없으면 모든 대상
    starts_at: datetime | None = None                               # 없으면 지금
    ends_at: datetime | None = None
    duration_sec: int | None = Field(default=None, ge=60, le=int(MAX_SILENCE.total_seconds()))
    reason: str = Field(min_length=1, max_length=500)


def _silence_state(s: dict[str, Any], now: datetime) -> str:
    # 일찍 해제·취소한 무음(길이 0 포함)은 시작 전이라도 끝난 것
    if s["ended_by"] is not None or s["ends_at"] <= s["starts_at"] or s["ends_at"] <= now:
        return "ended"
    if s["starts_at"] > now:
        return "upcoming"
    return "active" if s["ends_at"] > now else "ended"


def _coverage(spans: list[dict[str, Any]], starts_at: datetime, ends_at: datetime, now: datetime) -> tuple[datetime, datetime]:
    """새 무음과 이어지는(겹치거나 맞닿은) 같거나 더 넓은 무음들을 합친 구간 (지금 이후만)."""
    lo, hi = starts_at, ends_at
    grown = True
    while grown:
        grown = False
        for s in spans:
            a, b = s["starts_at"], s["ends_at"]
            if a <= hi and b >= lo and (a < lo or b > hi):
                lo, hi, grown = min(lo, a), max(hi, b), True
    return max(lo, now), hi


def _check_silence_scope(user: User, rule: str | None, group_key: str | None) -> None:
    """조회 범위가 있는 사용자는 자기가 볼 수 있는 규칙·대상에만 무음을 걸고 풀 수 있다 (남의 알림까지 막지 않게)."""
    if user.scopes is None:
        return
    if rule is None or group_key is None or not alert_visible(user, {"rule": rule, "group_key": group_key}):
        raise HTTPException(403, "조회 범위가 정해진 사용자는 볼 수 있는 규칙·대상 한 개에만 무음을 걸 수 있습니다")


@router.get("/api/alerts/silences")
async def list_silences(request: Request, since: str = "7d"):
    """적용 중·예정 무음 + 기간(since) 안에 끝난 무음. suppressed = 그 무음 때문에 보내지 않은 알림 수."""
    now, user = datetime.now(UTC), request.state.user
    rows = await repository.list_silences(_since(since))
    return {
        "items": [{**scrub_silence(user, r), "state": _silence_state(r, now)} for r in rows if silence_visible(user, r)],
        "max_days": MAX_SILENCE.days,
    }


@router.post("/api/alerts/silences")
async def create_silence(body: SilenceBody, request: Request, user: User = Depends(require_permission("alerts.handle"))):
    rule = (body.rule or "").strip() or None
    group_key = body.group_key.strip() if body.group_key is not None else None
    # 알림 기능 자체의 알림(엔진 멈춤 등)도 무음으로 막을 수 있다 — 메일 서버 점검처럼 예정된 일. 설정 변경 알림은 안 됨 (ADR-043)
    if rule is not None and rule not in {r.name for r in engine.config.rules} | SYSTEM_RULES:
        raise HTTPException(422, f"없는 규칙입니다: {rule}")
    _check_silence_scope(user, rule, group_key)
    now = datetime.now(UTC)
    for value in (body.starts_at, body.ends_at):
        if value is not None and value.tzinfo is None:
            raise HTTPException(422, "시각에 시간대가 없습니다 (예: 2026-10-14T09:00:00+09:00)")
    starts_at = max(body.starts_at or now, now)  # 지난 시각부터 걸어도 이미 보낸 알림은 바뀌지 않는다
    # 끝 시각을 '지금부터 30일 안'으로 묶는다. 길이만 묶으면 미래에 시작하는 무음을 이어 붙여 60일도 막을 수 있다.
    # 시작 시각을 먼저 확인해야 아주 먼 시각 + 기간 계산이 넘치지(OverflowError → 500) 않는다
    too_long = HTTPException(422, f"무음은 지금부터 {MAX_SILENCE.days}일 안에 끝나야 합니다. 더 길면 규칙을 끄세요")
    if starts_at - now >= MAX_SILENCE:
        raise too_long
    if body.ends_at is not None:
        ends_at = body.ends_at
    elif body.duration_sec is not None:
        ends_at = starts_at + timedelta(seconds=body.duration_sec)
    else:
        raise HTTPException(422, "끝나는 시각이나 기간을 정하세요")
    if ends_at <= starts_at:
        raise HTTPException(422, "끝나는 시각이 시작 시각보다 뒤여야 합니다")
    if ends_at - now > MAX_SILENCE:
        raise too_long
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(422, "무음 사유를 입력하세요")
    # 넓은 무음은 규칙을 끄는 것과 같다 (ADR-043). 길이는 한 줄이 아니라 지금부터 이어서 덮는 구간으로 잰다 —
    # 24시간짜리를 이어 붙이면 한 줄씩은 짧아도 한 달을 막을 수 있었다(검토에서 재현)
    covered_from, covered_until = _coverage(await repository.covering_silences(rule, group_key, now), starts_at, ends_at, now)
    wide = (rule is None and group_key is None) or covered_until - covered_from > configdiff.WIDE_SILENCE
    silence_id = await repository.insert_silence(rule, group_key, starts_at, ends_at, reason, user.username)
    target = f"{rule or '모든 규칙'} · {group_key if group_key is not None else '모든 대상'}"
    await db.audit(user.username, "alerts.silence.create", target,
                   {"id": silence_id, "rule": rule, "group_key": group_key, "starts_at": starts_at.isoformat(),
                    "ends_at": ends_at.isoformat(), "reason": reason, "wide": wide,
                    "covered_until": covered_until.isoformat()}, actor_ip=client_ip(request))
    if wide:
        # 그 규칙들의 받는 곳에 알린다. 실패해도 무음은 걸린다
        rules = [r for r in engine.config.rules if r.enabled and (rule is None or r.name == rule)]
        span = f"{local(covered_from)} ~ {local(covered_until)}"
        try:
            await engine.notify_change(
                f"넓은 무음: {target} ({span})",
                [f"무음 #{silence_id} {target}: {span}", f"사유: {reason}", f"건 사람: {user.username}"],
                rules, f"무음 · {user.username}")
        except Exception:
            log.exception("넓은 무음 알림 실패 (무음 #%s)", silence_id)
    return {"ok": True, "id": silence_id, "starts_at": starts_at, "ends_at": ends_at}


@router.delete("/api/alerts/silences/{silence_id}")
async def end_silence(silence_id: int, request: Request, user: User = Depends(require_permission("alerts.handle"))):
    """일찍 해제. 행은 남는다(언제까지 무음이었는지가 증적)."""
    silence = await repository.get_silence(silence_id)
    if silence is None or not silence_visible(user, silence):
        raise HTTPException(404, "무음을 찾을 수 없습니다")
    _check_silence_scope(user, silence["rule"], silence["group_key"])
    if not await repository.end_silence(silence_id, user.username):
        raise HTTPException(409, "이미 끝난 무음입니다")
    await db.audit(user.username, "alerts.silence.end", f"무음 #{silence_id}",
                   {"id": silence_id, "rule": silence["rule"], "group_key": silence["group_key"],
                    "reason": silence["reason"]}, actor_ip=client_ip(request))
    return {"ok": True}


async def _followup(alert: dict[str, Any]) -> dict[str, Any] | None:
    """이 알림 뒤 같은 규칙·대상에서 들어온 이벤트 (B-35) — 같은 대상의 가장 최근 알림일 때만(뒤 알림이 이어서 센다).
    지금 규칙의 조건으로 센다(규칙을 고쳤으면 고친 조건). 재알림 간격 동안 몇 건이 더 왔고 언제까지 계속됐는지가 사고 대응 증적이다."""
    rule = next((r for r in engine.config.rules if r.name == alert["rule"]), None)
    if rule is None or rule.kind != "count" or not alert["is_latest"]:
        return None
    f = _with_group(replace(rule.event_filter(), received_since=alert["fired_at"]), rule.group_by, alert["group_key"])
    try:
        result = await repository.count_and_last(f)
    except db.QueryTimeout:
        return None
    return {"n": result["n"], "last_at": result["last_at"]}


# 경로 변수 하나짜리 GET 이라 맨 마지막에 둔다 (/api/alerts/config, /api/alerts/silences 를 가리지 않게)
@router.get("/api/alerts/{alert_id}", dependencies=[Depends(read_time_limit)])
async def get_alert(alert_id: int, request: Request):
    user = request.state.user
    row = await repository.get_alert(alert_id)
    if row is None or not alert_visible(user, row):
        raise HTTPException(404, "알림을 찾을 수 없습니다")
    if row["silence"]:
        row["silence"] = scrub_silence(user, row["silence"])
    row["followup"] = await _followup(row)
    return row  # related_unresolved: 같은 규칙·대상의 해결 안 된 다른 알림 수 — 함께 해결할 수 있게 (재발은 따로 기록, ADR-029)
