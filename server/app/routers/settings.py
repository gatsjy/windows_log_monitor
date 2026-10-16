"""환경설정 API (관리자 전용): 알림 수신자·그룹, 외부 연동(웹훅·Oracle), Oracle tnsnames.ora·쿼리, 메일 서버.

비밀값(비밀번호, 웹훅 주소·헤더)은 응답에 절대 포함하지 않는다 — 설정 여부(has_secret)만 돌려준다.
모든 변경과 Oracle 쿼리 실행은 audit_log 에 남는다.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import archive, backups, db, oracle, partitions, secrets
from ..alerts import targets
from ..alerts.engine import engine
from ..alerts.message import AlertMessage, search_link
from ..alerts.messenger import FORMATS, URL_WARNINGS
from ..alerts.notifiers import (
    ORACLE_BINDS,
    ORACLE_DEFAULT_SQL,
    ORACLE_DEFAULT_TABLE,
    EmailNotifier,
    NotifierError,
    WebhookNotifier,
)
from ..auth.deps import client_ip, require_permission
from ..auth.service import User
from ..config import settings
from ..reports import config as report_config

router = APIRouter(tags=["settings"], dependencies=[Depends(require_permission("settings.manage"))])


def _fail(exc: Exception, status: int | None = None) -> HTTPException:
    return HTTPException(status or getattr(exc, "status", 400), getattr(exc, "message", None) or str(exc))


def _used() -> dict[str, list[str]]:
    engine.reload()
    return engine.config.used_targets()


async def _used_all() -> dict[str, list[str]]:
    """대상 이름 → 쓰는 곳 (알림 규칙 이름들 + 점검 보고서 표시). 이름 바꾸기·삭제를 막을 때 쓴다."""
    used = {k: list(v) for k, v in _used().items()}
    for name in (await report_config.load())["targets"]:
        used.setdefault(name, []).append(targets.REPORT_USE)
    return used


def _sample_message(name: str) -> AlertMessage:
    now = datetime.now(UTC)
    return AlertMessage(
        rule="테스트 알림", severity="info", kind="test", group_by="host", group_key="TEST-PC", event_count=1,
        threshold=1, window_sec=300, fired_at=now, first_event_at=now - timedelta(minutes=1), last_event_at=now,
        alert_id=int(now.timestamp()), test=True, description=f"'{name}' 연결 확인용 테스트",
        link=f"{settings.public_url}/#/alerts",
    )


def _example_message(severity: str) -> AlertMessage:
    """형식 미리보기용 예시 알림 (실제 알림과 같은 모양 — 테스트 알림은 항목이 적어 미리보기로 부족하다)."""
    now = datetime.now(UTC).replace(microsecond=0)
    samples = [
        {"id": 1, "ts": (now - timedelta(seconds=40)).isoformat(), "host": "DC-01", "level": 3, "channel": "Security",
         "event_id": 4625, "message": "계정을 로그온하지 못했습니다. 계정 이름: admin, 원본 주소: 203.0.113.9"},
        {"id": 2, "ts": (now - timedelta(seconds=90)).isoformat(), "host": "DC-01", "level": 3, "channel": "Security",
         "event_id": 4625, "message": "계정을 로그온하지 못했습니다. 계정 이름: kim, 원본 주소: 203.0.113.9"},
    ]
    return AlertMessage(
        rule="로그온 실패 급증", severity=severity, kind="count", group_by="host", group_key="DC-01", event_count=27,
        threshold=20, window_sec=600, fired_at=now, first_event_at=now - timedelta(minutes=9), last_event_at=now,
        description="짧은 시간에 로그온 실패가 몰렸습니다 (무차별 대입 의심)", tags=["MITRE T1110", "ISMS 2.11.3"],
        alert_id=1234, samples=samples, link=search_link({"since": (now - timedelta(minutes=10)).isoformat(), "event_id": "4625", "host": "DC-01"}),
    )


# ------------------------------------------------------------------ 개요

@router.get("/api/settings/meta")
async def meta():
    return {
        "secret_key_set": bool(settings.secret_key),
        "oracle_modes": oracle.MODES,
        "oracle_binds": ORACLE_BINDS,
        "oracle_default_sql": ORACLE_DEFAULT_SQL.format(table=ORACLE_DEFAULT_TABLE),
        # 웹훅 보내는 형식 (메신저 프리셋). hosts = 주소로 형식을 권할 때 쓰는 호스트 끝부분
        "webhook_formats": [{"key": f.key, "label": f.label, "hosts": list(f.hosts), "https_only": f.https_only}
                            for f in FORMATS.values()],
        "webhook_url_warnings": [{"match": m, "text": t} for m, t in URL_WARNINGS],
        "tns_file": str(oracle.tns_file()),
        "used_targets": _used(),
    }


# -------------------------------------------------------------- 메일 서버

class SmtpBody(BaseModel):
    host: str = Field(default="", max_length=255)
    port: int = 587
    security: str = "starttls"
    user: str = Field(default="", max_length=255)
    sender: str = Field(default="", max_length=255)
    password: str | None = Field(default=None, max_length=512)  # 빈 값 = 기존 유지, null = 그대로
    clear_password: bool = False


@router.get("/api/settings/smtp")
async def get_smtp():
    return await targets.smtp_settings()


@router.put("/api/settings/smtp")
async def put_smtp(body: SmtpBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    password: str | None = None if body.clear_password else (body.password or "")
    try:
        await targets.save_smtp(body.model_dump(), password, admin.username, client_ip(request))
    except targets.TargetError as exc:
        raise _fail(exc) from exc
    return await targets.smtp_settings()


class SmtpTestBody(BaseModel):
    to: str = Field(max_length=254)


@router.post("/api/settings/smtp/test")
async def test_smtp(body: SmtpTestBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    smtp, source = await targets.smtp_config()
    notifier = EmailNotifier("메일 서버 테스트", [body.to.strip()], smtp)
    try:
        await asyncio.wait_for(notifier.send(_sample_message("메일 서버")), timeout=30)
        ok, error = True, None
    except (NotifierError, TimeoutError) as exc:
        ok, error = False, str(exc) or "시간 초과"
    await db.audit(admin.username, "settings.smtp.test", body.to, {"ok": ok, "error": error, "source": source},
                   actor_ip=client_ip(request))
    if not ok:
        raise HTTPException(502, error)
    return {"ok": True}


# ---------------------------------------------------------------- 수신자

class ContactBody(BaseModel):
    name: str = Field(max_length=100)
    email: str | None = Field(default=None, max_length=254)
    phone: str | None = Field(default=None, max_length=40)
    department: str = Field(default="", max_length=100)
    memo: str = Field(default="", max_length=500)
    is_active: bool = True
    group_ids: list[int] | None = None


@router.get("/api/settings/contacts")
async def list_contacts():
    return {"items": await targets.list_contacts()}


@router.post("/api/settings/contacts")
async def create_contact(body: ContactBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        return {"id": await targets.save_contact(None, body.model_dump(exclude_none=True), admin.username,
                                                 client_ip(request))}
    except targets.TargetError as exc:
        raise _fail(exc) from exc


@router.put("/api/settings/contacts/{contact_id}")
async def update_contact(contact_id: int, body: ContactBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        await targets.save_contact(contact_id, body.model_dump(exclude_none=True), admin.username, client_ip(request))
    except targets.TargetError as exc:
        raise _fail(exc) from exc
    return {"ok": True}


@router.delete("/api/settings/contacts/{contact_id}")
async def delete_contact(contact_id: int, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        await targets.delete_contact(contact_id, admin.username, client_ip(request))
    except targets.TargetError as exc:
        raise _fail(exc) from exc
    return {"ok": True}


# ------------------------------------------------------------- 수신 그룹

class GroupBody(BaseModel):
    name: str = Field(max_length=64)
    description: str = Field(default="", max_length=200)
    min_severity: str = "info"
    member_ids: list[int] | None = None


@router.get("/api/settings/groups")
async def list_groups():
    used = _used()
    report = set((await report_config.load())["targets"])
    items = await targets.list_groups()
    for g in items:
        g["used_by"] = used.get(g["name"], [])
        g["report_target"] = g["name"] in report
    return {"items": items}


@router.post("/api/settings/groups")
async def create_group(body: GroupBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        return {"id": await targets.save_group(None, body.model_dump(exclude_none=True), await _used_all(), admin.username,
                                               client_ip(request))}
    except targets.TargetError as exc:
        raise _fail(exc) from exc


@router.put("/api/settings/groups/{group_id}")
async def update_group(group_id: int, body: GroupBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        await targets.save_group(group_id, body.model_dump(exclude_none=True), await _used_all(), admin.username,
                                 client_ip(request))
    except targets.TargetError as exc:
        raise _fail(exc) from exc
    return {"ok": True}


@router.delete("/api/settings/groups/{group_id}")
async def delete_group(group_id: int, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        await targets.delete_group(group_id, await _used_all(), admin.username, client_ip(request))
    except targets.TargetError as exc:
        raise _fail(exc) from exc
    return {"ok": True}


# ------------------------------------------------------------- 외부 연동

class ChannelBody(BaseModel):
    name: str = Field(max_length=64)
    type: str = "webhook"
    description: str = Field(default="", max_length=200)
    is_active: bool = True
    min_severity: str = "info"
    config: dict[str, Any] = {}
    # 비밀값: 빈 문자열/생략 = 기존 값 유지
    password: str | None = Field(default=None, max_length=512)     # oracle
    url: str | None = Field(default=None, max_length=2000)          # webhook
    headers: dict[str, str] | None = None                           # webhook (인증 헤더 등). {} = 모두 삭제


def _secret_updates(body: ChannelBody) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    if body.password:
        updates["password"] = body.password
    if body.url:
        updates["url"] = body.url.strip()
    if body.headers is not None:
        updates["headers"] = {k.strip(): v for k, v in body.headers.items() if k.strip()} or None
    return updates


@router.get("/api/settings/channels")
async def list_channels():
    used = _used()
    report = set((await report_config.load())["targets"])
    items = await targets.list_channels()
    for c in items:
        c["used_by"] = used.get(c["name"], [])
        c["report_target"] = c["name"] in report
    return {"items": items}


@router.post("/api/settings/channels")
async def create_channel(body: ChannelBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        return {"id": await targets.save_channel(None, body.model_dump(), _secret_updates(body), await _used_all(),
                                                 admin.username, client_ip(request))}
    except targets.TargetError as exc:
        raise _fail(exc) from exc


@router.put("/api/settings/channels/{channel_id}")
async def update_channel(channel_id: int, body: ChannelBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        await targets.save_channel(channel_id, body.model_dump(), _secret_updates(body), await _used_all(), admin.username,
                                   client_ip(request))
    except targets.TargetError as exc:
        raise _fail(exc) from exc
    return {"ok": True}


@router.delete("/api/settings/channels/{channel_id}")
async def delete_channel(channel_id: int, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    try:
        await targets.delete_channel(channel_id, await _used_all(), admin.username, client_ip(request))
    except targets.TargetError as exc:
        raise _fail(exc) from exc
    return {"ok": True}


async def _channel(channel_id: int) -> dict:
    try:
        return await targets.get_channel(channel_id)
    except targets.TargetError as exc:
        raise _fail(exc) from exc


class WebhookPreviewBody(BaseModel):
    format: str = Field(max_length=20)
    severity: str = Field(default="warning", pattern="^(info|warning|error|critical)$")


@router.post("/api/settings/webhook-preview")
async def webhook_preview(body: WebhookPreviewBody):
    """형식별로 실제로 보낼 본문·헤더 예시 (보내지 않는다). 사용자가 넣은 헤더는 비밀값일 수 있어 빼고 보여 준다."""
    if body.format not in FORMATS:
        raise HTTPException(422, f"알 수 없는 형식: {body.format}")
    hook = WebhookNotifier("미리보기", "https://example.invalid/hook", body.format)
    return {"format": body.format, "headers": hook.request_headers(), "body": hook.payload(_example_message(body.severity))}


@router.post("/api/settings/channels/{channel_id}/test")
async def test_channel(channel_id: int, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    """웹훅: 테스트 메시지 전송 / Oracle: 접속해서 DB 정보 조회."""
    row = await _channel(channel_id)
    try:
        if row["type"] == "oracle":
            conn = targets.oracle_conn(row["config"], row["secret_enc"])
            result = await asyncio.to_thread(oracle.test_connection, conn)
        else:
            notifier = targets.build_channel(row)
            await asyncio.wait_for(notifier.send(_sample_message(row["name"])), timeout=30)
            result = {"sent": True}
        ok, error = True, None
    except (NotifierError, oracle.OracleError, secrets.SecretError, TimeoutError) as exc:
        ok, error, result = False, str(exc) or "시간 초과", None
    await db.audit(admin.username, "settings.channel.test", row["name"], {"type": row["type"], "ok": ok, "error": error},
                   actor_ip=client_ip(request))
    if not ok:
        raise HTTPException(502, error)
    return {"ok": True, "result": result}


class OracleProbeBody(BaseModel):
    config: dict[str, Any]
    password: str | None = Field(default=None, max_length=512)
    channel_id: int | None = None  # 비밀번호를 비워 두면 이 연동에 저장된 비밀번호 사용


@router.post("/api/settings/oracle/test-connection")
async def oracle_probe(body: OracleProbeBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    """저장하기 전에 입력한 값으로 연결 시험."""
    try:
        secret_enc = (await _channel(body.channel_id))["secret_enc"] if body.channel_id and not body.password else None
        conn = targets.oracle_conn(body.config, secret_enc, body.password)
        result = await asyncio.to_thread(oracle.test_connection, conn)
    except (oracle.OracleError, secrets.SecretError) as exc:
        await db.audit(admin.username, "settings.oracle.test", oracle_describe(body.config), {"ok": False, "error": str(exc)},
                       actor_ip=client_ip(request))
        raise HTTPException(502, str(exc)) from exc
    await db.audit(admin.username, "settings.oracle.test", conn.describe(), {"ok": True}, actor_ip=client_ip(request))
    return result


def oracle_describe(config: dict[str, Any]) -> str:
    try:
        return oracle.OracleConn.from_config(config, "").describe()
    except oracle.OracleError:
        return str(config.get("mode", ""))


class DryRunBody(BaseModel):
    commit: bool = False


@router.post("/api/settings/channels/{channel_id}/oracle/dry-run")
async def oracle_dry_run(channel_id: int, body: DryRunBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    """알림 SQL 을 테스트 값으로 실행. commit=false 면 실행 후 되돌린다."""
    row = await _channel(channel_id)
    if row["type"] != "oracle":
        raise HTTPException(400, "Oracle 연동이 아닙니다")
    try:
        notifier = targets.build_channel(row)
        message = _sample_message(row["name"])
        if body.commit:
            await notifier.send(message)
            count = None
        else:
            count = await notifier.dry_run(message)
    except (NotifierError, oracle.OracleError, secrets.SecretError) as exc:
        await db.audit(admin.username, "settings.oracle.dry_run", row["name"],
                       {"commit": body.commit, "ok": False, "error": str(exc)}, actor_ip=client_ip(request))
        raise HTTPException(502, str(exc)) from exc
    await db.audit(admin.username, "settings.oracle.dry_run", row["name"], {"commit": body.commit, "ok": True,
                                                                           "rowcount": count},
                   actor_ip=client_ip(request))
    return {"ok": True, "rowcount": count, "committed": body.commit, "binds": sorted(notifier.binds(message))}


class QueryBody(BaseModel):
    sql: str = Field(max_length=20000)
    max_rows: int = 100


@router.post("/api/settings/channels/{channel_id}/oracle/query")
async def oracle_query(channel_id: int, body: QueryBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    """조회 전용 쿼리 실행 (SELECT/WITH, 읽기 전용 트랜잭션, 최대 500행). 실행한 SQL 은 감사로그에 남는다."""
    row = await _channel(channel_id)
    if row["type"] != "oracle":
        raise HTTPException(400, "Oracle 연동이 아닙니다")
    started = datetime.now(UTC)
    try:
        conn = targets.oracle_conn(row["config"], row["secret_enc"])
        result = await asyncio.to_thread(oracle.run_query, conn, body.sql, body.max_rows)
    except (oracle.OracleError, secrets.SecretError) as exc:
        await db.audit(admin.username, "settings.oracle.query", row["name"],
                       {"sql": body.sql[:2000], "ok": False, "error": str(exc)}, actor_ip=client_ip(request))
        raise HTTPException(400, str(exc)) from exc
    elapsed_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    await db.audit(admin.username, "settings.oracle.query", row["name"],
                   {"sql": body.sql[:2000], "ok": True, "rows": len(result["rows"]), "ms": elapsed_ms},
                   actor_ip=client_ip(request))
    return {**result, "elapsed_ms": elapsed_ms}


# ---------------------------------------------------------- 로그 보관

# ---------------------------------------------------------- 점검 보고서 (ADR-032)

@router.get("/api/settings/report")
async def report_settings():
    return {"config": await report_config.load(), "targets": await report_config.report_targets(),
            "tz": settings.display_tz}


@router.put("/api/settings/report")
async def save_report_settings(request: Request, admin: User = Depends(require_permission("settings.manage"))):
    body = await request.json()
    try:
        cfg = report_config.clean(body if isinstance(body, dict) else {}, set(await report_config.report_targets()))
    except report_config.ReportConfigError as exc:
        raise HTTPException(422, str(exc)) from exc
    await report_config.save(cfg, admin.username)
    await db.audit(admin.username, "settings.report.save", "report", cfg, actor_ip=client_ip(request))
    return {"ok": True, "config": cfg}


@router.get("/api/settings/retention")
async def retention_status():
    """로그 로테이션 정책과 현재 DB 파티션·보관 파일·DB 백업 (설정 값은 .env, 화면은 조회만)."""
    async with await db.connect_autocommit() as conn:
        parts = await partitions.list_partitions(conn)
    return {
        "backup": await backups.backup_status(),
        "policy": {
            "db_retention_days": settings.db_retention_days, "retention_days": settings.retention_days,
            "archiving": partitions.archiving_enabled(), "archive_dir": settings.archive_dir,
        },
        "partitions": parts,
        "archives": archive.list_archives(),
    }


@router.post("/api/settings/retention/rotate")
async def retention_rotate(request: Request, admin: User = Depends(require_permission("settings.manage"))):
    """로그 로테이션 즉시 실행 (보통은 1시간마다 자동)."""
    await db.audit(admin.username, "retention.rotate_now", None, {}, actor_ip=client_ip(request))
    await partitions.run_maintenance()
    return await retention_status()


class RestoreBody(BaseModel):
    partition: str = Field(pattern=r"^events_\d{4}_\d{2}$")
    hold_days: int = Field(default=14, ge=1, le=365)


@router.post("/api/settings/retention/restore")
async def retention_restore(body: RestoreBody, admin: User = Depends(require_permission("settings.manage"))):
    """보관 파일을 DB 로 다시 불러와 검색할 수 있게 한다 (hold_days 동안 자동 정리 제외)."""
    try:
        rows = await archive.restore(body.partition, body.hold_days, admin.username)
    except archive.ArchiveError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"rows": rows}


@router.post("/api/settings/retention/verify")
async def retention_verify(request: Request, admin: User = Depends(require_permission("settings.manage"))):
    results = [await asyncio.to_thread(archive.verify, a["partition"]) for a in archive.list_archives()]
    bad = [r["file"] for r in results if not r["ok"]]
    await db.audit(admin.username, "retention.verify_archives", None, {"files": len(results), "bad": bad},
                   actor_ip=client_ip(request))
    return {"items": results}


# --------------------------------------------------------- tnsnames.ora

class TnsBody(BaseModel):
    text: str = Field(max_length=200_000)


@router.get("/api/settings/oracle/tnsnames")
async def get_tnsnames():
    path = oracle.tns_file()
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    return {"path": str(path), "text": text, "aliases": oracle.tns_aliases(text)}


@router.put("/api/settings/oracle/tnsnames")
async def put_tnsnames(body: TnsBody, request: Request, admin: User = Depends(require_permission("settings.manage"))):
    aliases = oracle.tns_aliases(body.text)
    if body.text.strip() and not aliases:
        raise HTTPException(422, "별칭을 하나도 찾지 못했습니다. 'ALIAS = (DESCRIPTION = ...)' 형식인지 확인하세요")
    path = oracle.tns_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body.text if body.text.endswith("\n") else body.text + "\n")
        os.replace(tmp, path)
    except OSError as exc:
        Path(tmp).unlink(missing_ok=True)
        raise HTTPException(500, f"저장 실패: {exc}") from exc
    await db.audit(admin.username, "settings.oracle.tnsnames.save", path.name, {"aliases": aliases},
                   actor_ip=client_ip(request))
    return {"path": str(path), "aliases": aliases}
