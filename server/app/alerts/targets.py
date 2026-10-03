"""환경설정의 알림 대상 (DB): 수신자, 수신 그룹, 외부 연동(웹훅·Oracle), 메일 서버(SMTP).

알림 규칙(config/alerts.yaml)의 notify 에는 '수신 그룹 이름' 또는 '외부 연동 이름'을 쓴다.
두 종류의 이름은 서로 겹칠 수 없다. 모든 변경은 audit_log 에 남는다 (비밀값 자체는 남기지 않음).
"""

from __future__ import annotations

import json
from typing import Any

from .. import db, oracle, secrets
from ..config import settings
from .notifiers import (
    ORACLE_DEFAULT_SQL,
    ORACLE_DEFAULT_TABLE,
    EmailNotifier,
    Notifier,
    NotifierError,
    OracleNotifier,
    SmtpConfig,
    WebhookNotifier,
)

CHANNEL_TYPES = ("webhook", "oracle")
SEVERITIES = ("info", "warning", "error", "critical")


def _min_severity(value: Any) -> str:
    return value if value in SEVERITIES else "info"


class TargetError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


def _check_name(name: str) -> str:
    name = (name or "").strip()
    if not name or len(name) > 64 or "," in name:
        raise TargetError("이름은 1~64자, 쉼표 없이")
    return name


async def _name_taken(name: str, *, group_id: int | None = None, channel_id: int | None = None) -> bool:
    row = await db.fetch_one(
        "SELECT (SELECT count(*) FROM contact_groups WHERE name = %s AND id <> %s)"
        "     + (SELECT count(*) FROM channels WHERE name = %s AND id <> %s) AS n",
        (name, group_id or 0, name, channel_id or 0),
    )
    return row["n"] > 0


def _jsonb(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


# ---------------------------------------------------------------- 메일 서버

def _env_smtp() -> SmtpConfig:
    return SmtpConfig(host=settings.smtp_host, port=settings.smtp_port, security=settings.smtp_security,
                      user=settings.smtp_user, password=settings.smtp_password, sender=settings.smtp_from)


async def smtp_config() -> tuple[SmtpConfig, str]:
    """화면에서 설정했으면 그 값, 아니면 .env (WLM_SMTP_*)."""
    row = await db.fetch_one("SELECT value, secret_enc FROM app_settings WHERE key = 'smtp'")
    if row and row["value"].get("host"):
        v = row["value"]
        secret = secrets.decrypt(row["secret_enc"])
        return SmtpConfig(host=v["host"], port=int(v.get("port") or 587), security=v.get("security", "starttls"),
                          user=v.get("user", ""), password=secret.get("password", ""),
                          sender=v.get("sender") or settings.smtp_from), "db"
    return _env_smtp(), "env"


async def smtp_settings() -> dict[str, Any]:
    row = await db.fetch_one("SELECT value, secret_enc, updated_at, updated_by FROM app_settings WHERE key = 'smtp'")
    env = _env_smtp()
    current, source = await smtp_config()
    return {
        "value": row["value"] if row else {},
        "has_password": bool(row and row["secret_enc"]),
        "updated_at": row["updated_at"] if row else None,
        "updated_by": row["updated_by"] if row else None,
        "source": source,
        "effective": {"host": current.host, "port": current.port, "security": current.security,
                      "user": current.user, "sender": current.sender},
        "env": {"host": env.host, "port": env.port, "security": env.security, "user": env.user, "sender": env.sender},
    }


async def save_smtp(value: dict[str, Any], password: str | None, actor: str, ip: str | None) -> None:
    clean = {
        "host": str(value.get("host", "")).strip(),
        "port": int(value.get("port") or 587),
        "security": value.get("security", "starttls") if value.get("security") in ("none", "starttls", "ssl")
        else "starttls",
        "user": str(value.get("user", "")).strip(),
        "sender": str(value.get("sender", "")).strip(),
    }
    row = await db.fetch_one("SELECT secret_enc FROM app_settings WHERE key = 'smtp'")
    try:
        secret = secrets.merge(row["secret_enc"] if row else None, {"password": password})
    except secrets.SecretError as exc:
        raise TargetError(str(exc)) from exc
    await db.fetch_one(
        "INSERT INTO app_settings (key, value, secret_enc, updated_at, updated_by) VALUES ('smtp', %s::jsonb, %s, now(), %s)"
        " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, secret_enc = EXCLUDED.secret_enc,"
        " updated_at = now(), updated_by = EXCLUDED.updated_by RETURNING key",
        (_jsonb(clean), secret, actor),
    )
    await db.audit(actor, "settings.smtp.save", "smtp", {**clean, "password_changed": password not in (None, "")},
                   actor_ip=ip)


# ------------------------------------------------------------------ 수신자

async def list_contacts() -> list[dict]:
    return await db.fetch_all(
        "SELECT c.*, COALESCE(array_agg(g.name ORDER BY g.name) FILTER (WHERE g.id IS NOT NULL), '{}') AS groups,"
        "       COALESCE(array_agg(g.id) FILTER (WHERE g.id IS NOT NULL), '{}') AS group_ids"
        "  FROM contacts c"
        "  LEFT JOIN contact_group_members m ON m.contact_id = c.id"
        "  LEFT JOIN contact_groups g ON g.id = m.group_id"
        " GROUP BY c.id ORDER BY c.department, c.name"
    )


async def save_contact(contact_id: int | None, data: dict[str, Any], actor: str, ip: str | None) -> int:
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip() or None
    if not name:
        raise TargetError("이름을 입력하세요")
    if email and ("@" not in email or " " in email or len(email) > 254):
        raise TargetError("이메일 형식이 올바르지 않습니다")
    values = (name[:100], email, (data.get("phone") or "").strip()[:40] or None, (data.get("department") or "").strip()[:100],
              (data.get("memo") or "").strip()[:500], bool(data.get("is_active", True)))
    if contact_id:
        row = await db.fetch_one(
            "UPDATE contacts SET name = %s, email = %s, phone = %s, department = %s, memo = %s, is_active = %s,"
            " updated_at = now() WHERE id = %s RETURNING id", (*values, contact_id))
        if row is None:
            raise TargetError("수신자가 없습니다", 404)
    else:
        row = await db.fetch_one(
            "INSERT INTO contacts (name, email, phone, department, memo, is_active) VALUES (%s, %s, %s, %s, %s, %s)"
            " RETURNING id", values)
    cid = row["id"]
    if "group_ids" in data:
        await _set_contact_groups(cid, [int(g) for g in data.get("group_ids") or []])
    await db.audit(actor, "settings.contact.save", name, {"id": cid, "email": email, "active": values[5],
                                                         "groups": data.get("group_ids")}, actor_ip=ip)
    return cid


async def _set_contact_groups(contact_id: int, group_ids: list[int]) -> None:
    async with db.pool().connection() as conn:
        await conn.execute("DELETE FROM contact_group_members WHERE contact_id = %s", (contact_id,))
        for gid in sorted(set(group_ids)):
            await conn.execute(
                "INSERT INTO contact_group_members (group_id, contact_id) SELECT id, %s FROM contact_groups WHERE id = %s",
                (contact_id, gid))


async def delete_contact(contact_id: int, actor: str, ip: str | None) -> None:
    row = await db.fetch_one("DELETE FROM contacts WHERE id = %s RETURNING name, email", (contact_id,))
    if row is None:
        raise TargetError("수신자가 없습니다", 404)
    await db.audit(actor, "settings.contact.delete", row["name"], {"id": contact_id, "email": row["email"]}, actor_ip=ip)


# ------------------------------------------------------------- 수신 그룹

async def list_groups() -> list[dict]:
    return await db.fetch_all(
        "SELECT g.*, COALESCE(array_agg(c.id ORDER BY c.name) FILTER (WHERE c.id IS NOT NULL), '{}') AS member_ids,"
        "       count(c.id) AS members,"
        "       count(c.id) FILTER (WHERE c.is_active AND c.email IS NOT NULL) AS deliverable"
        "  FROM contact_groups g"
        "  LEFT JOIN contact_group_members m ON m.group_id = g.id"
        "  LEFT JOIN contacts c ON c.id = m.contact_id"
        " GROUP BY g.id ORDER BY g.name"
    )


async def save_group(group_id: int | None, data: dict[str, Any], used_by_rules: dict[str, list[str]],
                     actor: str, ip: str | None) -> int:
    name = _check_name(data.get("name", ""))
    if await _name_taken(name, group_id=group_id):
        raise TargetError(f"'{name}' 은(는) 이미 그룹 또는 외부 연동 이름으로 쓰고 있습니다")
    description = (data.get("description") or "").strip()[:200]
    min_severity = _min_severity(data.get("min_severity"))
    if group_id:
        old = await db.fetch_one("SELECT name FROM contact_groups WHERE id = %s", (group_id,))
        if old is None:
            raise TargetError("그룹이 없습니다", 404)
        if old["name"] != name and used_by_rules.get(old["name"]):
            raise TargetError(f"알림 규칙 {used_by_rules[old['name']]} 에서 '{old['name']}' 을(를) 쓰고 있어 이름을 바꿀 수 없습니다."
                              " 규칙을 먼저 고치세요")
        await db.fetch_one(
            "UPDATE contact_groups SET name = %s, description = %s, min_severity = %s WHERE id = %s RETURNING id",
            (name, description, min_severity, group_id))
    else:
        group_id = (await db.fetch_one(
            "INSERT INTO contact_groups (name, description, min_severity) VALUES (%s, %s, %s) RETURNING id",
            (name, description, min_severity)))["id"]
    if "member_ids" in data:
        async with db.pool().connection() as conn:
            await conn.execute("DELETE FROM contact_group_members WHERE group_id = %s", (group_id,))
            for cid in sorted({int(c) for c in data.get("member_ids") or []}):
                await conn.execute(
                    "INSERT INTO contact_group_members (group_id, contact_id) SELECT %s, id FROM contacts WHERE id = %s",
                    (group_id, cid))
    await db.audit(actor, "settings.group.save", name,
                   {"id": group_id, "members": data.get("member_ids"), "min_severity": min_severity}, actor_ip=ip)
    return group_id


async def delete_group(group_id: int, used_by_rules: dict[str, list[str]], actor: str, ip: str | None) -> None:
    row = await db.fetch_one("SELECT name FROM contact_groups WHERE id = %s", (group_id,))
    if row is None:
        raise TargetError("그룹이 없습니다", 404)
    if used_by_rules.get(row["name"]):
        raise TargetError(f"알림 규칙 {used_by_rules[row['name']]} 에서 사용 중이라 지울 수 없습니다")
    await db.fetch_one("DELETE FROM contact_groups WHERE id = %s RETURNING id", (group_id,))
    await db.audit(actor, "settings.group.delete", row["name"], {"id": group_id}, actor_ip=ip)


# ------------------------------------------------------------- 외부 연동

def _public_channel(row: dict) -> dict:
    data = {k: row[k] for k in ("id", "name", "type", "description", "is_active", "config", "min_severity",
                                 "created_at", "updated_at", "updated_by")}
    data["has_secret"] = bool(row.get("secret_enc"))
    try:
        data["target"] = build_channel(row).target()
        data["error"] = None
    except (NotifierError, oracle.OracleError, secrets.SecretError) as exc:
        data["target"], data["error"] = "", str(exc)
    return data


async def list_channels() -> list[dict]:
    rows = await db.fetch_all("SELECT * FROM channels ORDER BY name")
    return [_public_channel(r) for r in rows]


async def get_channel(channel_id: int) -> dict:
    row = await db.fetch_one("SELECT * FROM channels WHERE id = %s", (channel_id,))
    if row is None:
        raise TargetError("외부 연동이 없습니다", 404)
    return row


def _clean_channel_config(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    if kind == "webhook":
        fmt = config.get("format", "json")
        return {"format": fmt if fmt in ("json", "text") else "json",
                "timeout_sec": min(max(float(config.get("timeout_sec") or 10), 1), 60)}
    mode = config.get("mode", "service")
    if mode not in oracle.MODES:
        raise TargetError(f"접속 방식은 {', '.join(oracle.MODES)} 중 하나")
    sql = (config.get("sql") or "").strip() or ORACLE_DEFAULT_SQL.format(table=ORACLE_DEFAULT_TABLE)
    return {
        "mode": mode, "user": str(config.get("user", "")).strip(), "tns_alias": str(config.get("tns_alias", "")).strip(),
        "host": str(config.get("host", "")).strip(), "port": int(config.get("port") or 1521),
        "sid": str(config.get("sid", "")).strip(), "service_name": str(config.get("service_name", "")).strip(),
        "dsn": str(config.get("dsn", "")).strip(), "sql": sql,
    }


async def save_channel(channel_id: int | None, data: dict[str, Any], secret_updates: dict[str, Any],
                       used_by_rules: dict[str, list[str]], actor: str, ip: str | None) -> int:
    name = _check_name(data.get("name", ""))
    kind = data.get("type")
    old = await get_channel(channel_id) if channel_id else None
    if old:
        kind = old["type"]
    if kind not in CHANNEL_TYPES:
        raise TargetError(f"종류는 {', '.join(CHANNEL_TYPES)} 중 하나")
    if await _name_taken(name, channel_id=channel_id):
        raise TargetError(f"'{name}' 은(는) 이미 그룹 또는 외부 연동 이름으로 쓰고 있습니다")
    if old and old["name"] != name and used_by_rules.get(old["name"]):
        raise TargetError(f"알림 규칙 {used_by_rules[old['name']]} 에서 '{old['name']}' 을(를) 쓰고 있어 이름을 바꿀 수 없습니다")
    config = _clean_channel_config(kind, data.get("config") or {})
    try:
        secret = secrets.merge(old["secret_enc"] if old else None, secret_updates)
    except secrets.SecretError as exc:
        raise TargetError(str(exc)) from exc
    candidate = {"id": channel_id, "name": name, "type": kind, "config": config, "secret_enc": secret}
    try:
        build_channel(candidate)  # 저장 전에 설정이 말이 되는지 확인
    except (NotifierError, oracle.OracleError) as exc:
        raise TargetError(str(exc)) from exc
    values = (name, (data.get("description") or "").strip()[:200], bool(data.get("is_active", True)),
              _jsonb(config), secret, actor, _min_severity(data.get("min_severity")))
    if old:
        await db.fetch_one(
            "UPDATE channels SET name = %s, description = %s, is_active = %s, config = %s::jsonb, secret_enc = %s,"
            " updated_by = %s, min_severity = %s, updated_at = now() WHERE id = %s RETURNING id", (*values, channel_id))
    else:
        channel_id = (await db.fetch_one(
            "INSERT INTO channels (name, description, is_active, config, secret_enc, updated_by, min_severity, type)"
            " VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s) RETURNING id", (*values, kind)))["id"]
    await db.audit(actor, "settings.channel.save", name,
                   {"id": channel_id, "type": kind, "config": {k: v for k, v in config.items() if k != "sql"},
                    "min_severity": values[6],
                    "sql_changed": bool(old) and old["config"].get("sql") != config.get("sql") if kind == "oracle" else None,
                    "secret_changed": sorted(k for k, v in secret_updates.items() if v not in ("",))},
                   actor_ip=ip)
    return channel_id


async def delete_channel(channel_id: int, used_by_rules: dict[str, list[str]], actor: str, ip: str | None) -> None:
    row = await get_channel(channel_id)
    if used_by_rules.get(row["name"]):
        raise TargetError(f"알림 규칙 {used_by_rules[row['name']]} 에서 사용 중이라 지울 수 없습니다")
    await db.fetch_one("DELETE FROM channels WHERE id = %s RETURNING id", (channel_id,))
    await db.audit(actor, "settings.channel.delete", row["name"], {"id": channel_id, "type": row["type"]}, actor_ip=ip)


def oracle_conn(config: dict[str, Any], secret_enc: str | None, password_override: str | None = None) -> oracle.OracleConn:
    password = password_override or secrets.decrypt(secret_enc).get("password", "")
    return oracle.OracleConn.from_config(config, password)


def build_channel(row: dict) -> Notifier:
    config = row["config"]
    if row["type"] == "webhook":
        secret = secrets.decrypt(row.get("secret_enc"))
        if not secret.get("url"):
            raise NotifierError("웹훅 주소가 저장되어 있지 않습니다")
        return WebhookNotifier(row["name"], secret["url"], config.get("format", "json"), secret.get("headers") or {},
                               config.get("timeout_sec", 10))
    return OracleNotifier(row["name"], oracle_conn(config, row.get("secret_enc")), config.get("sql") or "")


# --------------------------------------------------------- 엔진이 쓰는 부분

async def load_notifiers() -> tuple[dict[str, Notifier], dict[str, str]]:
    """notify 이름 → 전송기. 만들 수 없는 것은 (이름 → 오류) 로."""
    notifiers: dict[str, Notifier] = {}
    errors: dict[str, str] = {}
    smtp, _ = await smtp_config()
    groups = await db.fetch_all(
        "SELECT g.name, g.min_severity, COALESCE(array_agg(c.email ORDER BY c.email)"
        "   FILTER (WHERE c.is_active AND c.email IS NOT NULL), '{}') AS emails"
        "  FROM contact_groups g LEFT JOIN contact_group_members m ON m.group_id = g.id"
        "  LEFT JOIN contacts c ON c.id = m.contact_id GROUP BY g.name, g.min_severity"
    )
    for g in groups:
        notifier = EmailNotifier(g["name"], list(g["emails"]), smtp)
        notifier.min_severity = g["min_severity"]
        notifiers[g["name"]] = notifier
    for row in await db.fetch_all("SELECT * FROM channels"):
        if not row["is_active"]:
            errors[row["name"]] = "사용 안 함으로 설정된 외부 연동입니다"
            continue
        try:
            notifier = build_channel(row)
            notifier.min_severity = row["min_severity"]
            notifiers[row["name"]] = notifier
        except (NotifierError, oracle.OracleError, secrets.SecretError) as exc:
            errors[row["name"]] = str(exc)
    return notifiers, errors


async def target_names() -> set[str]:
    rows = await db.fetch_all("SELECT name FROM contact_groups UNION SELECT name FROM channels")
    return {r["name"] for r in rows}
