"""사용자 그룹: 기능 권한(permissions)과 조회 범위(scope)를 그룹 단위로 준다.

- 관리자(role=admin)는 그룹과 상관없이 모든 기능·모든 로그.
- 조회자는 속한 그룹들의 권한을 합친 만큼 할 수 있다.
- 조회 범위: 그룹마다 '분류'와 'PC' 로 제한. 여러 그룹이면 합집합(어느 한 그룹에서라도 보이면 보임).
  범위가 비어 있는 그룹에 하나라도 속하거나, 그룹이 없으면 제한 없음(예전 동작).
- 범위는 서버에서 검색·통계·실시간·상세·수집 PC·알림 이력에 적용한다 (filters.Scope, repository.where_clause).
"""

from __future__ import annotations

from typing import Any

from .. import db
from ..filters import Scope
from ..normalizers.categories import CATEGORIES

# 관리자가 아닌 사용자에게 그룹으로 줄 수 있는 기능 권한. 사용자 관리는 관리자만 (권한 상승 방지)
PERMISSIONS = {
    "alerts.manage": "알림 규칙 관리 (추가·수정·켜기/끄기, 알림 대상 테스트)",
    "dashboards.edit": "대시보드 편집",
    "settings.manage": "환경설정 (수신자·수신 그룹·외부 연동·메일 서버·로그 보관)",
    "audit.view": "감사 로그 보기·내려받기",
    "agents.deploy": "에이전트 설치 묶음 내려받기 (수집 API 키 포함)",
}


class GroupError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


async def access_for(user_id: int) -> tuple[frozenset[str], tuple[Scope, ...] | None, tuple[str, ...]]:
    """(권한, 조회 범위 — None 이면 제한 없음, 그룹 이름들)."""
    rows = await db.fetch_all(
        "SELECT g.name, g.permissions, g.scope_categories, g.scope_hosts FROM user_groups g"
        " JOIN user_group_members m ON m.group_id = g.id WHERE m.user_id = %s ORDER BY g.name", (user_id,))
    perms = frozenset(p for r in rows for p in r["permissions"] if p in PERMISSIONS)
    scopes = tuple(Scope(tuple(r["scope_categories"]), tuple(r["scope_hosts"])) for r in rows)
    if not scopes or any(s.unrestricted for s in scopes):
        scopes = None
    return perms, scopes, tuple(r["name"] for r in rows)


async def list_groups() -> list[dict[str, Any]]:
    return await db.fetch_all(
        "SELECT g.id, g.name, g.description, g.permissions, g.scope_categories, g.scope_hosts, g.updated_at,"
        " COALESCE(array_agg(m.user_id ORDER BY m.user_id) FILTER (WHERE m.user_id IS NOT NULL), '{}') AS member_ids"
        " FROM user_groups g LEFT JOIN user_group_members m ON m.group_id = g.id GROUP BY g.id ORDER BY g.name")


async def memberships() -> dict[int, list[str]]:
    """사용자 id → 그룹 이름들 (사용자 목록 화면용)."""
    rows = await db.fetch_all(
        "SELECT m.user_id, g.name FROM user_group_members m JOIN user_groups g ON g.id = m.group_id ORDER BY g.name")
    out: dict[int, list[str]] = {}
    for r in rows:
        out.setdefault(r["user_id"], []).append(r["name"])
    return out


def clean(body: dict[str, Any]) -> dict[str, Any]:
    name = str(body.get("name") or "").strip()
    if not name or len(name) > 64:
        raise GroupError("그룹 이름은 1~64자로 입력하세요")
    perms = [p for p in body.get("permissions") or [] if p in PERMISSIONS]
    unknown = [p for p in body.get("permissions") or [] if p not in PERMISSIONS]
    if unknown:
        raise GroupError(f"알 수 없는 권한: {unknown}")
    cats = [c for c in body.get("scope_categories") or [] if c]
    bad = [c for c in cats if c not in CATEGORIES]
    if bad:
        raise GroupError(f"알 수 없는 분류: {bad}")
    hosts = []
    for h in body.get("scope_hosts") or []:
        h = str(h).strip()
        if not h:
            continue
        if len(h) > 128 or any(c in h for c in "%_?[]\\"):
            raise GroupError(f"PC 이름 형식: {h!r} — 글자·숫자·하이픈과 * 만 씁니다 (예: MED-*)")
        hosts.append(h)
    members = sorted({int(u) for u in body.get("member_ids") or []})
    return {"name": name, "description": str(body.get("description") or "").strip()[:200], "permissions": sorted(set(perms)),
            "scope_categories": sorted(set(cats)), "scope_hosts": sorted(set(hosts)), "member_ids": members}


async def save(group_id: int | None, body: dict[str, Any]) -> dict[str, Any]:
    g = clean(body)
    dup = await db.fetch_one("SELECT id FROM user_groups WHERE lower(name) = lower(%s) AND id IS DISTINCT FROM %s",
                             (g["name"], group_id))
    if dup:
        raise GroupError(f"같은 이름의 그룹이 있습니다: {g['name']}", 409)
    async with db.pool().connection() as conn, conn.transaction():
        if group_id is None:
            row = await (await conn.execute(
                "INSERT INTO user_groups (name, description, permissions, scope_categories, scope_hosts)"
                " VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (g["name"], g["description"], g["permissions"], g["scope_categories"], g["scope_hosts"]))).fetchone()
            group_id = row["id"]
        else:
            cur = await conn.execute(
                "UPDATE user_groups SET name = %s, description = %s, permissions = %s, scope_categories = %s,"
                " scope_hosts = %s, updated_at = now() WHERE id = %s",
                (g["name"], g["description"], g["permissions"], g["scope_categories"], g["scope_hosts"], group_id))
            if cur.rowcount == 0:
                raise GroupError("그룹을 찾을 수 없습니다", 404)
        await conn.execute("DELETE FROM user_group_members WHERE group_id = %s", (group_id,))
        if g["member_ids"]:
            await conn.execute(
                "INSERT INTO user_group_members (group_id, user_id) SELECT %s, id FROM users WHERE id = ANY(%s)",
                (group_id, g["member_ids"]))
    return {"id": group_id, **g}


async def delete(group_id: int) -> str:
    row = await db.fetch_one("DELETE FROM user_groups WHERE id = %s RETURNING name", (group_id,))
    if row is None:
        raise GroupError("그룹을 찾을 수 없습니다", 404)
    return row["name"]
