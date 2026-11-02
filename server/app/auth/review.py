"""분기 권한 검토 (BACKLOG B-72 2단계, ISMS 2.5.6, ADR-058).

- 시작하면 그때의 계정·역할·그룹·권한·조회 범위·마지막 사용·2단계 인증을 스냅샷으로 남긴다(access_reviews.users). 검토는 이 스냅샷으로 —
  검토하는 사이 권한을 바꿔도 무엇을 보고 판단했는지가 남는다.
- 결정·서명·승인·반려는 access_review_entries 에 한 줄씩(고칠 수 없음 — 마이그레이션 032). 같은 계정의 결정을 바꾸면 줄이 하나 더 생기고
  마지막 줄이 지금 결정이다.
- 흐름: 진행 중(결정) → 점검자 서명(켜진 계정을 모두 결정해야) → 다른 관리자가 승인(끝) 또는 반려(사유 필수, 다시 진행 중).
  상태는 줄을 차례로 읽어 정한다(state). 상태를 바꾸는 쓰기는 검토 행을 잠그고 한 트랜잭션에서 다시 읽은 뒤 판단한다.
- '회수'는 결정만 남긴다 — 계정을 끄는 것은 사용자 화면에서(감사로그). 승인한 검토의 회수 결정인데 계정이 아직 켜져 있으면
  운영 준비도·점검 보고서가 알린다(follow_up).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .. import db
from . import groups
from .service import ROLE_LABELS

DECISIONS = {"keep": "유지", "revoke": "회수", "change": "조정"}
STATUS_LABELS = {"open": "진행 중", "signed": "서명 — 승인 대기", "approved": "승인됨"}


class ReviewError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.message, self.status = message, status


async def snapshot() -> list[dict[str, Any]]:
    """지금의 모든 계정 (꺼진 계정도 — 남아 있는 계정 전체를 보았다는 증적)."""
    rows = await db.fetch_all(
        "SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.disabled_reason, u.mfa_enabled_at IS NOT NULL AS mfa,"
        " u.last_login_at, GREATEST(u.last_login_at, u.reenabled_at, u.created_at) AS last_used, u.created_at,"
        " COALESCE(array_agg(g.name ORDER BY g.name) FILTER (WHERE g.id IS NOT NULL), '{}') AS groups,"
        " COALESCE(array_agg(DISTINCT p) FILTER (WHERE p IS NOT NULL), '{}') AS permissions,"
        " bool_or(cardinality(g.scope_categories) > 0 OR cardinality(g.scope_hosts) > 0) AS any_scope,"
        " bool_or(g.id IS NOT NULL AND cardinality(g.scope_categories) = 0 AND cardinality(g.scope_hosts) = 0) AS any_unscoped"
        " FROM users u LEFT JOIN user_group_members m ON m.user_id = u.id LEFT JOIN user_groups g ON g.id = m.group_id"
        " LEFT JOIN LATERAL unnest(g.permissions) AS p ON true"
        " GROUP BY u.id ORDER BY u.username")
    out = []
    for r in rows:
        perms = sorted(p for p in r["permissions"] if p in groups.PERMISSIONS)
        out.append({
            "id": r["id"], "username": r["username"], "display_name": r["display_name"] or "", "role": r["role"],
            "role_label": ROLE_LABELS.get(r["role"], r["role"]), "is_active": r["is_active"],
            "disabled_reason": r["disabled_reason"], "mfa": r["mfa"], "groups": list(dict.fromkeys(r["groups"])),
            "permissions": ["(관리자 — 모든 기능)"] if r["role"] == "admin" else perms,
            # 조회 범위 (groups.access_for 와 같은 판단): 범위 없는 그룹이 하나라도 있으면 제한 없음
            "scoped": r["role"] != "admin" and bool(r["any_scope"]) and not r["any_unscoped"],
            "last_login_at": _iso(r["last_login_at"]), "last_used": _iso(r["last_used"]), "created_at": _iso(r["created_at"]),
        })
    return out


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def state(review: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    """줄을 차례로 읽어 지금 상태: status·계정마다 마지막 결정·서명·승인·반려 (DB 없이 — 시험이 표로 본다)."""
    status, decisions = "open", {}
    signed = approved = rejected = None
    for e in entries:
        if e["kind"] == "decision":
            decisions[e["user_id"]] = {"decision": e["decision"], "note": e["note"], "author": e["author"], "at": e["at"]}
        elif e["kind"] == "sign":
            status, signed = "signed", e
        elif e["kind"] == "reject":
            status, rejected, signed = "open", e, None
        elif e["kind"] == "approve":
            status, approved = "approved", e
    active = [u for u in review["users"] if u["is_active"]]
    return {"status": status, "decisions": decisions, "signed": signed, "approved": approved, "rejected": rejected,
            "active": len(active), "decided": sum(1 for u in active if u["id"] in decisions),
            "missing": [u["username"] for u in active if u["id"] not in decisions]}


async def start(title: str, actor: str) -> int:
    users = await snapshot()
    row = await db.fetch_one("INSERT INTO access_reviews (title, started_by, users) VALUES (%s, %s, %s::jsonb) RETURNING id",
                             (title, actor, json.dumps(users, ensure_ascii=False)))
    return row["id"]


async def _load(conn: Any, review_id: int, lock: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cur = await conn.execute("SELECT id, title, started_by, started_at, users FROM access_reviews WHERE id = %s"
                             + (" FOR UPDATE" if lock else ""), (review_id,))
    review = await cur.fetchone()
    if review is None:
        raise ReviewError("권한 검토가 없습니다", 404)
    cur = await conn.execute("SELECT id, kind, user_id, username, decision, note, author, at FROM access_review_entries"
                             " WHERE review_id = %s ORDER BY id", (review_id,))
    return review, await cur.fetchall()


async def get(review_id: int) -> dict[str, Any]:
    async with db.pool().connection() as conn:
        review, entries = await _load(conn, review_id, lock=False)
    st = state(review, entries)
    now_active = {r["id"]: r["is_active"] for r in await db.fetch_all(
        "SELECT id, is_active FROM users WHERE id = ANY(%s)", ([u["id"] for u in review["users"]],))}
    for u in review["users"]:
        u["decision"] = st["decisions"].get(u["id"])
        u["now_active"] = now_active.get(u["id"])      # None = 지운 계정
    return {**review, "entries": entries, **{k: v for k, v in st.items() if k != "decisions"},
            "follow_up": follow_up(review["users"], st)}


def follow_up(users: list[dict[str, Any]], st: dict[str, Any]) -> list[str]:
    """회수로 정했는데 아직 켜져 있는 계정 (승인 전에도 보인다 — 화면은 '지금 끄기', 보고서는 승인된 검토만)."""
    return [u["username"] for u in users
            if (st["decisions"].get(u["id"]) or {}).get("decision") == "revoke" and u.get("now_active")]


async def add(review_id: int, kind: str, actor: str, *, user_id: int | None = None, decision: str | None = None,
              note: str = "") -> dict[str, Any]:
    """결정·서명·승인·반려 한 줄. 검토 행을 잠근 채 상태를 다시 읽어 판단한다(두 사람이 같이 눌러도 한쪽만)."""
    note = note.strip()[:1000]
    async with db.pool().connection() as conn, conn.transaction():
        review, entries = await _load(conn, review_id, lock=True)
        st = state(review, entries)
        username = None
        if kind == "decision":
            if st["status"] != "open":
                raise ReviewError("서명한 검토는 결정을 바꿀 수 없습니다 — 책임자가 반려하면 다시 바꿀 수 있습니다")
            user = next((u for u in review["users"] if u["id"] == user_id), None)
            if user is None or not user["is_active"]:
                raise ReviewError("이 검토에서 결정할 계정이 아닙니다 (시작할 때 켜져 있던 계정만)", 422)
            if decision not in DECISIONS:
                raise ReviewError(f"결정은 {', '.join(DECISIONS)} 중 하나", 422)
            if decision != "keep" and len(note) < 2:
                raise ReviewError("회수·조정은 사유를 적으세요", 422)
            username = user["username"]
        elif kind == "sign":
            if st["status"] != "open":
                raise ReviewError("이미 서명했거나 승인한 검토입니다")
            if st["missing"]:
                raise ReviewError(f"결정하지 않은 계정 {len(st['missing'])}개: {', '.join(st['missing'][:5])}", 422)
        elif kind in ("approve", "reject"):
            if st["status"] != "signed":
                raise ReviewError("서명한(승인 대기) 검토만 승인·반려합니다")
            if st["signed"]["author"] == actor:
                raise ReviewError("서명한 사람이 아닌 다른 관리자가 승인·반려합니다 (2단계 결재)", 403)
            if kind == "reject" and len(note) < 2:
                raise ReviewError("반려 사유를 적으세요", 422)
        else:
            raise ReviewError("알 수 없는 동작", 422)
        cur = await conn.execute(
            "INSERT INTO access_review_entries (review_id, kind, user_id, username, decision, note, author)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id, kind, user_id, username, decision, note, author, at",
            (review_id, kind, user_id if kind == "decision" else None, username, decision if kind == "decision" else None,
             note, actor))
        return {"entry": await cur.fetchone(), "title": review["title"]}


async def list_reviews() -> list[dict[str, Any]]:
    reviews = await db.fetch_all("SELECT id, title, started_by, started_at, users FROM access_reviews ORDER BY id DESC LIMIT 100")
    entries = await db.fetch_all(
        "SELECT review_id, id, kind, user_id, username, decision, note, author, at FROM access_review_entries"
        " WHERE review_id = ANY(%s) ORDER BY id", ([r["id"] for r in reviews],))
    by_review: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        by_review.setdefault(e["review_id"], []).append(e)
    out = []
    for r in reviews:
        st = state(r, by_review.get(r["id"], []))
        revokes = sum(1 for d in st["decisions"].values() if d["decision"] == "revoke")
        out.append({"id": r["id"], "title": r["title"], "started_by": r["started_by"], "started_at": r["started_at"],
                    "users": len(r["users"]), "active": st["active"], "decided": st["decided"], "status": st["status"],
                    "revokes": revokes, "signed_by": st["signed"] and st["signed"]["author"],
                    "approved_by": st["approved"] and st["approved"]["author"],
                    "approved_at": st["approved"] and st["approved"]["at"]})
    return out


async def overview(now: datetime, days: int) -> dict[str, Any]:
    """운영 준비도·점검 보고서용: 마지막 승인 시각·지난 날수·주기 넘김·진행 중인 검토·승인한 검토의 회수인데 켜진 계정."""
    reviews = await list_reviews()
    approved = next((r for r in reviews if r["status"] == "approved"), None)
    pending = [r for r in reviews if r["status"] != "approved"]
    follow: list[str] = []
    if approved:
        detail = await get(approved["id"])
        follow = detail["follow_up"]
    age = (now - approved["approved_at"]).days if approved else None
    return {"days": days, "last_approved_at": approved and approved["approved_at"], "age_days": age,
            "last_title": approved and approved["title"],
            "overdue": bool(days) and (age is None or age > days), "in_progress": [r["title"] for r in pending][:3],
            "follow_up": follow}


def attention(ar: dict[str, Any] | None) -> list[dict[str, str]]:
    """점검 필요 문구: 회수로 정했는데 켜진 계정, 주기를 넘긴 검토 — 점검 보고서·운영 준비도 공용."""
    if not ar:
        return []
    out = []
    if ar["follow_up"]:
        out.append({"level": "bad", "text": f"권한 검토에서 회수로 정했는데 아직 켜진 계정 {len(ar['follow_up'])}개: "
                                            f"{', '.join(ar['follow_up'][:5])} — 사용자 화면에서 끄세요"})
    if ar["overdue"]:
        when = (f"마지막 승인 {ar['age_days']}일 전('{ar['last_title']}')" if ar["age_days"] is not None
                else "승인한 권한 검토가 없습니다")
        out.append({"level": "warn", "text": f"권한 검토 주기({ar['days']}일)를 넘겼습니다 — {when}. 사용자 > 권한 검토"})
    return out
