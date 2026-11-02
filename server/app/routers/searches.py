"""저장한 검색 API (BACKLOG B-64): 정기 점검의 반복 검색을 이름 붙여 저장·공유하고 최근 검색을 다시 쓴다.

- 누구나 자기 검색을 저장한다. 공유(shared)하면 모두에게 보인다. 고치고 지우는 것은 만든 사람이나 관리자.
- 보호(protected): 점검 기준으로 정한 검색 — 관리자만 고치거나 지운다.
- 알림 규칙이 match.saved 로 쓰는 검색은 지우거나 이름을 바꿀 수 없다(쓰는 곳). 문장을 고치면 다음 평가부터 그 규칙에 반영된다.
  그래서 규칙이 쓰는 검색은 알림 규칙을 고칠 수 있는 사람(alerts.manage)만 고치고(보호된 것은 그래도 관리자만), 고치면 관리 작업 알림을
  보낸다 — 만든 사람이 문장을 바꿔 탐지를 조용히 끌 수 있었다(규칙 파일의 판본·약화 알림을 거치지 않는 길).
- 규칙이 가리키는데 아직 없는 이름(파일을 직접 고침·DB 복원)으로 새로 만들거나 이름을 바꾸는 것도 같다 — 그 규칙의 조건을 정하는 일이라
  alerts.manage 가 있어야 하고 관리 작업 알림을 보낸다(검토에서 재현: 조회자가 빈 이름을 먼저 만들어 규칙을 끌 수 있었다).
- 규칙의 문장·예외와 합친 조건이 검색 문장 한도를 넘으면 저장하지 않는다(평가마다 실패하지 않게).
- 검색 문장은 querylang 으로 확인해 정본 표기로 저장한다. 최근 검색은 이 사용자의 접속기록(events.search)에서.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import db, repository
from ..alerts import adminwatch
from ..alerts.engine import engine, rule_filter
from ..auth.deps import client_ip, require_user
from ..auth.service import User
from ..filters import FilterError
from ..querylang import QueryError, format_query, parse_terms

router = APIRouter(tags=["searches"])
RECENT_DAYS = 30


class SearchBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    query: str = Field(min_length=1, max_length=2000)
    description: str = Field(default="", max_length=500)
    shared: bool = False
    protected: bool = False


def _canonical(text: str) -> str:
    try:
        terms = parse_terms(text)
    except QueryError as exc:
        raise HTTPException(400, f"검색 문장 오류: {exc}") from exc
    if not terms:
        raise HTTPException(400, "빈 검색은 저장하지 않습니다")
    return format_query(terms)


def used_by(name: str) -> list[str]:
    """이 검색을 쓰는 알림 규칙 (match.saved)."""
    return [r.name for r in engine.config.rules if r.match.get("saved") == name]


def _view(row: dict[str, Any], user: User) -> dict[str, Any]:
    users = used_by(row["name"])
    if row["protected"]:
        can_edit = user.is_admin
    elif users:
        can_edit = user.can("alerts.manage")
    else:
        can_edit = user.is_admin or row["owner"] == user.username
    return {**row, "used_by": users, "can_edit": can_edit}


def _refusal(row: dict[str, Any]) -> str:
    if row["protected"]:
        return "보호된 검색은 관리자만 고칠 수 있습니다"
    if used_by(row["name"]):
        return "알림 규칙이 쓰는 검색은 알림 규칙을 고칠 수 있는 사람만 고칩니다"
    return "만든 사람이나 관리자만 고칠 수 있습니다"


async def _rules_accept(name: str, query: str, user: User) -> list[str]:
    """이 이름을 쓰는 규칙(지금 없는 이름을 가리키는 규칙 포함): 그 규칙의 조건을 정하는 일이라 alerts.manage, 합친 조건이 한도 안인지."""
    users = used_by(name)
    if not users:
        return []
    if not user.can("alerts.manage"):
        raise HTTPException(403, f"알림 규칙 {', '.join(users)} 이(가) 이 이름의 검색을 씁니다 — 알림 규칙을 고칠 수 있는 사람만 정합니다")
    now = datetime.now(UTC)
    for rule in engine.config.rules:
        if rule.name in users:
            try:
                await rule_filter(rule, now, saved=query)
            except FilterError as exc:
                raise HTTPException(400, f"알림 규칙 '{rule.name}' 의 조건과 합치면: {exc}") from exc
    return users


async def _notify_rules(user: User, name: str, rules: list[str], lines: list[str]) -> None:
    await adminwatch.notify(user.username, "알림 규칙이 쓰는 저장한 검색을 바꿨습니다 — 다음 평가부터 그 규칙의 조건이 바뀝니다",
                            [f"검색 '{name}'", *lines, *(f"규칙 '{r}'" for r in rules)])


async def _editable(search_id: int, user: User) -> dict[str, Any]:
    row = await repository.get_saved_search(search_id)
    if row is None or not (row["shared"] or row["owner"] == user.username or user.is_admin):
        raise HTTPException(404, "저장한 검색이 없습니다")
    if not _view(row, user)["can_edit"]:
        raise HTTPException(403, _refusal(row))
    return row


@router.get("/api/searches")
async def list_searches(user: User = Depends(require_user)):
    rows = await repository.list_saved_searches(user.username, everything=user.is_admin)
    return {"items": [_view(r, user) for r in rows]}


@router.get("/api/searches/recent")
async def recent(user: User = Depends(require_user)):
    """최근 검색 문장 (이 사용자의 접속기록에서, 30일)."""
    rows = await repository.recent_searches(user.username, datetime.now(UTC) - timedelta(days=RECENT_DAYS))
    return {"items": rows}


@router.post("/api/searches")
async def create_search(body: SearchBody, request: Request, user: User = Depends(require_user)):
    query = _canonical(body.query)
    if body.protected and not user.is_admin:
        raise HTTPException(403, "보호는 관리자만 정합니다")
    rules = await _rules_accept(body.name.strip(), query, user)
    row = await repository.insert_saved_search(body.name.strip(), query, body.description.strip(), user.username, body.shared)
    if row is None:
        raise HTTPException(409, f"'{body.name.strip()}' 이름의 검색이 이미 있습니다")
    if body.protected:
        row = await repository.update_saved_search(row["id"], row["name"], query, row["description"], row["shared"], True)
    await db.audit(user.username, "search.save", row["name"], {"query": query, "shared": row["shared"],
                                                                 "protected": row["protected"], "used_by": rules},
                   actor_ip=client_ip(request))
    if rules:
        await _notify_rules(user, row["name"], rules, [f"새로 만듦: {query}"])
    return _view(row, user)


@router.put("/api/searches/{search_id}")
async def update_search(search_id: int, body: SearchBody, request: Request, user: User = Depends(require_user)):
    old = await _editable(search_id, user)
    query = _canonical(body.query)
    name = body.name.strip()
    if body.protected != old["protected"] and not user.is_admin:
        raise HTTPException(403, "보호는 관리자만 정합니다")
    if name != old["name"] and (users := used_by(old["name"])):
        raise HTTPException(409, f"알림 규칙 {', '.join(users)} 이(가) 이 이름으로 씁니다 — 이름을 바꾸려면 규칙부터 고치세요")
    rules = await _rules_accept(name, query, user)   # 이름이 같으면 지금 쓰는 규칙, 바꾸면 그 이름을 가리키던 규칙
    row = await repository.update_saved_search(search_id, name, query, body.description.strip(), body.shared, body.protected)
    if row is None:
        raise HTTPException(409, f"'{name}' 이름의 검색이 이미 있습니다")
    await db.audit(user.username, "search.update", row["name"],
                   {"old_name": old["name"], "old_query": old["query"], "query": query, "shared": row["shared"],
                    "protected": row["protected"], "used_by": rules}, actor_ip=client_ip(request))
    if rules and (query != old["query"] or name != old["name"]):
        await _notify_rules(user, row["name"], rules,
                            [f"이름: {old['name']} → {name}"] * (name != old["name"]) + [f"전: {old['query']}", f"후: {query}"])
    return _view(row, user)


@router.delete("/api/searches/{search_id}")
async def delete_search(search_id: int, request: Request, user: User = Depends(require_user)):
    old = await _editable(search_id, user)
    if users := used_by(old["name"]):
        raise HTTPException(409, f"알림 규칙 {', '.join(users)} 이(가) 이 검색을 씁니다 — 규칙에서 먼저 빼세요")
    await repository.delete_saved_search(search_id)
    await db.audit(user.username, "search.delete", old["name"], {"query": old["query"]}, actor_ip=client_ip(request))
    return {"ok": True}
