"""개체 페이지 API (BACKLOG B-67, ADR-064): PC·계정·IP 하나에 걸린 알림과 그 개체를 찾는 검색 문장.

- 알림은 개체 열(마이그레이션 046)로 찾고, 조회 범위는 알림 목록과 같은 (규칙, 대상, PC) 로 LIMIT 전에 거른다.
- 로그 쪽(건수·분류·상대 개체·최근 로그)은 화면이 검색 API(/api/events·/api/stats/*)를 여기서 준 문장으로 부른다 — 조회 범위·시간 상한·
  접속기록이 그쪽에서 그대로 붙는다(같은 조건을 두 번 구현하지 않게).
- 사람·IP 를 지목해 보는 조회라 접속기록(entity.view)을 남긴다 — 기록하지 못하면 503(ADR-042).
- 조회 범위가 있는 사용자: 개체 PC 는 그 알림의 규칙으로 볼 수 있는 것만(visibility.scrub_entities), PC 정보는 수집 PC 목록과 같은 판단.
  PC 정보가 범위 안 로그를 보므로 시간 상한(read_time_limit)을 건다.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .. import accesslog, repository
from ..alerts.visibility import entity_host_visible, scrub_entities
from ..filters import FilterError, parse_time
from ..querylang import QueryError, account_key, format_value, parse_terms
from .alerts import _visible_targets
from .query import agent_status, read_time_limit

router = APIRouter(tags=["entities"])

# 주소의 종류 → (alerts 개체 열의 종류, 검색 키). 사용자는 표기 통일 열쇠로 찾는다(account:, B-54)
KINDS = {"host": ("host", "host"), "user": ("account", "account"), "ip": ("ip", "ip")}
VALUE_MAX = 256   # wlm_alert_entities 가 넣는 값의 상한과 같게


@router.get("/api/entities/{kind}/{value:path}", dependencies=[Depends(read_time_limit)])
async def entity(kind: str, value: str, request: Request, since: str = "7d", limit: int = Query(200, ge=1, le=500)):
    if kind not in KINDS:
        raise HTTPException(404, "개체 종류는 host·user·ip 중 하나입니다")
    value = value.strip()
    if not value or len(value) > VALUE_MAX:
        raise HTTPException(400, f"값은 1~{VALUE_MAX}자입니다")
    column, key = KINDS[kind]
    if kind == "user":
        value = account_key(value)
    query = f"{key}:{format_value(value)}"
    try:
        parse_terms(query)   # 제어 문자 등 문장으로 만들 수 없는 값
        start = parse_time(since, datetime.now(UTC))
    except (QueryError, FilterError) as exc:
        raise HTTPException(400, str(exc)) from exc
    user = request.state.user
    pairs = _visible_targets(user, await repository.alert_group_counts(start)) if user.scopes is not None else None
    if pairs is not None and kind == "host":
        # 그 규칙으로 이 PC 를 볼 수 있는 알림만 — 보이는 알림(내 PC 의 처음 보는 값)이 범위 밖 PC 도 개체로 가지면 그 PC 이름으로
        # 찾아 '그 PC 에도 같은 값이 나왔다'를 알 수 있었다(검토에서 재현). LIMIT 전에 거른다
        pairs = [p for p in pairs if entity_host_visible(user, p[0], value)]
    rows = [scrub_entities(user, r) for r in await repository.entity_alerts(column, value, start, limit + 1, pairs)]
    agent = None
    if kind == "host":
        agent = await repository.agent_row(value, start, user.scopes)   # 수집 PC 목록과 같은 범위 판단
        if agent is not None:
            agent["status"] = agent_status(agent["silent_sec"])
    await accesslog.record(request, user.username, "entity.view", f"{kind}:{value}",
                           {"since": since, "alerts": len(rows[:limit])}, key={"since": since})
    return {"kind": kind, "value": value, "query": query, "alerts": rows[:limit], "truncated": len(rows) > limit,
            "agent": agent}
