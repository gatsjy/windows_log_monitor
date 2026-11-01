"""이 시스템의 접속기록 (ADR-042, BACKLOG B-38): 개인정보가 보이는 조회를 감사로그에 남긴다.

대시보드 위젯·실시간 화면(다시 연결)·보고서 화면(목록 + iframe)은 같은 조건으로 되풀이해 부르므로, 같은 사람·같은 행위·같은 조건은
10분에 한 번만 기록한다. 기록을 못 하면 결과를 내주지 않는다(required=True → db.AuditError → 503) — 기록 없이 열람되지 않게.
묶음은 프로세스 메모리(워커 1개, ADR-006). 서버를 다시 시작하면 한 번 더 기록될 뿐이다.
"""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import Request

from . import db
from .auth.deps import client_ip

EVERY = 600.0
_seen: dict[tuple[str, str, str, str], float] = {}


def conditions(request: Request, drop: tuple[str, ...] = ("limit",)) -> dict[str, str]:
    """조회 조건(쿼리 문자열) — 건수 상한처럼 무엇을 봤는지와 상관없는 것은 뺀다."""
    return {k: v for k, v in request.query_params.items() if k not in drop}


async def record(request: Request, username: str, action: str, target: str | None, detail: dict[str, Any],
                 key: Any = None) -> None:
    """key: 같은 조회로 볼 기준(기본 detail). 결과 건수처럼 부를 때마다 달라지는 값은 detail 에만 넣고 key 에서 뺀다."""
    k = (username, action, target or "", json.dumps(detail if key is None else key, sort_keys=True, ensure_ascii=False, default=str))
    now = time.monotonic()
    if now - _seen.get(k, -EVERY) < EVERY:
        return
    if len(_seen) > 10000:
        _seen.clear()
    await db.audit(username, action, target, detail, actor_ip=client_ip(request), required=True)
    _seen[k] = now   # 기록에 성공한 뒤에만 (실패하면 다음 조회에서 다시 시도)


def forget() -> None:
    """시험용 — 묶음 기억을 비운다."""
    _seen.clear()
