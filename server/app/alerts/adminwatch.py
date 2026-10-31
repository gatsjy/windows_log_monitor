"""관리 작업 알림 (BACKLOG B-36 2단계, ADR-043 보완): 탐지를 약하게 하거나 권한을 넓히는 관리 작업을 행위자와 다른 사람에게 알린다.

알림 설정 판본(ADR-043)은 alerts.yaml 만 본다. 그런데 받는 곳 쪽에서도 탐지를 끌 수 있다 — 수신 그룹에서 사람을 빼거나, 연동을 끄거나,
'받을 최소 수준'을 올리면 규칙은 그대로인데 알림이 아무에게도 가지 않는다. 감사로그에는 남지만 받던 사람은 모른다.
- 받는 곳 약화: 규칙·대체 경로가 쓰는 받는 곳에서 받는 사람이 빠짐·꺼짐·지워짐·최소 수준 올림·보내는 곳이 바뀜.
- 관리 권한 부여: 관리자 계정을 만들거나 관리자로 바꿈, 사용자 그룹에 관리 권한을 주거나 그런 그룹에 사람을 넣음.
- 보관 파일 복원: 지난 로그(개인정보)를 다시 검색할 수 있게 됨.
받는 곳 = 대체 경로(fallback_notify, 없으면 점검 보고서 받는 곳) + 켜진 규칙이 쓰는 받는 곳 — 이번에 약해진 곳은 뺀다.
내장 규칙 '관리 작업 알림'(kind config)이라 무음으로 막을 수 없다.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from ..auth import groups
from ..config import settings
from . import targets
from .builtin import ADMIN_RULE
from .engine import engine
from .message import AlertMessage
from .notifiers import SEVERITY_RANK

log = logging.getLogger(__name__)

# 탐지·받는 곳·접속기록·수집 키를 바꾸거나 볼 수 있는 권한 — 이것을 주는 것은 관리 권한 부여다
PRIVILEGED = groups.PRIVILEGED


async def _snapshot() -> dict[str, dict[str, Any]]:
    notifiers, errors = await targets.load_notifiers()
    out: dict[str, dict[str, Any]] = {}
    for name, n in notifiers.items():
        # 메일은 받는 사람 목록, 그 밖은 보내는 곳(주소의 비밀 부분은 target() 이 가린다)
        dest = tuple(sorted(getattr(n, "to", None) or ())) if n.type == "email" else (n.target(),)
        out[name] = {"type": n.type, "min_severity": n.min_severity, "dest": dest}
    for name, error in errors.items():
        out[name] = {"type": "-", "error": error}
    return out


def target_changes(before: dict[str, dict], after: dict[str, dict], watched: set[str]) -> tuple[list[str], set[str]]:
    """규칙·대체 경로가 쓰는 받는 곳 중 약해진 것: (문장들, 약해진 이름들)."""
    lines: list[str] = []
    hit: set[str] = set()
    for name in sorted(watched):
        old, new = before.get(name), after.get(name)
        if old is None or "error" in old:   # 원래 보내지 못하던 곳
            continue
        found = len(lines)
        if new is None:
            lines.append(f"'{name}' 이(가) 꺼졌거나 지워져 이제 알림을 받지 못합니다")
        elif "error" in new:
            lines.append(f"'{name}'(으)로 이제 보낼 수 없습니다: {new['error'][:120]}")   # 꺼짐·비밀값 문제 등
        else:
            if SEVERITY_RANK[new["min_severity"]] > SEVERITY_RANK[old["min_severity"]]:
                lines.append(f"'{name}' 받을 최소 수준 {old['min_severity']} → {new['min_severity']} (그보다 낮은 알림은 받지 않음)")
            if old["type"] == "email" and (gone := set(old["dest"]) - set(new["dest"])):
                lines.append(f"'{name}' 에서 받는 사람 {len(gone)}명이 빠졌습니다 (남은 {len(new['dest'])}명)")
            elif old["type"] != "email" and old["dest"] != new["dest"]:
                lines.append(f"'{name}' 의 보내는 곳이 바뀌었습니다 ({old['dest'][0]} → {new['dest'][0]})")
        if len(lines) > found:
            hit.add(name)
    return lines, hit


@contextlib.asynccontextmanager
async def watch_targets(actor: str, what: str) -> AsyncIterator[None]:
    """받는 곳을 바꾸는 저장을 감싼다: 앞뒤를 비교해 약해졌으면 알린다. 저장이 실패하면(예외) 아무것도 하지 않는다."""
    watched = set(engine.config.used_targets())
    before = await _snapshot() if watched else {}
    yield
    if not watched:
        return
    try:
        lines, hit = target_changes(before, await _snapshot(), watched)
        if lines:
            await notify(actor, f"알림 받는 곳을 약하게 하는 변경 {len(lines)}건 ({what})", lines, exclude=hit)
    except Exception:
        log.exception("관리 작업 알림 실패 (%s)", what)


async def notify(actor: str, summary: str, lines: list[str], *, exclude: set[str] | frozenset[str] = frozenset()) -> int | None:
    from .watchdog import watchdog  # 감시와 같은 대체 경로 (순환 import 방지)

    names = list(dict.fromkeys([*await watchdog.recipients(),
                                *(n for r in engine.config.rules if r.enabled for n in r.notify)]))
    recipients = tuple(n for n in names if n not in exclude)
    message = AlertMessage(
        rule=ADMIN_RULE, severity="warning", kind="config", group_by="none", group_key=f"관리 작업 · {actor}",
        event_count=len(lines), threshold=0, window_sec=0, fired_at=datetime.now(UTC),
        description=summary + "\n" + "\n".join(f"- {line}" for line in lines[:30]),
        link=f"{settings.public_url}/#/alerts")
    try:
        return await engine.fire(message, recipients)
    except Exception:
        log.exception("관리 작업 알림 실패: %s", summary)
        return None


async def privileged_group(actor: str, name: str, old: dict[str, Any] | None, new: dict[str, Any]) -> None:
    """사용자 그룹 저장: 관리 권한을 새로 주거나, 관리 권한이 있는 그룹에 사람을 넣었으면."""
    granted = (set(new["permissions"]) & PRIVILEGED) - (set(old["permissions"]) if old else set())
    privileged = set(new["permissions"]) & PRIVILEGED
    joined = set(new["member_ids"]) - (set(old["member_ids"]) if old else set())
    lines = []
    if granted and new["member_ids"]:
        lines.append(f"그룹 '{name}' 에 관리 권한 {', '.join(sorted(granted))} 을(를) 주었습니다 (구성원 {len(new['member_ids'])}명)")
    if privileged and joined:
        lines.append(f"관리 권한({', '.join(sorted(privileged))})이 있는 그룹 '{name}' 에 {len(joined)}명을 넣었습니다")
    if lines:
        await notify(actor, "관리 권한 부여", lines)
