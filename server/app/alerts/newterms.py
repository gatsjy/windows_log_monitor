"""처음 보는 값 탐지 (BACKLOG B-47, ADR-063) — 엔진이 주기마다 부른다(engine.evaluate).

병원 서버는 접속 패턴이 안정적이라 '처음 보는 것'이 강한 신호다(관리자 계정의 새 출발지, 서버의 새 서비스, EMR DB 의 새 SQL 로그인).
- 받은 시각(received_at) 구간을 이어서 훑는다(new_terms_state.cursor_at) — 발생 시각(ts)은 PC 시계·밀린 로그에 흔들린다.
- 처음 켜면 learn 만큼 지난 로그로 거슬러 배우고(DB 에 있는 만큼), 모자란 기간은 앞으로 배운다. 배우는 동안 처음 본 값은 알리지 않는다.
- 조건(저장한 검색·match)이 바뀌면 본 값은 두고 다시 거슬러 배운다 — 배우는 동안 알림을 미뤄 '바꾼 직후 못 보는 구간'이 없게.
- 조합마다 알림 한 번(history 동안 다시 안 보이면 또). 알림을 넣는 것과 그 조합을 '알림'으로 바꾸는 것은 한 트랜잭션(insert_alert claim).
- 한 주기에 burst 개보다 많이 새로 보이면(서브넷 변경 등) 한 통으로 묶는다.
- max_terms 를 넘는 새 조합은 두지 않고 세기만 한다 — 그러면 규칙 오류로 알린다(지우면 '처음 보는 값'이 거짓으로 다시 나온다).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from .. import db, repository
from .configdiff import rule_key
from .message import AlertMessage, search_link
from .rules import Rule

OVERLAP = timedelta(minutes=2)          # 받은 시각은 트랜잭션 시작 시각 — 늦게 커밋된 행을 놓치지 않게 앞 구간과 겹쳐 본다
CATCHUP_MAX = timedelta(days=3)         # 이보다 오래 멈췄으면(규칙을 꺼 둠·장애) 그 사이는 알리지 않고 배운다
SCAN_BUDGET_SEC = 8                     # 한 주기에 이 규칙이 훑는 시간 (규칙 시간 상한 안에서)
CHUNK_MIN, CHUNK_MAX = 60, 6 * 3600
SUMMARY_ITEMS = 20
PURGE_EVERY = timedelta(hours=6)
_purged: dict[int, datetime] = {}       # 메모리 (워커 1개) — 다시 시작하면 한 번 더 지울 뿐


class CappedError(RuntimeError):
    """상한을 넘어 새 조합을 두지 못했다 — 규칙 오류로 보인다(감시가 '알림 규칙 동작 안 함'으로 알림)."""


def filter_sig(rule: Rule, saved: str | None) -> str:
    """조건의 지문 — 저장한 검색 문장 + match. 예외(B-46)는 넣지 않는다(예외를 바꿀 때마다 다시 배우지 않게)."""
    return hashlib.sha256(json.dumps([saved or "", sorted(rule.match.items())], ensure_ascii=False).encode()).hexdigest()


def _clamp_chunk(sec: float) -> int:
    return int(min(CHUNK_MAX, max(CHUNK_MIN, sec)))


async def _state(rule: Rule, saved: str | None, now: datetime) -> dict[str, Any]:
    key, fields, sig = rule_key(rule), list(rule.terms_fields), filter_sig(rule, saved)
    state = await repository.new_terms_state(key, fields)
    oldest = await repository.oldest_received() or now
    if state is None:
        start = max(now - rule.learn, oldest)
        # DB 에 있는 만큼 거슬러 배우고 모자란 만큼 앞으로 배운다
        learn_until = max(now, now + rule.learn - (now - start))
        return await repository.create_new_terms_state(key, fields, sig, now, learn_until, start, now, "처음")
    if state["filter_sig"] != sig:
        # 조건이 바뀜: 본 값은 두고 새 조건으로 다시 거슬러 배운다(그동안 알림은 미룸)
        await repository.update_new_terms_state(state["id"], filter_sig=sig, backfill_from=max(now - rule.learn, oldest),
                                                backfill_to=now, learn_until=max(state["learn_until"], now),
                                                relearn_reason="조건 바뀜")
        return await repository.new_terms_state(key, fields)
    if now - state["cursor_at"] > CATCHUP_MAX:
        # 오래 멈춤: 그 사이는 배우기만(밀린 것을 한꺼번에 '처음 보는 값'으로 알리지 않게)
        await repository.update_new_terms_state(state["id"], cursor_at=now, backfill_from=max(state["cursor_at"], now - rule.learn),
                                                backfill_to=now, learn_until=max(state["learn_until"], now),
                                                relearn_reason=f"{(now - state['cursor_at']).days}일 멈춤")
        return await repository.new_terms_state(key, fields)
    return state


async def evaluate(engine: Any, rule: Rule, now: datetime, run: Any = None) -> list[int]:
    from .engine import rule_filter, saved_text  # 엔진이 이 모듈을 가져온다 — 순환을 피해 부를 때

    saved = await saved_text(rule)
    exceptions = await repository.active_rule_exceptions(rule.name, now)
    base = await rule_filter(rule, now, saved=saved or "")
    state = await _state(rule, saved, now)
    ns, fields = state["id"], list(rule.terms_fields)
    started = time.monotonic()
    chunk = state["chunk_sec"]

    async def scan(start: datetime, end: datetime, learning: bool, cursor: datetime | None) -> dict[str, int]:
        nonlocal chunk
        t0 = time.monotonic()
        held = (await repository.new_terms_state(rule_key(rule), fields))["terms_n"]
        try:
            out = await repository.scan_new_terms(ns, base, fields, start, end, history=rule.history, learning=learning,
                                                  learn_until=state["learn_until"], room=max(0, rule.max_terms - held), cursor=cursor)
        except db.QueryTimeout:
            chunk = _clamp_chunk(chunk / 2)
            await repository.update_new_terms_state(ns, chunk_sec=chunk)
            raise
        if time.monotonic() - t0 < 2:
            chunk = _clamp_chunk(chunk * 2)
        return out

    # 1) 이어서 훑기 (알릴 것)
    cursor = state["cursor_at"]
    while cursor < now and time.monotonic() - started < SCAN_BUDGET_SEC:
        end = min(cursor + timedelta(seconds=chunk), now)
        await scan(cursor - OVERLAP, end, False, end)
        cursor = end
    # 2) 거슬러 배우기 (알리지 않음) — 최근부터 거꾸로
    backfilling = state["backfill_to"] is not None
    if backfilling:
        to, frm = state["backfill_to"], state["backfill_from"]
        while to > frm and time.monotonic() - started < SCAN_BUDGET_SEC * 2:
            start = max(frm, to - timedelta(seconds=chunk))
            await scan(start, to, True, None)
            to = start
        backfilling = to > frm
        await repository.update_new_terms_state(ns, backfill_to=to if backfilling else None,
                                                backfill_from=frm if backfilling else None, chunk_sec=chunk)
    else:
        await repository.update_new_terms_state(ns, chunk_sec=chunk)
    if (last := _purged.get(ns)) is None or now - last > PURGE_EVERY:
        await repository.purge_seen_terms(ns, now - rule.history - timedelta(days=1))
        _purged[ns] = now
    current = await repository.new_terms_state(rule_key(rule), fields)
    if run is not None:
        span = (state["backfill_to"] - state["backfill_from"]).total_seconds() if backfilling and state["backfill_from"] else 0
        run.terms = {"terms": current["terms_n"], "max": rule.max_terms, "overflow": current["overflow_n"],
                     "learn_until": current["learn_until"], "backfilling": backfilling,
                     "backfill_left_sec": int((current["backfill_to"] - current["backfill_from"]).total_seconds())
                     if current["backfill_to"] and current["backfill_from"] else 0, "backfill_span_sec": int(span),
                     "cursor_lag_sec": int((now - current["cursor_at"]).total_seconds()), "reason": current["relearn_reason"]}
    # 3) 알리기 — 거슬러 배우는 동안은 미룬다(배우다 '이미 본 값'으로 바뀔 수 있다)
    fired: list[int] = []
    if not backfilling:
        fired = await _fire(engine, rule, ns, base, saved, exceptions, now)
    if current["overflow_n"]:
        raise CappedError(f"값 조합 상한(max_terms {rule.max_terms:,}개)을 넘어 새 값 {current['overflow_n']:,}개를 두지 못했습니다 — "
                          "그 값들은 알리지 않습니다. 조건을 좁히거나 max_terms 를 늘리세요")
    return fired


def _host_of(rule: Rule, values: list[str], first_host: str | None) -> str | None:
    return values[rule.terms_fields.index("host")] if "host" in rule.terms_fields else first_host


def _scoped(rule: Rule, base, values: list[str]):
    from .engine import _with_group

    f = base
    for name, value in zip(rule.terms_fields, values, strict=True):
        f = _with_group(f, name, value)
    return f


def _link(rule: Rule, values: list[str], since: datetime, saved: str | None, exceptions: list[str]) -> str:
    from .engine import _link_params

    params = _link_params(rule, "", since, saved, exceptions)
    for name, value in zip(rule.terms_fields, values, strict=False):   # 몰려온 묶음 알림은 값 없이 규칙 조건만
        params[name] = value   # 주소 파라미터(account= 포함) — 문장에 붙이면 한도를 넘을 수 있다
    return search_link(params)


async def _fire(engine: Any, rule: Rule, ns: int, base, saved: str | None, exceptions: list[str], now: datetime) -> list[int]:
    from .engine import SAMPLE_COUNT, _sample

    pending = await repository.pending_terms(ns, max(rule.burst + 1, SUMMARY_ITEMS))
    if not pending:
        return []
    days = int(rule.history.total_seconds() // 86400)
    common = {"rule": rule.name, "severity": rule.severity, "kind": "new_terms", "description": rule.description,
              "group_by": "none", "threshold": 1, "window_sec": int(rule.history.total_seconds()), "fired_at": now,
              "tags": list(rule.tags)}
    if len(pending) > rule.burst:
        # 한꺼번에 몰려옴 — 알릴 차례인 것을 모두 묶어 한 통 (그 조합들은 '묶어 알림'으로)
        total = await repository.count_pending_terms(ns)
        items = [{"values": list(p["term"]), "first_ts": p["first_ts"].isoformat() if p["first_ts"] else None}
                 for p in pending[:SUMMARY_ITEMS]]
        message = AlertMessage(**common, group_key=f"처음 보는 값 {total:,}개", event_count=total,
                               first_event_at=pending[0]["first_ts"], last_event_at=pending[-1]["first_ts"],
                               terms={"fields": list(rule.terms_fields), "count": total, "items": items, "history_days": days},
                               link=_link(rule, [], pending[0]["first_seen"] - timedelta(minutes=1), saved, exceptions))
        alert_id = await engine.fire_rule(rule, message, claim={"ns": ns, "hashes": None, "state": "aggregated"})
        return [alert_id] if alert_id else []
    fired = []
    for p in pending:
        values = list(p["term"])
        scoped = replace(_scoped(rule, base, values), received_since=p["first_seen"] - timedelta(minutes=1))
        try:
            samples = await repository.list_events(scoped, SAMPLE_COUNT)
        except db.QueryTimeout:
            samples = []
        host = _host_of(rule, values, p["first_host"])
        message = AlertMessage(
            **common, group_key=" · ".join(values), event_count=1, first_event_at=p["first_ts"], last_event_at=p["first_ts"],
            samples=[_sample(s) for s in samples],
            terms={"fields": list(rule.terms_fields), "values": values, "host": host, "history_days": days,
                   "first_ts": p["first_ts"].isoformat() if p["first_ts"] else None,
                   "prev_last_seen": p["prev_last_seen"].isoformat() if p["prev_last_seen"] else None},
            link=_link(rule, values, (p["first_ts"] or p["first_seen"]) - timedelta(minutes=1), saved, exceptions))
        alert_id = await engine.fire_rule(rule, message, claim={"ns": ns, "hashes": [p["term_hash"]], "state": "alerted"})
        if alert_id:
            fired.append(alert_id)
    return fired
