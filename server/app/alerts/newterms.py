"""처음 보는 값 탐지 (BACKLOG B-47, ADR-063) — 엔진이 주기마다 부른다(engine.evaluate).

병원 서버는 접속 패턴이 안정적이라 '처음 보는 것'이 강한 신호다(관리자 계정의 새 출발지, 서버의 새 서비스, EMR DB 의 새 SQL 로그인).
- 받은 시각(received_at) 구간을 이어서 훑는다(new_terms_state.cursor_at) — 발생 시각(ts)은 PC 시계·밀린 로그에 흔들린다.
- 처음 켜면 learn 만큼 지난 로그로 거슬러 배우고(DB 에 있는 만큼), 모자란 기간은 앞으로 배운다. 배우는 동안 처음 본 값은 알리지 않는다.
- 조건(저장한 검색·match)이 바뀌면 본 값은 두고 다시 거슬러 배운다 — 배우는 동안 알림을 미뤄 '바꾼 직후 못 보는 구간'이 없게.
- 조합마다 알림 한 번(history 동안 다시 안 보이면 또). 알림을 넣는 것과 그 조합을 '알림'으로 바꾸는 것은 한 트랜잭션(insert_alert claim).
- 한 주기에 burst 개보다 많이 새로 보이면(서브넷 변경 등) 한 통으로 묶는다.
- max_terms 를 넘는 새 조합은 두지 않고 세기만 한다 — 그 평가는 규칙 오류로 알린다(지우면 '처음 보는 값'이 거짓으로 다시 나온다).
- 알릴 때 다시 본다: 지금 조건(예외 포함)에 맞는 로그가 없으면 알리지 않고 배운 것으로. 여러 PC 에서 보인 조합은 모든 PC 가 무음일 때만
  무음, 무음 중에 알린 조합이 무음이 끝난 뒤에도 보이면 다시 알린다.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from .. import db, repository
from ..config import display_zone
from .configdiff import rule_key
from .message import AlertMessage, search_link
from .rules import Rule

OVERLAP = timedelta(minutes=2)          # 받은 시각은 트랜잭션 시작 시각 — 늦게 커밋된 행을 놓치지 않게 앞 구간과 겹쳐 본다
CATCHUP_MAX = timedelta(days=3)         # 이보다 오래 멈췄으면(규칙을 꺼 둠·장애) 그 사이는 알리지 않고 배운다
SCAN_BUDGET_SEC = 8                     # 한 주기에 이 규칙이 훑는 시간 (규칙 시간 상한 안에서)
CHUNK_MIN, CHUNK_MAX = 60, 6 * 3600
SUMMARY_ITEMS = 20
PURGE_EVERY = timedelta(hours=6)
KEY_VALUE_MAX = 100                     # 대상 이름에 넣는 값 하나의 글자 수 — 알림 색인(btree 2704 바이트)을 넘지 않게 (값 전체는 payload 에)
FIRST_WINDOW = timedelta(hours=1)       # 알릴 때 다시 보는 구간: 처음 본 때부터 — 오래 미뤄 둔 조합이 며칠 치를 훑지 않게
HOSTS_MAX = 50
RECENT = timedelta(days=1)              # 알릴 때 PC 를 보는 최근 구간 (처음 본 때의 한 시간과 함께 — 오래 미뤘거나 무음 뒤 다시 연 조합)
SPREAD_EVERY = timedelta(minutes=5)     # PC 무음으로 보내지 않은 조합이 다른 PC 로 번졌나 보는 간격
SPREAD_MAX = 50
_spread: dict[int, datetime] = {}
_purged: dict[int, datetime] = {}       # 메모리 (워커 1개) — 다시 시작하면 한 번 더 지울 뿐
_ceiling: dict[int, int] = {}           # 시간 초과가 난 구간 크기 — 다시 그만큼 키우지 않는다 (다시 시작하면 한 번 더 겪을 뿐)


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
    if state is None and rule.sid is not None:
        # 손으로 쓴 규칙을 화면에서 저장하면 번호가 붙어 열쇠가 바뀐다 — 처음부터 다시 배우면 history 안의 값이 새 값이 됐다(검토에서 재현)
        legacy = await repository.new_terms_state(f"name:{rule.name}", fields)
        if legacy is not None:
            await repository.rekey_new_terms_state(legacy["id"], key)
            state = await repository.new_terms_state(key, fields)
    oldest = await repository.oldest_received() or now
    if state is None:
        start = max(now - rule.learn, oldest)
        # DB 에 있는 만큼 거슬러 배우고 모자란 만큼 앞으로 배운다
        learn_until = max(now, now + rule.learn - (now - start))
        return await repository.create_new_terms_state(key, fields, sig, now, learn_until, start, now, "처음")
    if now - state["cursor_at"] > CATCHUP_MAX:
        # 오래 멈춤(조건도 바뀌었으면 함께): 그 사이는 배우기만(밀린 것을 한꺼번에 '처음 보는 값'으로 알리지 않게). history 안이면 멈춘 때부터,
        # 조건이 바뀌었으면 새 조건으로 배우는 기간까지, 거슬러 배우던 중이었으면 그 남은 구간까지(덮어쓰면 앞부분을 영영 배우지 않았다).
        # 조건 바뀜을 먼저 보면 멈춘 동안 들어온 값이 모두 알림이 됐다(검토에서 재현)
        changed = state["filter_sig"] != sig
        frm = max(state["cursor_at"], now - rule.history)
        if changed:
            frm = min(frm, max(now - rule.learn, oldest))
        if state["backfill_to"] is not None and state["backfill_from"] is not None:
            frm = min(frm, state["backfill_from"])
        await repository.update_new_terms_state(state["id"], filter_sig=sig, cursor_at=now, backfill_from=frm, backfill_to=now,
                                                learn_until=max(state["learn_until"], now),
                                                relearn_reason=f"{(now - state['cursor_at']).days}일 멈춤"
                                                + (" · 조건 바뀜" if changed else ""))
        return await repository.new_terms_state(key, fields)
    if state["filter_sig"] != sig:
        # 조건이 바뀜: 본 값은 두고 새 조건으로 이미 훑은 곳(cursor_at)까지 다시 거슬러 배운다(그동안 알림은 미룸). 아직 훑지 않은
        # [cursor_at, 지금) 은 배우는 기간이 아니다 — 지금부터 거슬러 배우면 이어서 훑기보다 먼저 그 구간의 새 값을 '배운 값'으로 만들었다
        # (검토에서 재현). 그 구간의 값도 더 먼저 본 것이 있으면 거슬러 배우기가 배운 값으로 돌린다
        to = state["cursor_at"]
        frm = max(to - rule.learn, oldest)
        if state["backfill_to"] is not None and state["backfill_from"] is not None:
            frm = min(frm, state["backfill_from"])
        await repository.update_new_terms_state(state["id"], filter_sig=sig, backfill_from=min(frm, to), backfill_to=to,
                                                learn_until=max(state["learn_until"], state["cursor_at"]),
                                                relearn_reason="조건 바뀜")
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
    if state["overflow_n"] and state["terms_n"] < rule.max_terms:
        # 상한 오류는 자리가 다시 생길 때(max_terms 를 올림·오래된 값 정리)까지 — 한 평가만 오류로 두면 평가 간격이 길 때 감시가 알리지
        # 못한 채 두지 못한 값이 조용히 사라졌고(검토에서 재현), 끝없이 누적하면 상한을 올려도 오류가 영영 남았다
        await repository.update_new_terms_state(ns, overflow_n=0)

    async def scan(start: datetime, end: datetime, learning: bool, cursor: datetime | None,
                   count_from: datetime | None = None) -> dict[str, int]:
        nonlocal chunk
        t0 = time.monotonic()
        held = (await repository.new_terms_state(rule_key(rule), fields))["terms_n"]
        try:
            out = await repository.scan_new_terms(ns, base, fields, start, end, history=rule.history, learning=learning,
                                                  learn_until=state["learn_until"], room=max(0, rule.max_terms - held), cursor=cursor,
                                                  count_from=count_from)
        except db.QueryTimeout:
            _ceiling[ns] = min(_ceiling.get(ns, chunk), chunk)
            chunk = _clamp_chunk(chunk / 2)
            await repository.update_new_terms_state(ns, chunk_sec=chunk)
            raise
        # 꽉 찬 구간을 빨리 끝냈을 때만 키운다 — 이어서 훑기는 겹친 2분 남짓이라 늘 빨라서, 시간 초과로 줄인 크기를 다음 주기마다
        # 되돌려 거슬러 배우기가 같은 자리에서 영영 멈췄다(검토에서 재현). 시간 초과가 난 크기까지는 다시 키우지 않는다
        if end - start >= timedelta(seconds=chunk) and time.monotonic() - t0 < 2 and chunk * 2 < _ceiling.get(ns, CHUNK_MAX * 2):
            chunk = _clamp_chunk(chunk * 2)
        return out

    # 1) 이어서 훑기 (알릴 것)
    cursor = state["cursor_at"]
    while cursor < now and time.monotonic() - started < SCAN_BUDGET_SEC:
        end = min(cursor + timedelta(seconds=chunk), now)
        await scan(cursor - OVERLAP, end, False, end, count_from=cursor)   # 겹쳐 본 2분의 넘친 값은 앞 구간에서 셌다
        cursor = end
    # 2) 거슬러 배우기 (알리지 않음) — 최근부터 거꾸로, 구간마다 진행을 남긴다(시간 초과 한 번에 그 주기의 진행을 모두 잃지 않게)
    backfilling = state["backfill_to"] is not None
    if backfilling:
        to, frm = state["backfill_to"], state["backfill_from"]
        while to > frm and time.monotonic() - started < SCAN_BUDGET_SEC * 2:
            start = max(frm, to - timedelta(seconds=chunk))
            await scan(start, to, True, None)
            to = start
            if to > frm:
                await repository.update_new_terms_state(ns, backfill_to=to, chunk_sec=chunk)
        backfilling = to > frm
    await repository.update_new_terms_state(ns, chunk_sec=chunk,
                                            **({} if backfilling else {"backfill_to": None, "backfill_from": None}))
    if (last := _purged.get(ns)) is None or now - last > PURGE_EVERY:
        # 기준은 이어서 훑은 곳까지 — 지금으로 하면 아직 훑지 못한(밀린) 구간에 다시 보인 값을 지워 거짓 '처음 보는 값'이 됐다
        await repository.purge_seen_terms(ns, min(cursor, now) - rule.history - timedelta(days=1))
        _purged[ns] = now
    await repository.reopen_silenced_terms(ns, now)
    await _reopen_spread(rule, ns, base, now)
    current = await repository.new_terms_state(rule_key(rule), fields)
    over = current["overflow_n"]
    if run is not None:
        run.terms = {"terms": current["terms_n"], "max": rule.max_terms, "overflow": over,
                     "learn_until": current["learn_until"], "backfilling": backfilling,
                     "backfill_left_sec": int((current["backfill_to"] - current["backfill_from"]).total_seconds())
                     if current["backfill_to"] and current["backfill_from"] else 0,
                     "cursor_lag_sec": int((now - current["cursor_at"]).total_seconds()), "reason": current["relearn_reason"]}
    # 3) 알리기 — 거슬러 배우는 동안은 미룬다(배우다 '이미 본 값'으로 바뀔 수 있다)
    fired: list[int] = []
    if not backfilling:
        fired = await _fire(engine, rule, ns, base, saved, exceptions, now)
    if over:
        raise CappedError(f"값 조합 상한(max_terms {rule.max_terms:,}개)에 닿아 새 값을 두지 못하고 있습니다(지금까지 {over:,}번) — "
                          "그 값들은 알리지 않습니다. 조건을 좁히거나 max_terms 를 늘리세요")
    return fired


def _scoped(rule: Rule, base, values: list[str]):
    """그 조합의 로그만 — 잘린 값(256자, seen_terms)은 같음으로 찾을 수 없어 그 칸은 빼고 본다(더 넓게: 놓치는 쪽보다)."""
    from .engine import _with_group

    f = base
    for name, value in zip(rule.terms_fields, values, strict=True):
        if len(value) < TERM_SHOWN:
            f = _with_group(f, name, value)
    return f


TERM_SHOWN = 256   # seen_terms.term 에 두는 값 하나의 글자 수 (마이그레이션 039 의 left(v, 256))


def _key(values: list[str], term_hash: bytes) -> str:
    """대상 이름 — 값을 자르면 조합 열쇠(전체 값의 해시) 앞 10자리를 붙인다. 앞 100자가 같은 다른 값(인코딩한 PowerShell 등)이 같은
    대상이 되어 한쪽에 건 무음·함께 해결·중복 제거가 다른 쪽을 가렸다(검토에서 재현)."""
    cut = any(len(v) > KEY_VALUE_MAX for v in values)
    text = " · ".join(v if len(v) <= KEY_VALUE_MAX else v[:KEY_VALUE_MAX] + "…" for v in values)
    return f"{text} #{bytes(term_hash).hex()[:10]}" if cut else text


async def _hosts(rule: Rule, base, values: list[str], first_seen: datetime, now: datetime) -> list[str] | None:
    """그 조합을 본 PC — 처음 본 때부터 한 시간과 최근 하루. 없으면 [] (지금 조건에 맞는 로그 없음), 시간 초과면 None(모름)."""
    windows = [(first_seen - timedelta(minutes=1), first_seen + FIRST_WINDOW)]
    if first_seen + FIRST_WINDOW < now:
        windows.append((max(first_seen + FIRST_WINDOW, now - RECENT), now + timedelta(seconds=1)))
    hosts: dict[str, None] = {}
    try:
        for since, until in windows:
            f = replace(_scoped(rule, base, values), received_since=since, received_before=until)
            hosts.update(dict.fromkeys(r["value"] for r in await repository.top(f, "host", HOSTS_MAX) if r["value"]))
    except db.QueryTimeout:
        return None
    return list(hosts)


async def _reopen_spread(rule: Rule, ns: int, base, now: datetime) -> None:
    """PC 로 건 무음으로만 보내지 않은 조합이 그 뒤 무음이 없는 PC 에서도 보이면 다시 알릴 차례로 (5분마다, 50개까지).
    한 PC 의 점검 무음이 나중에 다른 PC 로 번진 새 값을 무음이 끝날 때까지 가렸다(검토에서 재현)."""
    if "host" in rule.terms_fields or (now - _spread.get(ns, now - SPREAD_EVERY)) < SPREAD_EVERY:
        return
    _spread[ns] = now
    reopen = []
    for row in await repository.host_silenced_terms(ns, now, SPREAD_MAX):
        values = list(row["term"])
        f = replace(_scoped(rule, base, values), received_since=max(row["fired_at"] - OVERLAP, now - RECENT))
        try:
            hosts = [r["value"] for r in await repository.top(f, "host", HOSTS_MAX) if r["value"]]
        except db.QueryTimeout:
            continue
        for h in hosts:
            if await repository.active_silence(rule.name, row["group_key"], now, h) is None:
                reopen.append((row["term_hash"], h))
                break
    if reopen:
        await repository.reopen_terms(ns, reopen)


def _link(rule: Rule, values: list[str], since: datetime, saved: str | None, exceptions: list[str]) -> str:
    from .engine import _link_params

    params = _link_params(rule, "", since, saved, exceptions)
    for name, value in zip(rule.terms_fields, values, strict=False):   # 몰려온 묶음 알림은 값 없이 규칙 조건만
        if len(value) < TERM_SHOWN:   # 잘린 값은 같음으로 찾지 못한다 — 그 칸은 빼고
            params[name] = value   # 주소 파라미터(account= 포함) — 문장에 붙이면 한도를 넘을 수 있다
    return search_link(params)


async def _fire(engine: Any, rule: Rule, ns: int, base, saved: str | None, exceptions: list[str], now: datetime) -> list[int]:
    from .engine import SAMPLE_COUNT, _sample, _with_group

    pending = await repository.pending_terms(ns, max(rule.burst + 1, SUMMARY_ITEMS))
    if not pending:
        return []
    days = int(rule.history.total_seconds() // 86400)
    common = {"rule": rule.name, "severity": rule.severity, "kind": "new_terms", "description": rule.description,
              "group_by": "none", "threshold": 1, "window_sec": int(rule.history.total_seconds()), "fired_at": now,
              "tags": list(rule.tags)}
    if len(pending) > rule.burst:
        # 한꺼번에 몰려옴 — 알릴 차례인 것을 모두 묶어 한 통 (그 조합들은 '묶어 알림'으로). 대상 이름에 처음 본 시각을 넣어 묶음마다
        # 다르게 — 수만 같으면 서로 다른 사고가 '같은 대상'이 되어 함께 해결·무음·중복 제거됐다(검토에서 재현)
        total = await repository.count_pending_terms(ns)
        items = [{"values": list(p["term"]), "first_ts": p["first_ts"].isoformat() if p["first_ts"] else None}
                 for p in pending[:SUMMARY_ITEMS]]
        since = pending[0]["first_seen"]
        message = AlertMessage(**common, group_key=f"처음 보는 값 {total:,}개 · {since.astimezone(display_zone()):%m-%d %H:%M:%S}~",
                               event_count=total, first_event_at=pending[0]["first_ts"], last_event_at=pending[-1]["first_ts"],
                               terms={"fields": list(rule.terms_fields), "count": total, "items": items, "history_days": days},
                               link=_link(rule, [], since - timedelta(minutes=1), saved, exceptions))
        alert_id = await engine.fire_rule(rule, message, claim={"ns": ns, "hashes": None, "state": "aggregated"})
        return [alert_id] if alert_id else []
    fired = []
    for p in pending:
        values = list(p["term"])
        first = replace(_scoped(rule, base, values), received_since=p["first_seen"] - timedelta(minutes=1),
                        received_before=p["first_seen"] + FIRST_WINDOW)
        # 다시 보기: 미뤄 둔 동안(거슬러 배우는 중) 예외를 걸었거나 조건을 바꿨으면 지금 조건에 맞는 로그가 없다 — 알리지 않고 배운 것으로.
        # 시간 초과면 모르니 알린다(놓치는 쪽보다)
        hosts = await _hosts(rule, base, values, p["first_seen"], now)
        if hosts == []:
            await repository.settle_terms(ns, [p["term_hash"]], "learned")
            continue
        if "host" in rule.terms_fields:
            host = values[rule.terms_fields.index("host")]
        else:
            host = p["first_host"] if not hosts or p["first_host"] in hosts else hosts[0]
        # 표본은 그 알림의 PC 것만 — 조회 범위·PC 경로로 받는 사람에게 범위 밖 PC 의 로그가 보였다(검토에서 재현).
        # 처음 본 때부터 지금까지(번진 PC 는 첫 한 시간 뒤에 보였을 수 있다)
        since_first = replace(first, received_before=None)
        try:
            samples = await repository.list_events(_with_group(since_first, "host", host) if host else since_first, SAMPLE_COUNT)
        except db.QueryTimeout:
            samples = []
        message = AlertMessage(
            **common, group_key=_key(values, p["term_hash"]), event_count=1, first_event_at=p["first_ts"], last_event_at=p["first_ts"],
            samples=[_sample(s) for s in samples],
            terms={"fields": list(rule.terms_fields), "values": values, "host": host, "history_days": days,
                   "first_ts": p["first_ts"].isoformat() if p["first_ts"] else None,
                   "prev_last_seen": p["prev_last_seen"].isoformat() if p["prev_last_seen"] else None},
            link=_link(rule, values, (p["first_ts"] or p["first_seen"]) - timedelta(minutes=1), saved, exceptions))
        # 여러 PC 에서 보인 조합은 PC 점검 무음이 모든 PC 에 걸렸을 때만 무음 — 한 PC 의 점검 무음이 다른 PC 의 새 출발지를 가렸다
        alert_id = await engine.fire_rule(rule, message, claim={"ns": ns, "hashes": [p["term_hash"]], "state": "alerted"},
                                          hosts=hosts if "host" not in rule.terms_fields and hosts and len(hosts) > 1 else None)
        if alert_id:
            fired.append(alert_id)
    return fired
