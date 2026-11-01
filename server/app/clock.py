"""PC·서버 시계 차이 판단 (BACKLOG B-57 1단계, ISMS 2.9.6 시각 동기화).

하트비트의 발생 시각(PC 시계)과 받은 시각의 차이를 일정 시간 동안의 최솟값으로 걸러 시계 차이로 본다(repository.CLOCK_OFFSET_SQL).
값 = 서버 시계 − PC 시계: 양수면 PC 시계가 늦고(또는 전송이 늦고), 음수면 PC 시계가 빠르다.
로그의 발생 시각(ts)이 틀리면 검색·알림 구간·사고 시간선이 어긋나고, 5분을 넘으면 Kerberos 인증도 실패한다.
여러 PC 가 같은 쪽으로 쏠리면 PC 들보다 서버 시계를 먼저 의심한다 — 서버 시계 점검은 따로 없고 이것이 맡는다.
수집 PC 화면·점검 보고서·운영 준비도가 같이 쓴다(판단을 한 곳에).
"""

from __future__ import annotations

from statistics import median
from typing import Any

WARN_SEC = 60          # 로그 시각이 1분 넘게 어긋나면 사고 시간선을 맞추기 어렵다
BAD_SEC = 300          # Kerberos 허용 오차(기본 5분) — 넘으면 도메인 로그온이 실패한다
SERVER_MIN_PCS = 5     # 서버 시계를 의심하려면 이만큼의 PC 가 시계를 알려야 한다
SERVER_SHARE = 0.8     # 그중 이 비율이 같은 쪽으로 WARN_SEC 넘게 어긋나면


def level(offset_ms: int | None) -> str | None:
    if offset_ms is None:
        return None
    sec = abs(offset_ms) / 1000
    return "bad" if sec >= BAD_SEC else "warn" if sec >= WARN_SEC else "ok"


def describe(offset_ms: int) -> str:
    """'PC 시계가 2분 늦음' / '… 빠름' (화면·보고서 공용 문구)."""
    sec = round(abs(offset_ms) / 1000)
    amount = f"{sec // 3600}시간 {sec % 3600 // 60}분" if sec >= 3600 else f"{sec // 60}분 {sec % 60}초" if sec >= 60 else f"{sec}초"
    return f"PC 시계가 {amount} {'늦음' if offset_ms > 0 else '빠름'}"


def assess(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """rows = repository.agents 의 행(host, clock_offset_ms). 시계를 아는 PC 만 본다.
    server_suspect: 대부분의 PC 가 같은 쪽으로 어긋남 — PC 마다 고치기 전에 서버 시계(NTP)부터."""
    known = [r for r in rows if r.get("clock_offset_ms") is not None]
    off = [{"host": r["host"], "offset_ms": int(r["clock_offset_ms"]), "level": level(r["clock_offset_ms"]),
            "text": describe(int(r["clock_offset_ms"]))}
           for r in known if level(r["clock_offset_ms"]) != "ok"]
    off.sort(key=lambda o: -abs(o["offset_ms"]))
    suspect = None
    if len(known) >= SERVER_MIN_PCS:
        for sign in (1, -1):
            same = [r for r in known if sign * r["clock_offset_ms"] >= WARN_SEC * 1000]
            if len(same) >= SERVER_SHARE * len(known):
                mid = int(median(r["clock_offset_ms"] for r in same))
                suspect = {"pcs": len(same), "of": len(known), "median_ms": mid,
                           "text": f"PC {len(known)}대 중 {len(same)}대가 같은 쪽으로 어긋남(가운데 값 {describe(mid)})"
                                   f" — 서버 시계가 {'빠를' if sign > 0 else '늦을'} 수 있습니다. 서버의 NTP 부터 확인하세요"}
    return {"known": len(known), "off": off, "bad": sum(1 for o in off if o["level"] == "bad"),
            "warn": sum(1 for o in off if o["level"] == "warn"), "server_suspect": suspect}
