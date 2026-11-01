"""PC·서버 시계 차이 판단 (BACKLOG B-57 1단계, ISMS 2.9.6) — DB 없는 단위 시험."""

from __future__ import annotations

import pytest

from app import clock


@pytest.mark.parametrize(("ms", "level", "text"), [
    (None, None, None),
    (900, "ok", "PC 시계가 1초 늦음"),
    (-59_000, "ok", "PC 시계가 59초 빠름"),
    (61_000, "warn", "PC 시계가 1분 1초 늦음"),
    (-301_000, "bad", "PC 시계가 5분 1초 빠름"),
    (7_260_000, "bad", "PC 시계가 2시간 1분 늦음"),
])
def test_level_and_text(ms, level, text):
    assert clock.level(ms) == level
    if ms is not None:
        assert clock.describe(ms) == text


def _rows(*offsets):
    return [{"host": f"PC-{i}", "clock_offset_ms": ms} for i, ms in enumerate(offsets)]


def test_single_pcs_off():
    r = clock.assess(_rows(1_000, -2_000, 90_000, -400_000, None))
    assert r["known"] == 4 and r["warn"] == 1 and r["bad"] == 1 and r["server_suspect"] is None
    assert [o["host"] for o in r["off"]] == ["PC-3", "PC-2"]          # 많이 어긋난 것부터


def test_server_clock_suspected_when_most_pcs_lean_the_same_way():
    """PC 다섯 대 중 넷이 같은 쪽으로 2분씩 — PC 마다 고치기 전에 서버 시계부터."""
    r = clock.assess(_rows(120_000, 125_000, 118_000, 121_000, 500))
    assert r["server_suspect"]["pcs"] == 4 and "서버 시계가 빠를" in r["server_suspect"]["text"]
    r = clock.assess(_rows(-120_000, -125_000, -118_000, -121_000, -119_000))
    assert "서버 시계가 늦을" in r["server_suspect"]["text"]
    assert clock.assess(_rows(120_000, 125_000, 118_000, 121_000))["server_suspect"] is None     # 네 대로는 판단 안 함
    assert clock.assess(_rows(120_000, -125_000, 118_000, -121_000, 500))["server_suspect"] is None   # 양쪽으로 갈림
