"""대시보드 변수 (BACKLOG B-07 2단계) — DB 없는 단위 시험: 저장 전 변수 정의 검증.
화면 쪽 적용(문장에 조건 하나를 AND, Python 파서와 같은 뜻)은 server/tests/js/dashvars.test.mjs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.routers.dashboards import _validate

WIDGETS = [{"type": "events", "query": {"query": "event_id:4625"}}]


def _doc(variables):
    return {"widgets": WIDGETS, "variables": variables}


def test_valid_variables():
    _validate(_doc([{"name": "host", "key": "host", "label": "PC", "default": ""},
                    {"name": "logon_type", "key": "f.EventData.LogonType", "default": "10"},
                    {"name": "eid", "key": "event_id", "default": "4625"}]))
    _validate({"widgets": WIDGETS})   # 변수 없는 예전 대시보드


@pytest.mark.parametrize(("variables", "error"), [
    ("host", "배열"),
    ([{"name": f"v{i}", "key": "host"} for i in range(6)], "5개"),
    ([{"name": "Host", "key": "host"}], "name"),
    ([{"name": "host", "key": "host"}, {"name": "host", "key": "user"}], "겹칩니다"),
    ([{"name": "host", "key": "hostname"}], "key"),
    ([{"name": "x", "key": "f.."}], "key"),
    ([{"name": "eid", "key": "event_id", "default": "abc"}], "default"),
    ([{"name": "lvl", "key": "level", "default": 3}], "문자열"),
])
def test_bad_variables(variables, error):
    with pytest.raises(HTTPException) as exc:
        _validate(_doc(variables))
    assert exc.value.status_code == 422 and error in exc.value.detail


def test_shipped_dashboards_are_valid():
    # 저장소: server/tests → ../../config, 컨테이너: /app/tests → /app/config
    root = Path(__file__).resolve().parents[1]
    folder = next(p for p in (root / "config" / "dashboards", root.parent / "config" / "dashboards") if p.exists())
    docs = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in folder.glob("*.json")}
    for doc in docs.values():
        _validate(doc)
    assert docs["server"]["variables"][0]["key"] == "host"   # 서버 한 대 상세 — 변수의 예
