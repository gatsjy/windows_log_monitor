"""대시보드 설정 API. 대시보드는 config/dashboards/<name>.json 파일이다 (git 으로 이력 관리 가능).

위젯 종류와 옵션은 docs/PROJECT.md '대시보드 위젯' 참고.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from .. import db
from ..auth.deps import client_ip, require_permission
from ..auth.service import User
from ..config import settings
from ..filters import MAX_FIELD_FILTERS, field_filters
from ..querylang import QueryError, format_value, parse_terms

router = APIRouter(tags=["dashboards"])

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
WIDGET_TYPES = {"stat", "timeseries", "top", "events", "hosts", "text", "alerts"}


def _path(name: str) -> Path:
    if not _NAME_RE.match(name):
        raise HTTPException(400, "대시보드 이름은 영문 소문자/숫자/-/_ 만 가능합니다")
    return Path(settings.dashboard_dir) / f"{name}.json"


VAR_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
VAR_KEYS = ("host", "user", "ip", "channel", "provider", "source", "category", "event_id", "level")   # web/js/dashvars.js 와 같게
MAX_VARS = 5


def _validate_variables(raw: object) -> None:
    """대시보드 변수 (B-07 2단계): [{name, key, label?, default?}] — key 는 검색 키 또는 f.<원본 경로>."""
    if raw is None:
        return
    if not isinstance(raw, list) or len(raw) > MAX_VARS:
        raise HTTPException(422, f"variables 는 {MAX_VARS}개까지의 배열이어야 합니다")
    names = set()
    for i, v in enumerate(raw):
        where = f"variables[{i}]"
        if not isinstance(v, dict) or not isinstance(v.get("name"), str) or not VAR_NAME_RE.match(v["name"]):
            raise HTTPException(422, f"{where}.name 은 영문 소문자로 시작하는 32자 이내 이름이어야 합니다 (주소의 var-<이름>)")
        if v["name"] in names:
            raise HTTPException(422, f"{where}.name 이 겹칩니다 ({v['name']})")
        names.add(v["name"])
        key = v.get("key")
        if not isinstance(key, str) or not (key in VAR_KEYS or (key.startswith("f.") and any(key[2:].split(".")))):
            raise HTTPException(422, f"{where}.key 는 {', '.join(VAR_KEYS)} 또는 f.<원본 경로>")
        for opt in ("label", "default"):
            if opt in v and not isinstance(v[opt], str):
                raise HTTPException(422, f"{where}.{opt} 는 문자열이어야 합니다")
        if (v.get("default") or "").strip():   # 기본값도 그 키의 값이어야 한다 (화면이 문장에 더하는 것과 같은 모양으로 확인)
            try:
                parse_terms(f"{key}:{format_value(v['default'].strip())}")
            except QueryError as exc:
                raise HTTPException(422, f"{where}.default: {exc}") from exc


def _validate(doc: dict) -> None:
    if not isinstance(doc, dict):
        raise HTTPException(422, "대시보드는 JSON 객체여야 합니다")
    _validate_variables(doc.get("variables"))
    widgets = doc.get("widgets")
    if not isinstance(widgets, list):
        raise HTTPException(422, "widgets 배열이 필요합니다")
    for i, widget in enumerate(widgets):
        if not isinstance(widget, dict) or widget.get("type") not in WIDGET_TYPES:
            raise HTTPException(422, f"widgets[{i}].type 은 {sorted(WIDGET_TYPES)} 중 하나여야 합니다")
        if "query" in widget and not isinstance(widget["query"], dict):
            raise HTTPException(422, f"widgets[{i}].query 는 객체여야 합니다")
        # 검색 문장(query.query)만 미리 확인한다. 옛 키는 지금처럼 그대로 저장 (기존 JSON 이 모두 저장되게)
        text = (widget.get("query") or {}).get("query")
        if text is not None:
            if not isinstance(text, str):
                raise HTTPException(422, f"widgets[{i}].query.query 는 문자열이어야 합니다")
            budget = MAX_FIELD_FILTERS - len(field_filters({str(k): v for k, v in widget["query"].items()}))
            try:
                parse_terms(text, field_budget=budget)
            except QueryError as exc:
                raise HTTPException(422, f"widgets[{i}].query.query: {exc}") from exc


@router.get("/api/dashboards")
async def list_dashboards():
    items = []
    for path in sorted(Path(settings.dashboard_dir).glob("*.json")):
        try:
            title = json.loads(path.read_text(encoding="utf-8")).get("title") or path.stem
        except (json.JSONDecodeError, OSError):
            title = f"{path.stem} (읽기 오류)"
        items.append({"name": path.stem, "title": title})
    items.sort(key=lambda d: (d["name"] != "overview", d["name"]))
    return {"items": items}


@router.get("/api/dashboards/{name}")
async def get_dashboard(name: str):
    path = _path(name)
    if not path.exists():
        raise HTTPException(404, "대시보드가 없습니다")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(500, f"{path.name} JSON 오류: {exc}") from exc


def _write(path: Path, doc: dict) -> str:
    """원자적 저장: 임시파일에 쓴 뒤 교체. 쓴 글을 돌려준다(감사로그 해시)."""
    text = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        Path(tmp).unlink(missing_ok=True)
        raise HTTPException(500, f"저장 실패: {exc}") from exc
    return text


# 위젯 더하기는 파일을 읽어 덧붙이고 쓴다 — 같은 대시보드에 두 사람이 동시에 더해도 하나가 사라지지 않게 (워커 1개, ADR-006)
_APPEND_LOCK = asyncio.Lock()


@router.put("/api/dashboards/{name}")
async def save_dashboard(name: str, request: Request, doc: dict = Body(...),
                         admin: User = Depends(require_permission("dashboards.edit"))):
    path = _path(name)
    _validate(doc)
    async with _APPEND_LOCK:
        text = _write(path, doc)
    await db.audit(
        admin.username,
        "dashboard.save",
        name,
        {"widgets": len(doc["widgets"]), "sha256": hashlib.sha256(text.encode()).hexdigest()},
        actor_ip=client_ip(request),
    )
    return doc


@router.post("/api/dashboards/{name}/widgets")
async def add_widget(name: str, request: Request, widget: dict = Body(...),
                     admin: User = Depends(require_permission("dashboards.edit"))):
    """검색 화면의 [대시보드에 추가] (B-07 1단계): 위젯 하나를 맨 뒤에 — 파일을 서버에서 읽어 덧붙인다(화면이 옛 JSON 을 통째로
    덮어 다른 사람의 변경을 지우지 않게). 검증·감사로그는 저장과 같다."""
    path = _path(name)
    async with _APPEND_LOCK:
        if not path.exists():
            raise HTTPException(404, "대시보드가 없습니다")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise HTTPException(409, f"{path.name} JSON 오류 — 편집기에서 먼저 고치세요: {exc}") from exc
        doc = {**doc, "widgets": [*(doc.get("widgets") or []), widget]}
        _validate(doc)
        text = _write(path, doc)
    await db.audit(admin.username, "dashboard.widget_add", name,
                   {"type": widget.get("type"), "title": widget.get("title"), "query": widget.get("query"),
                    "widgets": len(doc["widgets"]), "sha256": hashlib.sha256(text.encode()).hexdigest()},
                   actor_ip=client_ip(request))
    return {"ok": True, "index": len(doc["widgets"]) - 1}
