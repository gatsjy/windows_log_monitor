"""대시보드 설정 API. 대시보드는 config/dashboards/<name>.json 파일이다 (git 으로 이력 관리 가능).

위젯 종류와 옵션은 docs/PROJECT.md '대시보드 위젯' 참고.
"""

from __future__ import annotations

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

router = APIRouter(tags=["dashboards"])

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
WIDGET_TYPES = {"stat", "timeseries", "top", "events", "hosts", "text", "alerts"}


def _path(name: str) -> Path:
    if not _NAME_RE.match(name):
        raise HTTPException(400, "대시보드 이름은 영문 소문자/숫자/-/_ 만 가능합니다")
    return Path(settings.dashboard_dir) / f"{name}.json"


def _validate(doc: dict) -> None:
    if not isinstance(doc, dict):
        raise HTTPException(422, "대시보드는 JSON 객체여야 합니다")
    widgets = doc.get("widgets")
    if not isinstance(widgets, list):
        raise HTTPException(422, "widgets 배열이 필요합니다")
    for i, widget in enumerate(widgets):
        if not isinstance(widget, dict) or widget.get("type") not in WIDGET_TYPES:
            raise HTTPException(422, f"widgets[{i}].type 은 {sorted(WIDGET_TYPES)} 중 하나여야 합니다")
        if "query" in widget and not isinstance(widget["query"], dict):
            raise HTTPException(422, f"widgets[{i}].query 는 객체여야 합니다")


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


@router.put("/api/dashboards/{name}")
async def save_dashboard(name: str, request: Request, doc: dict = Body(...),
                         admin: User = Depends(require_permission("dashboards.edit"))):
    path = _path(name)
    _validate(doc)
    text = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    # 원자적 저장: 임시파일에 쓴 뒤 교체
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        Path(tmp).unlink(missing_ok=True)
        raise HTTPException(500, f"저장 실패: {exc}") from exc
    await db.audit(
        admin.username,
        "dashboard.save",
        name,
        {"widgets": len(doc["widgets"]), "sha256": hashlib.sha256(text.encode()).hexdigest()},
        actor_ip=client_ip(request),
    )
    return doc
