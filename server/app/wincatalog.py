"""Windows 이벤트 해석 (BACKLOG B-68): 한 줄 요약과 코드 풀이.

목록·알림 표본이 Windows 가 렌더링한 Message 를 그대로 보여 주는데 길고, 서버 언어에 따라 한국어·영어가 섞이며,
LogonType 10·SubStatus 0xC000006A·%%2313 같은 코드는 사전 없이 읽을 수 없었다. 사전은 app/catalog/windows.json —
요약 틀은 EventData 이름({TargetUserName})으로 쓰고, 코드인 칸은 그 칸 이름의 사전으로 풀어 쓴다.
값은 로그에서 온 것이므로 화면·보고서에 넣을 때 escape 한다(이 모듈은 글만 만든다).
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).parent / "catalog" / "windows.json"
_PLACE = re.compile(r"\{([A-Za-z0-9_/]+)\}")
_BLANK = ("", "-")
SUMMARY_MAX = 300


@lru_cache(maxsize=1)
def catalog() -> dict[str, Any]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def event_data(raw: Any) -> dict[str, Any] | None:
    """저장된 원본에서 EventData 이름 맵 — 에이전트가 보낸 맵, 없으면 서버가 StringInserts 에 붙인 맵 (ADR-038)."""
    if not isinstance(raw, dict):
        return None
    data = raw.get("EventData")
    if isinstance(data, dict):
        return data
    win = raw.get("winevtlog")
    data = win.get("EventData") if isinstance(win, dict) else None
    return data if isinstance(data, dict) else None


def _book(field: str, overrides: dict[str, str]) -> dict[str, str] | None:
    books = catalog()["codes"]
    book = books.get(overrides.get(field, field))
    if isinstance(book, str):          # 다른 사전을 가리키는 이름 (SubStatus → Status)
        book = books.get(book)
    return book if isinstance(book, dict) else None


def meaning(field: str, value: Any, overrides: dict[str, str] | None = None) -> str | None:
    """코드의 뜻. 16진수는 대소문자·앞의 0 과 상관없이(0xC000006A = 0xc000006a, 0x00000018 = 0x18)."""
    book = _book(field, overrides or {})
    if book is None or value is None:
        return None
    text = str(value).strip()
    key = text.lower()
    if key.startswith("0x"):
        try:
            key = hex(int(key, 16))
        except ValueError:
            pass
    return book.get(key) or book.get(text)


def _empty(value: Any) -> bool:
    return value is None or str(value).strip() in _BLANK


def _render(data: dict[str, Any], names: str, overrides: dict[str, str]) -> str | None:
    """{A/B}: A 가 비었거나 0x0(성공·해당 없음)이면 B — 4625 의 SubStatus 는 0x0 일 때 Status 가 실제 이유다."""
    choices = names.split("/")
    for n, name in enumerate(choices):
        value = data.get(name)
        last = n == len(choices) - 1
        if _empty(value) or (not last and str(value).strip().lower() in ("0x0", "0x00000000")):
            if last:
                return None
            continue
        return meaning(name, value, overrides) or str(value).strip()
    return None


def summarize(provider: str | None, event_id: Any, raw: Any) -> str | None:
    """한 줄 요약 (사전에 없는 이벤트·EventData 가 없으면 None). 값이 없는 칸은 '–', 그 칸만 든 괄호·꼬리는 뺀다."""
    spec = catalog()["events"].get(provider or "", {}).get(str(event_id))
    data = event_data(raw)
    if not spec or data is None:
        return None
    overrides = spec.get("codes") or {}
    text = _PLACE.sub(lambda m: _render(data, m.group(1), overrides) or "–", spec["summary"])
    text = text.replace(" (–)", "")
    text = text.removesuffix(" — –")
    return text[:SUMMARY_MAX]


def decode(provider: str | None, event_id: Any, raw: Any) -> list[dict[str, Any]]:
    """코드인 칸의 뜻 — 상세 패널의 '코드 풀이' (사전에 있는 칸만)."""
    data = event_data(raw)
    if data is None:
        return []
    spec = catalog()["events"].get(provider or "", {}).get(str(event_id)) or {}
    overrides = spec.get("codes") or {}
    out = []
    for field, value in data.items():
        text = meaning(field, value, overrides)
        if text:
            out.append({"field": field, "value": value, "meaning": text})
    return out
