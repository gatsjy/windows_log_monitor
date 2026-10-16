"""검색 문장의 상수·오류 문구가 서버(querylang.py)와 화면(web/js/querylang.js)에서 같은지 (B-01, ADR-033).

컨테이너에는 node 가 없어서 JS 파서는 개발 PC 에서 따로 시험한다(node --test 'server/tests/js/*.test.mjs').
여기서는 JS 파일의 @sync 블록(엄격한 JSON)을 읽어 Python 의 SYNC 와 비교한다 — 어휘·문구가 어긋나면 node 없이도 실패.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.alerts.message import LEVEL_LABELS
from app.alerts.rules import MATCH_KEYS
from app.config import settings
from app.normalizers.categories import CATEGORIES
from app.querylang import SYNC

JS = Path(settings.web_dir) / "js" / "querylang.js"


def js_sync() -> dict:
    text = JS.read_text(encoding="utf-8")
    m = re.search(r"/\* @sync:begin \*/(.*?)/\* @sync:end \*/", text, re.DOTALL)
    assert m, "web/js/querylang.js 에 @sync 블록이 없습니다"
    return json.loads(m.group(1))


def test_js_constants_match_python():
    assert js_sync() == SYNC


def test_vocabulary_matches_the_rest_of_the_app():
    assert SYNC["categories"] == list(CATEGORIES)          # 분류를 추가하면 여기도 (닫힌 집합)
    assert {int(k): v[0] for k, v in SYNC["levels"].items()} == LEVEL_LABELS
    assert set(SYNC["keys"]) - {"msg"} == MATCH_KEYS - {"q", "query"}
    assert all(code in SYNC["categories"] for code in SYNC["category_hints"].values())
