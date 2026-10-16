"""crossfuzz.test.mjs 가 부른다: 표준 입력의 JSON 줄(검색 문장)마다 Python 쪽 결과를 JSON 줄로 낸다.

개발 PC 의 python3 -I 로 돈다 (querylang·filters 는 표준 라이브러리만 쓴다). -I 는 PYTHONPATH 를 무시하므로
<저장소>/server 를 직접 sys.path 에 넣는다.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.filters import EventFilter  # noqa: E402
from app.querylang import QueryError, parse_terms  # noqa: E402

CASES = json.loads((Path(__file__).resolve().parents[1] / "querylang_cases.json").read_text(encoding="utf-8"))

for line in sys.stdin:
    text = json.loads(line)
    try:
        terms = [t.to_json() for t in parse_terms(text)]
    except QueryError as exc:
        print(json.dumps({"error": exc.as_dict()}, ensure_ascii=False))
        continue
    f = EventFilter.from_params({"query": text}, default_since=None)
    print(json.dumps({"terms": terms, "ids": [fx["id"] for fx in CASES["fixtures"] if f.matches(fx)]}, ensure_ascii=False))
