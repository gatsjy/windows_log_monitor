"""옛 검색 조건의 SQL 고정 (B-01, ADR-033): 검색 문장을 넣어도 기존 파라미터가 만드는 SQL 은 한 글자도 바뀌지 않아야 한다.

대상: 벤치 시나리오, 배포된 알림 규칙(config/alerts.yaml)의 match, 대시보드 위젯 query, 기존 필터 시험의 조건.
같은 SQL 이면 같은 실행 계획이라 '기존 검색 대비 느려지지 않음'이 구조로 보장된다.
일부러 바꿨다면 다시 만든다:
  docker compose exec -e WLM_UPDATE_SNAPSHOTS=1 api python -m pytest tests/test_where_snapshot.py
"""

from __future__ import annotations

import ast
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import yaml

from app.filters import EventFilter
from app.repository import where_clause

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = Path(__file__).resolve().parent / "snapshots" / "where_clause_legacy.json"
NOW = datetime(2026, 10, 3, 5, 0, 0, tzinfo=UTC)


class Params(dict):
    def getlist(self, key):
        value = self.get(key)
        return [] if value is None else [value]

    def multi_items(self):
        return list(self.items())


def _bench_scenarios() -> list[tuple[str, dict]]:
    # bench.py 는 import 하면 환경변수를 벤치 DB 로 바꾼다 → 소스에서 SCENARIOS 만 읽는다
    path = ROOT / "tools" / "bench" / "bench.py"
    if not path.exists():
        path = ROOT.parent / "tools" / "bench" / "bench.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "SCENARIOS" for t in node.targets):
            # 검색 문장(query) 시나리오는 새 기능이라 옛 SQL 고정 대상이 아니다
            return [(f"bench: {name}", params) for name, _path, params in ast.literal_eval(node.value)
                    if params and "query" not in params]
    raise AssertionError("bench.py 에 SCENARIOS 가 없습니다")


def _alert_rules() -> list[tuple[str, dict]]:
    doc = yaml.safe_load((ROOT / "config" / "alerts.yaml").read_text(encoding="utf-8"))
    out = []
    for rule in doc.get("rules") or []:
        match = {str(k): ",".join(map(str, v)) if isinstance(v, list) else str(v) for k, v in (rule.get("match") or {}).items()}
        if rule.get("kind", "count") == "count":   # 끊김 규칙(agent_silent·stream_silent)은 이벤트 조건이 없다
            out.append((f"rule: {rule['name']}", match))
    return out


def _dashboards() -> list[tuple[str, dict]]:
    out = []
    for path in sorted((ROOT / "config" / "dashboards").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        for i, widget in enumerate(doc.get("widgets") or []):
            if isinstance(widget.get("query"), dict):
                out.append((f"dashboard: {path.stem}[{i}] {widget.get('title', '')}", {k: str(v) for k, v in widget["query"].items()}))
    return out


FILTER_CASES = [
    ("filters: lists", {"since": "1h", "host": "A,B", "level": "1,2"}),
    ("filters: field", {"f.EventData.User": "admin", "level": "3"}),
    ("filters: field number", {"f.EventID": "4625"}),
    ("filters: like escape", {"since": "1h", "host": "A", "q": "50%_off"}),
    ("filters: q or", {"q": "timeout|refused"}),
    ("filters: category user ip", {"category": "iis", "user": "kim", "ip": "10.0.0.5"}),
    ("filters: everything", {"since": "7d", "until": "2026-10-03T04:00:00+00:00", "host": "A", "channel": "Security",
                             "provider": "P", "source": "winevtlog", "category": "security", "user": "u", "ip": "1.2.3.4",
                             "level": "1,2", "event_id": "4625,4740", "q": "a|b", "f.x.y": "1", "f.StringInserts.5": "z"}),
]


def snapshot() -> list[dict]:
    rows = []
    for name, params in _bench_scenarios() + _alert_rules() + _dashboards() + FILTER_CASES:
        params = {k: v for k, v in params.items() if k not in ("limit", "compare", "group", "buckets", "field")}
        where, args = where_clause(EventFilter.from_params(Params(params), now=NOW))
        rows.append({"name": name, "params": params, "sql": repr(where), "args": [str(a) for a in args]})
    return rows


def test_legacy_params_make_the_same_sql():
    actual = json.dumps(snapshot(), ensure_ascii=False, indent=1) + "\n"
    if os.environ.get("WLM_UPDATE_SNAPSHOTS") == "1":
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(actual, encoding="utf-8")
    assert SNAPSHOT.exists(), f"스냅샷 없음: {SNAPSHOT.name} — WLM_UPDATE_SNAPSHOTS=1 로 만들고 내용을 확인한 뒤 커밋하세요"
    assert json.loads(actual) == json.loads(SNAPSHOT.read_text(encoding="utf-8"))
