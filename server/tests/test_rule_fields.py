"""기본 규칙·대시보드가 쓰는 Windows 이름 필드(f.EventData.<이름>)가 실제로 붙는 이름인지 (벤치마킹 검토, ADR-038).

f.EventData.<이름> 은 서버가 템플릿(normalizers/win_templates.py)으로 붙인 이름을 본다. 이름 오타(Logontype)나 그 이벤트에 없는 이름은
검사 없이 통과하고 실제 PC 에서 영영 맞지 않는다 — 1000007·1000009 가 그렇게 몇 주 동안 동작하지 않았다.
- 규칙·위젯의 event_id 마다 그 이름이 템플릿에 있어야 한다.
- 템플릿은 윈도 CI 실측 레코드(tests/fixtures/winevtlog)로 확인한 것이어야 한다. 문서만 보고 만든 템플릿(4768·4769 …)에
  기대는 기본 규칙은 실측을 더하거나 UNVERIFIED_OK 에 이유와 함께 적는다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.alerts.rules import parse_text
from app.normalizers import win_templates as wt
from app.querylang import parse_terms

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in (HERE.parent, HERE.parents[1]) if (p / "config" / "alerts.yaml").exists())
REAL = {(r["ProviderName"], r["EventID"]) for r in map(json.loads, (HERE / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl")
                                                       .read_text(encoding="utf-8").splitlines()) if r}
UNVERIFIED_OK: dict[tuple[str, int], str] = {}   # (공급자, 이벤트 ID) → 실측 없이 기본 규칙이 기대도 되는 이유


def _uses(params: dict) -> list[tuple[list[int], str]]:
    """조건(옛 파라미터 + 검색 문장)에서 (event_id 목록, EventData 이름)."""
    event_ids = [int(x) for x in str(params.get("event_id") or "").split(",") if x.strip().isdigit()]
    names = [k.split(".", 2)[2] for k in params if k.startswith("f.EventData.")]
    if params.get("query"):
        for term in parse_terms(str(params["query"])):
            if term.key == "f" and len(term.path) == 2 and term.path[0] == "EventData":
                names.append(term.path[1])
            elif term.key == "event_id" and not term.neg:
                event_ids += [int(v) for v in term.values]
    return [(event_ids, name) for name in names]


def _shipped_uses() -> list[tuple[str, list[int], str]]:
    out = []
    for rule in parse_text((ROOT / "config" / "alerts.yaml").read_text(encoding="utf-8")).rules:
        out += [(f"규칙 {rule.sid} {rule.name}", ids, name) for ids, name in _uses(rule.match)]
    for path in sorted((ROOT / "config" / "dashboards").glob("*.json")):
        for w in json.loads(path.read_text(encoding="utf-8")).get("widgets", []):
            out += [(f"{path.name} '{w.get('title')}'", ids, name) for ids, name in _uses(w.get("query") or {})]
    return out


USES = _shipped_uses()


def test_there_are_name_based_uses_to_check():
    assert len(USES) >= 4   # 1000007·1000009·1000022·1000023·보안 대시보드 위젯


@pytest.mark.parametrize(("where", "event_ids", "name"), USES, ids=[u[0] for u in USES])
def test_name_exists_in_a_verified_template_for_each_event(where, event_ids, name):
    assert event_ids, f"{where}: event_id 없이 EventData.{name} 를 쓰면 어느 템플릿 이름인지 정할 수 없습니다"
    for eid in event_ids:
        templates = {key: names for key, names in wt.TEMPLATES.items() if key[1] == eid}
        assert any(name in names for names in templates.values()), f"{where}: 이벤트 {eid} 에 이름 {name} 가 없습니다"
        for key, names in templates.items():
            if name in names:
                assert key in REAL or key in UNVERIFIED_OK, (
                    f"{where}: {key} 템플릿은 실측으로 확인되지 않았습니다 — 윈도 CI 캡처에 더하거나 UNVERIFIED_OK 에 이유를")


def test_typo_is_caught():
    assert _uses({"event_id": "4625", "f.EventData.Logontype": "10"}) == [([4625], "Logontype")]
    templates = [names for key, names in wt.TEMPLATES.items() if key[1] == 4625]
    assert not any("Logontype" in names for names in templates)
