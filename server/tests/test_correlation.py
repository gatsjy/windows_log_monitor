"""상관 알림의 전술 표·짝짓기·묶기·규칙 검증 (BACKLOG B-67 2단계, ADR-065) — DB 없는 단위 시험."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.alerts import configdiff, correlation, tactics
from app.alerts.rules import ConfigError, parse_text

CA, PE, PR, DE, IA, LM, EX = "TA0006", "TA0003", "TA0004", "TA0005", "TA0001", "TA0008", "TA0002"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


# ------------------------------------------------------------------ 전술 표

@pytest.mark.parametrize(("tag", "expected"), [
    ("MITRE T1110", (CA,)),
    ("MITRE T1110.003", (CA,)),                 # 표에 없는 하위 기법은 상위 기법으로
    ("mitre  t1543.003", (PE, PR)),             # 대소문자·공백
    ("MITRE TA0005", (DE,)),                    # 전술을 직접
    ("MITRE T1078", (DE, PE, PR, IA)),
    ("MITRE T9999", ()),                        # 모르는 기법 — 전술 없음
    ("MITRE TA9999", ()),
    ("ISMS 2.11.3", None),                      # MITRE 태그가 아님
    ("MITRE", None),
])
def test_of_tag(tag, expected):
    assert tactics.of_tag(tag) == expected


def test_of_tags_merges_in_flow_order_and_reports_unknown():
    assert tactics.of_tags(["ISMS 2.11.3", "MITRE T1070.001", "MITRE T1110", "MITRE T1021.001"]) == (DE, CA, LM)
    assert tactics.unknown_tags(["MITRE T9999", "MITRE T1110", "ISMS 2.9.4"]) == ["MITRE T9999"]


def test_shipped_rules_have_only_known_mitre_tags():
    """기본 규칙의 MITRE 태그는 모두 전술 표에 있다 — 오타면 상관 알림에서 조용히 빠진다."""
    root = Path(__file__).resolve().parents[1]   # 컨테이너는 /app, 저장소는 server/ — 설정은 그 옆 또는 위
    path = next(p for p in (root / "config" / "alerts.yaml", root.parent / "config" / "alerts.yaml") if p.exists())
    config = parse_text(path.read_text(encoding="utf-8"))
    assert {r.name: tactics.unknown_tags(r.tags) for r in config.rules if tactics.unknown_tags(r.tags)} == {}
    names = {r.name for r in config.rules if r.kind == "correlation"}
    assert names == {"공격 흐름 (여러 전술)"}


@pytest.mark.parametrize(("rules", "count"), [
    ({"a": (CA,), "b": (PE,), "c": (DE,)}, 3),
    ({"t1078": (DE, PE, PR, IA)}, 1),                           # 여러 전술에 속한 기법 하나는 하나로
    ({"a": (CA,), "b": (CA,)}, 1),                              # 같은 전술 둘은 하나
    ({"a": (CA,), "b": (CA, PE)}, 2),                           # 짝짓기 — b 는 PE 로
    ({"a": (CA, PE), "b": (CA,), "c": (PE,)}, 2),
    ({"x": (CA, PE), "y": (CA, PE), "z": (CA, PE, DE)}, 3),     # 증가 경로가 필요한 경우
])
def test_assign_counts_distinct_tactics_one_per_rule(rules, count):
    picked = tactics.assign(rules)
    assert len(picked) == count
    assert len(set(picked.values())) == len(picked)
    assert all(t in rules[r] for r, t in picked.items())


# ------------------------------------------------------------------ 묶기 (엔진·미리보기)

def _row(i, rule, minutes, tags, hosts=(), accounts=(), ips=()):
    return {"id": i, "rule": rule, "severity": "warning", "fired_at": NOW + timedelta(minutes=minutes), "group_key": "",
            "terms_host": None, "tags": list(tags), "entity_hosts": list(hosts), "entity_accounts": list(accounts),
            "entity_ips": list(ips)}


def test_chains_need_min_tactics_per_entity():
    rows = correlation.with_tactics([
        _row(1, "대입", -50, ["MITRE T1110"], hosts=["DC-01"], ips=["10.0.0.5"]),
        _row(2, "새 서비스", -30, ["MITRE T1543.003"], hosts=["DC-01"], accounts=["evil"]),
        _row(3, "로그 삭제", -10, ["MITRE T1070.001"], hosts=["DC-01"], accounts=["evil"]),
        _row(4, "대입", -5, ["MITRE T1110"], hosts=["PC-9"]),
    ])
    found = correlation.chains(rows, ("host", "account", "ip"), 3)
    assert [(c["kind"], c["value"]) for c in found] == [("host", "DC-01")]
    assert sorted(found[0]["picked"].values()) == sorted([CA, PE, DE]) and [r["id"] for r in found[0]["rows"]] == [1, 2, 3]
    assert [(c["kind"], c["value"]) for c in correlation.chains(rows, ("account",), 2)] == [("account", "evil")]
    assert correlation.chains(rows, ("host",), 4) == []


def test_machine_accounts_and_untagged_alerts_do_not_chain():
    rows = correlation.with_tactics([
        _row(1, "a", -3, ["MITRE T1110"], accounts=["system"]),
        _row(2, "b", -2, ["MITRE T1543"], accounts=["system"]),
        _row(3, "c", -1, ["MITRE T1070"], accounts=["system"]),
        _row(4, "d", -1, ["ISMS 2.9.2"], hosts=["X"]),
    ])
    assert correlation.chains(rows, ("host", "account", "ip"), 2) == []


def test_preview_slides_the_window():
    """미리보기는 개체마다 기간을 밀며 센다 — 61분 떨어진 둘은 한 구간이 아니다(경계)."""
    rows = correlation.with_tactics([
        _row(1, "a", -180, ["MITRE T1110"], hosts=["H"]),
        _row(2, "b", -150, ["MITRE T1543"], hosts=["H"]),
        _row(3, "c", -119, ["MITRE T1070"], hosts=["H"]),      # 1과 61분 차이 — 1·2·3 은 한 구간이 아님, 2·3 은 같은 구간
        _row(4, "d", -100, ["MITRE T1059"], hosts=["H"]),
    ])
    found = correlation.preview(rows, ("host",), 3, timedelta(hours=1))
    assert [[r["id"] for r in c["rows"]] for c in found] == [[2, 3, 4]]
    assert correlation.preview(rows, ("host",), 3, timedelta(minutes=30)) == []


# ------------------------------------------------------------------ 규칙 검증

RULE = """rules:
  - name: 공격 흐름
    kind: correlation
{extra}    severity: critical
    notify: [보안팀]
"""


def _parse(extra: str):
    return parse_text(RULE.format(extra=extra)).rules[0]


def test_defaults():
    rule = _parse("")
    assert (rule.window, rule.cooldown, rule.min_tactics, rule.entities) == (timedelta(hours=1), timedelta(hours=1), 3,
                                                                            ("host", "account", "ip"))
    rule = _parse("    window: 2h\n    entities: [ip, host]\n    min_tactics: 2\n")
    assert (rule.window, rule.cooldown, rule.entities, rule.min_tactics) == (timedelta(hours=2), timedelta(hours=2), ("host", "ip"), 2)


@pytest.mark.parametrize("extra", [
    '    match: { event_id: "4625" }\n',
    "    threshold: 3\n",
    "    group_by: host\n",
    "    window: 5m\n",
    "    window: 2d\n",
    "    window: 1h\n    cooldown: 30m\n",
    "    min_tactics: 1\n",
    "    min_tactics: 9\n",
    "    min_tactics: true\n",
    "    entities: []\n",
    "    entities: [user]\n",
    "    resolve: auto\n",
])
def test_invalid(extra):
    with pytest.raises(ConfigError):
        _parse(extra)


BASE = RULE.format(extra="    window: 1h\n    min_tactics: 3\n")


@pytest.mark.parametrize(("old", "new", "expected"), [
    ("    min_tactics: 3\n", "    min_tactics: 4\n", [("min_tactics", True)]),
    ("    min_tactics: 3\n", "    min_tactics: 2\n", [("min_tactics", False)]),
    ("    window: 1h\n", "    window: 30m\n", [("window", True), ("cooldown", False)]),
    ("    window: 1h\n", "    window: 1h\n    entities: [host, ip]\n", [("entities", True)]),
    ("    window: 1h\n", "    window: 1h\n    cooldown: 6h\n", [("cooldown", True)]),
])
def test_weakening(old, new, expected):
    changes = configdiff.diff(parse_text(BASE), parse_text(BASE.replace(old, new, 1)))
    assert [(c["change"], c["weakens"]) for c in changes] == expected
