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


def test_failed_logons_alone_stay_one_tactic():
    """기본 규칙 중 실패한 인증(4625·4771·18456·SSH 실패)을 보는 규칙들은 모두 합쳐도 전술 하나 — 인터넷 봇의 RDP 대입만으로
    '공격 흐름(전술 3개)'이 울리지 않게(내부 이동·계정 탐색 태그 때문에 울렸다, 검토에서 재현)."""
    root = Path(__file__).resolve().parents[1]
    path = next(p for p in (root / "config" / "alerts.yaml", root.parent / "config" / "alerts.yaml") if p.exists())
    config = parse_text(path.read_text(encoding="utf-8"))
    failed = {r.name: tactics.of_tags(r.tags) for r in config.rules
              if r.kind == "count" and ({"4625", "4771", "4740", "18456"} & set(r.match.get("event_id", "").split(","))
                                        or "Failed password" in r.match.get("q", ""))}
    assert len(failed) >= 6, failed
    assert len(tactics.assign(failed)) == 1


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


FEEDERS = """rules:
  - name: 공격 흐름
    sid: 1
    kind: correlation
    severity: critical
    notify: [보안팀]
  - name: 로그 삭제
    sid: 2
    match: { event_id: "1102" }
    severity: critical
    tags: [MITRE T1070.001, ISMS 2.11.3]
    notify: [운영팀]
"""


@pytest.mark.parametrize(("new", "weakens"), [
    ("    tags: [ISMS 2.11.3]\n", True),                      # 전술 태그를 지움
    ("    tags: [MITRE T9999, ISMS 2.11.3]\n", True),         # 모르는 기법으로 (오타)
    ("    tags: [MITRE T1070, ISMS 2.11.3]\n", False),        # 같은 전술
    ("    tags: [MITRE T1070.001, MITRE T1059, ISMS 2.11.3]\n", False),   # 늘림
])
def test_feeder_tactic_loss_weakens_the_correlation_rule(new, weakens):
    """상관 알림이 세던 규칙의 MITRE 태그를 지우면 상관 알림이 약해진다 — 그 상관 규칙의 받는 곳으로 알린다 (검토에서 재현)."""
    old = parse_text(FEEDERS)
    after = parse_text(FEEDERS.replace("    tags: [MITRE T1070.001, ISMS 2.11.3]\n", new, 1))
    changes = configdiff.diff(old, after)
    lost = [c for c in changes if c["change"] == "feeder_tactics"]
    assert bool(lost) is weakens and all(c["weakens"] for c in lost)
    if weakens:
        assert lost[0]["rule"] == "공격 흐름" and "방어 회피" in lost[0]["text"]
        assert configdiff.recipients(configdiff.affected(old, after, changes), old) == ("보안팀",)


def test_feeder_removed_or_observed_weakens_too():
    old = parse_text(FEEDERS)
    removed = parse_text(FEEDERS.split("  - name: 로그 삭제")[0])
    assert any(c["change"] == "feeder_tactics" for c in configdiff.diff(old, removed))
    observed = parse_text(FEEDERS.replace('    severity: critical\n    tags', '    mode: observe\n    severity: critical\n    tags', 1))
    assert any(c["change"] == "feeder_tactics" for c in configdiff.diff(old, observed))
    off = parse_text(FEEDERS.replace("    kind: correlation\n", "    kind: correlation\n    enabled: false\n", 1))
    assert not any(c["change"] == "feeder_tactics" for c in configdiff.diff(off, parse_text(FEEDERS.replace(
        "    kind: correlation\n", "    kind: correlation\n    enabled: false\n", 1).replace("MITRE T1070.001, ", ""))))



# ------------------------------------------------------------------ 검토 보완 (2차)

def _v(corr_on=True, tags="MITRE T1070.001, ", feeder_on=True, corr=True):
    corr_block = (f"""  - name: 공격 흐름
    sid: 1
    kind: correlation
    enabled: {'true' if corr_on else 'false'}
    severity: critical
    notify: [보안팀]
""" if corr else "")
    return parse_text(f"""rules:
{corr_block}  - name: 로그 삭제
    sid: 2
    enabled: {'true' if feeder_on else 'false'}
    match: {{ event_id: "1102" }}
    severity: critical
    tags: [{tags}ISMS 2.11.3]
    notify: [운영팀]
""")


def _feeder(changes):
    return [(c["change"], c["weakens"], c["rule"]) for c in changes if c["change"] == "feeder_tactics"]


def test_off_edit_on_bypass_is_reported_when_the_correlation_rule_comes_back():
    """상관 규칙을 끄고 → 다른 규칙의 태그를 지우고 → 다시 켜도, 켜는 판본에서 그때(마지막으로 켜져 있던 판본)와 비교해 알린다 (검토에서 재현)."""
    v1, v2, v3, v4 = _v(), _v(corr_on=False), _v(corr_on=False, tags=""), _v(tags="")
    assert _feeder(configdiff.diff(v1, v2)) == [] and _feeder(configdiff.diff(v2, v3)) == []
    base = {"sid:1": (v1.rules[0], 1)}
    changes = configdiff.diff(v3, v4, base, {1: v1})
    [(_, weakens, rule)] = _feeder(changes)
    assert weakens and rule == "공격 흐름"
    assert "다시 켬" in next(c["text"] for c in changes if c["change"] == "feeder_tactics")
    assert configdiff.recipients(configdiff.affected(v3, v4, changes, base), v1) == ("보안팀",)
    # 지웠다가 다시 추가해도
    w2, w3 = _v(corr=False), _v(corr=False, tags="")
    changes = configdiff.diff(w3, v4, base, {1: v1})
    assert _feeder(changes) and "다시 추가" in next(c["text"] for c in changes if c["change"] == "feeder_tactics")
    assert _feeder(configdiff.diff(w2, w3)) == []
    # 그 사이 태그를 그대로 두었으면 알리지 않는다
    assert _feeder(configdiff.diff(_v(corr_on=False), _v(), base, {1: v1})) == []


def test_feeder_off_edit_on_is_compared_with_its_last_enabled_shape():
    """다른 규칙을 끄고(알림) → 태그를 지우고 → 다시 켜면, 다시 켤 때 그 규칙이 마지막으로 켜져 있던 모양과 비교한다."""
    v1, v3, v4 = _v(), _v(feeder_on=False, tags=""), _v(tags="")
    assert _feeder(configdiff.diff(v1, _v(feeder_on=False)))   # 끄는 것 자체도 알린다
    changes = configdiff.diff(v3, v4, {"sid:2": (v1.rules[1], 1)}, {1: v1})
    assert [(c, w) for c, w, _ in _feeder(changes)] == [("feeder_tactics", True)]


ROUTED = """routes:
  - name: 의료정보과 PC
    match: {{ hosts: ["MED-*"]{extra} }}
    notify: [의료정보과]
rules:
  - name: 공격 흐름
    sid: 1
    kind: correlation
    entities: [{entities}]
    severity: critical
    notify: [운영팀]
"""


@pytest.mark.parametrize("extra", ["", ", rules: [공격 흐름]"])
def test_pc_routes_reach_correlation_alerts_in_samples(extra):
    """상관 알림의 PC 개체는 발생 때 PC 경로를 탄다(fire_rule host=) — 받는 곳 표본(설정 변경 알림·시험 전송·상태)도 같게 (검토에서 재현)."""
    cfg = parse_text(ROUTED.format(extra=extra, entities="host, account, ip"))
    rule = cfg.rules[0]
    assert "의료정보과" in cfg.reachable(rule) and "의료정보과" in cfg.delivery_targets()
    off = parse_text(ROUTED.format(extra=extra, entities="host, account, ip").replace("    kind: correlation\n",
                                                                                      "    kind: correlation\n    enabled: false\n"))
    changes = configdiff.diff(cfg, off)
    assert "의료정보과" in configdiff.recipients(configdiff.affected(cfg, off, changes), cfg)
    # PC 개체를 보지 않으면 PC 경로를 타지 않는다 (발생 때와 같게)
    no_host = parse_text(ROUTED.format(extra=extra, entities="account, ip"))
    assert "의료정보과" not in no_host.reachable(no_host.rules[0])


def test_hub_hosts_do_not_chain_by_pc_but_accounts_still_do():
    """도메인 컨트롤러에 여러 직원의 일상 알림(잠금·새 계정·정책 반영)이 모여도 hub_hosts 면 PC 로 잇지 않는다 — 같은 계정의 흐름은 그대로."""
    rows = correlation.with_tactics([
        _row(1, "계정 잠금", -50, ["MITRE T1110"], hosts=["DC-01"], accounts=["nurse1"]),
        _row(2, "새 사용자 계정", -40, ["MITRE T1136.001"], hosts=["DC-01"], accounts=["helpdesk"]),
        _row(3, "감사 정책 변경", -30, ["MITRE T1562.002"], hosts=["DC-01"], accounts=["gpo"]),
        _row(4, "관리자 그룹 추가", -20, ["MITRE T1098"], hosts=["DC-01"], accounts=["evil"]),
        _row(5, "새 서비스", -15, ["MITRE T1543.003"], hosts=["DC-01"], accounts=["evil"]),
        _row(6, "로그 삭제", -10, ["MITRE T1070.001"], hosts=["DC-01"], accounts=["evil"]),
    ])
    kinds = ("host", "account", "ip")
    assert ("host", "DC-01") in {(c["kind"], c["value"]) for c in correlation.chains(rows, kinds, 3)}
    found = {(c["kind"], c["value"]) for c in correlation.chains(rows, kinds, 3, ("dc-*",))}
    assert found == {("account", "evil")}
    assert correlation.preview(rows, ("host",), 3, timedelta(hours=1), ("DC-*",)) == []


def test_hub_hosts_validation_and_weakening():
    assert _parse("    hub_hosts: [DC-*, AD01]\n").hub_hosts == ("DC-*", "AD01")
    for bad in ('    hub_hosts: ["*"]\n', '    hub_hosts: [""]\n'):
        with pytest.raises(ConfigError):
            _parse(bad)
    changes = configdiff.diff(parse_text(BASE), parse_text(BASE.replace("    window: 1h\n", "    window: 1h\n    hub_hosts: [DC-*]\n", 1)))
    assert [(c["change"], c["weakens"]) for c in changes] == [("hub_hosts", True)]
