"""기본 규칙 표본 (B-45) — 수집 → 엔진의 SQL 집계로도 같은 결과인지, 규칙 시험기 API 와도 같은지 (통합 시험).

test_rule_samples 는 파이썬 매처로 판단한다. 여기서는 표본을 실제 수집(/api/ingest)으로 넣고 — 기준 건수만큼, 서로 다른 값 수 규칙은
그 값만 바꾼 사본으로 — 엔진이 쓰는 repository.alert_candidates 로 센다. 파이썬과 SQL 이 갈리면 화면(규칙 시험기)과 알림이 달라진다.
표본마다 PC 이름이 달라 서로 섞이지 않는다(조건에 그 PC 들만 더한다).
"""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
import rulesamples as rs

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
HERE = Path(__file__).resolve().parent
ALERTS = next(p for p in (HERE.parent / "config" / "alerts.yaml", HERE.parents[1] / "config" / "alerts.yaml") if p.exists())
SAMPLES = rs.all_samples()


def _rules() -> dict:
    from app.alerts.rules import parse_text

    return {r.sid: r for r in parse_text(ALERTS.read_text(encoding="utf-8")).rules}


RULES = _rules()


def _plan() -> dict[str, tuple[list[str], list[dict]]]:
    """표본마다 (PC 이름들, 보낼 레코드) — 기준 건수·서로 다른 값 수를 채우는 사본."""
    out = {}
    for n, sample in enumerate(SAMPLES):
        rule = RULES[sample.sid]
        copies = max(rule.threshold, rule.distinct_min, 1) if rule.kind == "count" else 1
        hosts, records = [], []
        for i in range(copies):
            host = f"RS{n}-{i}" if rule.distinct_field == "host" else f"RS{n}"
            batch = rs.with_host(sample.records, host)
            if rule.distinct_field in ("user", "ip"):
                batch = rs.vary(batch, rule.distinct_field, i)
            hosts.append(host)
            records += batch
        out[sample.id] = (sorted(set(hosts)), records)
    return out


PLAN = _plan()


@pytest.fixture(scope="module")
def ctx():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.alerts.engine import engine
    from app.main import app

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(ALERTS.read_text(encoding="utf-8"), encoding="utf-8")
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            start = datetime.now(UTC) - timedelta(seconds=5)
            for sample_id, (_hosts, records) in PLAN.items():   # 표본마다 한 요청 — MSSQL 머리줄·본문은 그 안에서 차례로
                r = c.post("/api/ingest", json=records, headers=KEY)
                assert r.status_code == 200 and r.json()["accepted"] == len(records), (sample_id, r.text)
            yield c, start
    finally:
        # 기본 규칙 팩(처음 보는 값의 거슬러 배우기 포함)이 다음 모듈까지 엔진에서 돌지 않게 — 첫 실행에서 정리가 멈췄다(검토)
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def test_every_shipped_rule_is_loaded(ctx):
    from app.alerts.engine import engine

    assert {r.sid for r in engine.config.rules} == set(RULES)


@pytest.mark.parametrize("sample", SAMPLES, ids=[s.id for s in SAMPLES])
def test_engine_counts_the_sample_like_the_rule_tester(ctx, sample: rs.Sample):
    from app import repository
    from app.alerts.engine import rule_filter

    c, start = ctx
    rule = RULES[sample.sid]
    hosts, _records = PLAN[sample.id]
    f = replace(c.portal.call(rule_filter, rule, datetime.now(UTC)), hosts=hosts, received_since=start)
    if rule.kind == "new_terms":   # 볼 값마다 비지 않은 로그가 있어야 조합이 생긴다
        counted = all(c.portal.call(repository.alert_candidates, f, field, 1) for field in rule.terms_fields)
    else:
        rows = c.portal.call(repository.alert_candidates, f, rule.group_by, rule.threshold,
                             rule.distinct_field, rule.distinct_min)
        counted = bool(rows)
    assert counted == sample.expect, (
        f"{sample.id} '{rule.name}': 엔진(SQL)이 {'세지 않습니다' if sample.expect else '셉니다'} — {sample.why}")
    if len(sample.records) == 1:   # 시험기는 원본 하나 — MSSQL 짝(머리줄 + 본문)은 본문만으로는 번호를 모른다
        body = {"name": rule.name, "sample": rs.with_host(sample.records, hosts[0])[0]}
        r = c.post("/api/alerts/rules/test", json=body, headers=CSRF)
        assert r.status_code == 200, r.text
        failed = {rs.label(x) for x in r.json()["checks"] if not x["ok"]}
        assert r.json()["matched"] is sample.expect and failed == set(sample.fails_on), (sample.id, sorted(failed))
