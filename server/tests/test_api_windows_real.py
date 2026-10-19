"""기본 규칙·대시보드가 실제 에이전트 레코드로 동작하는지 (ADR-038) — 통합 시험.

회귀: 에이전트(Fluent Bit 4.0)는 EventData 이름을 보내지 않는데 기본 규칙 1000007(원격 데스크톱 무차별 대입)·
1000009(관리자 그룹 추가)와 보안 대시보드의 위젯이 f.EventData.* 로 걸러 실제 PC 에서는 맞을 수 없었다.
시험·시뮬레이터가 EventData 를 넣어 보내 아무도 몰랐다 → 여기서는 윈도 CI 가 받은 실제 레코드 모양만 쓴다.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
HERE = Path(__file__).resolve().parent
REAL = [json.loads(line) for line in (HERE / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl")
        .read_text(encoding="utf-8").splitlines() if line.strip()]
ROOT = HERE.parent


def _shipped(name: str) -> Path:
    return next(p for p in (ROOT / "config" / name, ROOT.parent / "config" / name) if p.exists())


def _record(event_id: int, host: str, **inserts) -> dict:
    """실제 레코드를 바탕으로, 템플릿 위치의 값만 바꾼다 (시각은 지금)."""
    from app.normalizers import win_templates as wt

    base = next(r for r in REAL if r["EventID"] == event_id and (event_id != 4732 or "S-1-5-32-544" in r["StringInserts"]))
    values = list(base["StringInserts"])
    names = wt.TEMPLATES[(base["ProviderName"], event_id)]
    for name, value in inserts.items():
        values[names.index(name)] = value
    now = datetime.now(UTC)
    return {**base, "StringInserts": values, "TimeCreated": now.strftime("%Y-%m-%d %H:%M:%S +0000"),
            "Computer": host, "agent_host": host, "log_source": "winevtlog"}


@pytest.fixture(scope="module")
def client():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        records = [_record(4625, "RDP-T", LogonType=10, IpAddress="198.51.100.23") for _ in range(10)]
        records += [_record(4625, "LAN-T", LogonType=3, IpAddress="198.51.100.24") for _ in range(10)]
        records += [_record(4732, "ADM-T")]
        assert c.post("/api/ingest", json=records, headers=KEY).json()["accepted"] == len(records)
        yield c


def _rule(sid: int):
    from app.alerts.rules import parse_text

    return next(r for r in parse_text(_shipped("alerts.yaml").read_text(encoding="utf-8")).rules if r.sid == sid)


def _candidates(client, rule) -> list[dict]:
    from app import repository

    f = replace(rule.event_filter(), received_since=datetime.now(UTC) - timedelta(minutes=10))
    return client.portal.call(repository.alert_candidates, f, rule.group_by, rule.threshold)


def test_rdp_brute_force_rule_fires_on_real_agent_records(client):
    rows = _candidates(client, _rule(1000007))
    assert [(r["key"], r["n"]) for r in rows] == [("198.51.100.23", 10)]   # 네트워크 로그온(3) 실패는 세지 않는다


def test_admin_group_rule_fires_on_real_agent_records(client):
    rows = _candidates(client, _rule(1000009))
    assert [(r["key"], r["n"]) for r in rows] == [("ADM-T", 1)]


def test_security_dashboard_rdp_widget(client):
    widget = next(w for w in json.loads(_shipped("dashboards/security.json").read_text(encoding="utf-8"))["widgets"]
                  if "원격 데스크톱" in w.get("title", ""))
    r = client.get("/api/stats/top", params={"since": "1h", "field": widget["field"], **widget["query"]}, headers=CSRF)
    assert [(i["value"], i["n"]) for i in r.json()["items"]] == [("198.51.100.23", 10)]


def test_search_by_name_and_detail_shows_the_derived_names(client):
    r = client.get("/api/events", params={"since": "1h", "query": "f.EventData.LogonType:10"}, headers=CSRF)
    items = r.json()["items"]
    assert len(items) == 10 and {i["src_ip"] for i in items} == {"198.51.100.23"}
    detail = client.get(f"/api/events/{items[0]['id']}", headers=CSRF).json()
    assert detail["raw"]["winevtlog"]["EventData"]["LogonType"] == 10 and "EventData" not in detail["raw"]
    fields = client.get("/api/fields", headers=CSRF).json()
    paths = {f["path"] for f in (fields["items"] if isinstance(fields, dict) else fields)}
    assert "winevtlog.EventData.LogonType" in paths   # 필드 탐색에 이름으로 보인다
