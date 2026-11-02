"""수집 품질 지표 (BACKLOG B-56 1단계, ISMS 2.9.4) — 통합 시험: 수집 → agent_streams 칸 → 점검 보고서 절·점검 필요 → 운영 준비도.

회귀 대상이 아니라 새 기능: 들어오는데 해석이 깨진 것(템플릿 불일치·IIS 원문·정규화 오류)과 늦게·미래 시각으로 오는 로그를 몰랐다.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
FIXTURE = Path(__file__).parent / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl"


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
        yield c


def _4625(host, when, short=False):
    record = next(r for r in map(json.loads, FIXTURE.read_text(encoding="utf-8").splitlines()) if r.get("EventID") == 4625)
    inserts = record["StringInserts"][:15] if short else record["StringInserts"]
    return {**record, "Computer": host, "agent_host": host, "log_source": "winevtlog", "StringInserts": inserts,
            "TimeCreated": when.isoformat()}


def test_quality_columns_report_and_readiness(client):
    from app import readiness, repository
    from app.reports import builder, render

    now = datetime.now(UTC)
    records = [_4625("DC-Q", now) for _ in range(3)]
    records += [_4625("DC-Q", now, short=True) for _ in range(2)]                        # 템플릿 불일치
    records += [_4625("PC-LATE", now - timedelta(hours=3)) for _ in range(150)]          # 밀린 로그
    records += [_4625("PC-FUTURE", now + timedelta(hours=2))]                             # PC 시계가 앞섬
    records += [{"log": "garbage line that is not w3c", "file": "W3SVC9\\u_ex1.log", "agent_host": "WEB-Q",
                 "log_source": "iis"}]                                                     # 열 순서를 모르는 IIS 줄
    r = client.post("/api/ingest", json=records, headers=KEY)
    assert r.status_code == 200 and r.json()["accepted"] == len(records)

    q = client.portal.call(repository.ingest_quality, now - timedelta(hours=1), now)
    t = q["total"]
    assert (t["template_mismatch"], t["unparsed"], t["late_n"], t["future_n"], t["parse_errors"]) == (2, 1, 150, 1, 0)
    by = {r["host"]: r for r in q["rows"]}
    assert set(by) == {"DC-Q", "PC-LATE", "PC-FUTURE", "WEB-Q"} and by["PC-LATE"]["max_lag_sec"] >= 3 * 3600 - 60
    assert by["WEB-Q"]["source"] == "iis" and by["WEB-Q"]["unparsed"] == 1

    payload = client.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    texts = [a["text"] for a in payload["attention"]]
    assert any(x.startswith("필드 수가 템플릿과 다른 Windows 이벤트 2건 — DC-Q") for x in texts)
    assert any("원문 그대로 둔 IIS 줄 1건" in x for x in texts) and any("5분 넘게 미래인 로그 1건 — PC-FUTURE" in x for x in texts)
    assert any("1시간 넘게 늦게 들어온 로그 150건" in x for x in texts)
    page = render.html(payload, 1)
    assert "수집 품질 — 해석이 깨졌거나 늦게 온 로그" in page and "PC-LATE" in page
    assert "수집 품질" not in render.html({k: v for k, v in payload.items() if k != "ingest_quality"}, 1)   # 옛 보고서도 그린다

    items = {i.key: i for i in readiness.judge(client.portal.call(readiness.collect, now))}
    assert items["ingest_quality"].status == "warn" and "DC-Q" in items["ingest_quality"].detail
