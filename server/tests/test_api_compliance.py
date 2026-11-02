"""심사 대응 (BACKLOG B-73) — 통합 시험: ISMS 항목별 현황, 증적 묶음의 MANIFEST 해시·감사로그, 수식 주입 방지, 권한·사유."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
RULES = """settings:
  interval_sec: 30

rules:
  - name: 로그온 실패 급증
    enabled: false
    match: { event_id: "4625" }
    severity: warning
    tags: [MITRE T1110, ISMS 2.11.3]
    notify: [운영팀]
  - name: 보안 감사 로그 삭제
    match: { event_id: "1102" }
    severity: critical
    tags: [ISMS 2.9.4]
    notify: [운영팀]
"""


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _alert(rule, tags, key, status="open", resolution=None, minutes_ago=60):
    sql("INSERT INTO alerts (fired_at, rule, severity, group_key, event_count, payload, status, resolution, resolved_at, resolved_by)"
        " VALUES (now() - make_interval(mins => %s), %s, 'warning', %s, 1, %s::jsonb, %s, %s,"
        " CASE WHEN %s = 'resolved' THEN now() END, CASE WHEN %s = 'resolved' THEN 'kim' END)",
        (minutes_ago, rule, key, json.dumps({"tags": tags}), status, resolution, status, status))


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

    Path(os.environ["WLM_ALERTS_FILE"]).write_text(RULES, encoding="utf-8")
    try:
        with TestClient(app) as admin:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            admin.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            admin.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            engine.reload(force=True)
            _alert("로그온 실패 급증", ["MITRE T1110", "ISMS 2.11.3"], "=HYPERLINK(\"http://x\")", "resolved", "fp_rule")
            _alert("로그온 실패 급증", ["MITRE T1110", "ISMS 2.11.3"], "PC-2", "resolved", "tp_malicious")
            _alert("로그온 실패 급증", ["MITRE T1110", "ISMS 2.11.3"], "PC-3")
            _alert("옛 규칙", ["ISMS 2.10.1"], "PC-4")                               # 지금은 없는 규칙의 태그도 센다
            _alert("로그온 실패 급증", ["ISMS 2.11.3"], "PC-5", minutes_ago=200 * 24 * 60)   # 기간 밖
            temp = admin.post("/api/users", json={"username": "viewer", "role": "viewer"}, headers=CSRF).json()
            viewer = TestClient(app)
            viewer.post("/api/auth/login", json={"username": "viewer", "password": temp["temp_password"]}, headers=CSRF)
            viewer.post("/api/auth/password", json={"current_password": temp["temp_password"], "new_password": "Reader#Pass2026q"},
                        headers=CSRF)
            yield {"admin": admin, "viewer": viewer}
    finally:
        Path(os.environ["WLM_ALERTS_FILE"]).write_text("settings:\n  interval_sec: 30\n\nrules:\n", encoding="utf-8")
        engine.reload(force=True)


def test_summary_per_isms_item(ctx):
    items = {i["item"]: i for i in ctx["admin"].get("/api/compliance/isms", params={"since": "90d"}).json()["items"]}
    assert list(items) == ["2.9.4", "2.10.1", "2.11.3"]                     # 번호 순 (글자 순이면 2.10 이 앞)
    a = items["2.11.3"]
    assert (a["alerts"], a["resolved"], a["unresolved"], a["true_positive"], a["false_positive"]) == (3, 2, 1, 1, 1)
    assert [r["name"] for r in a["rules"]] == ["로그온 실패 급증"] and a["enabled"] == 0
    assert items["2.9.4"]["alerts"] == 0 and items["2.9.4"]["enabled"] == 1
    assert items["2.10.1"]["rules"] == [] and items["2.10.1"]["alerts"] == 1
    assert ctx["viewer"].get("/api/compliance/isms").status_code == 403


def test_bundle_manifest_verifies_and_is_logged(ctx):
    admin = ctx["admin"]
    assert admin.get("/api/compliance/isms/bundle", params={"since": "90d"}).status_code == 400      # 사유 필수
    assert admin.get("/api/compliance/isms/bundle", params={"since": "500d", "reason": "심사 준비"}).status_code == 400
    r = admin.get("/api/compliance/isms/bundle", params={"since": "90d", "reason": "ISMS 심사 준비"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"README.txt", "요약.csv", "MANIFEST.txt", "ISMS_2.11.3/규칙.txt", "ISMS_2.11.3/알림.csv", "ISMS_2.10.1/알림.csv"} <= names
    manifest = z.read("MANIFEST.txt")
    for line in manifest.decode().splitlines():                             # sha256sum -c 와 같은 대조
        digest, path = line.split("  ", 1)
        assert hashlib.sha256(z.read(path)).hexdigest() == digest, path
    assert len(manifest.decode().splitlines()) == len(names) - 1
    sha = hashlib.sha256(manifest).hexdigest()
    assert r.headers["X-WLM-Manifest-SHA256"] == sha
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'compliance.bundle'")
    assert detail["manifest_sha256"] == sha and detail["reason"] == "ISMS 심사 준비"
    rows = list(csv.reader(io.StringIO(z.read("ISMS_2.11.3/알림.csv").decode("utf-8-sig"))))
    assert rows[0][4] == "대상" and len(rows) == 4
    assert any(row[4].startswith("'=HYPERLINK") for row in rows[1:])      # 로그에서 온 값이 엑셀 수식이 되지 않게
    assert "종료 분류" in rows[0] and "오탐 — 규칙 문제" in {row[11] for row in rows[1:]}
    assert ctx["viewer"].get("/api/compliance/isms/bundle", params={"reason": "보기"}).status_code == 403
