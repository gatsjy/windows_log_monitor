"""감사로그 해시 체인 — 이미 감사로그가 쌓인 설치를 올릴 때 (BACKLOG B-71, ADR-050).

회귀(검토에서 재현): 처음에는 022 이전 행을 genesis 해시 하나로 묶었는데,
- 업그레이드 직후 첫 앵커가 해시 없는 행을 가리켜 '앵커의 #N 가 없습니다'가 매일 났고,
- 022 이전 행의 만료 삭제가 '지운 마지막 해시 = NULL' 을 남겨 '보관기간 만료가 아닌 방법으로 지워졌습니다'가 났다.
이제 022 가 기존 행에도 해시를 채운다. 시험 DB 를 021 까지 만든 뒤 행을 넣고 앱을 띄워 022 를 적용한다.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from functools import partial

import psycopg
import pytest

TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]
PRE_ROWS = [  # (며칠 전, actor, actor_ip, action, target, detail)
    (1500, "admin", "10.0.0.1", "user.create", "kim", '{"role": "admin"}'),
    (1499, "admin", None, "user.role", None, "{}"),
    (1498, "system", "", "retention.purge_audit", "", '{"deleted": 3, "cutoff": "2022-01-01"}'),   # 옛 이미지의 만료 기록 (해시 없음)
    (10, "kim", "10.0.0.2", "events.search", "q|x", '{"q": "user:\'김\' | ip:10.0.0.2"}'),
    (9, "🎵", None, "auth.login", "", "[]"),
    (8, "lee", "10.0.0.3", "events.view", None, '{"id": 1}'),
]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from app import db, integrity
    from app.main import app

    # 021 까지 (db.migrate 와 같은 방식) + 그때의 감사로그
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        for path in sorted(db.MIGRATIONS_DIR.glob("*.sql")):
            if path.stem >= "022":
                break
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.stem,))
        for days, actor, ip, action, target, detail in PRE_ROWS:
            conn.execute("INSERT INTO audit_log (at, actor, actor_ip, action, target, detail)"
                         " VALUES (now() - make_interval(days => %s), %s, %s, %s, %s, %s::jsonb)",
                         (days, actor, ip, action, target, detail))
    original = integrity.settings
    integrity.settings = replace(original, archive_dir=str(tmp_path_factory.mktemp("archive")))
    try:
        with TestClient(app) as c:
            yield c
    finally:
        integrity.settings = original


def test_upgrade_fills_hashes_and_the_first_purge_and_anchor_verify(client):
    from app import integrity

    [(rows, top)] = sql("SELECT backfill_rows, backfill_max_id FROM audit_chain")
    assert rows == len(PRE_ROWS) and top > 0
    assert sql("SELECT count(*) FROM audit_log WHERE row_hash IS NULL")[0][0] == 0
    # 기동 때 만료 삭제가 022 이전의 오래된 행을 지웠고, 같은 트랜잭션에 지운 마지막 해시를 남겼다
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'retention.purge_audit' AND detail ? 'upto_id'")
    assert detail["deleted"] == 3 and detail["last_hash"]
    assert sql("SELECT count(*) FROM audit_log WHERE at < now() - interval '1000 days'")[0][0] == 0
    # 기동 뒤 첫 정기 실행의 앵커는 (아직 새 기록이 없으면) 022 가 해시를 채운 행을 가리킨다 — 그래도 맞아야 한다
    now = datetime.now(UTC)
    client.portal.call(integrity.daily, now)
    [a] = integrity.list_anchors()
    assert a["audit_last_id"] > 0
    result = client.portal.call(partial(integrity.verify, now))
    assert result["ok"], result["problems"]
    assert result["anchors_checked"] == 1


def test_editing_a_row_from_before_the_upgrade_is_detected(client):
    from app import integrity

    [(rid,)] = sql("SELECT id FROM audit_log WHERE action = 'events.view'")
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute("UPDATE audit_log SET actor = 'park' WHERE id = %s", (rid,))
    problems = client.portal.call(integrity.verify)["problems"]
    assert any(f"#{rid} 내용이 해시와 다릅니다" in p for p in problems)
