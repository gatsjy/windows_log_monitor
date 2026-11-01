"""감사로그 위·변조 증명 — 해시 체인과 DB 밖 앵커 (BACKLOG B-71, ADR-050) — 통합 시험.

회귀: 감사로그는 트리거로 수정·삭제를 막지만 DB 슈퍼유저(이 배포의 wlm)는 트리거를 끄고 고칠 수 있었고, 고쳤는지 보일 방법이 없었다.
시험은 session_replication_role = replica(이 연결의 트리거를 모두 건너뜀)로 슈퍼유저의 변조를 흉내 낸다(시험 DB 라 지울 수 있다).
검토에서 재현한 우회·거짓 경보마다 시험이 하나씩 있다.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from functools import partial
from itertools import pairwise
from pathlib import Path

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]


def sql(query, params=()):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def superuser(*statements):
    """슈퍼유저처럼: 이 연결에서만 모든 트리거(수정 금지·체인·머리 지키기)를 건너뛰고 고친다."""
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        for st in statements:
            if isinstance(st, tuple):
                conn.execute(*st)
            else:
                conn.execute(st)


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

    from app import integrity
    from app.main import app

    original = integrity.settings
    integrity.settings = replace(original, archive_dir=str(tmp_path_factory.mktemp("archive")))
    try:
        with TestClient(app) as c:
            initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
            c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
            c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
            yield c
    finally:
        integrity.settings = original


def write(client, n, tag="기록"):
    from app import db

    async def run():
        for i in range(n):
            await db.audit("admin", "settings.contact.save", f"{tag}-{i}", {"i": i})

    client.portal.call(run)


def verify(client, now=None, dirs=()):
    from app import integrity

    return client.portal.call(partial(integrity.verify, now, dirs))


def head():
    [(last_id, last_hash, start_hash)] = sql("SELECT last_id, last_hash, start_hash FROM audit_chain")
    return last_id, last_hash, start_hash


def anchor(name, row_id, row_hash, at=None, last_at=None, folder=None):
    from app import integrity

    body = {"at": (at or datetime.now(UTC)).isoformat(), "audit_last_id": row_id, "audit_last_hash": row_hash}
    if last_at:
        body["audit_last_at"] = last_at.isoformat()
    Path(folder or integrity.anchor_dir(), name).write_text(json.dumps(body))
    return name


def clear_anchors():
    from app import integrity

    for p in Path(integrity.anchor_dir()).glob("integrity-*.json"):
        p.unlink()


def anchor_head(name):
    """지금 머리를 가리키는 앵커 (그 행의 시각과 함께) — 매일 남기는 앵커와 같은 모양."""
    last_id, last_hash, _ = head()
    [(at,)] = sql("SELECT at FROM audit_log WHERE id = %s", (last_id,))
    return anchor(name, last_id, last_hash, last_at=at), last_id


def problems_of(client, **kw):
    return verify(client, **kw)["problems"]


def assert_clean(client, rechain):
    """다음 시험을 위해: 체인을 다시 잇고 앵커를 비운 뒤 정상인지."""
    rechain()
    clear_anchors()
    result = verify(client)
    assert result["ok"], result["problems"]


def test_every_new_row_is_chained_and_the_chain_verifies(client):
    write(client, 5)
    rows = sql("SELECT id, prev_hash, row_hash FROM audit_log ORDER BY id")
    assert all(r[2] for r in rows)
    assert all(b[1] == a[2] for a, b in pairwise(rows))
    last_id, last_hash, start_hash = head()
    assert (last_id, last_hash) == (rows[-1][0], rows[-1][2]) and rows[0][1] == start_hash
    result = verify(client)
    assert result["ok"], result["problems"]
    assert result["rows"] == len(rows)


def test_python_and_sql_canonical_forms_agree(client):
    """두 구현이 한 글자라도 다르면 모든 행이 '고쳐진 행'이 된다 — 구분 문자·NULL·빈 글·한글·BMP 밖 글자·중첩 JSON."""
    from app import integrity

    cases = [("kim", None, "user.create", None, '{"a": 1}'), ("kim", "", "user.create", "", "{}"),
             ("a|b", "10.0.0.1", "x|y", "대상 |", '{"q": "event_id:4625 | user:\'김\'", "n": [1, 2.5, null]}'),
             ("🎵𝄞", None, "act", "t", "[]")]
    for actor, ip, action, target, detail in cases:
        sql("INSERT INTO audit_log (actor, actor_ip, action, target, detail) VALUES (%s, %s, %s, %s, %s::jsonb)",
            (actor, ip, action, target, detail))
    rows = sql("SELECT id, prev_hash, (extract(epoch FROM at) * 1000000)::bigint, actor, actor_ip, action, target, detail::text,"
               " audit_log_canonical(prev_hash, id, at, actor, actor_ip, action, target, detail), row_hash"
               " FROM audit_log ORDER BY id DESC LIMIT 4")
    for r in rows:
        text = integrity.canonical(r[1], r[0], *r[2:8])
        assert text == r[8]
        assert integrity.row_hash(text) == r[9]
    # NULL 과 빈 글은 다른 글이 된다 (같으면 슈퍼유저가 바꿔도 검증이 통과했다 — 검토에서 재현)
    assert integrity.canonical("h", 1, 0, None, None, "a", None, None) != integrity.canonical("h", 1, 0, "", "", "a", "", "")
    assert verify(client)["ok"]


def test_trigger_sets_the_time_and_guards_the_head(client):
    """시각은 트리거가 정한다(과거·미래로 넣어 체인을 지키면서 기록을 꾸밀 수 없게). 머리는 앞으로만 간다."""
    sql("INSERT INTO audit_log (at, actor, action, target) VALUES (now() - interval '400 days', 'kim', 'user.delete', 'lee')")
    [(at,)] = sql("SELECT at FROM audit_log WHERE target = 'lee'")
    assert abs(at - datetime.now(UTC)) < timedelta(minutes=1)
    for bad in ("UPDATE audit_chain SET last_id = last_id - 1", "UPDATE audit_chain SET start_hash = 'x'",
                "DELETE FROM audit_chain", "TRUNCATE audit_chain"):
        with pytest.raises(psycopg.errors.RaiseException):
            sql(bad)
    assert verify(client)["ok"]


def test_missing_head_stops_audit_writes_and_is_reported(client):
    """머리를 지우면 예전에는 체인 없이 조용히 쌓이고 검증이 KeyError 로 멈춰 화면에서 카드가 사라졌다(검토에서 재현)."""
    from app import integrity

    [saved] = sql("SELECT id, start_hash, started_at, backfill_rows, backfill_max_id, last_id, last_hash FROM audit_chain")
    superuser("DELETE FROM audit_chain")
    try:
        with pytest.raises(psycopg.errors.RaiseException):
            sql("INSERT INTO audit_log (actor, action) VALUES ('x', 'y')")
        result = client.portal.call(integrity.record_verify)
        assert not result["ok"] and "체인 머리" in result["problems"][0]
        status = client.get("/api/settings/integrity").json()
        assert status["head"] is None and any(n["level"] == "bad" for n in status["notices"])
    finally:
        superuser(("INSERT INTO audit_chain VALUES (%s, %s, %s, %s, %s, %s, %s)", saved))
    assert verify(client)["ok"]


def test_concurrent_writers_keep_the_chain_in_id_order(client):
    from app import db

    async def burst():
        async def one(w):
            for i in range(20):
                await db.audit("admin", "settings.contact.save", f"동시-{w}-{i}", {"w": w, "i": i})

        await asyncio.gather(*(one(w) for w in range(8)))

    client.portal.call(burst)
    result = verify(client)
    assert result["ok"], result["problems"]


def test_retention_purge_keeps_the_chain_verifiable(client, rechain):
    """만료 삭제는 번호 앞부분만 지우고 지운 마지막 번호·해시를 같은 트랜잭션의 감사로그에 남긴다 — 남은 첫 행이 그 해시로 이어진다."""
    from app import partitions

    superuser("UPDATE audit_log SET at = now() - interval '1200 days' WHERE id IN (SELECT id FROM audit_log ORDER BY id LIMIT 6)")
    rechain()
    anchor_head("integrity-2026-01-01.json")       # 보관기간 안의 앵커 — 지워지지 않는 행을 가리킨다
    client.portal.call(partitions.purge_audit)
    [(detail, mark_id)] = sql("SELECT detail, id FROM audit_log WHERE action = 'retention.purge_audit' ORDER BY id DESC LIMIT 1")
    assert detail["deleted"] == 6 and len(detail["last_hash"]) == 64
    [(first_id, first_prev)] = sql("SELECT id, prev_hash FROM audit_log ORDER BY id LIMIT 1")
    assert first_prev == detail["last_hash"] and first_id > detail["upto_id"] and mark_id > first_id
    result = verify(client)
    assert result["ok"], result["problems"]
    assert result["anchors_checked"] == 1
    clear_anchors()


def test_purge_refuses_to_launder_tampered_rows(client, rechain):
    """고친 행의 시각을 과거로 돌려 만료 삭제가 지우게 하면 변조가 사라졌다(검토에서 재현) — 지울 행이 체인과 맞지 않으면 멈춘다."""
    from app import integrity, partitions

    [(victim,)] = sql("SELECT min(id) FROM audit_log")
    superuser(("UPDATE audit_log SET at = now() - interval '1200 days', target = '고침' WHERE id = %s", (victim,)))
    client.portal.call(partitions.purge_audit)
    client.portal.call(partitions.purge_audit)           # 시간마다 다시 보지만 기록은 하루 한 번
    assert sql("SELECT count(*) FROM audit_log WHERE id = %s", (victim,))[0][0] == 1
    refused = sql("SELECT detail FROM audit_log WHERE action = 'retention.purge_audit_refused'")
    assert len(refused) == 1 and f"#{victim}" in refused[0][0]["problems"][0]
    notices = client.portal.call(integrity.status)["notices"]
    assert any(n["level"] == "bad" and "만료 삭제를 멈췄습니다" in n["text"] for n in notices)
    assert_clean(client, rechain)
    client.portal.call(partitions.purge_audit)            # 고쳐진 행이 없으면 다시 지운다
    assert sql("SELECT count(*) FROM audit_log WHERE id = %s", (victim,))[0][0] == 0
    assert not any("만료 삭제" in n["text"] for n in client.portal.call(integrity.status)["notices"])


def test_daily_writes_one_anchor_and_verifies_even_if_the_anchor_fails(client, monkeypatch):
    from dataclasses import replace

    from app import integrity

    now = datetime.now(UTC)
    client.portal.call(integrity.daily, now)
    client.portal.call(integrity.daily, now + timedelta(minutes=5))
    [a] = integrity.list_anchors()
    last_id, _, _ = head()
    assert a["audit_last_id"] <= last_id and a["audit_last_at"] is not None
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'integrity.anchor'")[0][0] == 1
    verifies = sql("SELECT count(*) FROM audit_log WHERE action = 'integrity.verify'")[0][0]
    assert verifies >= 1
    # 보관 폴더에 쓸 수 없어도(파일을 폴더로 씀) 검증은 하고, 실패 기록은 하루 한 번
    blocker = Path(integrity.anchor_dir()) / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setattr(integrity, "settings", replace(integrity.settings, archive_dir=str(blocker)))
    later = now + timedelta(days=1)
    client.portal.call(integrity.daily, later)
    client.portal.call(integrity.daily, later + timedelta(hours=1))
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'integrity.anchor_failed'")[0][0] == 1
    assert sql("SELECT count(*) FROM audit_log WHERE action = 'integrity.verify'")[0][0] > verifies
    monkeypatch.undo()
    blocker.unlink()
    clear_anchors()


def test_tampering_is_detected(client, rechain):

    write(client, 6, "변조 시험")
    ids = [r[0] for r in sql("SELECT id FROM audit_log ORDER BY id DESC LIMIT 6")][::-1]

    # 1) 내용 고치기 · NULL ↔ 빈 글
    superuser(("UPDATE audit_log SET detail = '{\"i\": 99}' WHERE id = %s", (ids[1],)),
              ("UPDATE audit_log SET actor_ip = '' WHERE id = %s", (ids[2],)))
    problems = problems_of(client)
    assert any(f"#{ids[1]} 내용이 해시와 다릅니다" in p for p in problems)
    assert any(f"#{ids[2]} 내용이 해시와 다릅니다" in p for p in problems)
    assert_clean(client, rechain)

    # 2) 가운데 지우기 · 트리거를 끄고 넣기
    superuser(("DELETE FROM audit_log WHERE id = %s", (ids[3],)),
              "INSERT INTO audit_log (actor, action, target) VALUES ('ghost', 'user.create', 'backdoor')")
    problems = problems_of(client)
    assert any(f"#{ids[4]} 앞 행(#{ids[2]})과 이어지지 않습니다" in p for p in problems)
    assert any("해시가 없습니다" in p and "user.create" in p for p in problems)
    superuser("DELETE FROM audit_log WHERE actor = 'ghost'")
    assert_clean(client, rechain)

    # 3) 해시를 맞춰 끝에 꾸민 행 붙이기 — 미래·과거 시각 (트리거는 지금 시각을 넣으므로 트리거를 끈 것)
    for when, text in (("now() + interval '30 days'", "시각이 미래입니다"), ("now() - interval '30 days'", "앞 행보다 이릅니다")):
        last_id, last_hash, _ = head()
        superuser(f"INSERT INTO audit_log (id, at, actor, action, target, prev_hash, row_hash)"
                  f" SELECT {last_id} + 1000, t, 'system', 'backup.restore', 'fake', '{last_hash}',"
                  f" audit_log_hash(audit_log_canonical('{last_hash}', {last_id} + 1000, t, 'system', NULL, 'backup.restore', 'fake', NULL))"
                  f" FROM (SELECT {when} AS t) s",
                  f"UPDATE audit_chain SET last_id = {last_id} + 1000, last_hash = (SELECT row_hash FROM audit_log WHERE id = {last_id} + 1000)")
        assert any(text in p for p in problems_of(client)), text
        superuser(f"DELETE FROM audit_log WHERE id = {last_id} + 1000")
        assert_clean(client, rechain)

    # 4) 머리를 되돌려 그 뒤 행을 고치면 — 예전 검증은 머리 뒤의 행을 보지 않았다(검토에서 재현)
    superuser(("UPDATE audit_chain SET last_id = %s, last_hash = (SELECT row_hash FROM audit_log WHERE id = %s)", (ids[0], ids[0])),
              ("UPDATE audit_log SET target = '고침' WHERE id = %s", (ids[4],)))
    problems = problems_of(client)
    assert any("체인 머리" in p for p in problems) and any(f"#{ids[4]} 내용이 해시와 다릅니다" in p for p in problems)
    assert_clean(client, rechain)

    # 5) 끝을 지우고 머리까지 고치면 — DB 밖 앵커가 잡는다
    name, last_id = anchor_head("integrity-2099-01-01.json")
    superuser(("DELETE FROM audit_log WHERE id = %s", (last_id,)),
              "UPDATE audit_chain SET (last_id, last_hash) = (SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1)")
    assert any(f"앵커 {name} 의 #{last_id} 가 없습니다" in p for p in problems_of(client))
    assert_clean(client, rechain)

    # 6) 체인을 통째로 다시 쓰면(내용을 고치고 해시를 다시 계산) — 앵커와 다르다
    name, last_id = anchor_head("integrity-2099-01-02.json")
    superuser(("UPDATE audit_log SET target = '다시 씀' WHERE id = %s", (ids[1],)))
    rechain()
    assert any(f"앵커 {name} 의 #{last_id} 가 다릅니다" in p for p in problems_of(client))
    clear_anchors()
    assert verify(client)["ok"]


def test_prefix_deletion_is_not_explained_by_a_forged_purge_record(client, rechain):
    """앞부분을 지우고 '만료 삭제' 기록을 꾸며 넣으면 예전 검증은 통과했다(검토에서 재현).
    시스템이 남기지 않았거나 보관기간이 맞지 않는 기록은 체인 시작을 설명하지 못하고, 보관기간 안의 앵커가 가리키는 행은 있어야 한다."""
    write(client, 4, "앞부분")
    name, anchored = anchor_head("integrity-2099-02-01.json")
    write(client, 3, "그 뒤")
    [(cut_hash,)] = sql("SELECT row_hash FROM audit_log WHERE id = %s", (anchored,))
    # 꾸민 기록 1: 보관기간 1일 — 체인 시작으로 인정하지 않는다
    sql("INSERT INTO audit_log (actor, action, target, detail) VALUES ('system', 'retention.purge_audit', 'audit_log', %s)",
        (json.dumps({"deleted": 1, "retention_days": 1, "cutoff": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                     "upto_id": anchored, "last_hash": cut_hash}),))
    superuser("SET wlm.audit_purge = 'on'", ("DELETE FROM audit_log WHERE id <= %s", (anchored,)))
    problems = problems_of(client)
    assert any("체인의 시작이 맞지 않습니다" in p for p in problems)
    assert any(f"앵커 {name} 의 #{anchored} 가 없습니다 — 보관기간 안인데" in p for p in problems)
    # 꾸민 기록 2: 앞뒤가 맞는 보관기간 — 체인 시작은 통과해도 보관기간 안의 앵커가 잡는다
    sql("INSERT INTO audit_log (actor, action, target, detail) VALUES ('system', 'retention.purge_audit', 'audit_log', %s)",
        (json.dumps({"deleted": 1, "retention_days": 1095, "cutoff": (datetime.now(UTC) - timedelta(days=1095)).isoformat(),
                     "upto_id": anchored, "last_hash": cut_hash}),))
    problems = problems_of(client)
    assert not any("체인의 시작" in p for p in problems)
    assert any(f"앵커 {name} 의 #{anchored} 가 없습니다" in p for p in problems)
    # 보관기간이 지난 행을 가리키는 앵커라면 지워진 것이 정상 (만료로 셈)
    result = verify(client, now=datetime.now(UTC) + timedelta(days=1100))
    assert not any(name in p for p in result["problems"]) and result["anchors_expired"] == 1
    assert_clean(client, rechain)


def test_restore_from_backup_is_not_reported_as_tampering(client, rechain):
    """백업으로 DB 를 되돌리면 백업 뒤에 남긴 앵커는 사라진 행이나 같은 번호의 다른 행을 가리킨다 — 복원 한 번으로 검증이 영영
    '위·변조 의심'이 됐다(실제 pg_restore 로 재현). 복원 기록(backup.sh 의 backup.restore) 바로 앞 행 시각과 복원 사이에 남긴 앵커는
    버려진 갈래로 따로 알리고, 그 밖의 앵커는 그대로 대조한다. 잘못 고른 백업을 안전 사본으로 다시 되돌린 경우도 같다."""
    from app import integrity

    write(client, 3, "백업 전")
    kept_id, kept_hash, _ = head()
    [(seq,)] = sql("SELECT last_value FROM audit_log_id_seq")
    anchor("integrity-2098-01-01.json", kept_id, kept_hash)                 # 백업에 든 행 — 계속 대조
    write(client, 3, "버려질 갈래")
    lost, lost_id = anchor_head("integrity-2098-01-02.json")

    def restore():
        """pg_restore 처럼: 백업 시점의 행·머리·번호로 되돌리고(트리거 없이) backup.sh 가 복원 기록을 남긴다."""
        superuser(("DELETE FROM audit_log WHERE id > %s", (kept_id,)),
                  ("UPDATE audit_chain SET last_id = %s, last_hash = %s", (kept_id, kept_hash)),
                  ("SELECT setval('audit_log_id_seq', %s)", (seq,)))
        sql("INSERT INTO audit_log (actor, action, target, detail) VALUES ('system', 'backup.restore', 'wlm-x.dump', '{}')")

    restore()
    write(client, 5, "복원 뒤")                      # 같은 번호 범위에 새 갈래가 쌓인다
    assert sql("SELECT count(*) FROM audit_log WHERE id = %s", (lost_id,))[0][0] == 1
    result = verify(client)
    assert result["ok"], result["problems"]
    assert [s["file"] for s in result["superseded"]] == [lost] and result["anchors_checked"] >= 1
    # 정상적인 복원과 가짜 복원 기록은 같은 모양 — 한 달 동안 사람에게 확인을 묻는다 (실패는 아님)
    assert client.portal.call(integrity.record_verify)["ok"]
    notices = client.portal.call(integrity.status)["notices"]
    assert any(n["level"] == "warn" and "DB 복원 기록" in n["text"] for n in notices), notices
    later = client.portal.call(integrity.status, datetime.now(UTC) + timedelta(days=31))["notices"]
    assert not any("DB 복원 기록" in n["text"] for n in later)

    # 복원 뒤에 남긴 앵커는 그대로 대조한다 — 복원 기록이 그 뒤의 변조를 덮지 않는다
    after, after_id = anchor_head("integrity-2098-01-03.json")
    superuser(("UPDATE audit_log SET target = '고침' WHERE id = %s", (after_id,)))
    rechain()
    assert any(f"앵커 {after} 의 #{after_id} 가 다릅니다" in p for p in problems_of(client))
    Path(integrity.anchor_dir(), after).unlink()
    result = verify(client)
    assert result["ok"], result["problems"]
    clear_anchors()


def test_api_cli_and_report_show_a_broken_chain(client, rechain, tmp_path):
    from app import integrity
    from app.reports import builder

    # 외부 복제본의 앵커로 대조 (--anchors): 이 서버의 앵커를 지워도 복제본이 잡는다
    replica = tmp_path / "replica"
    replica.mkdir()
    last_id, last_hash, _ = head()
    anchor("integrity-2099-03-01.json", last_id, last_hash, folder=replica)
    env = dict(os.environ, WLM_ARCHIVE_DIR=str(integrity.anchor_dir()))
    ok = subprocess.run([sys.executable, "-m", "app.cli", "verify-chain", "--anchors", str(replica)],
                        check=False, capture_output=True, text=True, env=env, timeout=120)
    assert ok.returncode == 0 and "정상" in ok.stdout, ok.stdout + ok.stderr
    # 복제본 경로를 틀리면 아무것도 대조하지 않고 '정상'이 나왔다 — 문제로 알린다
    typo = subprocess.run([sys.executable, "-m", "app.cli", "verify-chain", "--anchors", str(tmp_path / "no-such")],
                          check=False, capture_output=True, text=True, env=env, timeout=120)
    assert typo.returncode != 0 and "앵커(integrity-*.json)가 하나도 없습니다" in typo.stdout, typo.stdout + typo.stderr
    superuser(("UPDATE audit_log SET target = '다시 씀' WHERE id = %s", (last_id,)))
    rechain()
    bad = subprocess.run([sys.executable, "-m", "app.cli", "verify-chain", "--anchors", str(replica)],
                         check=False, capture_output=True, text=True, env=env, timeout=120)
    assert bad.returncode != 0 and f"#{last_id} 가 다릅니다" in bad.stdout, bad.stdout + bad.stderr
    assert "replica/integrity-2099-03-01.json" in bad.stdout

    superuser("UPDATE audit_log SET target = '고침' WHERE id = (SELECT max(id) FROM audit_log)")
    r = client.post("/api/settings/integrity/verify", headers=CSRF)
    assert r.status_code == 200 and r.json()["ok"] is False
    status = client.get("/api/settings/integrity").json()
    assert status["last_verify"]["detail"]["ok"] is False and status["head"]["last_id"] > 0
    assert any(n["level"] == "bad" and "위·변조 검증 실패" in n["text"] for n in status["notices"])
    now = datetime.now(UTC)
    payload = client.portal.call(builder.build, "daily", now - timedelta(hours=1), now + timedelta(minutes=1))
    chain = payload["retention"]["audit_chain"]
    assert chain["verify"]["ok"] is False and chain["last_at"]
    assert any("감사로그 위·변조 검증 실패" in a["text"] for a in payload["attention"])
    assert_clean(client, rechain)


def test_a_verify_that_crashes_is_recorded_as_a_failure(client, rechain):
    """검증이 예외로 멈추면 예전 '정상'이 그대로 보였다(검토에서 재현: at = infinity 로 형 변환 오류)."""
    from app import integrity

    superuser("UPDATE audit_log SET at = 'infinity' WHERE id = (SELECT max(id) FROM audit_log)")
    result = client.portal.call(integrity.record_verify)
    assert not result["ok"] and any("시각이 올바르지 않습니다" in p for p in result["problems"])

    async def boom(*_a, **_k):
        raise RuntimeError("시험용 오류")

    original = integrity.verify
    integrity.verify = boom
    try:
        result = client.portal.call(integrity.record_verify)
    finally:
        integrity.verify = original
    assert not result["ok"] and "검증하지 못했습니다" in result["problems"][0]
    [(detail,)] = sql("SELECT detail FROM audit_log WHERE action = 'integrity.verify' ORDER BY id DESC LIMIT 1")
    assert detail["ok"] is False
    superuser("UPDATE audit_log SET at = now() WHERE at = 'infinity'")
    assert_clean(client, rechain)


def test_stale_verify_and_anchor_are_warned(client):
    """매일 검증·앵커가 멈추면(정기 정리가 돌지 않음·보관 폴더에 못 씀) 예전 '정상'만 보였다 — 이틀 넘으면 경고."""
    from app import integrity

    client.portal.call(integrity.daily)
    fresh = client.portal.call(integrity.status)["notices"]
    assert not [n for n in fresh if "이틀" in n["text"]], fresh
    later = client.portal.call(integrity.status, datetime.now(UTC) + timedelta(days=3))["notices"]
    texts = " ".join(n["text"] for n in later)
    assert "검증이 이틀 넘게 없습니다" in texts and "앵커를 이틀 넘게" in texts
    clear_anchors()
