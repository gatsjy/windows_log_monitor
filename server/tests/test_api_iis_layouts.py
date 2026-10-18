"""IIS 열 순서 영속화(ADR-037, BACKLOG B-08) 통합 테스트: 요청 사이·서버 재시작·멈춘 사이 새 파일·실패한 요청·정리,
그리고 MSSQL 줄마다(0.3.0)·묶음(0.4.0) 레코드를 섞어 넣어도 같게 세는지."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import psycopg
import pytest

CSRF = {"X-WLM-CSRF": "1"}
KEY = {"X-API-Key": "test-key"}
TEST_DB_NAME = os.environ["WLM_DATABASE_URL"].rpartition("/")[2]

# 사용자 지정 15열 — 칸 수가 기본 순서와 같아서 예전에는 재시작 뒤 기본 순서로 잘못 읽었다
FIELDS = ("date time s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
          "cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken")
DIR = r"C:\inetpub\logs\LogFiles\W3SVC3"


def sql(query, params=None):
    with psycopg.connect(os.environ["WLM_DATABASE_URL"], autocommit=True) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _line(user="lee", ip="198.51.100.9", status=401):
    return f"{datetime.now(UTC):%Y-%m-%d %H:%M:%S} WEB03 10.0.0.10 POST /login - 443 {user} {ip} Mozilla/5.0 {status} 1 0 15"


def _iis(host, file, log):
    return {"log": log, "file": file, "agent_host": host, "log_source": "iis"}


@pytest.fixture(scope="module")
def client():
    try:
        with psycopg.connect(os.environ["WLM_ADMIN_DATABASE_URL"], autocommit=True, connect_timeout=3) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}" WITH (FORCE)')
            conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    except psycopg.Error as exc:
        pytest.skip(f"테스트 DB 를 만들 수 없음: {exc}")
    from fastapi.testclient import TestClient

    from app import repository
    from app.main import app

    repository.forget_iis_layouts()
    with TestClient(app) as c:
        initial = os.environ["WLM_ADMIN_INITIAL_PASSWORD"]
        c.post("/api/auth/login", json={"username": "admin", "password": initial}, headers=CSRF)
        c.post("/api/auth/password", json={"current_password": initial, "new_password": "Root#Changed2026"}, headers=CSRF)
        yield c


def _ingest(client, records):
    r = client.post("/api/ingest", json=records, headers=KEY)
    assert r.status_code == 200, r.text
    return r.json()


def _items(client, **params):
    r = client.get("/api/events", params={"since": "1h", **params}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def _event(client, item):
    r = client.get(f"/api/events/{item['id']}", headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()


def test_header_only_request_is_stored_and_used_by_the_next_request(client):
    file = DIR + r"\u_ex261019.log"
    assert _ingest(client, [_iis("WEB-L1", file, "#Software: Microsoft Internet Information Services 10.0"),
                            _iis("WEB-L1", file, "#Fields: " + FIELDS)]) == {"accepted": 0, "heartbeats": 0}
    rows = sql("SELECT dir, fields FROM iis_layouts WHERE host = 'WEB-L1' AND file = %s", (file,))
    assert rows == [("C:/inetpub/logs/LogFiles/W3SVC3", FIELDS)]
    _ingest(client, [_iis("WEB-L1", file, _line())])
    [item] = _items(client, host="WEB-L1")
    assert (item["src_ip"], item["username"], item["event_id"], item["level"]) == ("198.51.100.9", "lee", 401, 3)
    assert "_layout" not in _event(client, item)["raw"]["iis"]


OTHER = ("date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) "
         "sc-status sc-substatus sc-win32-status time-taken sc-bytes")  # 같은 폴더의 더 새 파일 — 다른 구성 (16칸)


def test_server_restart_reads_the_files_own_layout_from_db(client):
    from app import repository

    file, newer = DIR + r"\u_ex261017.log", DIR + r"\u_ex261018.log"
    _ingest(client, [_iis("WEB-R", file, "#Fields: " + FIELDS)])
    _ingest(client, [_iis("WEB-R", newer, "#Fields: " + OTHER)])  # 폴더의 '최신'은 다른 구성
    repository.forget_iis_layouts()  # 캐시를 비우지 않으면 캐시 덕분에 통과한다
    _ingest(client, [_iis("WEB-R", file, _line(user="park", ip="198.51.100.10"))])  # 늦게 온 어제 파일의 줄
    [item] = _items(client, host="WEB-R", user="park")
    assert (item["src_ip"], item["event_id"]) == ("198.51.100.10", 401)
    assert "_layout" not in _event(client, item)["raw"]["iis"]  # 폴더 순서가 아니라 그 파일의 순서로


def test_new_file_while_agent_was_stopped_uses_the_folder_layout(client):
    # 어제 파일의 머리줄은 받았고, 에이전트가 멈춘 사이 생긴 오늘 파일은 끝부터 읽혀 머리줄이 오지 않았다
    old, new = DIR + r"\u_ex261018.log", DIR + r"\u_ex261019.log"
    _ingest(client, [_iis("WEB-L2", old, "#Fields: " + FIELDS)])
    from app import repository

    repository.forget_iis_layouts()
    _ingest(client, [_iis("WEB-L2", new, _line(user="choi", ip="198.51.100.11")),
                     _iis("WEB-L2", new, "garbage line with five parts")])
    [parsed] = _items(client, host="WEB-L2", user="choi")
    assert _event(client, parsed)["raw"]["iis"]["_layout"] == "site"
    raw = [i for i in _items(client, host="WEB-L2") if i["message"] == "garbage line with five parts"]
    assert len(raw) == 1 and raw[0]["event_id"] is None  # 칸 수가 다르면 원문 그대로
    # 새 파일의 행은 생기지 않는다 (머리줄을 받은 적 없음)
    assert sql("SELECT count(*) FROM iis_layouts WHERE host = 'WEB-L2'") == [(1,)]


def test_folder_layout_learned_while_running_serves_the_next_new_file(client):
    # 서버를 다시 시작하지 않은 채: 폴더에 아무것도 없다고 캐시한 뒤 머리줄이 오면, 그 뒤 새 파일도 그 순서로
    a, b, c = (DIR + rf"\u_ex2610{d}.log" for d in ("01", "02", "03"))
    _ingest(client, [_iis("WEB-C", a, _line(user="kang", ip="198.51.100.30"))])   # 폴더 = 없음 (캐시)
    _ingest(client, [_iis("WEB-C", b, "#Fields: " + FIELDS)])
    _ingest(client, [_iis("WEB-C", c, _line(user="jung", ip="198.51.100.31"))])
    [item] = _items(client, host="WEB-C", user="jung")
    assert (item["src_ip"], _event(client, item)["raw"]["iis"]["_layout"]) == ("198.51.100.31", "site")
    assert _items(client, host="WEB-C", user="kang") == []  # 그 전 줄은 원문으로 남았다 (틀리게 읽지 않음)


def test_failed_request_does_not_teach_the_cache(client, monkeypatch):
    from app import repository

    file = DIR + r"\u_ex261020.log"

    async def broken(*args, **kwargs):
        raise RuntimeError("DB 쓰기 실패 흉내")

    monkeypatch.setattr(repository, "insert_batch", broken)
    with pytest.raises(RuntimeError):
        client.post("/api/ingest", json=[_iis("WEB-L3", file, "#Fields: " + FIELDS)], headers=KEY)
    monkeypatch.undo()
    assert ("WEB-L3", file) not in repository._IIS_FILE
    assert sql("SELECT count(*) FROM iis_layouts WHERE host = 'WEB-L3'") == [(0,)]
    # 에이전트가 청크째 다시 보내면 그때 배운다
    _ingest(client, [_iis("WEB-L3", file, "#Fields: " + FIELDS), _iis("WEB-L3", file, _line(user="han"))])
    assert [i["username"] for i in _items(client, host="WEB-L3")] == ["han"]


def test_purge_keeps_the_latest_layout_of_each_folder(client):
    from app import partitions

    now = datetime.now(UTC)
    rows = [("PURGE", "A/old.log", "A", now - timedelta(days=50)),     # 같은 폴더에 더 새 것이 있음 → 지움
            ("PURGE", "A/mid.log", "A", now - timedelta(days=40)),     # 오래됐지만 폴더 A 의 최신 → 남김
            ("PURGE", "B/old.log", "B", now - timedelta(days=60)),     # 더 새 것이 최근 → 지움
            ("PURGE", "B/new.log", "B", now - timedelta(days=1)),
            ("PURGE", "C/only.log", "C", now - timedelta(days=400))]   # 폴더에 하나뿐 → 남김
    for host, file, directory, seen in rows:
        sql("INSERT INTO iis_layouts (host, file, dir, fields, seen_at) VALUES (%s, %s, %s, 'date time', %s)",
            (host, file, directory, seen))
    client.portal.call(partitions.purge_iis_layouts)  # 앱의 이벤트 루프에서 (연결 풀은 그 루프의 것)
    left = sql("SELECT file FROM iis_layouts WHERE host = 'PURGE' ORDER BY file")
    assert [r[0] for r in left] == ["A/mid.log", "B/new.log", "C/only.log"]


def test_mssql_plain_and_multiline_records_count_the_same(client):
    stamp = datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S.00")
    plain = [  # 0.3.0 이하: 줄마다
        f"{stamp} Server      Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)",
        "\tCopyright (C) 2022 Microsoft Corporation",
        f"{stamp} Logon       Error: 18456, Severity: 14, State: 8.",
        f"{stamp} Logon       Login failed for user 'sa'. Reason: x [CLIENT: 198.51.100.20]",
    ]
    merged = [plain[0] + "\r\n" + plain[1] + "\r\n", plain[2] + "\r\n", plain[3] + "\r\n"]  # 0.4.0: 묶여 옴
    records = [{"log": log, "agent_host": "DB-P", "log_source": "mssql", "file": r"I1\ERRORLOG"} for log in plain]
    records += [{"log": log, "agent_host": "DB-M", "log_source": "mssql", "file": r"I1\ERRORLOG"} for log in merged]
    assert _ingest(client, records)["accepted"] == 7
    for host in ("DB-P", "DB-M"):
        assert [(i["username"], i["src_ip"]) for i in _items(client, host=host, event_id="18456")] == \
            [("sa", "198.51.100.20")]
    [banner] = [i for i in _items(client, host="DB-M") if i["provider"] == "Server"]
    assert _event(client, banner)["raw"]["mssql"]["lines"] == 2


def test_custom_layout_ip_and_user_are_searchable_and_counted(client):
    file = DIR + r"\u_ex261021.log"
    _ingest(client, [_iis("WEB-T1", file, "#Fields: " + FIELDS), _iis("WEB-T1", file, _line(user="yoon", ip="198.51.100.40")),
                     _iis("WEB-T1", file, _line(user="yoon", ip="198.51.100.40")), _iis("WEB-T1", file, _line(user="seo", ip="198.51.100.41"))])
    params = {"since": "1h", "host": "WEB-T1", "category": "iis"}
    r = client.get("/api/stats/top", params={**params, "field": "ip"}, headers=CSRF)
    assert [(i["value"], i["n"]) for i in r.json()["items"]] == [("198.51.100.40", 2), ("198.51.100.41", 1)]
    r = client.get("/api/stats/top", params={**params, "field": "user"}, headers=CSRF)
    assert [(i["value"], i["n"]) for i in r.json()["items"]] == [("yoon", 2), ("seo", 1)]
    assert len(_items(client, host="WEB-T1", ip="198.51.100.41")) == 1
