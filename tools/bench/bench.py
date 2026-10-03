"""검색 성능 벤치마크 — 별도 DB(wlm_bench)에 대량 이벤트를 만들고 실제 API 로 응답 시간을 잰다.

개발 DB 는 건드리지 않는다. api 컨테이너 안에서 실행한다 (개발용 override 가 tools/ 를 마운트):

  docker compose exec api python tools/bench/bench.py --rows 5000000 --days 30     # 생성 + 측정
  docker compose exec api python tools/bench/bench.py --skip-seed                  # 측정만 다시
  docker compose exec api python tools/bench/bench.py --drop                       # 벤치 DB 삭제

결과는 docs/PERFORMANCE.md 에 기록한다.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from datetime import UTC, datetime, timedelta

import psycopg

DEV_URL = os.environ.get("WLM_DATABASE_URL", "postgresql://wlm:wlm@db:5432/wlm")
BASE, _, DEV_DB = DEV_URL.rpartition("/")
BENCH_DB = f"{DEV_DB}_bench"
BENCH_URL = f"{BASE}/{BENCH_DB}"

# app 을 import 하기 전에 벤치 DB 를 가리키게 한다
os.environ.update({
    "WLM_DATABASE_URL": BENCH_URL,
    "WLM_ADMIN_INITIAL_PASSWORD": "Bench#Init2026",
    "WLM_PASSWORD_HASH_N": str(2**12),
    "WLM_ALERTS_FILE": "/tmp/wlm-bench/alerts.yaml",   # 알림 엔진은 규칙 없이 (메일 안 보냄)
    "WLM_DASHBOARD_DIR": "/tmp/wlm-bench/dashboards",
    "WLM_INGEST_API_KEYS": "bench-key",
})
sys.path.insert(0, "/app")

CSRF = {"X-WLM-CSRF": "1"}

# (채널, 공급자, 이벤트ID, 수준, 메시지, 가중치) — 실제 Windows 환경 비율을 흉내
TEMPLATES = [
    ("Security", "Microsoft-Windows-Security-Auditing", 4624, 4, "계정이 성공적으로 로그온되었습니다.", 30),
    ("Security", "Microsoft-Windows-Security-Auditing", 4672, 4, "새 로그온에 특수 권한을 할당했습니다.", 12),
    ("Security", "Microsoft-Windows-Security-Auditing", 4634, 4, "계정이 로그오프되었습니다.", 15),
    ("Security", "Microsoft-Windows-Security-Auditing", 4625, 3, "계정을 로그온하지 못했습니다. 알 수 없는 사용자 이름 또는 잘못된 암호입니다.", 6),
    ("Security", "Microsoft-Windows-Security-Auditing", 4688, 4, "새 프로세스를 만들었습니다.", 10),
    ("Security", "Microsoft-Windows-Security-Auditing", 4740, 3, "사용자 계정이 잠겼습니다.", 0.2),
    ("System", "Service Control Manager", 7036, 4, "서비스가 실행 상태로 전환되었습니다.", 12),
    ("System", "Service Control Manager", 7031, 2, "서비스가 예기치 않게 종료되었습니다. 다음 수정 동작이 수행됩니다: 서비스 다시 시작.", 0.6),
    ("System", "Microsoft-Windows-DistributedCOM", 10016, 3, "응용 프로그램별 권한 설정에서 로컬 활성화 권한을 부여하지 않습니다.", 3),
    ("System", "disk", 51, 3, "페이징 작업 중 장치에서 오류가 발견되었습니다.", 0.5),
    ("System", "Microsoft-Windows-Kernel-Power", 41, 1, "먼저 시스템을 정상적으로 종료하지 않고 시스템이 다시 부팅되었습니다.", 0.05),
    ("Application", "Application Error", 1000, 2, "오류 있는 응용 프로그램 이름: w3wp.exe, 예외 코드: 0xc0000005", 1.5),
    ("Application", ".NET Runtime", 1026, 2, "처리되지 않은 예외로 인해 프로세스가 종료되었습니다. System.TimeoutException: The operation has timed out", 0.8),
    ("Application", "Microsoft-Windows-Security-SPP", 16384, 4, "소프트웨어 보호 서비스를 다시 시작하도록 예약했습니다.", 5),
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, 5, "스크립트 블록 텍스트 만들기: Get-Service", 3),
]


def seed(rows: int, days: int, hosts: int, chunk: int = 250_000) -> None:
    with psycopg.connect(BENCH_URL, autocommit=True) as conn:
        have = conn.execute("SELECT count(*) FROM events").fetchone()[0]
        if have >= rows:
            print(f"이미 {have:,}건 있음 — 생성 건너뜀")
            return
        # 생성 기간을 덮는 월 파티션 (앱은 이번 달부터만 만든다)
        now = datetime.now(UTC)
        month = (now - timedelta(days=days + 1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        while month <= now:
            following = (month + timedelta(days=32)).replace(day=1)
            conn.execute(f"CREATE TABLE IF NOT EXISTS events_{month:%Y_%m} PARTITION OF events"
                         f" FOR VALUES FROM ('{month:%Y-%m-%d}') TO ('{following:%Y-%m-%d}')")
            month = following

        conn.execute("DROP TABLE IF EXISTS bench_templates")
        conn.execute("CREATE TABLE bench_templates (id int, channel text, provider text, event_id int, level smallint,"
                     " message text)")
        idx = 0
        for ch, prov, eid, lvl, msg, weight in TEMPLATES:
            for _ in range(max(1, int(weight * 10))):
                idx += 1
                conn.execute("INSERT INTO bench_templates VALUES (%s, %s, %s, %s, %s, %s)", (idx, ch, prov, eid, lvl, msg))
        total_templates = idx

        sql = f"""
        INSERT INTO events (received_at, ts, host, source, channel, provider, event_id, level, message, raw)
        SELECT r_at, r_at - (random() * interval '3 seconds'), host, 'winevtlog', t.channel, t.provider, t.event_id,
               t.level, t.message || ' 계정 이름: ' || usr || ' 원본 주소: ' || ip,
               jsonb_build_object(
                 'ProviderName', t.provider, 'EventID', t.event_id, 'Level', CASE WHEN t.channel = 'Security' THEN 0 ELSE t.level END,
                 'Keywords', CASE WHEN t.event_id = 4625 THEN '0x8010000000000000' ELSE '0x8020000000000000' END,
                 'TimeCreated', to_char(r_at AT TIME ZONE 'Asia/Seoul', 'YYYY-MM-DD HH24:MI:SS') || ' +0900',
                 'EventRecordID', (random() * 1e9)::bigint, 'ProcessID', 4 + (random() * 9000)::int,
                 'ThreadID', (random() * 9000)::int, 'Channel', t.channel, 'Computer', host || '.corp.local',
                 'Message', t.message || ' 계정 이름: ' || usr || ' 원본 주소: ' || ip,
                 'StringInserts', jsonb_build_array('S-1-5-18', '-', '-', '0x3e7', 'S-1-5-21-1', usr, 'CORP',
                                                    '0x1a2b', '3', 'NtLmSsp', '-', ip),
                 'agent_host', host, 'log_source', 'winevtlog',
                 'date', to_char(r_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
          FROM (
            SELECT now() - random() * interval '{days} days' AS r_at,
                   'PC-' || lpad((1 + floor(random() * {hosts}))::int::text, 4, '0') AS host,
                   1 + floor(random() * {total_templates})::int AS tid,
                   'user' || floor(random() * 2000)::int AS usr,
                   '10.' || floor(random() * 4)::int || '.' || floor(random() * 255)::int || '.' || floor(random() * 255)::int AS ip
              FROM generate_series(1, %s)
          ) s JOIN bench_templates t ON t.id = s.tid
        """
        started = time.time()
        while have < rows:
            n = min(chunk, rows - have)
            t0 = time.time()
            conn.execute(sql, (n,))
            have += n
            rate = n / (time.time() - t0)
            print(f"  {have:>12,} / {rows:,}  ({rate:,.0f}건/초)", flush=True)
        conn.execute("INSERT INTO agents (host, last_seen, events_total) SELECT host, max(received_at), count(*)"
                     " FROM events GROUP BY host ON CONFLICT (host) DO NOTHING")
        print(f"생성 완료: {time.time() - started:,.0f}초. VACUUM ANALYZE …", flush=True)
        conn.execute("VACUUM (ANALYZE) events")  # 운영에서는 autovacuum 이 하는 일 (인덱스 전용 스캔에 필요)
        size = conn.execute("SELECT pg_size_pretty(pg_database_size(current_database()))").fetchone()[0]
        print(f"DB 크기: {size}")


SCENARIOS = [
    # (이름, 경로, 파라미터)
    ("최근 24시간 목록 (조건 없음)", "/api/events", {"since": "24h", "limit": 100}),
    ("24시간 · PC 1대", "/api/events", {"since": "24h", "host": "PC-0042", "limit": 100}),
    ("7일 · 오류(1,2)", "/api/events", {"since": "7d", "level": "1,2", "limit": 100}),
    ("30일 · 이벤트 4740 (드문 이벤트)", "/api/events", {"since": "30d", "event_id": "4740", "limit": 100}),
    ("30일 · PC 1대 + 4625", "/api/events", {"since": "30d", "host": "PC-0042", "event_id": "4625", "limit": 100}),
    ("24시간 · 메시지 검색 'TimeoutException'", "/api/events", {"since": "24h", "q": "TimeoutException", "limit": 100}),
    ("7일 · 메시지 검색 'user1234'", "/api/events", {"since": "7d", "q": "user1234", "limit": 100}),
    ("30일 · 메시지 검색 '다시 부팅' (드문 문구)", "/api/events", {"since": "30d", "q": "다시 부팅", "limit": 100}),
    ("7일 · 원본 필드 StringInserts.5=user77", "/api/events", {"since": "7d", "f.StringInserts.5": "user77", "limit": 100}),
    ("24시간 건수 + 직전 비교", "/api/stats/count", {"since": "24h", "compare": "true"}),
    ("7일 건수 · 오류", "/api/stats/count", {"since": "7d", "level": "1,2", "compare": "true"}),
    ("30일 건수 (전체)", "/api/stats/count", {"since": "30d"}),
    ("24시간 시계열 (수준별)", "/api/stats/timeseries", {"since": "24h", "group": "level", "buckets": 48}),
    ("7일 시계열 (수준별)", "/api/stats/timeseries", {"since": "7d", "group": "level", "buckets": 56}),
    ("30일 시계열 (수준별)", "/api/stats/timeseries", {"since": "30d", "group": "level", "buckets": 60}),
    ("24시간 상위 PC", "/api/stats/top", {"since": "24h", "field": "host", "limit": 10}),
    ("7일 상위 이벤트 ID (오류·경고)", "/api/stats/top", {"since": "7d", "field": "event_id", "level": "1,2,3", "limit": 10}),
    ("24시간 원본 필드 값 분포 (계정)", "/api/stats/top", {"since": "24h", "field": "f.StringInserts.5", "limit": 15}),
    ("수집 PC 목록 (24시간 집계)", "/api/agents", {"since": "24h"}),
]


def run_benchmarks(repeat: int) -> list[dict]:
    import logging

    from fastapi.testclient import TestClient

    logging.getLogger("httpx").setLevel(logging.WARNING)

    from app.main import app

    results = []
    with TestClient(app) as client:
        r = client.post("/api/auth/login", json={"username": "admin", "password": "Bench#Init2026"}, headers=CSRF)
        if r.json().get("must_change_password"):
            client.post("/api/auth/password", json={"current_password": "Bench#Init2026",
                                                    "new_password": "Bench#Run2026x"}, headers=CSRF)
        else:  # 두 번째 실행부터는 바뀐 비밀번호
            client.cookies.clear()
            client.post("/api/auth/login", json={"username": "admin", "password": "Bench#Run2026x"}, headers=CSRF)

        # 페이지 넘김: 10페이지째
        def page10():
            cursor, rows = None, 0
            for _ in range(10):
                body = client.get("/api/events", params={"since": "7d", "limit": 100, **({"cursor": cursor} if cursor else {})}).json()
                cursor, rows = body["next_cursor"], len(body["items"])
            return rows

        for name, path, params in SCENARIOS + [("7일 목록 10페이지째 (더 보기 10번)", None, None)]:
            times, rows = [], None
            for _ in range(repeat):
                t0 = time.perf_counter()
                if path is None:
                    rows = page10()
                else:
                    resp = client.get(path, params=params)
                    resp.raise_for_status()
                    body = resp.json()
                    rows = (len(body["items"]) if "items" in body else body.get("current")
                            if "current" in body else len(body.get("buckets", [])))
                times.append((time.perf_counter() - t0) * 1000)
            results.append({"name": name, "first": times[0], "median": statistics.median(times[1:] or times),
                            "rows": rows})
            print(f"  {name:<40} 첫 {times[0]:>8,.0f} ms   이후 {results[-1]['median']:>8,.0f} ms   결과 {rows}", flush=True)

        # 수집 처리량: 에이전트처럼 1,000건씩 gzip 으로 보낸다 (정규화 + COPY + PC·필드 통계 갱신 포함)
        import gzip
        import json

        from tools.simulate import HOSTS, win_record

        batches, size = 30, 1000
        payloads = []
        for _ in range(batches):
            now = datetime.now(UTC)
            records = [win_record(HOSTS[i % 8][0], now) for i in range(size)]
            payloads.append(gzip.compress(json.dumps(records, ensure_ascii=False).encode()))
        t0 = time.perf_counter()
        for body in payloads:
            client.post("/api/ingest", content=body, headers={"X-API-Key": "bench-key", "Content-Encoding": "gzip",
                                                               "Content-Type": "application/json"}).raise_for_status()
        elapsed = time.perf_counter() - t0
        rate = batches * size / elapsed
        print(f"  수집 처리량: {batches * size:,}건 / {elapsed:.1f}초 = {rate:,.0f}건/초 (배치 {size}건, 요청 1개씩 순차)")
        results.append({"name": f"수집 처리량 (배치 {size}건 순차)", "first": elapsed * 1000 / batches,
                        "median": elapsed * 1000 / batches, "rows": f"{rate:,.0f}건/초"})
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=5_000_000)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--hosts", type=int, default=200)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--skip-seed", action="store_true")
    parser.add_argument("--drop", action="store_true")
    parser.add_argument("--label", default="", help="결과 제목")
    args = parser.parse_args()

    with psycopg.connect(DEV_URL, autocommit=True) as admin:
        if args.drop:
            admin.execute(f'DROP DATABASE IF EXISTS "{BENCH_DB}" WITH (FORCE)')
            print(f"{BENCH_DB} 삭제")
            return
        if not admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", (BENCH_DB,)).fetchone():
            admin.execute(f'CREATE DATABASE "{BENCH_DB}"')

    import asyncio

    from app import db

    asyncio.run(db.migrate())
    if not args.skip_seed:
        print(f"{BENCH_DB} 에 {args.rows:,}건 생성 (최근 {args.days}일, PC {args.hosts}대)")
        seed(args.rows, args.days, args.hosts)
    with psycopg.connect(BENCH_URL) as conn:
        count = conn.execute("SELECT count(*) FROM events").fetchone()[0]
        size = conn.execute("SELECT pg_size_pretty(pg_database_size(current_database()))").fetchone()[0]
    with psycopg.connect(BENCH_URL) as conn:
        pg = {k: conn.execute(f"SHOW {k}").fetchone()[0]
              for k in ("shared_buffers", "work_mem", "max_parallel_workers_per_gather", "jit")}
    print(f"\n측정 {args.label} (이벤트 {count:,}건, DB {size}, 각 {args.repeat}회, {pg})")
    results = run_benchmarks(args.repeat)
    print("\n| 시나리오 | 첫 실행 ms | 반복 ms | 결과 |")
    print("|---|---:|---:|---:|")
    for r in results:
        print(f"| {r['name']} | {r['first']:,.0f} | {r['median']:,.0f} | {r['rows']} |")


if __name__ == "__main__":
    main()
