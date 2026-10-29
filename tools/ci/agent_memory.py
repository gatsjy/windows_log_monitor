"""윈도 에이전트 메모리·라우팅 실측 (윈도 CI, 실제 Fluent Bit · 표준 라이브러리만).

서버가 꺼진 동안 에이전트 메모리가 늘어나는지, 그리고 하트비트 출력 분리(ADR-039)가 의도대로 도는지 본다:
1. 서버 없이(연결 거부) --down 초 동안 돌리며 fluent-bit.exe 의 Private Bytes 를 잰다. 그 사이 Application 로그에
   표지 이벤트를 하나 쓴다.
2. 받는 쪽(가짜 /api/ingest)을 띄우고 표지 이벤트가 도착하는지 본다 — 장애 중 로그는 버리면 안 된다.
3. 장애 중에 만든 하트비트가 몇 개나 뒤늦게 오는지 센다 — 하트비트 출력은 2번 재시도 후 버리므로 거의 오지 않아야 한다.

하트비트 주기는 30초 → 1초로 줄여서 하루치 장애(2,880개)를 몇 분 안에 흉내 낸다 (하트비트마다 256KB 메모리 조각).
--baseline 에 옛 설정 틀을 주면 같은 조건으로 먼저 돌려 증가량을 비교한다 (새 설정이 옛 설정의 절반 이하여야 통과).

    python tools/ci/agent_memory.py --fluent-bit fb\\bin\\fluent-bit.exe --template agent/windows/fluent-bit.yaml
        [--baseline old-fluent-bit.yaml] [--down 120] [--work 폴더]

관리자 권한 필요 (eventcreate). 결과는 'WLMMEM {json}' 줄로도 남긴다.
"""

from __future__ import annotations

import argparse
import ctypes
import gzip
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from ctypes import wintypes
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA_DIR = r"C:\ProgramData\wlm-agent"


class _Counters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t)]


def private_mb(pid: int) -> float:
    """작업 관리자 '커밋 크기'와 같은 Private Bytes. Working Set 은 Windows 가 수시로 줄여서 증가 추세를 가린다."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ
    if not handle:
        raise OSError(ctypes.get_last_error(), f"OpenProcess {pid}")
    try:
        counters = _Counters()
        counters.cb = ctypes.sizeof(counters)
        if not kernel32.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise OSError(ctypes.get_last_error(), "K32GetProcessMemoryInfo")
        return counters.PrivateUsage / 1048576
    finally:
        kernel32.CloseHandle(handle)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def render(template: str, work: Path, port: int) -> str:
    """설치 스크립트처럼 자리를 채우되, 보낼 곳은 이 PC 의 빈 포트, 상태 폴더는 work, 하트비트는 1초."""
    text = template.replace("@SERVER_HOST@", "127.0.0.1").replace("@SERVER_PORT@", str(port)) \
        .replace("@API_KEY@", "ci-mem-key").replace("@CHANNELS@", "Application").replace("@TLS_SERVER_NAME@", "")
    text = text.replace(DATA_DIR, str(work))
    head, sep, rest = text.partition("tag: heartbeat")
    if not sep or "interval_sec: 30" not in rest:
        raise SystemExit("하트비트 입력(tag: heartbeat, interval_sec: 30)을 찾지 못했습니다")
    return head + sep + rest.replace("interval_sec: 30", "interval_sec: 1", 1)


class Sink:
    """가짜 /api/ingest: 받은 레코드를 모은다 (gzip JSON 배열)."""

    def __init__(self, port: int):
        self.records: list[dict] = []
        lock = threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if body[:2] == b"\x1f\x8b":
                    body = gzip.decompress(body)
                data = json.loads(body or b"[]")
                with lock:
                    sink.records.extend(data if isinstance(data, list) else [data])
                self.send_response(201)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _ts(record: dict) -> float:
    value = str(record.get("date", ""))
    if value.endswith("Z"):   # Fluent Bit iso8601 — 3.11 미만 fromisoformat 은 Z 를 못 읽는다
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).timestamp()


def run(exe: str, template: str, label: str, down: int, work: Path) -> dict:
    if work.exists():
        shutil.rmtree(work)
    (work / "buffer").mkdir(parents=True)
    port = free_port()
    cfg = work / "fluent-bit.yaml"
    cfg.write_text(render(template, work, port), encoding="utf-8")
    marker = f"WLMMEM-{label}-{uuid.uuid4().hex[:8]}"
    proc = subprocess.Popen([exe, "-c", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    samples: list[tuple[float, float]] = []
    sink = None
    try:
        start = time.time()
        time.sleep(10)   # 기동·첫 읽기가 끝난 뒤를 기준으로
        base = private_mb(proc.pid)
        wrote = False
        while time.time() - start < 10 + down:
            if proc.poll() is not None:
                raise SystemExit(f"[{label}] fluent-bit 가 멈췄습니다 (exit {proc.returncode}): {work / 'fluent-bit.log'}")
            samples.append((round(time.time() - start, 1), round(private_mb(proc.pid), 1)))
            if not wrote and time.time() - start > 10 + down / 2:
                # 장애 한가운데 생긴 로그: 서버가 돌아오면 반드시 와야 한다
                subprocess.run(["eventcreate", "/T", "INFORMATION", "/ID", "999", "/L", "APPLICATION",
                                "/SO", "WLMMemTest", "/D", marker], check=True, stdout=subprocess.DEVNULL)
                wrote = True
            time.sleep(5)
        down_end = time.time()
        peak = max(mb for _, mb in samples)
        sink = Sink(port)
        deadline = time.time() + 120
        while time.time() < deadline and not any(marker in json.dumps(r) for r in sink.records):
            time.sleep(2)
        time.sleep(10)   # 마저 오는 하트비트까지
        records = list(sink.records)
    finally:
        proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
        if sink:
            sink.close()
    beats = [r for r in records if r.get("type") == "heartbeat"]
    stale = [r for r in beats if _ts(r) < down_end - 15]   # 장애 중에 만든 하트비트 (재시도 몇 번 몫은 빼고)
    return {"label": label, "down_sec": down, "base_mb": round(base, 1), "peak_mb": round(peak, 1),
            "growth_mb": round(peak - base, 1), "made_while_down": down, "stale_heartbeats": len(stale),
            "heartbeats": len(beats), "records": len(records),
            "marker_delivered": any(marker in json.dumps(r) for r in records), "samples": samples}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fluent-bit", required=True)
    ap.add_argument("--template", default="agent/windows/fluent-bit.yaml")
    ap.add_argument("--baseline", help="비교할 옛 설정 틀 (예: git show origin/main:agent/windows/fluent-bit.yaml)")
    ap.add_argument("--down", type=int, default=120, help="서버가 꺼져 있는 시간(초). 하트비트 1초 = 이 개수만큼 쌓임")
    ap.add_argument("--work", default=str(Path(tempfile.gettempdir()) / "wlm-mem"))
    args = ap.parse_args()
    work = Path(args.work)
    results = []
    if args.baseline:
        results.append(run(args.fluent_bit, Path(args.baseline).read_text(encoding="utf-8"), "old", args.down, work / "old"))
    new = run(args.fluent_bit, Path(args.template).read_text(encoding="utf-8"), "new", args.down, work / "new")
    results.append(new)
    problems = []
    for r in results:
        print(f"[{r['label']}] Private Bytes {r['base_mb']} → 최고 {r['peak_mb']} MB (+{r['growth_mb']}), "
              f"장애 중 하트비트 {r['made_while_down']}개 중 뒤늦게 온 것 {r['stale_heartbeats']}개, "
              f"표지 로그 도착 {r['marker_delivered']}")
        print("WLMMEM " + json.dumps(r, ensure_ascii=False))
    if not new["marker_delivered"]:
        problems.append("장애 중에 쓴 로그가 서버가 돌아온 뒤에도 오지 않았습니다 (로그 유실)")
    if new["heartbeats"] - new["stale_heartbeats"] < 3:
        problems.append("서버가 돌아온 뒤 하트비트가 오지 않습니다 (하트비트 출력 라우팅)")
    # retry_limit 2 면 하트비트는 길어야 35초쯤 남는다 (scheduler.base 5). 실측 14개 / 옛 설정 45개 (2분 장애)
    if new["stale_heartbeats"] > 30:
        problems.append(f"장애 중 하트비트가 버려지지 않았습니다 ({new['stale_heartbeats']}개 도착)")
    if args.baseline:
        old = results[0]
        if old["growth_mb"] >= 4 and new["growth_mb"] > old["growth_mb"] / 2:
            problems.append(f"메모리 증가가 줄지 않았습니다: 옛 설정 +{old['growth_mb']}MB, 새 설정 +{new['growth_mb']}MB")
        if old["stale_heartbeats"] <= new["stale_heartbeats"] * 2:
            problems.append(f"옛 설정보다 하트비트가 덜 버려지지 않았습니다: 옛 {old['stale_heartbeats']}개, 새 {new['stale_heartbeats']}개")
    for p in problems:
        print("실패:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
