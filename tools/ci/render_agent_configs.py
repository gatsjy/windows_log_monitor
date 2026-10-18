"""CI(B-15, B-06): 에이전트 설정 틀의 @자리@ 를 설치 스크립트와 같은 규칙으로 채워 검사용 파일을 만들고,
TLS 설정을 정적으로 검사한다 (표준 라이브러리만).

  python3 tools/ci/render_agent_configs.py <출력 폴더>
  python3 tools/ci/render_agent_configs.py --check-tls <설정 파일>... [--expect-vhost 이름] [--expect-port 번호]
                                          [--expect-ca-file 경로]   다른 곳에서 채운 TLS 설정만 검사 (install.ps1 -RenderOnly 결과)
  python3 tools/ci/render_agent_configs.py --ca-sha256 <ca.crt>      첫 인증서 DER 의 SHA-256 (서버·설치 스크립트와 따로 계산)
  python3 tools/ci/render_agent_configs.py --derive-mssql <채운 windows.yaml> <출력> --path P --state DIR --out FILE [--plain] [--down]
      채운 윈도 설정에서 multiline 정의와 MSSQL tail 만 꺼내 실제로 돌려 볼 설정을 만든다 (B-08, test_fluentbit_mssql.sh·윈도 CI).
      바꾸는 것은 경로·db·storage.path·read_from_head·출력(파일, 한 줄에 JSON 하나)뿐. --plain = multiline 을 뺀 0.3.0 방식,
      --down = 출력을 닿지 않는 서버로 (서버가 꺼진 채 멈추기)
  python3 tools/ci/render_agent_configs.py --derive-winlog <채운 windows.yaml> <출력> --state DIR --out FILE [--channels A,B]
      winevtlog 입력은 그대로 두고 출력만 파일로 — 윈도 CI 가 실제 이벤트를 일으켜 에이전트 레코드 모양을 기록한다

- linux.yaml        agent/linux/install.sh 의 sed 와 같은 치환 (평문)
- linux-tls.yaml    같은 치환 + TLS 블록을 켠 것 (TLS_CA_FILE 을 준 설치)
- windows.yaml      agent/windows/install.ps1 과 같은 치환 + IIS·MSSQL 묶음을 켠 것(Enable-Block)
- windows-min.yaml  묶음을 켜지 않은 기본
- windows-tls.yaml  IIS·MSSQL·TLS 를 모두 켠 것
스크립트의 기본값과 같게 TLS 판의 포트는 6977, 평문 판의 @TLS_SERVER_NAME@ 은 빈 값이다 (주석 줄에만 남는 자리).

채운 뒤 남은 @자리@ 가 있으면 실패한다. Fluent Bit 문법 검사(--dry-run)는 CI 가 컨테이너로 돌린다
(윈도 설정의 winevtlog 입력은 윈도 빌드에만 있어 리눅스 이미지로는 문법만 본다 — .github/workflows/ci.yml).

--dry-run 은 없는 tls.ca_file 과 키 오타를 통과시킨다. 그래서 TLS 는 여기서 정적으로 본다 (실패하면 exit 1):
- TLS 판(과 tools/ci/tls-probe.yaml): http 출력에 tls·tls.verify·tls.verify_hostname 이 on, tls.min_version 이 TLSv1.2 이상,
  tls.vhost·tls.ca_file 이 비어 있지 않음. 틀의 tls.ca_file 은 설치 스크립트가 CA 를 복사하는 자리와 같아야 한다.
  tls.verify_hostname 은 Fluent Bit 기본값이 off 라서, 빠지면 같은 CA 가 발급한 어떤 인증서든 통과한다.
- 평문 판: http 출력에 켜진 tls 키가 없음
- agent/·collector/ 의 어떤 파일에도 'tls.verify: off'·'tls.verify_hostname: off' 줄이 없음
  (주석 처리된 줄도 — 블록을 켜는 순간 검증이 꺼진다. ADR-036: 검증을 끄는 선택지는 두지 않는다)

multiline 도 정적으로 본다 (B-08, ADR-037) — 채운 모든 설정에서:
- 켜진 입력의 multiline.parser 이름이 그 파일의 multiline_parsers[].name 이나 내장 이름에 있음.
  --dry-run 은 없는 이름을 통과시키고, 실제 기동에서는 'parser not registered' 로 엔진 전체(윈도 이벤트 수집까지)가 멈춘다(실측).
- multiline 을 쓰는 입력은 storage.type: filesystem (메모리면 에이전트를 멈출 때 묶던 레코드를 잃는다 — 실측).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALUES = {"@SERVER_HOST@": "logmon.ci.local", "@SERVER_PORT@": "6976", "@API_KEY@": "ci-test-key",
          "@AGENT_HOST@": "ci-agent", "@CHANNELS@": "System,Application,Security",
          "@IIS_PATH@": r"C:\inetpub\logs\LogFiles\W3SVC1\*.log",
          "@MSSQL_PATH@": r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG",
          "@TLS_SERVER_NAME@": "logmon.ci.internal"}
_UNCOMMENT = re.compile(r"^(\s*)# (- |  )")

LINUX = "agent/linux/fluent-bit.yaml"
WINDOWS = "agent/windows/fluent-bit.yaml"
# 출력 파일: (틀, 켤 묶음, TLS 여부)
VARIANTS = {
    "linux.yaml": (LINUX, (), False),
    "linux-tls.yaml": (LINUX, ("TLS",), True),
    "windows-min.yaml": (WINDOWS, (), False),
    "windows.yaml": (WINDOWS, ("IIS", "MSSQL"), False),
    "windows-tls.yaml": (WINDOWS, ("IIS", "MSSQL", "TLS"), True),
}
# 설치 스크립트가 CA 를 복사하는 자리 (install.sh: /etc/wlm-agent/ca.crt, install.ps1: $DataDir\ca.crt)
CA_TARGET = {LINUX: "/etc/wlm-agent/ca.crt", WINDOWS: r"C:\ProgramData\wlm-agent\ca.crt"}
PROBE = "tools/ci/tls-probe.yaml"

_ON = {"on", "true", "yes"}
_MIN_VERSIONS = {"TLSv1.2", "TLSv1.3"}
# 줄 첫머리(주석이어도)의 검증 끄기 — 따옴표 친 키("tls.verify": off)도. 문서의 설명 문장은 줄 중간이라 걸리지 않는다
_VERIFY_OFF = re.compile(r"^\s*(#\s*)?['\"]?tls\.verify(_hostname)?['\"]?\s*:\s*['\"]?(off|false|no|0)\b", re.IGNORECASE)


def fill(text: str, tls: bool = False) -> str:
    # 스크립트와 같게: TLS 면 포트 기본값이 6977(WLM_INGEST_TLS_PORT), 아니면 인증서 이름을 빈 값으로 바꾼다
    values = {**VALUES, "@SERVER_PORT@": "6977"} if tls else {**VALUES, "@TLS_SERVER_NAME@": ""}
    for key, value in values.items():
        text = text.replace(key, value)
    return text


def enable_block(text: str, name: str) -> str:
    """install.ps1 Enable-Block: '# @@NAME_BEGIN' 과 '# @@NAME_END' 사이의 주석 처리된 설정 줄을 켠다."""
    out, inside = [], False
    for line in text.split("\n"):
        if f"# @@{name}_BEGIN" in line:
            inside = True
        elif f"# @@{name}_END" in line:
            inside = False
        elif inside and _UNCOMMENT.match(line):
            line = re.sub(r"^(\s*)# ", r"\1", line, count=1)
        out.append(line)
    return "\n".join(out)


def _scalar(value) -> str:
    if value is True:
        return "on"
    if value is False:
        return "off"
    return "" if value is None else str(value)


def http_output(text: str) -> dict[str, str] | None:
    """첫 http 출력의 켜진 키·값 (값은 문자열, YAML 참/거짓은 on/off). yaml 이 없으면 들여쓰기로 읽는다."""
    try:
        import yaml  # CI 의 dev 이미지·개발 PC 에 있으면 파서로
    except ImportError:
        yaml = None
    if yaml is not None:
        doc = yaml.safe_load(text) or {}
        for out in ((doc.get("pipeline") or {}).get("outputs") or []):
            if isinstance(out, dict) and out.get("name") == "http":
                return {str(k): _scalar(v) for k, v in out.items()}
        return None
    lines = text.splitlines()
    for i, line in enumerate(lines):
        head = re.match(r"^(\s*)- name:\s*http\s*$", line)
        if not head:
            continue
        base, keys = len(head.group(1)), {"name": "http"}
        for nxt in lines[i + 1:]:
            if not nxt.strip() or nxt.lstrip().startswith("#"):
                continue
            if len(nxt) - len(nxt.lstrip()) <= base:
                break
            kv = re.match(r"^\s*['\"]?([A-Za-z0-9_.]+)['\"]?\s*:\s*(.*?)\s*(?:\s#.*)?$", nxt)
            if kv:
                keys[kv.group(1)] = kv.group(2).strip("'\"")
        return keys
    return None


def check_tls(text: str, ca_file: str | None = None, vhost: str | None = None, port: str | None = None) -> list[str]:
    out = http_output(text)
    if out is None:
        return ["http 출력이 없습니다"]
    errors = [f"{key}: on 이어야 합니다 (지금 {out.get(key) or '없음'})"
              for key in ("tls", "tls.verify", "tls.verify_hostname") if out.get(key, "").lower() not in _ON]
    if out.get("tls.min_version") not in _MIN_VERSIONS:
        errors.append(f"tls.min_version: TLSv1.2 이상이어야 합니다 (지금 {out.get('tls.min_version') or '없음'})")
    for key, want in (("tls.vhost", vhost), ("tls.ca_file", ca_file)):
        if not out.get(key):
            errors.append(f"{key}: 비어 있습니다")
        elif want is not None and out[key] != want:
            errors.append(f"{key}: {want} 이어야 합니다 (지금 {out[key]})")
    if port is not None and out.get("port") != port:
        errors.append(f"port: {port} 이어야 합니다 (지금 {out.get('port') or '없음'}) — TLS 를 평문 포트로 보내면 연결이 끊긴다")
    return errors


_BUILTIN_MULTILINE = {"docker", "cri", "go", "python", "java", "ruby"}


def _section_items(lines: list[str], start: int) -> list[dict[str, str]]:
    """start 줄(예: 'inputs:') 아래 목록의 켜진 항목들 — 들여쓰기로 읽는다(주석 줄은 건너뜀, 값은 문자열)."""
    base = len(lines[start]) - len(lines[start].lstrip())
    items: list[dict[str, str]] = []
    item_indent = None
    for line in lines[start + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base:
            break
        head = re.match(r"^(\s*)- (.*)$", line)
        if head and (item_indent is None or len(head.group(1)) == item_indent):
            item_indent = len(head.group(1))
            items.append({})
            line = head.group(1) + "  " + head.group(2)
        kv = re.match(r"^\s*['\"]?([A-Za-z0-9_.]+)['\"]?\s*:\s*(.*?)\s*(?:\s#.*)?$", line)
        if kv and items and (len(line) - len(line.lstrip())) == item_indent + 2:
            items[-1][kv.group(1)] = kv.group(2).strip("'\"")
    return items


def config_parts(text: str) -> tuple[set[str], list[dict[str, str]]]:
    """(정의된 multiline 파서 이름, 켜진 입력들). yaml 이 있으면 파서로, 없으면(윈도 러너) 들여쓰기로."""
    try:
        import yaml
    except ImportError:
        yaml = None
    if yaml is not None:
        doc = yaml.safe_load(text) or {}
        names = {str(p.get("name")) for p in (doc.get("multiline_parsers") or []) if isinstance(p, dict)}
        inputs = [{str(k): _scalar(v) for k, v in i.items()}
                  for i in ((doc.get("pipeline") or {}).get("inputs") or []) if isinstance(i, dict)]
        return names, inputs
    lines = text.splitlines()
    names: set[str] = set()
    inputs: list[dict[str, str]] = []
    for i, line in enumerate(lines):
        if re.match(r"^multiline_parsers:\s*$", line):
            names |= {item.get("name", "") for item in _section_items(lines, i)}
        elif re.match(r"^\s+inputs:\s*$", line):
            inputs += _section_items(lines, i)
    return names, inputs


def check_multiline(text: str) -> list[str]:
    names, inputs = config_parts(text)
    errors = []
    for item in inputs:
        wanted = [n.strip() for n in item.get("multiline.parser", "").split(",") if n.strip()]
        for name in wanted:
            if name not in names and name not in _BUILTIN_MULTILINE:
                errors.append(f"입력 {item.get('tag') or item.get('name')}: multiline.parser '{name}' 가 정의되어 있지 않습니다"
                              " (dry-run 은 통과하지만 기동 때 엔진 전체가 멈춘다)")
        if wanted and item.get("storage.type") != "filesystem":
            errors.append(f"입력 {item.get('tag') or item.get('name')}: multiline 을 쓰면 storage.type: filesystem 이어야 합니다"
                          " (멈출 때 묶던 레코드를 잃는다)")
    return errors


def derive_mssql(text: str, path: str, state: str, out_file: str, plain: bool = False, down: bool = False) -> str:
    """채운 윈도 설정의 multiline 정의 + MSSQL tail 로, 어느 OS 에서나 돌릴 수 있는 설정 (winevtlog 없음).
    down: 출력을 닿지 않는 서버(127.0.0.1:9)로 — 서버가 꺼진 채 에이전트를 멈추는 경우를 흉내 낸다."""
    _names, inputs = config_parts(text)
    tails = [i for i in inputs if i.get("tag") == "file.mssql"]
    if not tails:
        raise SystemExit("MSSQL tail 입력이 없습니다 (IIS·MSSQL 묶음을 켠 windows.yaml 을 주세요)")
    tail = dict(tails[0])
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"^multiline_parsers:\s*$", line)), None)
    parsers: list[str] = []
    if start is not None and not plain:
        parsers.append(lines[start])
        for line in lines[start + 1:]:
            if line.strip() and not line.startswith((" ", "#")):
                break
            parsers.append(line)
    if plain:
        tail.pop("multiline.parser", None)
    tail.update({"path": path, "db": f"{state}/tail-mssql.sqlite", "read_from_head": "true", "refresh_interval": "1"})
    tail.pop("mem_buf_limit", None)
    out_dir, _, out_name = out_file.replace("\\", "/").rpartition("/")
    body = ["service:", "  flush: 1", "  log_level: warn", f"  storage.path: {state}/buffer", "  storage.sync: normal", "",
            *parsers, "pipeline:", "  inputs:", "    - name: tail"]
    body += [f"      {k}: {v}" for k, v in tail.items() if k != "name"]
    if down:
        body += ["  outputs:", "    - name: http", "      match: '*'", "      host: 127.0.0.1", "      port: 9",
                 "      retry_limit: no_limits", ""]
    else:
        body += ["  outputs:", "    - name: file", "      match: '*'", f"      path: {out_dir or '.'}",
                 f"      file: {out_name}", "      format: plain", ""]
    return "\n".join(body)


def derive_winlog(text: str, state: str, out_file: str, channels: str | None = None) -> str:
    """채운 윈도 설정의 winevtlog 입력(설정 그대로) + 파일 출력 — 실제 에이전트가 만드는 레코드 모양을 잡아 보는 용도
    (B-08 후속: EventData 이름이 오지 않는 문제, 윈도 CI 가 실제 이벤트를 일으켜 기록한다)."""
    _names, inputs = config_parts(text)
    wins = [i for i in inputs if i.get("name") == "winevtlog"]
    if not wins:
        raise SystemExit("winevtlog 입력이 없습니다")
    win = dict(wins[0])
    win.update({"db": f"{state}/winevtlog.sqlite"})
    if channels:
        win["channels"] = channels
    win.pop("mem_buf_limit", None)
    out_dir, _, out_name = out_file.replace("\\", "/").rpartition("/")
    body = ["service:", "  flush: 1", "  log_level: warn", f"  storage.path: {state}/buffer", "", "pipeline:", "  inputs:",
            "    - name: winevtlog"]
    body += [f"      {k}: {v}" for k, v in win.items() if k != "name"]
    body += ["  outputs:", "    - name: file", "      match: '*'", f"      path: {out_dir or '.'}", f"      file: {out_name}",
             "      format: plain", ""]
    return "\n".join(body)


def check_plain(text: str) -> list[str]:
    out = http_output(text)
    if out is None:
        return ["http 출력이 없습니다"]
    keys = sorted(k for k in out if k == "tls" or k.startswith("tls."))
    return [f"평문 설정에 켜진 TLS 키가 있습니다: {keys}"] if keys else []


def scan_verify_off() -> list[str]:
    found = []
    for top in ("agent", "collector"):
        for path in sorted((ROOT / top).rglob("*")):
            if not path.is_file() or path.stat().st_size > 1_000_000:
                continue
            for no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if _VERIFY_OFF.match(line):
                    found.append(f"{path.relative_to(ROOT)}:{no}: 인증서 검증을 끄는 줄 — {line.strip()}")
    return found


def leftover(text: str, active_only: bool = False) -> list[str]:
    """채우지 않은 @자리@. active_only: 주석 줄은 빼고 (install.ps1 은 켜지 않은 IIS·MSSQL 묶음의 자리를 남겨 둔다)."""
    if active_only:
        text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return sorted(set(re.findall(r"(?<!@)@[A-Z_]+@(?!@)", text)))


def ca_sha256(path: str) -> str:
    """첫 인증서 DER 의 SHA-256 — tlsutil(cryptography)·install.ps1·install.sh 와 따로 계산해 셋을 대조하는 기준."""
    import base64
    import hashlib

    text = Path(path).read_bytes().decode("ascii", errors="ignore")
    m = re.search(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----", text)
    if not m:
        raise SystemExit(f"PEM 인증서가 아닙니다: {path}")
    return hashlib.sha256(base64.b64decode(re.sub(r"\s", "", m.group(1)))).hexdigest()


def check_files(paths: list[str], expect: dict[str, str]) -> int:
    failed = False
    for name in paths:
        text = Path(name).read_text(encoding="utf-8")
        left = leftover(text, active_only=True)
        problems = check_tls(text, expect.get("ca-file"), expect.get("vhost"), expect.get("port")) \
            + ([f"채우지 않은 자리 {left}"] if left else [])
        for problem in problems:
            print(f"{name}: {problem}", file=sys.stderr)
        failed |= bool(problems)
    print("TLS 정적 검사:", "실패" if failed else "통과", ", ".join(paths))
    return 1 if failed else 0


def main(out_dir: str) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rendered = {}
    for name, (template, blocks, tls) in VARIANTS.items():
        text = (ROOT / template).read_text(encoding="utf-8")
        for block in blocks:
            text = enable_block(text, block)
        rendered[name] = fill(text, tls)
    failed = False

    def fail(name: str, problems: list[str]) -> None:
        nonlocal failed
        for problem in problems:
            print(f"{name}: {problem}", file=sys.stderr)
        failed |= bool(problems)

    for name, text in rendered.items():
        left = leftover(text)
        fail(name, [f"채우지 않은 자리 {left}"] if left else [])
        (out / name).write_text(text, encoding="utf-8")
    try:
        import yaml  # CI 의 dev 이미지·개발 PC 에 있으면 문법도 본다
    except ImportError:
        yaml = None
    if yaml is not None:
        for name in rendered:
            doc = yaml.safe_load((out / name).read_text(encoding="utf-8"))
            pipeline = (doc or {}).get("pipeline") or {}
            if not pipeline.get("inputs") or not pipeline.get("outputs"):
                fail(name, ["pipeline.inputs/outputs 가 없습니다"])

    for name, text in rendered.items():
        fail(name, check_multiline(text))
    for name, (template, _blocks, tls) in VARIANTS.items():
        if tls:
            fail(name, check_tls(rendered[name], CA_TARGET[template], VALUES["@TLS_SERVER_NAME@"]))
        else:
            fail(name, check_plain(rendered[name]))
    fail(PROBE, check_tls((ROOT / PROBE).read_text(encoding="utf-8")))
    fail("agent/·collector/", scan_verify_off())

    print("에이전트 설정 채움:", ", ".join(str(out / n) for n in rendered))
    print("검사 (남은 자리·TLS·검증 끄기·multiline):", "실패" if failed else "통과")
    return 1 if failed else 0


if __name__ == "__main__":
    # 윈도 러너는 파이프 출력을 ANSI(cp1252)로 써서 한글에서 UnicodeEncodeError 로 멈춘다
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = sys.argv[1:]
    if args[:1] == ["--ca-sha256"] and len(args) == 2:
        print(ca_sha256(args[1]))
        sys.exit(0)
    if args[:1] == ["--check-multiline"]:
        problems = {f: check_multiline(Path(f).read_text(encoding="utf-8")) for f in args[1:]}
        for f, errs in problems.items():
            for err in errs:
                print(f"{f}: {err}", file=sys.stderr)
        print("multiline 정적 검사:", "실패" if any(problems.values()) else "통과", ", ".join(args[1:]))
        sys.exit(1 if any(problems.values()) else 0)
    if args[:1] == ["--derive-mssql"] and len(args) >= 3:
        src, dst, rest, opts = args[1], args[2], args[3:], {}
        while rest:
            item = rest.pop(0)
            if item in ("--plain", "--down"):
                opts[item[2:]] = True
            elif item.startswith("--") and rest:
                opts[item[2:]] = rest.pop(0)
        Path(dst).write_text(derive_mssql(Path(src).read_text(encoding="utf-8"), opts["path"], opts["state"], opts["out"],
                                          bool(opts.get("plain")), bool(opts.get("down"))), encoding="utf-8")
        sys.exit(0)
    if args[:1] == ["--derive-winlog"] and len(args) >= 3:
        src, dst, rest, opts = args[1], args[2], args[3:], {}
        while rest:
            item = rest.pop(0)
            if item.startswith("--") and rest:
                opts[item[2:]] = rest.pop(0)
        Path(dst).write_text(derive_winlog(Path(src).read_text(encoding="utf-8"), opts["state"], opts["out"],
                                           opts.get("channels")), encoding="utf-8")
        sys.exit(0)
    if args[:1] == ["--check-tls"]:
        files, expect, rest = [], {}, args[1:]
        while rest:
            item = rest.pop(0)
            if item.startswith("--expect-") and rest:
                expect[item.removeprefix("--expect-")] = rest.pop(0)
            else:
                files.append(item)
        sys.exit(check_files(files, expect) if files else "사용법: render_agent_configs.py --check-tls <설정 파일>...")
    sys.exit(main(args[0] if args else "agent-render"))
