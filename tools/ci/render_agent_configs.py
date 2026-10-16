"""CI(B-15, B-06): 에이전트 설정 틀의 @자리@ 를 설치 스크립트와 같은 규칙으로 채워 검사용 파일을 만들고,
TLS 설정을 정적으로 검사한다 (표준 라이브러리만).

  python3 tools/ci/render_agent_configs.py <출력 폴더>
  python3 tools/ci/render_agent_configs.py --check-tls <설정 파일>...   다른 곳에서 채운 TLS 설정만 검사
                                                                       (예: install.ps1 -RenderOnly 결과)

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
# 줄 첫머리(주석이어도)의 검증 끄기. 문서의 설명 문장은 줄 중간이라 걸리지 않는다
_VERIFY_OFF = re.compile(r"^\s*(#\s*)?tls\.verify(_hostname)?\s*:\s*['\"]?(off|false|no|0)\b", re.IGNORECASE)


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
            kv = re.match(r"^\s*([A-Za-z0-9_.]+)\s*:\s*(.*?)\s*(?:\s#.*)?$", nxt)
            if kv:
                keys[kv.group(1)] = kv.group(2).strip("'\"")
        return keys
    return None


def check_tls(text: str, ca_file: str | None = None, vhost: str | None = None) -> list[str]:
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
    return errors


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


def check_files(paths: list[str]) -> int:
    failed = False
    for name in paths:
        text = Path(name).read_text(encoding="utf-8")
        left = leftover(text, active_only=True)
        problems = check_tls(text) + ([f"채우지 않은 자리 {left}"] if left else [])
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

    for name, (template, _blocks, tls) in VARIANTS.items():
        if tls:
            fail(name, check_tls(rendered[name], CA_TARGET[template], VALUES["@TLS_SERVER_NAME@"]))
        else:
            fail(name, check_plain(rendered[name]))
    fail(PROBE, check_tls((ROOT / PROBE).read_text(encoding="utf-8")))
    fail("agent/·collector/", scan_verify_off())

    print("에이전트 설정 채움:", ", ".join(str(out / n) for n in rendered))
    print("검사 (남은 자리·TLS·검증 끄기):", "실패" if failed else "통과")
    return 1 if failed else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--check-tls"]:
        sys.exit(check_files(args[1:]) if args[1:] else "사용법: render_agent_configs.py --check-tls <설정 파일>...")
    sys.exit(main(args[0] if args else "agent-render"))
