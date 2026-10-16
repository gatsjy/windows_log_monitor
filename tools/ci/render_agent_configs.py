"""CI(B-15): 에이전트 설정 틀의 @자리@ 를 설치 스크립트와 같은 규칙으로 채워 검사용 파일을 만든다 (표준 라이브러리만).

  python3 tools/ci/render_agent_configs.py <출력 폴더>

- linux.yaml      agent/linux/install.sh 의 sed 와 같은 치환
- windows.yaml    agent/windows/install.ps1 과 같은 치환 + IIS·MSSQL 묶음을 켠 것(Enable-Block)
- windows-min.yaml  묶음을 켜지 않은 기본

채운 뒤 남은 @자리@ 가 있으면 실패한다. Fluent Bit 문법 검사(--dry-run)는 CI 가 컨테이너로 돌린다
(윈도 설정의 winevtlog 입력은 윈도 빌드에만 있어 리눅스 이미지로는 문법만 본다 — .github/workflows/ci.yml).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALUES = {"@SERVER_HOST@": "logmon.ci.local", "@SERVER_PORT@": "6976", "@API_KEY@": "ci-test-key",
          "@AGENT_HOST@": "ci-agent", "@CHANNELS@": "System,Application,Security",
          "@IIS_PATH@": r"C:\inetpub\logs\LogFiles\W3SVC1\*.log",
          "@MSSQL_PATH@": r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG"}
_UNCOMMENT = re.compile(r"^(\s*)# (- |  )")


def fill(text: str) -> str:
    for key, value in VALUES.items():
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


def main(out_dir: str) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    linux = (ROOT / "agent/linux/fluent-bit.yaml").read_text(encoding="utf-8")
    windows = (ROOT / "agent/windows/fluent-bit.yaml").read_text(encoding="utf-8")
    rendered = {
        "linux.yaml": fill(linux),
        "windows-min.yaml": fill(windows),
        "windows.yaml": fill(enable_block(enable_block(windows, "IIS"), "MSSQL")),
    }
    failed = False
    for name, text in rendered.items():
        left = sorted(set(re.findall(r"(?<!@)@[A-Z_]+@(?!@)", text)))
        if left:
            print(f"{name}: 채우지 않은 자리 {left}", file=sys.stderr)
            failed = True
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
                print(f"{name}: pipeline.inputs/outputs 가 없습니다", file=sys.stderr)
                failed = True
    print("에이전트 설정 채움:", ", ".join(str(out / n) for n in rendered))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "agent-render"))
