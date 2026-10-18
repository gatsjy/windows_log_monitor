"""에이전트 설정 틀과 서버 정규화기의 맞춤 (B-08, ADR-037) — 그리고 실제 Fluent Bit 출력(고정 자료)으로 본 MSSQL 집계.

- 윈도 틀의 multiline 'mssql_errorlog' 가 새 레코드로 자르는 줄 = 서버 mssql._LINE 이 시각으로 읽는 줄.
  어긋나면 묶인 레코드의 첫 줄을 서버가 못 읽거나(받은 시각·번호 없음), 한 레코드여야 할 줄이 둘로 갈린다.
- 고정 자료 fixtures/mssql/fb-*.jsonl 은 tools/ci/test_fluentbit_mssql.sh 가 Fluent Bit 4.0 으로 만든 실제 출력
  (같은 합성 ERRORLOG.utf16 을 multiline 으로 읽은 것·줄마다 읽은 것). CI 가 그 스크립트로 Fluent Bit 동작이 그대로인지 본다.
"""

from __future__ import annotations

import importlib.util
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from app.config import settings
from app.normalizers import mssql, normalize

HERE = Path(__file__).resolve().parent
NOW = datetime(2026, 10, 4, 3, 0, 0, tzinfo=UTC)


def _template() -> str:
    path = Path(settings.agent_dir) / "windows" / "fluent-bit.yaml"
    if not path.exists():
        pytest.skip(f"에이전트 틀이 없습니다: {path}")
    return path.read_text(encoding="utf-8")


def _render_tool():
    for root in (HERE.parent, HERE.parents[1]):  # 컨테이너 /app/tools, 저장소 tools/
        path = root / "tools" / "ci" / "render_agent_configs.py"
        if path.exists():
            spec = importlib.util.spec_from_file_location("render_agent_configs", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    pytest.skip("tools/ci/render_agent_configs.py 가 없습니다")


def _rules() -> dict[str, re.Pattern]:
    # @자리@ 는 YAML 에서 쓸 수 없는 글자로 시작하므로 채운 뒤 읽는다
    doc = yaml.safe_load(re.sub(r"@[A-Z_]+@", "x", _template()))
    [parser] = [p for p in doc["multiline_parsers"] if p["name"] == "mssql_errorlog"]
    rules = {r["state"]: r["regex"] for r in parser["rules"]}
    # Fluent Bit 은 '/정규식/' 모양(Onigmo). 여기 쓰는 문법(\d, \s, (?!…))은 파이썬 re 와 같다
    return {state: re.compile(regex.strip("/")) for state, regex in rules.items()}


LINES = [
    ("2026-10-04 10:15:22.53 Logon       Error: 18456, Severity: 14, State: 8.", True),
    ("2026-10-04 10:15:22 spid51      no fraction", True),
    ("2026-10-04 10:15:22.531 Server      three digit fraction", True),
    ("2026-10-04 10:15:22.53\tServer\ttabs", True),
    ("\tJul 10 2024 14:09:09 ", False),
    ("\t -d C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\DATA\\master.mdf", False),
    ("second line of the RAISERROR WITH LOG message", False),
    ("2026-10-17 junk", False),
    ("2026-10-04 10:15:22.53", False),
    ("", False),
]


@pytest.mark.parametrize(("line", "starts"), LINES)
def test_multiline_start_matches_server_line_parser(line, starts):
    rules = _rules()
    assert bool(rules["start_state"].match(line)) is starts
    assert bool(rules["cont"].match(line)) is not starts  # 시작이 아니면 앞 레코드에 붙는다
    assert bool(mssql._LINE.match(line)) is starts


def test_mssql_tail_uses_the_parser_with_filesystem_storage():
    tool = _render_tool()
    text = tool.fill(tool.enable_block(tool.enable_block(_template(), "IIS"), "MSSQL"))
    assert tool.check_multiline(text) == []
    _names, inputs = tool.config_parts(text)
    [tail] = [i for i in inputs if i.get("tag") == "file.mssql"]
    assert (tail["multiline.parser"], tail["storage.type"]) == ("mssql_errorlog", "filesystem")
    # 깨뜨린 사본은 정적 검사가 잡는다 (dry-run 은 통과하는 것들)
    assert tool.check_multiline(text.replace("multiline.parser: mssql_errorlog", "multiline.parser: mssql_errlog"))
    broken = text.replace("tail-mssql.sqlite\n      storage.type: filesystem", "tail-mssql.sqlite\n      storage.type: memory")
    assert broken != text and tool.check_multiline(broken)


def _records(name: str) -> list[dict]:
    path = HERE / "fixtures" / "mssql" / name
    return [{**json.loads(line), "agent_host": "DB-FB", "log_source": "mssql", "file": "C:\\SQL\\Log\\ERRORLOG"}
            for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_fluent_bit_records_count_the_same_with_and_without_multiline():
    plain = [e for e in (normalize(r, NOW) for r in _records("fb-plain.jsonl")) if e]
    merged = [e for e in (normalize(r, NOW) for r in _records("fb-ml.jsonl")) if e]
    assert len(merged) < len(plain)
    # 오류 번호 집계가 같다 (로그인 실패 18456·사용자 오류 50000·로그 가득 참 9002 각 1건 — 머리줄은 세지 않음)
    assert Counter(e.event_id for e in plain if e.event_id) == Counter(e.event_id for e in merged if e.event_id) \
        == Counter({18456: 1, 50000: 1, 9002: 1})
    # 시각이 있는 줄의 (시각, 프로세스, 번호, 수준)이 같다 — 0.3.0 의 이어지는 줄만 사라진다
    key = lambda e: (e.ts, e.provider, e.event_id, e.level)
    assert [key(e) for e in plain if e.provider] == [key(e) for e in merged]
    assert all(e.ts != NOW for e in merged)  # 모든 묶음이 첫 줄의 시각으로


def test_fluent_bit_multiline_banner_and_message():
    merged = {e.message.split("\n")[0].strip(): e for e in (normalize(r, NOW) for r in _records("fb-ml.jsonl"))}
    banner = merged["Microsoft SQL Server 2022 (RTM-CU14) (KB5038325) - 16.0.4135.4 (X64)"]
    assert (banner.provider, banner.raw["mssql"]["lines"], banner.level) == ("Server", 4, 4)
    assert banner.ts == datetime(2026, 10, 4, 1, 0, 0, 110000, tzinfo=UTC)  # Asia/Seoul
    assert "\r" not in banner.message and banner.raw["log"].endswith("\n\r\n")  # 원본은 Fluent Bit 이 준 그대로
    params = merged["Registry startup parameters:"]
    assert params.raw["mssql"]["lines"] == 4 and params.message.count("\t -") == 3
    body = merged["야간 작업 실패: 3단계"]
    assert (body.event_id, body.level, body.raw["mssql"]["severity"], body.raw["mssql"]["lines"]) == (50000, 3, 16, 3)
    assert body.message.endswith("second line of the RAISERROR WITH LOG message\n\tthird line (indented)")
