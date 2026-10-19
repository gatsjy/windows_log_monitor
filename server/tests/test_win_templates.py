"""Windows EventData 이름 붙이기 (ADR-038) — 실제 에이전트 레코드(tests/fixtures/winevtlog, 윈도 CI 에서 받은 것)로 본다.

에이전트(Fluent Bit 4.0)는 EventData 를 이름 없이 StringInserts 로만 보낸다. 서버가 템플릿으로 이름을 붙여
raw.winevtlog.EventData 에 덧붙이고, 검색·규칙의 f.EventData.<이름> 은 그 값을 본다.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.normalizers import normalize
from app.normalizers import win_templates as wt

NOW = datetime(2026, 10, 19, 0, 0, 0, tzinfo=UTC)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl"
REAL = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def _agent(record: dict) -> dict:
    return {**record, "agent_host": "WIN-CI", "log_source": "winevtlog"}


def _real(event_id: int, n: int = 0) -> dict:
    return [r for r in REAL if r["EventID"] == event_id][n]


def test_real_agent_records_have_no_event_data_names():
    # 이 사실이 바뀌면(에이전트 5.1 의 event_data_as_map) 이 파일과 ADR-038 을 다시 본다
    assert REAL and all("EventData" not in r and isinstance(r["StringInserts"], list) for r in REAL)


@pytest.mark.parametrize("record", REAL, ids=[f'{r["EventID"]}v{r.get("Version")}' for r in REAL])
def test_template_length_matches_the_real_version(record):
    # 템플릿이 그 버전의 필드 수와 정확히 같다 — 4624 v3 처럼 중간에 끼운 필드를 놓치면 뒤 이름이 밀린다
    key = (record["ProviderName"], record["EventID"])
    names = wt.VERSIONED.get((*key, int(record.get("Version") or 0))) or wt.TEMPLATES.get(key)
    assert names is not None, f"{key} 템플릿이 없습니다"
    assert len(names) == len(record["StringInserts"])


def test_names_land_on_the_right_values():
    e = normalize(_agent(_real(4625)), NOW)
    data = e.raw["winevtlog"]["EventData"]
    assert (data["TargetUserName"], data["LogonType"], data["Status"], data["SubStatus"]) == ("wlmci", 2, "0xc000006d", "0xc000006a")  # 잘못된 암호
    assert e.raw["StringInserts"] == _real(4625)["StringInserts"] and "EventData" not in e.raw  # 원본은 그대로
    admins = next(r for r in REAL if r["EventID"] == 4732 and "S-1-5-32-544" in r["StringInserts"])
    data = normalize(_agent(admins), NOW).raw["winevtlog"]["EventData"]
    assert (data["TargetSid"], data["TargetUserName"]) == ("S-1-5-32-544", "Administrators")
    v3 = normalize(_agent(_real(4624)), NOW).raw["winevtlog"]["EventData"]
    assert (v3["LogonType"], v3["ImpersonationLevel"], v3["ElevatedToken"]) == (3, "%%1833", "%%1842")
    assert normalize(_agent(_real(7045)), NOW).raw["winevtlog"]["EventData"]["ServiceName"] == "wlmcisvc"
    assert "wlm-scriptblock-check" in normalize(_agent(_real(4104)), NOW).raw["winevtlog"]["EventData"]["ScriptBlockText"]


def test_common_fields_from_derived_names():
    assert normalize(_agent(_real(4625)), NOW).username == "wlmci"
    assert normalize(_agent(_real(4720)), NOW).username == "wlmci"            # 만들어진 계정 (예전 위치표와 같음)
    group = normalize(_agent(_real(4732)), NOW)
    assert group.username == "runneradmin"   # 그룹 변경은 그룹 이름이 아니라 바꾼 사람 (TargetUserName = 그룹)
    assert normalize(_agent(_real(4688)), NOW).username == "runneradmin"      # TargetUserName '-' → 행위자


def test_agent_names_win_and_unknown_events_are_untouched():
    named = {**_agent(_real(4625)), "EventData": {"TargetUserName": "from-agent"}}
    e = normalize(named, NOW)
    assert "winevtlog" not in e.raw and e.username == "from-agent"
    unknown = {**_agent(_real(4625)), "EventID": 9999}
    assert "winevtlog" not in normalize(unknown, NOW).raw
    clash = {**_agent(_real(4625)), "winevtlog": "agent value"}   # 원본 키를 덮지 않는다
    assert normalize(clash, NOW).raw["winevtlog"] == "agent value"


def test_older_version_with_fewer_fields_drops_trailing_names():
    short = {**_agent(_real(4697)), "StringInserts": _real(4697)["StringInserts"][:9], "Version": 0}
    data = normalize(short, NOW).raw["winevtlog"]["EventData"]
    assert data["ServiceAccount"] == "LocalSystem" and "ParentProcessId" not in data
