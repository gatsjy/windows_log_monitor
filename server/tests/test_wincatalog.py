"""Windows 이벤트 해석 (BACKLOG B-68) — 한 줄 요약과 코드 풀이. DB 없이.

실제 에이전트 모양(tests/fixtures/winevtlog/agent-fb4.0.14.jsonl — EventData 없이 StringInserts 만)으로 시험한다:
EventData 맵을 넣은 레코드로만 시험하면 실제 PC 에서 틀리는 것이 통과한다(AGENTS.md, ADR-038).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app import wincatalog
from app.normalizers import normalize

FIXTURE = Path(__file__).parent / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl"
SECURITY = "Microsoft-Windows-Security-Auditing"


def _fixture_events():
    out = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        rec.update(log_source="winevtlog", agent_host=rec["Computer"])
        out.append(normalize(rec, datetime.now(UTC)))
    return out


def _summary(event_id, n=0):
    ev = [e for e in _fixture_events() if e.event_id == event_id][n]
    return wincatalog.summarize(ev.provider, ev.event_id, ev.raw)


@pytest.mark.parametrize(("event_id", "expected"), [
    (4625, "wlmci 로그온 실패 — 비밀번호가 틀림, 대화형(PC 앞에서), 접속지 WIN-CI"),
    (4624, "wlmci 로그온 성공 — 네트워크(공유 폴더·원격 관리 등), 접속지 WIN-CI"),
    (4688, "runneradmin 이(가) 프로그램 실행 — C:\\Windows\\System32\\auditpol.exe (전체 권한 토큰(UAC 없이 관리자))"),
    (4720, "runneradmin 이(가) 계정 만듦 — wlmci"),
    (4726, "runneradmin 이(가) 계정 삭제 — wlmci"),
    (4697, "runneradmin 이(가) 서비스 설치 — wlmcisvc (C:\\Windows\\System32\\cmd.exe /c exit)"),
    (7045, "서비스 설치 — wlmcisvc (C:\\Windows\\System32\\cmd.exe /c exit), 실행 계정 LocalSystem"),
    (4104, "PowerShell 스크립트 블록 기록"),                     # 경로가 없으면 꼬리를 뺀다
])
def test_summaries_from_real_agent_records(event_id, expected):
    assert _summary(event_id) == expected


def test_group_member_falls_back_to_sid_and_every_template_names_exist():
    """그룹 구성원 이름이 '-' 면 SID. 사전의 {이름}은 그 이벤트 템플릿에 있는 이름이어야 한다 — 오타는 영영 '–' 로만 보인다."""
    from app.normalizers import win_templates

    assert _summary(4732).endswith("구성원 추가 — S-1-5-21-4239583824-265399229-1323058055-1003")
    for provider, events in wincatalog.catalog()["events"].items():
        for event_id, spec in events.items():
            names = win_templates.TEMPLATES.get((provider, int(event_id)))
            assert names, (provider, event_id)
            for placeholder in wincatalog._PLACE.findall(spec["summary"]):
                for name in placeholder.split("/"):
                    assert name in names, (event_id, name)


@pytest.mark.parametrize(("field", "value", "overrides", "expected"), [
    ("LogonType", 10, None, "원격 데스크톱"),                       # 에이전트는 숫자로 보낸다
    ("LogonType", "3", None, "네트워크(공유 폴더·원격 관리 등)"),
    ("SubStatus", "0xC000006A", None, "비밀번호가 틀림"),             # 대소문자
    ("Status", "0xc0000234", None, "계정이 잠김"),
    ("Status", "0x18", {"Status": "KerberosStatus"}, "사전 인증 실패 — 대개 비밀번호가 틀림"),
    ("Status", "0x00000018", {"Status": "KerberosStatus"}, "사전 인증 실패 — 대개 비밀번호가 틀림"),   # 앞의 0
    ("FailureReason", "%%2313", None, "사용자 이름이 없거나 비밀번호가 틀림"),
    ("LogonType", "99", None, None), ("Unknown", "1", None, None), ("Status", "not-hex", None, None),
])
def test_code_meanings(field, value, overrides, expected):
    assert wincatalog.meaning(field, value, overrides) == expected


def test_substatus_zero_falls_back_to_status_and_kerberos_override():
    raw = {"EventData": {"TargetUserName": "kim", "Status": "0xC0000234", "SubStatus": "0x0", "LogonType": "10",
                         "IpAddress": "10.0.0.5", "WorkstationName": "PC-1"}}
    assert wincatalog.summarize(SECURITY, 4625, raw) == "kim 로그온 실패 — 계정이 잠김, 원격 데스크톱, 접속지 10.0.0.5"
    raw = {"EventData": {"TargetUserName": "kim", "Status": "0x18", "IpAddress": "::ffff:10.0.0.9"}}
    assert wincatalog.summarize(SECURITY, 4771, raw) == "kim Kerberos 사전 인증 실패 — 사전 인증 실패 — 대개 비밀번호가 틀림, 접속지 ::ffff:10.0.0.9"
    assert [d["meaning"] for d in wincatalog.decode(SECURITY, 4771, raw)] == ["사전 인증 실패 — 대개 비밀번호가 틀림"]


def test_unknown_or_missing_data():
    assert wincatalog.summarize(SECURITY, 9999, {"EventData": {}}) is None
    assert wincatalog.summarize(SECURITY, 4624, {"StringInserts": ["a"]}) is None   # 이름 맵이 없음
    assert wincatalog.summarize(None, 4624, None) is None
    assert wincatalog.decode(SECURITY, 4624, "not a dict") == []
    # 서버가 붙인 이름(raw.winevtlog.EventData)도 읽는다
    assert wincatalog.event_data({"winevtlog": {"EventData": {"a": 1}}}) == {"a": 1}
