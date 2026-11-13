"""기본 규칙 표본 (B-45) — tests/fixtures/rules/<sid>.yaml 을 에이전트가 보내는 모양의 레코드로 만든다. 형식: fixtures/rules/README.md

test_rule_samples.py(DB 없이, 규칙 시험기와 같은 판단)와 test_api_rule_samples.py(수집 → 엔진의 SQL 집계)가 같이 쓴다.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.normalizers import Event, mssql, normalize
from app.normalizers import win_templates as wt
from app.normalizers.iis import IisContext

HERE = Path(__file__).resolve().parent
RULES_DIR = HERE / "fixtures" / "rules"
WINLOG = [json.loads(line) for line in (HERE / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl")
          .read_text(encoding="utf-8").splitlines() if line.strip()]
IIS_FILE = r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex261109.log"
ERRORLOG = r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG"
# 실측이 없어 문서로 만든 Windows 표본은 판단에 쓰이는 값을 모두 적는다 — 봉투(실측 레코드)에서 따오면 다른 이벤트의 값이 남는다
DOC_FIELDS = ("ProviderName", "Channel", "Level", "Keywords", "Version", "Message")
# 실측 표본이 바꾸면 다른 이벤트가 되는 키 — 그런 표본은 실측이 아니다(envelope 로 문서 기반 표본을 만든다)
IDENTITY = ("EventID", "ProviderName", "ProviderGuid", "Channel", "Version")
KINDS = ("windows", "iis", "mssql", "journald", "syslog", "record")
SPEC_KEYS = {"why", "ref", "fails_on", "fields", "inserts", "strings", "file", *KINDS}


class SampleError(ValueError):
    """표본 파일이 형식에 맞지 않는다."""


@dataclass(frozen=True)
class Sample:
    sid: int
    index: int
    expect: bool                 # True = 규칙이 세야 함, False = 세면 안 됨
    why: str
    records: tuple[dict, ...]    # 이 순서로 보내고 마지막 레코드로 판단한다 (MSSQL 머리줄 + 본문)
    real: bool                   # 윈도 CI 실측 레코드에서 만들었는가 (아니면 ref 로 근거)
    ref: str | None
    # 안 맞음 표본이 떨어져야 하는 조건 (label 의 이름) — 다른 조건으로도 떨어지면 그 경계를 지키지 못한다(B-45 검토)
    fails_on: frozenset[str] = frozenset()

    @property
    def id(self) -> str:
        return f"{self.sid}-{'맞음' if self.expect else '아님'}{self.index}"


def _real_windows(event_id: int, where: dict | None = None, provider: str | None = None) -> dict | None:
    """실측 레코드 — 같은 ID 가 여럿이면 where(템플릿 이름 → 값)로 고른다. 이벤트 ID 는 공급자마다 뜻이 달라 provider 로도."""
    for record in WINLOG:
        if record["EventID"] != event_id or (provider is not None and record["ProviderName"] != provider):
            continue
        named = dict(zip(template(record) or (), record["StringInserts"], strict=False))
        if all(named.get(k) == v for k, v in (where or {}).items()):
            return record
    return None


def template(record: dict) -> tuple[str, ...] | None:
    """서버가 이 레코드에 붙일 이름 순서 (normalizers/win_templates.named 와 같은 고르기)."""
    key = (record.get("ProviderName") or "", int(record.get("EventID") or 0))
    return wt.VERSIONED.get((*key, wt._version(record.get("Version")))) or wt.TEMPLATES.get(key)


def _windows(spec: dict) -> tuple[list[dict], bool]:
    w = spec["windows"]
    if not isinstance(w, dict) or "event" not in w:
        raise SampleError("windows: {event: 이벤트 ID} 가 필요합니다")
    event_id = int(w["event"])
    fields, inserts = dict(spec.get("fields") or {}), dict(spec.get("inserts") or {})
    if unknown := set(w) - {"event", "provider", "where", "envelope"}:
        raise SampleError(f"windows: 모르는 키 {sorted(unknown)}")
    # 이벤트 ID 는 windows.event, 값은 inserts·strings 로만 — fields 로 바꾸면 실측·문서 기반의 구분을 비켜 간다(검토)
    if bad := sorted(k for k in ("EventID", "StringInserts") if k in fields):
        raise SampleError(f"fields 에 {bad} 를 쓰지 않습니다 (windows.event·inserts·strings 로)")
    if "envelope" not in w:
        providers = {r["ProviderName"] for r in WINLOG if r["EventID"] == event_id}
        if len(providers) > 1 and "provider" not in w:
            raise SampleError(f"{event_id} 실측 레코드의 공급자가 여럿입니다 {sorted(providers)} — windows.provider 로 고릅니다")
        base = _real_windows(event_id, w.get("where"), w.get("provider"))
        if base is None:
            raise SampleError(f"{event_id} 실측 레코드가 없습니다{' (where ' + str(w['where']) + ')' if w.get('where') else ''}"
                              " — envelope(봉투로 쓸 실측 이벤트 ID)·fields·ref 로 문서 기반 표본을 만듭니다")
        if "strings" in spec:
            raise SampleError(f"{event_id} 는 실측 레코드가 있습니다 — strings 없이 inserts 로 값만 바꿉니다")
        if changed := sorted(k for k in fields if k in IDENTITY):
            raise SampleError(f"{event_id} 실측 표본은 {changed} 를 바꾸지 않습니다 — 다른 이벤트면 envelope 로 문서 기반 표본을 만듭니다")
        record, real = copy.deepcopy(base), True
    else:
        if "where" in w or "provider" in w:
            raise SampleError("envelope 표본은 where·provider 를 쓰지 않습니다 (공급자는 fields.ProviderName)")
        if _real_windows(event_id, provider=fields.get("ProviderName")) is not None:
            raise SampleError(f"{fields.get('ProviderName')} {event_id} 는 실측 레코드가 생겼습니다 — envelope 대신 실측으로 바꿉니다")
        envelope = _real_windows(int(w["envelope"]))
        if envelope is None:
            raise SampleError(f"envelope {w['envelope']} 실측 레코드가 없습니다")
        if missing := [k for k in DOC_FIELDS if k not in fields]:
            raise SampleError(f"실측이 없는 표본은 fields 에 {missing} 를 적습니다 (봉투의 값이 남지 않게)")
        record, real = {**copy.deepcopy(envelope), "EventID": event_id}, False
    record.update(fields)
    names = template(record)
    if real:
        values = list(record["StringInserts"])
        for name, value in inserts.items():
            if names is None or name not in names:
                raise SampleError(f"{event_id} 템플릿에 {name} 가 없습니다")
            values[names.index(name)] = value
    elif "strings" in spec:
        if inserts or names is not None:
            raise SampleError(f"{event_id} 는 템플릿이 {'있어 inserts 로 모든 이름을' if names else '없어 strings 만'} 씁니다")
        values = list(spec["strings"])
    else:
        if names is None:
            raise SampleError(f"{event_id} 템플릿이 없습니다 — strings 로 StringInserts 를 그대로 적습니다")
        if missing := [n for n in names if n not in inserts] or [n for n in inserts if n not in names]:
            raise SampleError(f"실측이 없는 표본은 템플릿 이름을 모두 적습니다 (빠지거나 남는 이름 {missing})")
        values = [inserts[n] for n in names]
    record["StringInserts"] = values
    record["log_source"] = "winevtlog"
    return [record], real


def _lines(value: Any, what: str) -> list[str]:
    lines = [value] if isinstance(value, str) else value
    if not isinstance(lines, list) or not lines or not all(isinstance(x, str) for x in lines):
        raise SampleError(f"{what}: 줄 하나 또는 줄 목록이어야 합니다")
    return lines


def label(check: dict) -> str:
    """시험기 조건 하나의 이름 — 조건 키(event_id·f.EventData.LogonType·q …), 묶음 값·볼 값은 앞에 표시(group_key:ip),
    제외 조건은 검색 문장처럼 앞에 '-'(-user·-msg) — 같은 키의 포함과 제외가 한 이름이 되지 않게(검토)."""
    if check["op"] in ("group_key", "term_field"):
        return f"{check['op']}:{check['key']}"
    return f"-{check['key']}" if check["op"] in ("not_in", "msg_not") else str(check["key"])


def _build(spec: dict) -> tuple[list[dict], bool]:
    if unknown := sorted(set(spec) - SPEC_KEYS):
        raise SampleError(f"모르는 키 {unknown} (오타면 조용히 무시되던 것)")
    kinds = [k for k in KINDS if k in spec]
    if len(kinds) != 1:
        raise SampleError(f"표본마다 {KINDS} 중 하나만 씁니다 (지금 {kinds})")
    kind = kinds[0]
    if kind != "windows" and (bad := sorted(k for k in ("fields", "inserts", "strings") if k in spec)):
        raise SampleError(f"{bad} 는 windows 표본에만 씁니다")
    if kind not in ("iis", "mssql") and "file" in spec:
        raise SampleError("file 은 iis·mssql 표본에만 씁니다")
    if kind == "windows":
        return _windows(spec)
    if kind == "iis":   # Fluent Bit tail(path_key: file) + modify(log_source)
        return [{"log": line, "file": spec.get("file", IIS_FILE), "log_source": "iis"} for line in _lines(spec["iis"], kind)], False
    if kind == "mssql":   # 에이전트 0.4.0: 시각으로 시작하는 줄마다 한 레코드 (multiline mssql_errorlog)
        return [{"log": line, "file": spec.get("file", ERRORLOG), "log_source": "mssql"} for line in _lines(spec["mssql"], kind)], False
    if kind in ("journald", "syslog"):   # 리눅스 에이전트 systemd 입력 / syslog 수신기(collector) — 둘 다 log_source 를 붙인다
        if not isinstance(spec[kind], dict):
            raise SampleError(f"{kind}: 레코드(키: 값)여야 합니다")
        return [{**spec[kind], "log_source": kind}], False
    if not isinstance(spec["record"], dict):
        raise SampleError("record: 레코드(키: 값)여야 합니다")
    return [dict(spec["record"])], False


def load(path: Path) -> list[Sample]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sid = doc.get("rule")
    if sid != int(path.stem):
        raise SampleError(f"{path.name}: rule 은 파일 이름과 같은 규칙 번호여야 합니다 (지금 {sid!r})")
    if unknown := set(doc) - {"rule", "match", "no_match"}:
        raise SampleError(f"{path.name}: 모르는 키 {sorted(unknown)}")
    out = []
    for key, expect in (("match", True), ("no_match", False)):
        for i, spec in enumerate(doc.get(key) or [], 1):
            if not isinstance(spec, dict) or not str(spec.get("why") or "").strip():
                raise SampleError(f"{path.name} {key} {i}: why(왜 맞거나 안 맞아야 하는지)가 필요합니다")
            try:
                records, real = _build(spec)
            except SampleError as exc:
                raise SampleError(f"{path.name} {key} {i}: {exc}") from exc
            ref = spec.get("ref")
            if not real and not ref:
                raise SampleError(f"{path.name} {key} {i}: 실측 레코드에서 만들지 않은 표본은 ref(형식의 근거)가 필요합니다")
            fails_on = spec.get("fails_on")
            if expect and fails_on is not None:
                raise SampleError(f"{path.name} {key} {i}: fails_on 은 no_match 표본에만 씁니다")
            if not expect and (not isinstance(fails_on, list) or not fails_on or not all(isinstance(x, str) for x in fails_on)):
                raise SampleError(f"{path.name} {key} {i}: no_match 표본은 fails_on(떨어져야 하는 조건 목록)이 필요합니다")
            out.append(Sample(sid=sid, index=i, expect=expect, why=str(spec["why"]).strip(), records=tuple(records),
                              real=real, ref=ref, fails_on=frozenset(fails_on or ())))
    return out


def all_samples() -> list[Sample]:
    return [s for path in sorted(RULES_DIR.glob("*.yaml")) for s in load(path)]


def with_host(records: list[dict] | tuple[dict, ...], host: str) -> list[dict]:
    """표본마다 다른 PC 이름 — 에이전트가 붙이는 agent_host 가 PC 이름이다(pick_host). syslog 수신기는 agent_host 를
    붙이지 않고 장비가 보낸 host 를 쓴다."""
    out = []
    for record in copy.deepcopy(list(records)):
        if record.get("log_source") == "syslog":
            record["host"] = host
        else:
            record["agent_host"] = host
        if record.get("log_source") == "winevtlog":
            record["Computer"] = host
        out.append(record)
    return out


def normalize_all(records: list[dict], now: datetime) -> list[Event]:
    """수집처럼 차례로 정규화한다 — 같은 표본 안의 MSSQL 머리줄·IIS #Fields 는 다음 줄에 쓰이고, 프로세스 상태는 되돌린다."""
    pending = dict(mssql._pending)
    mssql._pending.clear()
    ctx = IisContext()
    try:
        return [e for r in records if isinstance(e := normalize(copy.deepcopy(r), now, ctx), Event)]
    finally:
        mssql._pending.clear()
        mssql._pending.update(pending)


def vary(records: list[dict], field: str, i: int) -> list[dict]:
    """서로 다른 값 수 규칙(ADR-041)의 i 번째 사본 — 그 값만 바꾼다(Windows 표본의 템플릿 이름으로)."""
    name = {"user": "TargetUserName", "ip": "IpAddress"}.get(field)
    out = []
    for record in copy.deepcopy(records):
        names = template(record) if record.get("log_source") == "winevtlog" else None
        if name is None or names is None or name not in names:
            raise SampleError(f"{field} 를 바꿀 수 없는 표본입니다 (Windows 템플릿의 {name} 만)")
        values = record["StringInserts"]
        at = names.index(name)
        values[at] = f"{values[at]}{i}" if field == "user" else f"198.18.{i // 250}.{i % 250 + 1}"
        out.append(record)
    return out
