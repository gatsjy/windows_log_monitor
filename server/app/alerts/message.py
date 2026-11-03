"""알림 메시지: 모든 알림 대상(메일/웹훅/Oracle)이 같은 내용을 쓰도록 한 곳에서 만든다."""

from __future__ import annotations

import hashlib
import html
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode

from ..config import display_zone, settings

SEVERITY_LABELS = {"critical": "심각", "error": "오류", "warning": "경고", "info": "정보"}
# 심각도 색: 메일 왼쪽 막대와 메신저(Slack 색 막대·두레이·잔디)가 같은 색을 쓴다
SEVERITY_COLORS = {"critical": "#d03b3b", "error": "#ec835a", "warning": "#fab219", "info": "#2a78d6"}
RESOLVED_COLOR = "#2f9e5b"   # 해소 통지 (B-35 2단계)
LEVEL_LABELS = {1: "심각", 2: "오류", 3: "경고", 4: "정보", 5: "상세"}
# 알림 종료 분류 (B-44) — 해결할 때 사람이 고른다. auto 는 엔진의 자동 해소(사람이 고를 수 없음)
RESOLUTION_LABELS = {"tp_malicious": "정탐 — 의심 행위", "tp_expected": "정탐 — 예상된 관리 작업", "fp_rule": "오탐 — 규칙 문제",
                     "fp_data": "오탐 — 데이터 문제", "undetermined": "판단 불가", "auto": "자동 해소"}


def local(dt: datetime | None) -> str:
    return dt.astimezone(display_zone()).strftime("%Y-%m-%d %H:%M:%S") if dt else "-"


def _window_text(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}시간"
    if seconds % 60 == 0:
        return f"{seconds // 60}분"
    return f"{seconds}초"


def escalation_text(seconds: int, unless: str) -> str:
    """에스컬레이션 문구 (B-43): '15분 동안 아무도 확인하지 않음'·'1시간 동안 해결되지 않음' — 제목 머리말·처리 기록에 같이."""
    return f"{_window_text(seconds)} 동안 {'아무도 확인하지 않음' if unless == 'acked' else '해결되지 않음'}"


def ack_timeout_text(seconds: int) -> str:
    """확인 시간 초과 문구 (B-43 2단계): '4시간 동안 해결되지 않음' — 확인한 뒤의 시간."""
    return f"확인한 뒤 {_window_text(seconds)} 동안 해결되지 않음"


def escalation_from_action(action: str) -> str | None:
    """alert_deliveries.action 'escalate:<초>:<acked|resolved>'·'acktimeout:<초>:<회차>' → 문구. 다시 알림이 아니면 None."""
    parts = action.split(":")
    if len(parts) != 3 or not parts[1].isdigit():
        return None
    if parts[0] == "escalate":
        return escalation_text(int(parts[1]), parts[2])
    if parts[0] == "acktimeout":
        return ack_timeout_text(int(parts[1]))
    return None


SEVERITY_RANK = {"info": 1, "warning": 2, "error": 3, "critical": 4}
GROUP_LIST_MAX = 20      # 묶음 알림 본문에 대상을 몇 줄까지 (나머지는 '외 n건' + 알림 화면 링크)
GROUP_TITLE_KEYS = 3     # 제목에 보일 대상 이름 수
GROUP_SAMPLES = 5        # 묶음 알림의 최근 이벤트 (알림마다 하나씩, 앞에서부터)


# 서로 다른 값 수 규칙의 필드 이름 (화면 web/js/ruleform.js GROUP_LABELS 와 같은 말)
DISTINCT_LABELS = {"user": "사용자", "ip": "IP", "host": "PC", "event_id": "이벤트 ID", "category": "분류",
                   "channel": "채널", "provider": "공급자", "source": "소스", "level": "수준"}


@dataclass
class AlertMessage:
    rule: str
    severity: str
    kind: str
    group_by: str
    group_key: str
    event_count: int
    threshold: int
    window_sec: int
    fired_at: datetime
    description: str = ""
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    link: str = ""
    samples: list[dict[str, Any]] = field(default_factory=list)
    alert_id: int | None = None
    test: bool = False
    tags: list[str] = field(default_factory=list)
    # 서로 다른 값 수 규칙 (ADR-041): 필드·기준·센 수·앞의 값 몇 개
    distinct_field: str = ""
    distinct_min: int = 0
    distinct_count: int = 0
    distinct_values: list[str] = field(default_factory=list)
    # 같은 규칙·대상의 앞 알림 (B-35): 그 뒤 몇 건이 더 왔는지, 해결된 뒤 새로 발생한 재발인지
    previous_id: int | None = None
    previous_fired_at: datetime | None = None
    since_previous: int = 0
    recurred: bool = False
    # 해소 통지 (B-35 2단계): trigger = 알림, resolve = 조건이 풀려 자동으로 해결했다는 통지 (resolved_at = 해결 시각)
    event_action: str = "trigger"
    resolved_at: datetime | None = None
    started_at: datetime | None = None   # 해소 통지: 함께 자동 해결된 알림 중 가장 이른 발생 (문제가 얼마나 갔나)
    # 채널 끊김 (B-37 2단계): {host, source, channel, per_day} — 다시 들어왔는지 볼 때 어느 채널인지 (대상 이름은 사람이 읽는 문구)
    stream: dict[str, Any] | None = None
    observe: bool = False   # 관찰 모드 규칙의 알림 (B-52) — 기록만, 보내지 않음
    escalation: str = ""    # 에스컬레이션으로 다시 보내는 알림 (B-43) — 문구(escalation_text). 저장되는 payload 에는 없음(전송 때만)
    routes: list[str] = field(default_factory=list)   # 받는 곳을 정한 경로 이름 (B-26) — 증적, 경로가 없으면 빈 목록
    # 묶음 알림 (B-41): 같은 규칙의 알림 여럿을 한 통으로 — [{id, group_key, event_count, fired_at}]. 전송 때만 만든다(저장 안 함)
    grouped: list[dict[str, Any]] = field(default_factory=list)
    # 처음 보는 값 (B-47): {fields, values, host, first_ts, prev_last_seen, history_days} 또는 몰려온 묶음 {fields, count, items:[{values, first_ts}]}
    terms: dict[str, Any] | None = None
    # 상관 알림 (B-67 2단계): {entity: {kind, value}, tactics: [{tactic, name, rule, alert_id}], alerts: [{id, rule, severity, fired_at,
    # group_key, tactics}], count}
    correlation: dict[str, Any] | None = None

    # ------------------------------------------------------------ 직렬화
    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.event_action == "trigger":   # 저장되는 payload 는 늘 알림 — 예전과 같게
            for key in ("event_action", "resolved_at", "started_at"):
                data.pop(key)
        if self.stream is None:
            data.pop("stream")
        if not self.observe:
            data.pop("observe")
        if not self.escalation:
            data.pop("escalation")
        if not self.routes:
            data.pop("routes")
        if not self.grouped:
            data.pop("grouped")
        if self.terms is None:
            data.pop("terms")
        if self.correlation is None:
            data.pop("correlation")
        if not self.distinct_field:   # 건수 규칙의 본문(웹훅 json·저장된 payload)은 예전과 같게
            for key in ("distinct_field", "distinct_min", "distinct_count", "distinct_values"):
                data.pop(key)
        if self.previous_id is None:   # 처음 알림의 본문도 예전과 같게
            for key in ("previous_id", "previous_fired_at", "since_previous", "recurred"):
                data.pop(key)
        for key in ("fired_at", "first_event_at", "last_event_at", "previous_fired_at", "resolved_at", "started_at"):
            if key in data:
                data[key] = data[key].isoformat() if data[key] else None
        return data

    @classmethod
    def group(cls, items: list[AlertMessage]) -> AlertMessage:
        """같은 규칙·종류의 알림 여럿 → 한 통 (B-41). 가장 심각한·이른 알림을 바탕으로 건수는 합, 시각은 처음~마지막,
        최근 이벤트는 알림마다 하나씩. 알림 번호는 없다(각 알림의 증적은 alert_deliveries 에 그대로)."""
        items = sorted(items, key=lambda m: (-SEVERITY_RANK.get(m.severity, 1), m.fired_at, m.alert_id or 0))
        base = items[0]
        merged = cls.from_dict(base.to_dict())
        merged.event_action, merged.resolved_at, merged.started_at = base.event_action, base.resolved_at, base.started_at
        merged.escalation = base.escalation
        firsts = [m.first_event_at for m in items if m.first_event_at]
        lasts = [m.last_event_at for m in items if m.last_event_at]
        resolved = [m.resolved_at for m in items if m.resolved_at]
        merged.alert_id, merged.group_key = None, ""
        merged.event_count = sum(m.event_count for m in items)
        merged.fired_at = min(m.fired_at for m in items)
        merged.first_event_at, merged.last_event_at = (min(firsts) if firsts else None), (max(lasts) if lasts else None)
        merged.resolved_at = max(resolved) if resolved else merged.resolved_at
        merged.samples = [m.samples[0] for m in items if m.samples][:GROUP_SAMPLES]
        merged.previous_id, merged.previous_fired_at, merged.since_previous, merged.recurred = None, None, 0, False
        merged.distinct_count, merged.distinct_values, merged.stream = 0, [], None
        merged.routes = sorted({r for m in items for r in m.routes})
        merged.link = alerts_link(base.rule)
        merged.grouped = [{"id": m.alert_id, "group_key": m.group_key, "event_count": m.event_count,
                           "fired_at": m.fired_at.isoformat()} for m in sorted(items, key=lambda m: (m.fired_at, m.alert_id or 0))]
        return merged

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertMessage:
        values = dict(data)
        for key in ("fired_at", "first_event_at", "last_event_at", "previous_fired_at", "resolved_at", "started_at"):
            if values.get(key):
                values[key] = datetime.fromisoformat(values[key])
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in values.items() if k in known})

    # -------------------------------------------------------------- 문구
    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, self.severity)

    @property
    def resolved(self) -> bool:
        return self.event_action == "resolve"

    @property
    def dedup_key(self) -> str:
        """같은 규칙·대상이면 같은 값 — 사내 사고관리·SMS 가 알림(trigger)으로 연 것을 해소(resolve)로 닫게 (B-35 2단계).
        규칙 이름이 재알림 간격의 키인 것과 같다: 이름을 바꾸면 다른 문제로 본다.
        처음 보는 값(B-47)은 대상이 (대상 이름, PC) — 같은 값 조합이 다른 PC 에서 다시 알림이 되면 다른 사고다(같은 키면 받는 쪽이 열린 사고에
        합쳤다, 검토에서 재현). 다른 알림은 예전과 같은 값."""
        host = (self.terms or {}).get("host")
        return hashlib.sha256(f"{self.rule}\x1f{self.group_key}{chr(31) + host if host else ''}".encode()).hexdigest()[:32]

    @property
    def color(self) -> str:
        return RESOLVED_COLOR if self.resolved else SEVERITY_COLORS.get(self.severity, "#898781")

    def title(self) -> str:
        target = f" · {self.group_key}" if self.group_key else ""
        if self.grouped:   # '[오류] 서비스 비정상 종료 · 37대 (PC-001, PC-002, PC-003 외 34대)'
            keys = [_short(g["group_key"] or "-", 40) for g in self.grouped[:GROUP_TITLE_KEYS]]
            rest = len(self.grouped) - len(keys)
            unit = self.group_unit
            target = f" · {len(self.grouped)}{unit} ({', '.join(keys)}{f' 외 {rest}{unit}' if rest > 0 else ''})"
        prefix = ("[테스트] " if self.test else "[해소] " if self.resolved
                  else f"[다시 알림 — {self.escalation}] " if self.escalation else "")
        return f"{prefix}[{self.severity_label}] {self.rule}{target}"

    def summary(self) -> str:
        text = self._summary()
        if self.escalation and not self.resolved and not self.test:   # 에스컬레이션 (B-43): 왜 다시 오는지 먼저
            return f"{self.escalation} — 담당자가 확인하세요. {text}"
        return text

    @property
    def group_unit(self) -> str:
        """묶음 알림의 대상 세는 말 — PC 면 '대', 그 밖(사용자·IP·채널 등)은 '건'."""
        return "대" if self.group_by == "host" or self.kind == "agent_silent" else "건"

    def fired_text(self) -> str:
        """발생 시각 — 묶음이면 처음 ~ 마지막."""
        if self.grouped:
            times = [t for g in self.grouped if (t := _dt(g.get("fired_at")))]
            if times and min(times) != max(times):
                return f"{local(min(times))} ~ {local(max(times))}"
        return local(self.fired_at)

    def _summary(self) -> str:
        if self.test:
            return "알림 대상 연결 확인용 테스트 메시지입니다."
        if self.grouped:
            return self._group_summary()
        if self.resolved:
            if self.kind == "agent_silent":
                return f"{self.group_key} 에서 로그/하트비트가 다시 들어옵니다 — 자동으로 해결했습니다 ({local(self.resolved_at)})"
            if self.kind == "stream_silent":
                return f"{self.group_key} 로그가 다시 들어옵니다 — 자동으로 해결했습니다 ({local(self.resolved_at)})"
            target = f"{self.group_key} 에서 " if self.group_key else ""
            return (f"{target}최근 {_window_text(self.window_sec)} 동안 조건에 맞는 이벤트가 기준({self.threshold:,}건) 아래로 "
                    f"내려가 자동으로 해결했습니다 ({local(self.resolved_at)})")
        if self.kind in ("config", "system"):   # 내장 알림 (ADR-043·045): 설명 첫 줄이 요약, 나머지가 내용
            return self.description.split("\n", 1)[0]
        if self.kind == "agent_silent":
            return (f"{self.group_key} 에서 {_window_text(self.window_sec)} 이상 로그/하트비트가 들어오지 않았습니다 "
                    f"(마지막 수신 {local(self.last_event_at)})")
        if self.kind == "stream_silent":
            per_day = (self.stream or {}).get("per_day")
            usual = f"평소 하루 {per_day:,}건, " if per_day else ""
            return (f"{self.group_key} 로그가 {_window_text(self.window_sec)} 넘게 들어오지 않습니다 — PC 는 살아 있습니다 "
                    f"({usual}마지막 수신 {local(self.last_event_at)}). 감사 정책·에이전트 설정을 확인하세요")
        if self.kind == "new_terms" and self.terms:
            return self._terms_summary()
        if self.kind == "correlation" and self.correlation:
            steps = " → ".join(f"{s['name']}({s['rule']})" for s in self.correlation.get("tactics", []))
            return (f"{self.group_key} 에서 최근 {_window_text(self.window_sec)} 동안 서로 다른 전술 "
                    f"{len(self.correlation.get('tactics', [])):,}개 (기준 {self.threshold:,}개 이상) — {steps}")
        target = f"{self.group_key} 에서 " if self.group_key else ""
        if self.distinct_field:
            label = DISTINCT_LABELS.get(self.distinct_field, self.distinct_field.removeprefix("f."))
            return (f"{target}최근 {_window_text(self.window_sec)} 동안 서로 다른 {label} {self.distinct_count:,}개 "
                    f"(기준 {self.distinct_min:,}개 이상) · 이벤트 {self.event_count:,}건")
        return (f"{target}최근 {_window_text(self.window_sec)} 동안 조건에 맞는 이벤트 {self.event_count:,}건 "
                f"(기준 {self.threshold:,}건 이상)")

    def _terms_summary(self) -> str:
        """처음 보는 값 (B-47) — 어떤 필드의 어떤 값 조합을 언제 처음 봤는지."""
        t = self.terms or {}
        labels = [DISTINCT_LABELS.get(f, f.removeprefix("f.")) for f in t.get("fields", [])]
        days = t.get("history_days") or 0
        if "items" in t:   # 한 주기에 몰려온 새 조합 — 하나로 (burst)
            first = [" · ".join(f"{label} {v}" for label, v in zip(labels, item["values"], strict=False)) for item in t["items"][:5]]
            return (f"처음 보는 값 조합 {t.get('count', len(t['items'])):,}개가 한꺼번에 들어왔습니다 (최근 {days}일 동안 없던 값) — "
                    + ", ".join(first) + (" 외" if t.get("count", 0) > 5 else "") + ". 네트워크·계정 변경이 아니면 확인하세요")
        pairs = " · ".join(f"{label} {v}" for label, v in zip(labels, t.get("values", []), strict=False))
        again = ""
        if t.get("prev_last_seen"):
            again = f" — 마지막으로 본 지 {_days_since(t['prev_last_seen'], self.fired_at)}일 만에 다시"
        where = f" ({t['host']})" if t.get("host") else ""
        return f"처음 보는 값: {pairs}{where} — 최근 {days}일 동안 없던 조합입니다{again}"

    def _group_summary(self) -> str:
        n, unit = len(self.grouped), self.group_unit
        if self.resolved:
            return f"{n}{unit}의 알림이 조건이 풀려 자동으로 해결됐습니다 ({local(self.resolved_at)})"
        if self.kind == "agent_silent":
            return f"{n}대에서 {_window_text(self.window_sec)} 이상 로그/하트비트가 들어오지 않았습니다"
        if self.kind == "stream_silent":
            return (f"{n}{unit}의 로그가 {_window_text(self.window_sec)} 넘게 들어오지 않습니다 — PC 는 살아 있습니다. "
                    "감사 정책·에이전트 설정을 확인하세요")
        if self.kind in ("config", "system"):
            return f"같은 알림 {n}건을 묶어 보냅니다 — 내용은 알림 화면에서 확인하세요"
        if self.kind == "new_terms":
            return f"처음 보는 값 알림 {n}건을 묶어 보냅니다 — 값 조합은 아래와 알림 화면에서 확인하세요"
        if self.kind == "correlation":
            return f"여러 전술이 이어진 개체 {n}건을 묶어 보냅니다 — 묶은 알림은 알림 화면에서 확인하세요"
        basis = (f"서로 다른 {DISTINCT_LABELS.get(self.distinct_field, self.distinct_field)} {self.distinct_min:,}개 이상"
                 if self.distinct_field else f"기준 {self.threshold:,}건 이상")
        return (f"같은 규칙의 알림 {n}건을 묶어 보냅니다 — {n}{unit}에서 최근 {_window_text(self.window_sec)} 동안 조건에 맞는 "
                f"이벤트 ({basis}), 모두 {self.event_count:,}건")

    def group_lines(self) -> list[str]:
        """묶음 알림의 대상 목록 — '- PC-001 · 12건 · 2026-11-02 10:01:02 · #1234', 넘치면 '… 외 n건'."""
        lines = []
        for g in self.grouped[:GROUP_LIST_MAX]:
            count = f" · {int(g.get('event_count') or 0):,}건" if self.kind == "count" and not self.resolved else ""
            lines.append(f"- {_short(g['group_key'] or '-', 120)}{count} · {local(_dt(g.get('fired_at')))} · #{g['id']}")
        if len(self.grouped) > GROUP_LIST_MAX:
            lines.append(f"… 외 {len(self.grouped) - GROUP_LIST_MAX:,}건 — 전체는 알림 화면에서")
        return lines

    def distinct_line(self) -> str:
        """'서로 다른 사용자: a, b, c … 외 4' (서로 다른 값 수 규칙만, 묶음 알림은 알림마다 달라 빼고)"""
        if not self.distinct_field or not self.distinct_values or self.grouped:
            return ""
        label = DISTINCT_LABELS.get(self.distinct_field, self.distinct_field.removeprefix("f."))
        more = self.distinct_count - len(self.distinct_values)
        return f"서로 다른 {label}: " + ", ".join(self.distinct_values) + (f" … 외 {more:,}" if more > 0 else "")

    def correlation_lines(self) -> list[str]:
        """상관 알림 (B-67 2단계): 묶은 알림 — '- 10:01:02 [오류] 무차별 대입 · 10.0.0.5 (자격 증명 접근) #123'."""
        if self.kind != "correlation" or not self.correlation or self.grouped:
            return []
        items = self.correlation.get("alerts", [])
        lines = ["묶은 알림:"]
        for a in items:
            tactic = f" ({', '.join(a.get('tactics') or [])})" if a.get("tactics") else ""
            lines.append(f"- {local(_dt(a.get('fired_at')))} [{SEVERITY_LABELS.get(a.get('severity'), a.get('severity'))}] "
                         f"{a.get('rule')} · {_short(str(a.get('group_key') or '-'), 80)}{tactic} #{a.get('id')}")
        more = int(self.correlation.get("count") or len(items)) - len(items)
        if more > 0:
            lines.append(f"… 외 {more:,}건 — 전체는 알림 화면에서")
        return lines

    def lifecycle_line(self) -> str:
        """같은 규칙·대상의 앞 알림과의 관계 (B-35)."""
        if self.previous_id is None:
            return ""
        if self.recurred:
            return f"해결된 알림(#{self.previous_id}) 뒤 새로 발생했습니다 — 재알림 간격과 상관없이 알립니다"
        return f"지난 알림(#{self.previous_id}, {local(self.previous_fired_at)}) 이후 이 대상에서 {self.since_previous:,}건"

    def delayed_line(self) -> str:
        """발생 시각이 집계 구간보다 한참 앞선 이벤트가 섞였다 — 장애 뒤 에이전트가 밀린 로그를 한꺼번에 보내면 몇 시간에
        흩어진 이벤트가 '10분에 20건'처럼 보인다(B-35, ADR-039). 판정은 그대로(수신 기준), 받는 사람이 알게만 한다."""
        if self.kind != "count" or not self.first_event_at or not self.window_sec:
            return ""
        window = timedelta(seconds=self.window_sec)
        if self.fired_at - self.first_event_at <= max(2 * window, window + timedelta(hours=1)):
            return ""
        return (f"지연 수신분 포함 — 발생 시각 {local(self.first_event_at)} ~ {local(self.last_event_at)}"
                " (밀린 로그를 한꺼번에 받았거나 PC 시계가 틀렸을 수 있습니다)")

    def resolved_line(self) -> str:
        """해소 통지: 어느 알림이 언제부터 언제까지였나."""
        if not self.resolved:
            return ""
        number = f"알림 #{self.alert_id} " if self.alert_id else "알림 "
        start = min(self.started_at, self.fired_at) if self.started_at else self.fired_at
        first = "처음 알림 " if start < self.fired_at else ""   # 재알림 간격마다 다시 알렸으면 그 처음부터
        lasted = _lasted(start, self.resolved_at)
        return f"{number}— {first}{local(start)} 발생 → {local(self.resolved_at)} 해결{f' ({lasted})' if lasted else ''}"

    @property
    def detail(self) -> str:
        """요약 아래에 붙는 설명. 설정 변경 알림은 첫 줄(요약)을 뺀 변경 목록.
        앞 알림과의 관계·지연 수신 줄을 앞에 붙인다 — 메일·메신저 형식이 모두 이것을 쓴다.
        묶음 알림(B-41)은 대상 목록과 규칙 설명 (앞 알림 관계·지연 줄은 알림마다 달라 상세 화면에서)."""
        if self.grouped:
            extra = "" if self.resolved or self.kind in ("config", "system") else self.description
            return "\n".join(self.group_lines()) + (f"\n\n{extra}" if extra else "")
        if self.resolved:
            return self.resolved_line()
        if self.kind in ("config", "system"):
            return self.description.split("\n", 1)[1] if "\n" in self.description else ""
        return "\n".join(line for line in (self.lifecycle_line(), self.delayed_line(), *self.correlation_lines(), self.description)
                         if line)

    def text(self) -> str:
        lines = [self.title(), "", self.summary()]
        if self.distinct_line():
            lines.append(self.distinct_line())
        if self.detail:
            lines += ["", self.detail]
        if self.tags:
            lines += ["", "태그: " + ", ".join(self.tags)]
        lines += ["", f"발생 시각: {self.fired_text()}"]
        if self.resolved_at:
            lines.append(f"해소 시각: {local(self.resolved_at)}")
        if self.first_event_at:
            lines.append(f"이벤트 시각: {local(self.first_event_at)} ~ {local(self.last_event_at)}")
        if self.samples and not self.resolved:
            lines += ["", "최근 이벤트:"]
            for s in self.samples:
                head = f"- {local(_dt(s.get('ts')))} [{LEVEL_LABELS.get(s.get('level'), s.get('level'))}] {s.get('host')}"
                ident = " ".join(str(x) for x in (s.get("channel"), s.get("event_id")) if x)
                message = (s.get("message") or "").split("\n", 1)[0].strip()[:200]
                lines.append(f"{head} {ident} — {message}")
        if self.link:
            lines += ["", f"자세히 보기: {self.link}"]
        lines += ["", "— Log Monitor"]
        return "\n".join(lines)

    def html(self) -> str:
        e = html.escape
        samples = [] if self.resolved else self.samples   # 해소 통지에 알림 때의 이벤트를 다시 붙이지 않는다
        rows = "".join(
            "<tr>"
            f"<td style='padding:4px 8px;color:#52514e;white-space:nowrap'>{e(local(_dt(s.get('ts'))))}</td>"
            f"<td style='padding:4px 8px;white-space:nowrap'>{e(str(LEVEL_LABELS.get(s.get('level'), '')))}</td>"
            f"<td style='padding:4px 8px;white-space:nowrap'>{e(str(s.get('host') or ''))}</td>"
            f"<td style='padding:4px 8px;white-space:nowrap'>{e(' '.join(str(x) for x in (s.get('channel'), s.get('event_id')) if x))}</td>"
            f"<td style='padding:4px 8px'>{e((s.get('message') or '').split(chr(10), 1)[0][:200])}</td>"
            "</tr>"
            for s in samples
        )
        table = (f"<table style='border-collapse:collapse;font-size:13px;margin-top:8px'>{rows}</table>"
                 if rows else "")
        link = (f"<p><a href='{e(self.link)}' style='color:#1c5cab'>Log Monitor 에서 자세히 보기 →</a></p>"
                if self.link else "")
        desc = (f"<p style='color:#52514e'>{e(self.detail).replace(chr(10), '<br>')}</p>" if self.detail else "")
        if self.distinct_line():
            desc = f"<p style='font-size:13px'>{e(self.distinct_line())}</p>" + desc
        if self.tags:
            desc += f"<p style='font-size:12px;color:#52514e'>태그: {e(', '.join(self.tags))}</p>"
        return (
            "<div style='font-family:system-ui,-apple-system,\"Malgun Gothic\",sans-serif;color:#0b0b0b;max-width:760px'>"
            f"<div style='border-left:4px solid {self.color};padding:4px 0 4px 12px'>"
            f"<div style='font-size:12px;color:#52514e'>{e(self.severity_label)} · "
            f"{e(local(self.resolved_at) if self.resolved else self.fired_text())}</div>"
            f"<div style='font-size:17px;font-weight:600'>{e(self.title())}</div></div>"
            f"<p>{e(self.summary())}</p>{desc}{table}{link}"
            "<p style='font-size:12px;color:#898781'>— Log Monitor</p></div>"
        )


@dataclass
class Notice:
    """알림이 아닌 공지 (점검 보고서 등, ADR-032): 제목·요약 줄·링크. 메일은 html·text 본문을 따로 받는다.
    severity 는 색만 정한다 (점검 필요가 있으면 warning·error, 없으면 info)."""

    title: str
    lines: list[str]
    link: str = ""
    severity: str = "info"
    html: str = ""
    text: str = ""

    def plain(self) -> str:
        body = self.text or "\n".join([self.title, "", *self.lines])
        return f"{body}\n\n자세히 보기: {self.link}" if self.link and self.link not in body else body


def _lasted(start: datetime | None, end: datetime | None) -> str:
    if not start or not end or end < start:
        return ""
    minutes = int((end - start).total_seconds() // 60)
    if minutes < 60:
        return f"{minutes}분"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}시간 {minutes}분" if hours < 48 else f"{hours // 24}일 {hours % 24}시간"


def _dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def alerts_link(rule: str) -> str:
    """그 규칙의 알림 목록 (최근 7일 — 하루 뒤 다시 알림도 담기게) — 묶음 알림의 '자세히 보기'."""
    return f"{settings.public_url}/#/alerts?since=7d&rule={quote(rule, safe='')}"


def search_link(params: dict[str, str]) -> str:
    return f"{settings.public_url}/#/events?{urlencode(params)}"


def _days_since(when: Any, now: datetime) -> int:
    then = _dt(when)
    return max(0, (now - then).days) if then else 0
