"""알림 메시지: 모든 알림 대상(메일/웹훅/Oracle)이 같은 내용을 쓰도록 한 곳에서 만든다."""

from __future__ import annotations

import hashlib
import html
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from ..config import display_zone, settings

SEVERITY_LABELS = {"critical": "심각", "error": "오류", "warning": "경고", "info": "정보"}
# 심각도 색: 메일 왼쪽 막대와 메신저(Slack 색 막대·두레이·잔디)가 같은 색을 쓴다
SEVERITY_COLORS = {"critical": "#d03b3b", "error": "#ec835a", "warning": "#fab219", "info": "#2a78d6"}
RESOLVED_COLOR = "#2f9e5b"   # 해소 통지 (B-35 2단계)
LEVEL_LABELS = {1: "심각", 2: "오류", 3: "경고", 4: "정보", 5: "상세"}


def local(dt: datetime | None) -> str:
    return dt.astimezone(display_zone()).strftime("%Y-%m-%d %H:%M:%S") if dt else "-"


def _window_text(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}시간"
    if seconds % 60 == 0:
        return f"{seconds // 60}분"
    return f"{seconds}초"


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

    # ------------------------------------------------------------ 직렬화
    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.event_action == "trigger":   # 저장되는 payload 는 늘 알림 — 예전과 같게
            for key in ("event_action", "resolved_at", "started_at"):
                data.pop(key)
        if self.stream is None:
            data.pop("stream")
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
        규칙 이름이 재알림 간격의 키인 것과 같다: 이름을 바꾸면 다른 문제로 본다."""
        return hashlib.sha256(f"{self.rule}\x1f{self.group_key}".encode()).hexdigest()[:32]

    @property
    def color(self) -> str:
        return RESOLVED_COLOR if self.resolved else SEVERITY_COLORS.get(self.severity, "#898781")

    def title(self) -> str:
        target = f" · {self.group_key}" if self.group_key else ""
        prefix = "[테스트] " if self.test else "[해소] " if self.resolved else ""
        return f"{prefix}[{self.severity_label}] {self.rule}{target}"

    def summary(self) -> str:
        if self.test:
            return "알림 대상 연결 확인용 테스트 메시지입니다."
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
        target = f"{self.group_key} 에서 " if self.group_key else ""
        if self.distinct_field:
            label = DISTINCT_LABELS.get(self.distinct_field, self.distinct_field.removeprefix("f."))
            return (f"{target}최근 {_window_text(self.window_sec)} 동안 서로 다른 {label} {self.distinct_count:,}개 "
                    f"(기준 {self.distinct_min:,}개 이상) · 이벤트 {self.event_count:,}건")
        return (f"{target}최근 {_window_text(self.window_sec)} 동안 조건에 맞는 이벤트 {self.event_count:,}건 "
                f"(기준 {self.threshold:,}건 이상)")

    def distinct_line(self) -> str:
        """'서로 다른 사용자: a, b, c … 외 4' (서로 다른 값 수 규칙만)"""
        if not self.distinct_field or not self.distinct_values:
            return ""
        label = DISTINCT_LABELS.get(self.distinct_field, self.distinct_field.removeprefix("f."))
        more = self.distinct_count - len(self.distinct_values)
        return f"서로 다른 {label}: " + ", ".join(self.distinct_values) + (f" … 외 {more:,}" if more > 0 else "")

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
        앞 알림과의 관계·지연 수신 줄을 앞에 붙인다 — 메일·메신저 형식이 모두 이것을 쓴다."""
        if self.resolved:
            return self.resolved_line()
        if self.kind in ("config", "system"):
            return self.description.split("\n", 1)[1] if "\n" in self.description else ""
        return "\n".join(line for line in (self.lifecycle_line(), self.delayed_line(), self.description) if line)

    def text(self) -> str:
        lines = [self.title(), "", self.summary()]
        if self.distinct_line():
            lines.append(self.distinct_line())
        if self.detail:
            lines += ["", self.detail]
        if self.tags:
            lines += ["", "태그: " + ", ".join(self.tags)]
        lines += ["", f"발생 시각: {local(self.fired_at)}"]
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
            f"{e(local(self.resolved_at if self.resolved else self.fired_at))}</div>"
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


def search_link(params: dict[str, str]) -> str:
    return f"{settings.public_url}/#/events?{urlencode(params)}"
