"""알림 메시지: 모든 알림 대상(메일/웹훅/Oracle)이 같은 내용을 쓰도록 한 곳에서 만든다."""

from __future__ import annotations

import html
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from ..config import settings

SEVERITY_LABELS = {"critical": "심각", "error": "오류", "warning": "경고", "info": "정보"}
LEVEL_LABELS = {1: "심각", 2: "오류", 3: "경고", 4: "정보", 5: "상세"}


def _tz() -> ZoneInfo:
    try:
        return ZoneInfo(settings.display_tz)
    except Exception:  # noqa: BLE001 - 잘못된 시간대 이름이면 UTC
        return ZoneInfo("UTC")


def local(dt: datetime | None) -> str:
    return dt.astimezone(_tz()).strftime("%Y-%m-%d %H:%M:%S") if dt else "-"


def _window_text(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}시간"
    if seconds % 60 == 0:
        return f"{seconds // 60}분"
    return f"{seconds}초"


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

    # ------------------------------------------------------------ 직렬화
    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("fired_at", "first_event_at", "last_event_at"):
            data[key] = data[key].isoformat() if data[key] else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertMessage:
        values = dict(data)
        for key in ("fired_at", "first_event_at", "last_event_at"):
            if values.get(key):
                values[key] = datetime.fromisoformat(values[key])
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in values.items() if k in known})

    # -------------------------------------------------------------- 문구
    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, self.severity)

    def title(self) -> str:
        target = f" · {self.group_key}" if self.group_key else ""
        prefix = "[테스트] " if self.test else ""
        return f"{prefix}[{self.severity_label}] {self.rule}{target}"

    def summary(self) -> str:
        if self.test:
            return "알림 대상 연결 확인용 테스트 메시지입니다."
        if self.kind == "agent_silent":
            return (f"{self.group_key} 에서 {_window_text(self.window_sec)} 이상 로그/하트비트가 들어오지 않았습니다 "
                    f"(마지막 수신 {local(self.last_event_at)})")
        target = f"{self.group_key} 에서 " if self.group_key else ""
        return (f"{target}최근 {_window_text(self.window_sec)} 동안 조건에 맞는 이벤트 {self.event_count:,}건 "
                f"(기준 {self.threshold:,}건 이상)")

    def text(self) -> str:
        lines = [self.title(), "", self.summary()]
        if self.description:
            lines += ["", self.description]
        if self.tags:
            lines += ["", "태그: " + ", ".join(self.tags)]
        lines += ["", f"발생 시각: {local(self.fired_at)}"]
        if self.first_event_at:
            lines.append(f"이벤트 시각: {local(self.first_event_at)} ~ {local(self.last_event_at)}")
        if self.samples:
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
        colors = {"critical": "#d03b3b", "error": "#ec835a", "warning": "#fab219", "info": "#2a78d6"}
        rows = "".join(
            "<tr>"
            f"<td style='padding:4px 8px;color:#52514e;white-space:nowrap'>{e(local(_dt(s.get('ts'))))}</td>"
            f"<td style='padding:4px 8px;white-space:nowrap'>{e(str(LEVEL_LABELS.get(s.get('level'), '')))}</td>"
            f"<td style='padding:4px 8px;white-space:nowrap'>{e(str(s.get('host') or ''))}</td>"
            f"<td style='padding:4px 8px;white-space:nowrap'>{e(' '.join(str(x) for x in (s.get('channel'), s.get('event_id')) if x))}</td>"
            f"<td style='padding:4px 8px'>{e((s.get('message') or '').split(chr(10), 1)[0][:200])}</td>"
            "</tr>"
            for s in self.samples
        )
        table = (f"<table style='border-collapse:collapse;font-size:13px;margin-top:8px'>{rows}</table>"
                 if rows else "")
        link = (f"<p><a href='{e(self.link)}' style='color:#1c5cab'>Log Monitor 에서 자세히 보기 →</a></p>"
                if self.link else "")
        desc = f"<p style='color:#52514e'>{e(self.description)}</p>" if self.description else ""
        if self.tags:
            desc += f"<p style='font-size:12px;color:#52514e'>태그: {e(', '.join(self.tags))}</p>"
        return (
            "<div style='font-family:system-ui,-apple-system,\"Malgun Gothic\",sans-serif;color:#0b0b0b;max-width:760px'>"
            f"<div style='border-left:4px solid {colors.get(self.severity, '#898781')};padding:4px 0 4px 12px'>"
            f"<div style='font-size:12px;color:#52514e'>{e(self.severity_label)} · {e(local(self.fired_at))}</div>"
            f"<div style='font-size:17px;font-weight:600'>{e(self.title())}</div></div>"
            f"<p>{e(self.summary())}</p>{desc}{table}{link}"
            "<p style='font-size:12px;color:#898781'>— Log Monitor</p></div>"
        )


def _dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def search_link(params: dict[str, str]) -> str:
    return f"{settings.public_url}/#/events?{urlencode(params)}"
