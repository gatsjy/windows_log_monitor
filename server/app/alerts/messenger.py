"""웹훅 보내는 형식 (메신저 프리셋, BACKLOG B-04, ADR-030): 같은 알림을 받는 서비스가 바로 보여 줄 수 있는 모양으로 바꾼다.

형식      대상                                              본문
json     사내 시스템 연동                                    {"source", "title", "text", "alert": {...}}
text     Mattermost·Rocket.Chat 등 단순 메시지               {"text": "..."}
slack    Slack 수신 웹훅 (Incoming Webhooks 앱)              머리글 블록 + 색 막대 첨부(attachments) 안의 Block Kit
teams    Microsoft Teams 워크플로 웹훅 (Power Automate)       Adaptive Card 1.4 를 message 봉투에 (Office 365 커넥터는 2026-05 종료)
dooray   NHN 두레이 메신저 Incoming                           {"botName", "text", "attachments"} — 서식 없음, 링크는 titleLink 로만
jandi    잔디 Incoming                                      {"body", "connectColor", "connectInfo"} + 전용 Accept 헤더

형식은 2026-10-15 에 각 서비스 공식 문서와 실제 응답으로 확인했다 (docs/DECISIONS.md ADR-030).
- 받는 쪽 제한을 넘으면 메시지 전체가 거부되므로 글자 수는 보내기 전에 자른다.
- 샘플 이벤트 메시지·대상 이름은 로그에서 온 값이라 서비스별 서식 문자를 무력화한다(링크·멘션으로 바뀌지 않게).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .message import LEVEL_LABELS, SEVERITY_COLORS, AlertMessage, Notice, _dt, local

SAMPLE_LINE_MAX = 160     # 샘플 이벤트 한 줄 (메신저 화면에서 한두 줄로 보이게)
LINK_TITLE = "Log Monitor 에서 자세히 보기"
# 대상(group_key)은 로그에서 온 값이라 길이 제한이 없다(group_by: f.<경로> — 예: 수천 자 명령줄).
# 제목·요약·항목 값·링크를 형식과 상관없이 이만큼으로 자른다 (Teams 28KB 를 넘으면 202 를 받고도 게시가 실패해 알림이 사라진다)
TITLE_MAX = 200
TEXT_MAX = 1000
FACT_MAX = 300
LINK_MAX = 2000


# ---------------------------------------------------------------- 공통 재료

def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _title(m: AlertMessage) -> str:
    return _cut(m.title(), TITLE_MAX)


def _summary(m: AlertMessage) -> str:
    return _cut(m.summary(), TEXT_MAX)


def _description(m: AlertMessage) -> str:
    return _cut(m.detail, TEXT_MAX)


def _link(m: AlertMessage) -> str:
    """검색 링크에는 대상 값이 들어가서 아주 길어질 수 있다. 자르면 깨지므로 너무 길면 알림 화면으로 보낸다."""
    if len(m.link) <= LINK_MAX:
        return m.link
    return m.link.split("#", 1)[0] + "#/alerts"


def _facts(m: AlertMessage) -> list[tuple[str, str]]:
    """(항목, 값) — 모든 형식이 같은 순서로 쓴다. 값은 비어 있지 않다(빈 글자를 거부하는 서비스가 있다)."""
    facts = [("발생 시각", local(m.fired_at))]
    if m.first_event_at:
        facts.append(("이벤트 시각", f"{local(m.first_event_at)} ~ {local(m.last_event_at)}"))
    if m.kind in ("config", "system"):   # 내장 알림(ADR-043·045)에는 건수 기준이 없다 — 내용 줄 수
        facts.append(("변경", f"{m.event_count:,}건"))
    elif m.kind != "agent_silent" and not m.test:
        facts.append(("건수", f"{m.event_count:,}건 (기준 {m.threshold:,}건 이상)"))
    if m.group_key:
        facts.append(("대상", _cut(m.group_key, FACT_MAX)))
    if m.tags:
        facts.append(("태그", _cut(", ".join(m.tags), FACT_MAX)))
    if m.alert_id and not m.test:
        facts.append(("알림 번호", f"#{m.alert_id}"))
    return facts


def _sample_lines(m: AlertMessage) -> list[str]:
    """'시각 · 수준 · PC · 채널 이벤트 — 메시지' 한 줄씩. 공백 여러 칸 정렬은 메신저가 접어 버려서 · 로 나눈다."""
    lines = []
    for s in m.samples:
        when = local(_dt(s.get("ts")))[11:]  # 시각만 (날짜는 발생 시각에 있음)
        ident = " ".join(str(x) for x in (s.get("channel"), s.get("event_id")) if x)
        text = " ".join((s.get("message") or "").replace("\r", " ").split("\n", 1)[0].split())
        parts = [when, str(LEVEL_LABELS.get(s.get("level"), s.get("level"))), str(s.get("host") or ""), ident]
        lines.append(_cut(" · ".join(p for p in parts if p) + f" — {text}", SAMPLE_LINE_MAX))
    return lines


def _no_md_link(text: str) -> str:
    """마크다운 링크 [이름](주소) 를 깨 둔다 — 로그 한 줄이 클릭되는 링크로 바뀌지 않게 (Teams·잔디)."""
    return text.replace("](", "] (")


# -------------------------------------------------------------------- json·text

def build_json(m: AlertMessage) -> dict[str, Any]:
    return {"source": "log-monitor", "title": m.title(), "text": m.summary(), "alert": m.to_dict()}


def build_text(m: AlertMessage) -> dict[str, Any]:
    # Mattermost 는 16,383자를 넘으면 여러 글로 쪼갠다 → 다른 메신저 형식과 같은 상한
    text = f"{_title(m)}\n{_summary(m)}"
    if m.kind in ("config", "system") and m.detail:   # 무엇이 바뀌었는지가 본문이다 (요약만으로는 어느 규칙인지 모른다)
        text += "\n" + _description(m)
    return {"text": f"{text}\n{_link(m)}" if m.link else text}


# ------------------------------------------------------------------------ Slack

def _slack_escape(text: str) -> str:
    """mrkdwn 제어 문자 & < > 만 엔티티로 — 그래야 로그의 <!channel>·<주소|이름> 이 멘션·링크가 되지 않는다."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _mrkdwn(text: str, limit: int) -> str:
    """이스케이프한 뒤에도 제한 안 (엔티티가 중간에 잘리지 않게 원문을 줄여 가며 맞춘다)."""
    out = _slack_escape(text)
    while len(out) > limit:
        text = text[: max(1, int(len(text) * 0.9))]
        out = _slack_escape(text.rstrip()) + "…"
    return out


def _slack_url(url: str) -> str:
    """<주소|이름> 의 주소 부분: | < > 공백은 퍼센트 인코딩, 쿼리의 & 는 제어 문자 규칙대로 &amp; (Slack 이 표시·이동 때 되돌린다)."""
    return url.replace(" ", "%20").replace("|", "%7C").replace("<", "%3C").replace(">", "%3E").replace("&", "&amp;")


def build_slack(m: AlertMessage) -> dict[str, Any]:
    details: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": _mrkdwn(_summary(m), 3000)}},
    ]
    if m.detail:
        details.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _mrkdwn(_description(m), 3000)}]})
    # 굵은 항목명은 따로 한 줄 — 한글에 바로 붙은 *굵게* 는 굵게 안 보일 때가 있다
    details.append({"type": "section", "fields": [
        {"type": "mrkdwn", "text": f"*{k}*\n{_mrkdwn(v, 1900)}"} for k, v in _facts(m)][:10]})
    samples = _sample_lines(m)
    if samples:
        details.append({"type": "section", "text": {"type": "mrkdwn",
                                                     "text": "*최근 이벤트*\n" + _mrkdwn("\n".join(samples), 2900)}})
    if m.link:
        # 버튼(url)은 앱에 상호작용 설정이 없으면 누를 때 오류 표시가 떠서, 글자 링크로 둔다
        details.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"<{_slack_url(_link(m))}|{LINK_TITLE}>"}]})
    fallback = _mrkdwn(f"{_title(m)} — {_summary(m)}", 3000)
    return {
        "text": fallback,  # 휴대폰 푸시·검색에 쓰이는 대체 문구 (블록이 있으면 화면에는 안 보인다)
        "blocks": [{"type": "header", "text": {"type": "plain_text", "text": _cut(m.title(), 150)}}],
        # 심각도 색 막대는 attachments 에서만 된다 (Block Kit 에는 색이 없다)
        "attachments": [{"color": SEVERITY_COLORS[m.severity], "fallback": fallback, "blocks": details}],
    }


# ------------------------------------------------------------------------ Teams

# Adaptive Card 는 임의 색(#hex)을 받지 않는다 → 정해진 스타일 이름으로
TEAMS_STYLE = {"critical": "attention", "error": "attention", "warning": "warning", "info": "accent"}


def build_teams(m: AlertMessage) -> dict[str, Any]:
    head: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": _no_md_link(_title(m)), "weight": "Bolder",
         "size": "Large" if m.severity == "critical" else "Medium", "wrap": True},
        {"type": "TextBlock", "text": local(m.fired_at), "isSubtle": True, "spacing": "None", "wrap": True},
    ]
    body: list[dict[str, Any]] = [
        {"type": "Container", "style": TEAMS_STYLE.get(m.severity, "emphasis"), "bleed": True, "items": head},
        {"type": "TextBlock", "text": _no_md_link(_summary(m)), "wrap": True},
    ]
    if m.detail:
        body.append({"type": "TextBlock", "text": _no_md_link(_description(m)), "wrap": True, "isSubtle": True,
                     "spacing": "None"})
    body.append({"type": "FactSet", "facts": [{"title": k, "value": _no_md_link(v)} for k, v in _facts(m)]})
    samples = _sample_lines(m)
    if samples:
        # 줄바꿈 한 번은 Teams(특히 휴대폰)에서 무시될 때가 있어 한 줄에 TextBlock 하나
        body.append({"type": "TextBlock", "text": "최근 이벤트", "weight": "Bolder", "spacing": "Medium", "wrap": True})
        body += [{"type": "TextBlock", "text": _no_md_link(line), "wrap": True, "size": "Small", "fontType": "Monospace",
                  "spacing": "None"} for line in samples]
    card: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "msteams": {"width": "Full"}, "body": body}
    if m.link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": LINK_TITLE, "url": _link(m)}]
    # 워크플로 템플릿은 attachments 를 돌며 카드를 올린다 → 이 봉투가 필수 (contentUrl 은 항상 null)
    return {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


# ------------------------------------------------------------------------ 두레이

def build_dooray(m: AlertMessage) -> dict[str, Any]:
    """두레이 메신저 훅은 서식(마크다운)을 공식 지원하지 않는다 → 평문, 링크는 첨부 제목(titleLink)으로만."""
    facts = "\n".join(f"{k}: {v}" for k, v in _facts(m))
    color = SEVERITY_COLORS[m.severity]
    # 마크다운은 공식 지원이 아니지만 일부 렌더링된다는 보고가 있어, 로그에서 온 [이름](주소) 는 다른 형식처럼 깨 둔다
    text = f"{_description(m)}\n{facts}" if m.detail else facts
    first: dict[str, Any] = {"title": _no_md_link(_summary(m)), "text": _no_md_link(text), "color": color}
    if m.link:
        first["titleLink"] = _link(m)
    attachments = [first]
    samples = _sample_lines(m)
    if samples:
        attachments.append({"title": "최근 이벤트", "text": _no_md_link("\n".join(samples)), "color": color})
    return {"botName": "Log Monitor", "text": _no_md_link(_title(m)), "attachments": attachments}


# -------------------------------------------------------------------------- 잔디

JANDI_SHOWN_MAX = 5000  # 잔디는 메시지 앞 5,000자만 보여 준다


def build_jandi(m: AlertMessage) -> dict[str, Any]:
    # 제목에 [경고] 가 있어 [제목](주소) 로 감싸면 대괄호가 겹친다 → 링크는 따로 한 줄
    body = _no_md_link(_title(m))
    if m.link:
        body += f"\n[{LINK_TITLE}]({_link(m)})"
    info = [{"title": "요약", "description": _no_md_link(_summary(m))}]
    if m.detail:
        info.append({"title": "설명", "description": _no_md_link(_description(m))})
    info += [{"title": k, "description": _no_md_link(v)} for k, v in _facts(m)]
    samples = _sample_lines(m)
    if samples:
        info.append({"title": "최근 이벤트", "description": _no_md_link("\n".join(samples))})
    budget = JANDI_SHOWN_MAX - len(body)
    for item in info:  # 뒤쪽(샘플)이 잘리도록 앞에서부터 남은 글자 수를 나눠 쓴다
        item["description"] = _cut(item["description"], max(20, budget - len(item["title"])))
        budget -= len(item["title"]) + len(item["description"])
    # 공식 예시가 대문자 #RRGGBB 라 맞춘다
    return {"body": body, "connectColor": SEVERITY_COLORS[m.severity].upper(), "connectInfo": info}


# ------------------------------------------------------------------- 공지 (점검 보고서)
# 보고서 같은 공지는 제목·요약 몇 줄·링크만 보낸다 (자세한 내용은 화면과 메일 HTML). 줄은 우리가 만든 문구지만
# PC 이름 등 로그에서 온 값이 섞일 수 있어 알림과 같은 무력화를 한다.

def _notice_lines(n: Notice) -> list[str]:
    return [_cut(line, FACT_MAX) for line in n.lines[:20]]


def notice_json(n: Notice) -> dict[str, Any]:
    return {"source": "log-monitor", "type": "notice", "title": n.title, "text": "\n".join(n.lines), "link": n.link}


def notice_text(n: Notice) -> dict[str, Any]:
    text = "\n".join([_cut(n.title, TITLE_MAX), *_notice_lines(n)])
    return {"text": f"{text}\n{n.link}" if n.link else text}


def notice_slack(n: Notice) -> dict[str, Any]:
    details: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": _mrkdwn("\n".join(_notice_lines(n)) or n.title, 3000)}}]
    if n.link:
        details.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"<{_slack_url(n.link)}|{LINK_TITLE}>"}]})
    fallback = _mrkdwn(n.title, 3000)
    return {"text": fallback, "blocks": [{"type": "header", "text": {"type": "plain_text", "text": _cut(n.title, 150)}}],
            "attachments": [{"color": SEVERITY_COLORS.get(n.severity, SEVERITY_COLORS["info"]), "fallback": fallback,
                             "blocks": details}]}


def notice_teams(n: Notice) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {"type": "Container", "style": TEAMS_STYLE.get(n.severity, "accent"), "bleed": True, "items": [
            {"type": "TextBlock", "text": _no_md_link(_cut(n.title, TITLE_MAX)), "weight": "Bolder", "size": "Medium",
             "wrap": True}]},
        *({"type": "TextBlock", "text": _no_md_link(line), "wrap": True, "spacing": "None"} for line in _notice_lines(n)),
    ]
    card: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "msteams": {"width": "Full"}, "body": body}
    if n.link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": LINK_TITLE, "url": n.link}]
    return {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def notice_dooray(n: Notice) -> dict[str, Any]:
    attachment: dict[str, Any] = {"title": LINK_TITLE if n.link else "요약", "text": _no_md_link("\n".join(_notice_lines(n))),
                                  "color": SEVERITY_COLORS.get(n.severity, SEVERITY_COLORS["info"])}
    if n.link:
        attachment["titleLink"] = n.link
    return {"botName": "Log Monitor", "text": _no_md_link(_cut(n.title, TITLE_MAX)), "attachments": [attachment]}


def notice_jandi(n: Notice) -> dict[str, Any]:
    body = _no_md_link(_cut(n.title, TITLE_MAX)) + (f"\n[{LINK_TITLE}]({n.link})" if n.link else "")
    return {"body": body, "connectColor": SEVERITY_COLORS.get(n.severity, SEVERITY_COLORS["info"]).upper(),
            "connectInfo": [{"title": "요약", "description": _no_md_link("\n".join(_notice_lines(n)))}]}


# ------------------------------------------------------------------------ 목록

@dataclass(frozen=True)
class WebhookFormat:
    key: str
    label: str                                   # 화면 선택지
    build: Callable[[AlertMessage], dict[str, Any]]
    hosts: tuple[str, ...] = ()                  # 주소의 호스트가 이것(또는 그 하위 도메인)이면 이 형식을 권한다
    headers: dict[str, str] = field(default_factory=dict)  # 서비스가 요구하는 헤더 (사용자가 넣은 헤더가 우선)
    https_only: bool = False                     # 클라우드 메신저: 주소의 토큰이 평문으로 나가지 않게 (http 로도 받아 버림)
    min_interval_sec: float = 0.0                # 같은 주소로 보내는 최소 간격 (넘으면 버리거나 429 를 주는 서비스)
    notice: Callable[[Notice], dict[str, Any]] = notice_json  # 공지(점검 보고서) 본문


FORMATS: dict[str, WebhookFormat] = {f.key: f for f in (
    WebhookFormat("json", "json — 알림 전체 데이터 (사내 시스템 연동)", build_json),
    WebhookFormat("text", "text — {\"text\": \"...\"} (Mattermost·Rocket.Chat 등)", build_text, notice=notice_text),
    WebhookFormat("slack", "Slack — 수신 웹훅 (색 막대·항목·최근 이벤트)", build_slack,
                  ("hooks.slack.com", "hooks.slack-gov.com"), https_only=True, min_interval_sec=1.0, notice=notice_slack),
    WebhookFormat("teams", "Microsoft Teams — 워크플로 웹훅 (Adaptive Card)", build_teams,
                  ("environment.api.powerplatform.com",), https_only=True, min_interval_sec=0.3, notice=notice_teams),
    WebhookFormat("dooray", "두레이 — 메신저 Incoming", build_dooray,
                  ("hook.dooray.com", "hook.gov-dooray.com", "hook.dooray.co.kr", "hook.gov-dooray.co.kr"),
                  https_only=True, min_interval_sec=1.1, notice=notice_dooray),
    WebhookFormat("jandi", "잔디 — Incoming 웹훅", build_jandi, ("wh.jandi.com",),
                  {"Accept": "application/vnd.tosslab.jandi-v2+json"}, https_only=True, min_interval_sec=1.0, notice=notice_jandi),
)}

# 주소로 알 수 있는 '쓰면 안 되는' 웹훅 — 화면에서 경고 (저장은 막지 않는다: 사내 프록시 등 예외가 있을 수 있다)
URL_WARNINGS = [
    ("webhook.office.com", "Office 365 커넥터 웹훅은 2026년 5월에 종료되었습니다. Teams 에서 워크플로 웹훅을 새로 만들어 주소를 넣으세요."),
    ("outlook.office.com", "Office 365 커넥터 웹훅은 2026년 5월에 종료되었습니다. Teams 에서 워크플로 웹훅을 새로 만들어 주소를 넣으세요."),
    ("logic.azure.com", "옛 워크플로 주소(logic.azure.com)는 2025년 11월 30일부터 동작하지 않습니다. 워크플로 트리거에서 새 주소를 복사하세요."),
    ("hooks.slack.com/triggers/", "Slack 워크플로 빌더 주소는 지원하지 않습니다. 'Incoming Webhooks' 앱의 주소(hooks.slack.com/services/…)를 쓰세요."),
]
