"""보고서 그리기: 메일·화면·인쇄 공용 HTML 하나, 평문, 메신저 공지.

HTML 은 메일 클라이언트에서도 보이게 표·인라인 스타일만 쓰고, 밝은 바탕(인쇄·PDF 보관용)으로 그린다.
PC 이름·사용자·규칙 이름 등 로그에서 온 값이 들어가므로 모든 값을 html.escape 한다 — 화면은 이 HTML 을
같은 출처 iframe(sandbox)으로 보여 주므로 이스케이프가 빠지면 스크립트가 돌 수 있다(응답에 CSP 도 건다).
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

from ..alerts.message import SEVERITY_COLORS, SEVERITY_LABELS, Notice, local
from ..config import settings
from .builder import integrity_bad_count

INK, MUTED, LINE, WASH = "#0b0b0b", "#52514e", "#e4e4e1", "#f5f5f3"
BAD, WARN, GOOD = SEVERITY_COLORS["critical"], SEVERITY_COLORS["warning"], "#2f8f3a"
LEVEL_LABELS = {"critical": "심각", "error": "오류", "warning": "경고", "info": "정보", "verbose": "상세"}
STATUS_LABELS = {"open": "처리 안 됨", "acked": "확인함", "resolved": "해결됨"}


def report_link(report_id: int) -> str:
    return f"{settings.public_url}/#/reports/{report_id}"


def _t(iso: str | None) -> str:
    return local(datetime.fromisoformat(iso)) if iso else "-"


def _n(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else ("-" if value is None else str(value))


def _change(ev: dict[str, Any]) -> str:
    """비교 기간 대비 증감. 예전 보고서(비교 이름 없음)는 '직전 기간'."""
    current, previous = ev["total"], ev["previous"]
    if not previous:
        return ""
    pct = round((current - previous) / previous * 100)
    return f"{ev.get('previous_label', '직전 기간')} 대비 {'+' if pct >= 0 else ''}{pct}%"


def summary(payload: dict[str, Any]) -> dict[str, Any]:
    """목록·메신저·메일 제목에 쓰는 한 줄 요약."""
    attention = payload["attention"]
    bad = sum(1 for a in attention if a["level"] == "bad")
    return {"attention": len(attention), "bad": bad,
            "severity": "error" if bad else "warning" if attention else "info",
            "headline": f"점검 필요 {len(attention)}건" if attention else "특이 사항 없음"}


# --------------------------------------------------------------------- HTML 조각

def _section(title: str, body: str) -> str:
    return (f"<h2 style='font-size:15px;margin:26px 0 8px;padding-bottom:6px;border-bottom:1px solid {LINE}'>"
            f"{escape(title)}</h2>{body}")


def _table(head: list[str], rows: list[list[str]], right: tuple[int, ...] = ()) -> str:
    """rows 의 값은 이미 이스케이프된 HTML 조각이어야 한다 (_e 로 만든다)."""
    if not rows:
        return f"<p style='color:{MUTED};margin:6px 0'>없음</p>"
    th = "".join(f"<th style='text-align:{'right' if i in right else 'left'};padding:5px 8px;color:{MUTED};"
                 f"font-weight:600;font-size:12px;border-bottom:1px solid {LINE}'>{escape(h)}</th>" for i, h in enumerate(head))
    trs = "".join("<tr>" + "".join(
        f"<td style='padding:5px 8px;border-bottom:1px solid {LINE};text-align:{'right' if i in right else 'left'};"
        f"vertical-align:top'>{cell}</td>" for i, cell in enumerate(row)) + "</tr>" for row in rows)
    return f"<table style='border-collapse:collapse;width:100%;font-size:13px'><tr>{th}</tr>{trs}</table>"


CONFIG_SOURCES = {"ui": "화면", "file": "서버 파일 직접 수정", "startup": "서버 시작 때 발견"}


def _config_changes(al: dict[str, Any]) -> str:
    """알림 설정 변경·넓은 무음 (ADR-043). 규칙 이름·사유는 사용자가 쓴 값이라 모두 이스케이프한다."""
    rows = [[_e(f"#{c['version']}"), _e(_t(c["at"])), _e(CONFIG_SOURCES.get(c["source"], c["source"])), _e(c["actor"]),
             ("<b>약해짐</b> " if c["weakened"] else "") + "<br>".join(_e(t) for t in c["changes"])
             + (_e(f" … 외 {c['n'] - len(c['changes']):,}건") if c["n"] > len(c["changes"]) else "")]
            for c in al["config_changes"]]
    more = al["config_changes_total"] - len(al["config_changes"])
    out = ("<div style='margin-top:12px'><b style='font-size:13px'>알림 설정 변경</b>"
           + _table(["판본", "적용", "방법", "누가", "변경"], rows)
           + (f"<p style='color:{MUTED};margin:4px 0'>그 전 {more:,}건은 감사로그에 있습니다</p>" if more > 0 else "")
           + "</div>")
    silences = [[_e(f"#{s['id']}"), _e(s["rule"] or "모든 규칙"), _e(s["group_key"] if s["group_key"] is not None else "모든 대상"),
                 _e(f"{_t(s['starts_at'])} ~ {_t(s['ends_at'])}"), _e(s["created_by"]), _e(s["reason"])]
                for s in al["wide_silences"]]
    return out + ("<div style='margin-top:12px'><b style='font-size:13px'>넓은 무음 (모든 규칙·대상이거나 24시간 넘음)</b>"
                  + _table(["무음", "규칙", "대상", "기간", "건 사람", "사유"], silences) + "</div>")


def _e(value: Any) -> str:
    return escape(_n(value) if isinstance(value, int) or value is None else str(value))


def _stats(items: list[tuple[str, str, str]]) -> str:
    """(라벨, 값, 보조) 칸 여러 개. 좁은 화면(휴대폰 메일)에서는 다음 줄로 흐르게 inline-block 으로 둔다."""
    cells = "".join(
        f"<div style='display:inline-block;vertical-align:top;min-width:96px;margin:0 6px 6px 0;padding:10px 12px;"
        f"background:{WASH};border-radius:6px'>"
        f"<div style='font-size:12px;color:{MUTED};white-space:nowrap'>{escape(label)}</div>"
        f"<div style='font-size:20px;font-weight:700'>{escape(value)}</div>"
        f"<div style='font-size:11.5px;color:{MUTED}'>{escape(sub)}</div></div>" for label, value, sub in items)
    return f"<div>{cells}</div>"


def _trend(trend: dict[str, Any]) -> str:
    """막대(전체=파랑, 그중 오류 이상=빨강). 메일에서도 보이게 표 칸 + 높이를 준 div."""
    total, errors, buckets = trend["total"], trend["errors"], trend["buckets"]
    if not buckets:
        return ""
    peak = max(total) or 1
    hourly = trend["step_sec"] < 86400
    cols, labels = [], []
    for i, (n, e) in enumerate(zip(total, errors, strict=False)):
        h = round(n / peak * 60)
        he = round(e / peak * 60)
        when = local(datetime.fromisoformat(buckets[i]))
        cols.append(f"<td title='{escape(when)} · {n:,}건 (오류 이상 {e:,})' style='vertical-align:bottom;padding:0 1px'>"
                    f"<div style='height:{max(h - he, 0)}px;background:{SEVERITY_COLORS['info']}'></div>"
                    f"<div style='height:{he}px;background:{BAD}'></div></td>")
        show = (i % 6 == 0) if hourly else True
        label = (when[11:13] + "시") if hourly else when[5:10]
        # 칸이 좁아(24칸) 글자가 줄바꿈되지 않게 — 옆 빈 칸으로 넘쳐 보이게 둔다
        labels.append(f"<td style='font-size:10.5px;color:{MUTED};text-align:left;padding:2px 1px 0;white-space:nowrap;"
                      f"overflow:visible'>{label if show else ''}</td>")
    return (f"<table style='border-collapse:collapse;width:100%;table-layout:fixed;margin:10px 0 4px'>"
            f"<tr style='height:64px'>{''.join(cols)}</tr><tr>{''.join(labels)}</tr></table>"
            f"<div style='font-size:11.5px;color:{MUTED}'><span style='color:{SEVERITY_COLORS['info']}'>■</span> 전체 "
            f"<span style='color:{BAD}'>■</span> 그중 오류 이상</div>")


def html(payload: dict[str, Any], report_id: int | None = None, review: dict[str, Any] | None = None,
         link: bool = True) -> str:
    """link: 메일에는 '앱에서 보기' 링크를 넣는다. 화면 iframe(sandbox, 스크립트 없음)에서는 누르면 그 틀 안에서
    앱을 열려다 막히므로 넣지 않는다."""
    p = payload
    s = summary(p)
    ev, sec, al, ag, rt, bk = p["events"], p["security"], p["alerts"], p["agents"], p["retention"], p["backup"]
    out: list[str] = []

    # 머리
    out.append(f"<div style='font-size:12px;color:{MUTED}'>Log Monitor · 정기 점검 보고서{f' #{report_id}' if report_id else ''}</div>"
               f"<h1 style='font-size:20px;margin:4px 0 2px'>{escape(p['title'])}</h1>"
               f"<div style='font-size:12.5px;color:{MUTED}'>기간 {_e(_t(p['period']['start']))} ~ {_e(_t(p['period']['end']))}"
               f" ({_e(p['period']['tz'])}) · 만든 시각 {_e(_t(p['generated_at']))}</div>")

    # 점검 필요
    if p["attention"]:
        items = "".join(f"<li style='margin:3px 0'><span style='color:{BAD if a['level'] == 'bad' else WARN}'>●</span> "
                        f"{escape(a['text'])}</li>" for a in p["attention"])
        out.append(f"<div style='margin:16px 0 0;padding:12px 14px;border-left:4px solid {BAD if s['bad'] else WARN};"
                   f"background:{WASH}'><b>{escape(s['headline'])}</b><ul style='margin:6px 0 0;padding-left:18px'>{items}</ul></div>")
    else:
        out.append(f"<div style='margin:16px 0 0;padding:12px 14px;border-left:4px solid {GOOD};background:{WASH}'>"
                   f"<b>특이 사항 없음</b> — 아래 항목에서 확인이 필요한 것을 찾지 못했습니다.</div>")

    # 로그 현황
    lv = ev["by_level"]
    body = _stats([("전체 로그", _n(ev["total"]), _change(ev)),
                   ("심각", _n(lv.get("critical", 0)), ""), ("오류", _n(lv.get("error", 0)), ""),
                   ("경고", _n(lv.get("warning", 0)), ""), ("정보", _n(lv.get("info", 0)), "")])
    body += _trend(ev["trend"])
    body += "<div style='display:block;margin-top:12px'><b style='font-size:13px'>오류(오류 이상)가 많은 PC</b>" + _table(
        ["PC", "건수"], [[_e(r["value"]), _e(r["n"])] for r in ev["top_error_hosts"]], right=(1,)) + "</div>"
    body += "<div style='margin-top:12px'><b style='font-size:13px'>분류별</b>" + _table(
        ["분류", "건수"], [[_e(r["value"] or "(없음)"), _e(r["n"])] for r in ev["by_category"]], right=(1,)) + "</div>"
    out.append(_section("로그 현황", body))

    # 보안 이벤트
    rows = [[(f"<span style='color:{BAD if i['attention'] == 'bad' else WARN}'>●</span> " if i["attention"] else "")
             + _e(i["label"]), _e(", ".join(str(x) for x in i["event_ids"])), _e(i["n"])] for i in sec["items"]]
    body = _table(["항목", "이벤트 ID", "건수"], rows, right=(2,))
    if sec["logon_failed_users"] or sec["logon_failed_ips"]:
        body += ("<table style='width:100%;margin-top:10px'><tr><td style='vertical-align:top;width:50%;padding-right:8px'>"
                 "<b style='font-size:13px'>로그온 실패 — 계정</b>"
                 + _table(["계정", "건수"], [[_e(r["value"]), _e(r["n"])] for r in sec["logon_failed_users"]], right=(1,))
                 + "</td><td style='vertical-align:top;width:50%'><b style='font-size:13px'>로그온 실패 — 출발지 IP</b>"
                 + _table(["IP", "건수"], [[_e(r["value"]), _e(r["n"])] for r in sec["logon_failed_ips"]], right=(1,))
                 + "</td></tr></table>")
    out.append(_section("보안 이벤트", body))

    # 알림
    unresolved_total = sum(al["unresolved_by_severity"].values())
    body = _stats([("발생", _n(al["fired"]), " · ".join(f"{SEVERITY_LABELS.get(k, k)} {v:,}" for k, v in al["by_severity"].items())),
                   ("그중 해결됨", _n(al["by_status"].get("resolved", 0)), f"확인함 {al['by_status'].get('acked', 0):,}"),
                   ("지금 해결 안 됨", _n(unresolved_total), "보고서를 만든 시각 기준"),
                   ("해결까지 (중앙값)", f"{al['median_resolve_min']}분" if al["median_resolve_min"] is not None else "-",
                    f"기간 안에 해결 {al['resolved_in_period']:,}건")])
    body += "<div style='margin-top:12px'><b style='font-size:13px'>해결 안 된 알림 (심각한 것·오래된 것부터)</b>" + _table(
        ["번호", "발생", "심각도", "규칙", "대상", "상태"],
        [[_e(f"#{a['id']}"), _e(_t(a["fired_at"])), _e(SEVERITY_LABELS.get(a["severity"], a["severity"])), _e(a["rule"]),
          _e(a["group_key"] or "-"), _e(STATUS_LABELS.get(a["status"], a["status"]))] for a in al["unresolved_oldest"]]) + "</div>"
    if "config_changes" in al:   # ADR-043 이전 보고서에는 없다 (보고서는 고칠 수 없으므로 예전 형식도 그린다)
        body += _config_changes(al)
    out.append(_section("알림 처리", body))

    # 수집 PC
    body = _stats([("전체", _n(ag["total"]), "보고서를 만든 시각 기준"), ("온라인", _n(ag["online"]), ""),
                   ("지연", _n(ag["stale"]), ""), ("연락 끊김", _n(ag["offline"]), "")])
    body += "<div style='margin-top:12px'><b style='font-size:13px'>연락이 끊긴 PC (오래된 것부터)</b>" + _table(
        ["PC", "마지막 수신", "마지막 IP"], [[_e(a["host"]), _e(_t(a["last_seen"])), _e(a["last_ip"] or "-")] for a in ag["silent"]]) + "</div>"
    if ag.get("silent_streams"):   # B-37 이전 보고서에는 없다
        body += ("<div style='margin-top:12px'><b style='font-size:13px'>늘 오던 로그가 끊긴 채널 (PC 는 보내는 중)</b>" + _table(
            ["PC", "소스·채널", "마지막 수신", "평소 하루"],
            [[_e(s["host"]), _e(s["channel"] or s["source"]), _e(_t(s["last_at"])), _e(s["per_day"])] for s in ag["silent_streams"]],
            right=(3,)) + "</div>")
    if "ingest" in p:   # B-40 이전 보고서에는 없다
        ig = p["ingest"]
        body += (f"<div style='margin-top:12px'><b style='font-size:13px'>수집 거절·격리</b>"
                 f"<p style='color:{MUTED};margin:4px 0'>저장하지 못해 격리한 레코드 {_n(ig['quarantined'])}건</p>"
                 + _table(["거절", "요청", "보낸 곳"], [[_e(r["status"]), _e(r["n"]), _e(r["ips"])] for r in ig["rejected"]],
                          right=(1, 2)) + "</div>")
    out.append(_section("수집 PC", body))

    # 로그 보관·백업
    check = rt["last_integrity_check"]
    lb, lv2 = bk["last_backup"], bk["last_verify"]
    rows = [
        [_e("DB 보관"), _e(f"월 파티션 {rt['partitions']}개 · 약 {rt['rows_estimate']:,}건 · 최근 {rt['db_retention_days']}일")],
        [_e("보관 파일"), _e(f"{rt['archives']}개" + (f" (없는 파일 {rt['archives_missing']}개)" if rt["archives_missing"] else "")
                           + f" · 전체 보관 {rt['retention_days']}일")],
        [_e("마지막 무결성 확인"), _e(f"{_t(check['at'])} — 문제 {integrity_bad_count(check)}건" if check else "아직 없음")],
        [_e("마지막 백업"), _e(f"{_t(lb['at'])} · {lb['file']}" if lb else "없음")],
        [_e("마지막 복구 시험"), _e((f"{_t(lv2['at'])} — {'성공' if lv2.get('ok') else '실패'}") if lv2 else "없음")],
    ]
    body = _table(["항목", "상태"], rows)
    if bk["problems"]:
        body += "".join(f"<div style='color:{BAD};margin-top:6px'>● {escape(t)}</div>" for t in bk["problems"])
    out.append(_section("로그 보관 · 백업", body))

    # 끝: 링크·확인
    if report_id and link:
        out.append(f"<p style='margin:22px 0 0'><a href='{escape(report_link(report_id))}' style='color:#1c5cab'>"
                   f"Log Monitor 에서 보고서 보기 · 점검 확인 남기기 →</a></p>")
    if review and review.get("reviewed_at"):
        note = (f"<div style='margin-top:4px;white-space:pre-wrap'>{escape(review['review_note'])}</div>"
                if review.get("review_note") else "")
        out.append(f"<div style='margin-top:18px;padding:10px 12px;border:1px solid {LINE}'><b>점검 확인</b> "
                   f"{_e(review['reviewed_by'])} · {_e(local(review['reviewed_at']))}{note}</div>")
    out.append(f"<p style='font-size:11.5px;color:{MUTED};margin-top:18px'>이 보고서는 만든 뒤 고칠 수 없게 저장됩니다 (ISMS 2.9.5 점검 증적). — Log Monitor</p>")
    return ("<div style='font-family:system-ui,-apple-system,\"Malgun Gothic\",sans-serif;color:" + INK
            + ";max-width:860px;line-height:1.5;font-size:14px'>" + "".join(out) + "</div>")


def page(payload: dict[str, Any], report_id: int, review: dict[str, Any] | None = None) -> str:
    """화면 iframe·인쇄용 완전한 HTML 문서 (밝은 바탕)."""
    return ("<!doctype html><html lang='ko'><head><meta charset='utf-8'><title>" + escape(payload["title"]) + "</title>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'><link rel='icon' href='data:,'>"
            "<style>body{margin:0;padding:24px;background:#fff}@media print{body{padding:0}}</style></head><body>"
            + html(payload, report_id, review, link=False) + "</body></html>")


def text(payload: dict[str, Any], report_id: int | None = None) -> str:
    p = payload
    lines = [p["title"], f"기간 {_t(p['period']['start'])} ~ {_t(p['period']['end'])} ({p['period']['tz']})", ""]
    lines += [summary(p)["headline"]] + [f"- {a['text']}" for a in p["attention"]] + [""]
    ev, al, ag = p["events"], p["alerts"], p["agents"]
    lines.append(f"로그 {ev['total']:,}건 {_change(ev)}".rstrip())
    lines.append(f"알림 {al['fired']:,}건, 지금 해결 안 됨 {sum(al['unresolved_by_severity'].values()):,}건")
    lines.append(f"수집 PC {ag['online']:,}/{ag['total']:,} 온라인, 연락 끊김 {ag['offline']:,}대")
    lines.append("백업: " + ("정상" if not p["backup"]["problems"] else f"문제 {len(p['backup']['problems'])}건"))
    if report_id:
        lines += ["", f"보고서 보기·점검 확인: {report_link(report_id)}"]
    return "\n".join(lines)


def notice(payload: dict[str, Any], report_id: int) -> Notice:
    s = summary(payload)
    p = payload
    ev, al, ag = p["events"], p["alerts"], p["agents"]
    lines = [s["headline"]] + [f"· {a['text']}" for a in p["attention"][:5]]
    lines += [f"로그 {ev['total']:,}건 {_change(ev)}".rstrip(),
              f"알림 {al['fired']:,}건 · 지금 해결 안 됨 {sum(al['unresolved_by_severity'].values()):,}건",
              f"수집 PC {ag['online']:,}/{ag['total']:,} 온라인",
              "백업 " + ("정상" if not p["backup"]["problems"] else f"문제 {len(p['backup']['problems'])}건")]
    return Notice(title=f"{p['title']} — {s['headline']}", lines=lines, link=report_link(report_id),
                  severity=s["severity"], html=html(p, report_id), text=text(p, report_id))
