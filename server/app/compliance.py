"""심사 대응 (BACKLOG B-73): 규칙 태그의 'ISMS x.y.z' 로 항목별 탐지·처리 현황과 기간 증적 묶음(zip).

- 항목 = 규칙 태그 'ISMS 2.11.3' (config/alerts.yaml). 알림은 발생 때의 태그(payload.tags)로 센다 — 나중에 태그를 고쳐도
  그때 무엇으로 알렸는지가 증적이다.
- 증적 묶음: 항목마다 폴더(규칙 정의·알림 처리 CSV), 맨 위에 요약 CSV·README, 그리고 모든 파일의 SHA-256 을 담은 MANIFEST.txt.
  MANIFEST 자체의 해시는 내려받기 감사로그(compliance.bundle)에 남는다 → 나중에 받은 묶음이 바뀌지 않았는지 대조한다(ADR-042 방식).
  CSV 는 csvexport 의 수식 주입 방지를 거친다(로그에서 온 PC·사용자 이름).
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from collections import defaultdict
from datetime import datetime
from typing import Any

from . import repository
from .alerts.message import RESOLUTION_LABELS, SEVERITY_LABELS, local
from .alerts.rules import Rule
from .csvexport import csv_bytes

ISMS_TAG = re.compile(r"^ISMS\s+(\d+\.\d+(?:\.\d+)?)$")
BUNDLE_ALERTS_MAX = 10000          # 항목마다 — 넘으면 README·요약에 '잘림'
STATUS_LABELS = {"open": "처리 안 됨", "acked": "확인함", "resolved": "해결됨"}


def item_of(tag: str) -> str | None:
    m = ISMS_TAG.match(tag.strip())
    return m.group(1) if m else None


def rules_by_item(rules: tuple[Rule, ...]) -> dict[str, list[Rule]]:
    out: dict[str, list[Rule]] = defaultdict(list)
    for rule in rules:
        for tag in rule.tags:
            if (item := item_of(tag)) is not None:
                out[item].append(rule)
    return dict(out)


def _sort_key(item: str) -> tuple[int, ...]:
    return tuple(int(p) for p in item.split("."))


async def summary(rules: tuple[Rule, ...], coverage: dict[str, dict[str, Any]], since: datetime, until: datetime) -> list[dict]:
    """항목마다: 규칙(켜짐·관찰·데이터 없음), 기간 안 알림 수·해결·미해결·해결 시간 중앙값·오탐."""
    by_item = rules_by_item(rules)
    stats = {r["item"]: r for r in await repository.isms_alert_stats(since, until)}
    out = []
    for item in sorted(set(by_item) | set(stats), key=_sort_key):
        rs = by_item.get(item, [])
        # 데이터 없음 = 그 소스·채널을 보내는 PC 가 없다(B-37 판단과 같음). 드문 이벤트(30일에 한 번도 안 난 것)는 데이터 없음이 아니다(검토)
        no_data = [r.name for r in rs if r.enabled and (c := coverage.get(r.name)) is not None
                   and (c["pcs"] == 0 or c.get("channel_pcs") == 0)]
        s = stats.get(item) or {}
        out.append({
            "item": item,
            "rules": [{"name": r.name, "sid": r.sid, "enabled": r.enabled, "mode": r.mode} for r in rs],
            "enabled": sum(1 for r in rs if r.enabled and r.mode == "active"),
            "no_data": no_data,
            "alerts": s.get("n", 0), "resolved": s.get("resolved", 0), "unresolved": s.get("n", 0) - s.get("resolved", 0),
            "median_resolve_sec": int(s["median"]) if s.get("median") is not None else None,
            "false_positive": s.get("fp", 0), "true_positive": s.get("tp", 0),
        })
    return out


def _days(delta) -> str:
    sec = int(delta.total_seconds())
    return f"{sec // 86400}일" if sec % 86400 == 0 else f"{sec}초"


def _rule_lines(rule: Rule, exceptions: list[dict[str, Any]] = (), since: datetime | None = None,
                until: datetime | None = None) -> str:
    """규칙 정의 — 심사에서 '무엇을 어떻게 탐지했나'를 보이는 글. 기준(건수·서로 다른 값·끊김)과 그 기간에 걸려 있던 예외까지(검토)."""
    match = ", ".join(f"{k}={v}" for k, v in rule.match.items()) or "(모든 이벤트)"
    observe = " (관찰 모드 — 보내지 않음)" if rule.mode == "observe" else ""
    lines = [f"규칙: {rule.name}", f"번호(sid): {rule.sid or '-'}", f"사용: {'예' if rule.enabled else '아니오'}{observe}",
             f"종류: {rule.kind}", f"심각도: {SEVERITY_LABELS.get(rule.severity, rule.severity)}", f"태그: {', '.join(rule.tags)}",
             f"받는 곳: {', '.join(rule.notify)}"]
    if rule.kind == "count":
        distinct = f" · 서로 다른 {rule.distinct_field} {rule.distinct_min}개 이상" if rule.distinct_field else ""
        lines += [f"조건: {match}",
                  f"기준: {int(rule.window.total_seconds())}초 동안 {rule.threshold}건 이상{distinct} · 묶음 {rule.group_by}"]
    elif rule.kind == "new_terms":   # 처음 보는 값 (B-47) — '끊김' 기준으로 적혀 심사 증적이 규칙을 틀리게 설명했다(검토에서 재현)
        lines += [f"조건: {match}",
                  (f"기준: {' + '.join(rule.terms_fields)} 값 조합이 최근 {_days(rule.history)} 동안 없던 것이면 조합마다 한 번"
                   f" · 처음 {_days(rule.learn)}은 배우기만 · 한 주기에 {rule.burst}개 넘으면 한 통 · 둘 조합 상한 {rule.max_terms:,}개")]
    elif rule.kind == "correlation":   # 상관 알림 (B-67 2단계)
        lines += [(f"기준: 같은 {'·'.join({'host': 'PC', 'account': '계정', 'ip': 'IP'}[e] for e in rule.entities)}에서 "
                   f"{int(rule.window.total_seconds())}초 안에 다른 규칙 알림들의 서로 다른 MITRE 전술 {rule.min_tactics}개 이상")]
    else:
        lines += [f"기준: {int(rule.silent_for.total_seconds())}초 동안 수신 없음" if rule.kind == "agent_silent"
                  else "기준: 늘 오던 채널이 평소보다 오래 끊김", f"대상 PC: {', '.join(rule.hosts) or '전체'}"]
        if rule.kind == "stream_silent":
            lines.append(f"채널: {', '.join(rule.channels) or '전체'}")
    if rule.description:
        lines.append(f"설명: {rule.description}")
    for x in exceptions:   # 그 기간에 한 번이라도 걸려 있던 예외 (B-46) — 빠진 탐지도 증적
        live_in_period = (until is None or x["created_at"] < until) and (since is None or (
            (x["ended_at"] is None or x["ended_at"] > since) and (x["expires_at"] is None or x["expires_at"] > since)))
        if x["rule"] == rule.name and live_in_period:
            lines.append(f"예외: {x['term']} — {x['reason']} ({x['created_by']}, {local(x['created_at'])}"
                         f"{' ~ ' + local(x['ended_at']) if x['ended_at'] else ''})")
    return "\n".join(lines)


async def bundle(rules: tuple[Rule, ...], coverage: dict[str, dict[str, Any]], since: datetime, until: datetime,
                 who: str, reason: str, now: datetime) -> tuple[bytes, str, dict[str, Any]]:
    """기간 증적 묶음 (zip 바이트, MANIFEST 의 SHA-256, 요약). 같은 입력이면 파일 내용이 같다(zip 안 시각은 생성 시각 하나)."""
    items = await summary(rules, coverage, since, until)
    files: list[tuple[str, bytes]] = []
    files.append(("요약.csv", csv_bytes(
        ["ISMS 항목", "규칙 수", "켜진 규칙(보냄)", "데이터 없는 규칙", "알림", "해결", "미해결", "해결 시간 중앙값(분)", "정탐", "오탐"],
        [[i["item"], len(i["rules"]), i["enabled"], "; ".join(i["no_data"]), i["alerts"], i["resolved"], i["unresolved"],
          round(i["median_resolve_sec"] / 60, 1) if i["median_resolve_sec"] is not None else "", i["true_positive"],
          i["false_positive"]] for i in items])))
    truncated = []
    total_rows = 0
    by_item = rules_by_item(rules)
    exceptions = await repository.list_rule_exceptions()
    for i in items:
        folder = f"ISMS_{i['item']}"
        if by_item.get(i["item"]):
            files.append((f"{folder}/규칙.txt", ("\n\n".join(_rule_lines(r, exceptions, since, until)
                                                            for r in by_item[i["item"]]) + "\n").encode()))
        rows = await repository.isms_alerts(i["item"], since, until, BUNDLE_ALERTS_MAX + 1)
        total_rows += min(len(rows), BUNDLE_ALERTS_MAX)
        if len(rows) > BUNDLE_ALERTS_MAX:
            truncated.append(i["item"])
            rows = rows[:BUNDLE_ALERTS_MAX]
        files.append((f"{folder}/알림.csv", csv_bytes(
            ["번호", "발생 시각", "심각도", "규칙", "대상", "건수", "처리 상태", "확인한 사람", "확인 시각", "해결한 사람", "해결 시각", "종료 분류",
             "PC(처음 보는 값)"],
            [[a["id"], local(a["fired_at"]), SEVERITY_LABELS.get(a["severity"], a["severity"]), a["rule"], a["group_key"],
              a["event_count"], STATUS_LABELS.get(a["status"], a["status"]), a["acked_by"] or "",
              local(a["acked_at"]) if a["acked_at"] else "", a["resolved_by"] or "",
              local(a["resolved_at"]) if a["resolved_at"] else "", RESOLUTION_LABELS.get(a["resolution"] or "", ""),
              a["terms_host"] or ""]
             for a in rows])))
    readme = "\n".join([
        "심사 대응 기간 증적 묶음 (Log Monitor, BACKLOG B-73)",
        f"기간: {local(since)} ~ {local(until)}",
        f"만든 사람: {who} · 만든 시각: {local(now)}",
        f"사유: {reason}",
        "",
        "구성: 요약.csv(항목별 현황) · ISMS_<항목>/규칙.txt(그 항목 태그가 달린 규칙 정의) · ISMS_<항목>/알림.csv(기간 안 알림과 처리 기록)",
        "알림은 발생 때의 규칙 태그로 묶었습니다. MANIFEST.txt 에 모든 파일의 SHA-256 이 있고, MANIFEST.txt 자체의 해시는",
        "이 시스템의 감사로그(compliance.bundle)에 남습니다 — 받은 묶음이 바뀌지 않았는지 대조하세요(sha256sum -c MANIFEST.txt).",
        *([f"잘림: 항목 {', '.join(truncated)} 은 알림 {BUNDLE_ALERTS_MAX:,}건까지만 담았습니다 — 기간을 나눠 다시 받으세요."] if truncated else []),
    ]) + "\n"
    files.insert(0, ("README.txt", readme.encode()))
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {path}\n" for path, data in files).encode()
    stamp = (now.year, now.month, now.day, now.hour, now.minute, now.second)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for path, data in [*files, ("MANIFEST.txt", manifest)]:
            info = zipfile.ZipInfo(path, date_time=stamp)
            info.flag_bits |= 0x800   # 파일 이름 UTF-8 (한글 폴더·파일 이름)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue(), hashlib.sha256(manifest).hexdigest(), {"items": len(items), "files": len(files) + 1,
                                                                  "rows": total_rows, "truncated": truncated}
