"""운영 준비도 점검표 (BACKLOG B-75): 아직 안 된 것을 한 화면에.

1~2명이고 보안 전문가가 아닌 팀은 무엇이 아직 안 됐는지 모른다 — 신호가 사용자·알림·환경설정·수집 PC·로그 보관 화면과 서버 로그에
흩어져 있다. 여기서는 새로 판단하지 않고 각 화면·점검 보고서가 쓰는 원천(health, backups, coverage, 시험 전송 기록, 보관기간 경고 …)을
모아 빨강·노랑·초록으로 보인다. AIRGAP.md §9 설치 확인 체크리스트를 화면으로 옮긴 효과도 있다.

collect() 가 사실을 모으고 judge() 가 판정한다(판정은 DB 없이 시험).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from . import db, partitions, repository, tlsutil
from .config import settings

TEST_LOOKBACK = timedelta(days=8)       # 받는 곳 시험 전송 — 매주 정기 시험(B-34) + 하루
CHANGE_LOOKBACK = timedelta(days=7)
CERT_WARN_DAYS, CERT_BAD_DAYS = 30, 7


@dataclass
class Item:
    key: str
    group: str
    label: str
    status: str            # ok | warn | bad | skip
    detail: str
    link: str = ""         # 고치는 화면 (#/…)
    doc: str = ""          # 문서 (AIRGAP.md 절 등)


def _names(names: list[str], limit: int = 5) -> str:
    shown = ", ".join(names[:limit])
    return shown + (f" 외 {len(names) - limit}" if len(names) > limit else "")


async def collect(now: datetime | None = None) -> dict[str, Any]:
    from .alerts import coverage, health
    from .alerts.engine import engine
    from .alerts.targets import load_notifiers, smtp_config
    from .alerts.watchdog import watchdog
    from .backups import backup_status
    from .reports import config as report_config

    now = now or datetime.now(UTC)
    users = await db.fetch_all("SELECT username, role, is_active, must_change_password, mfa_enabled_at FROM users")
    rules = engine.config.rules
    enabled = [r for r in rules if r.enabled]
    fallback = await watchdog.recipients()
    used = sorted({n for r in enabled for n in r.notify} | set(fallback))
    notifiers, errors = await load_notifiers()
    smtp, _ = await smtp_config()
    agents = await repository.agents(now - timedelta(days=7))
    tls = tlsutil.status(settings, now)
    return {
        "admins": [u for u in users if u["role"] == "admin" and u["is_active"]],
        "mfa_required": settings.mfa_required, "secret_key": bool(settings.secret_key),
        "health": await health.current(now, fresh=True),
        "enabled_rules": len(enabled),
        "unknown_targets": sorted({n for r in enabled for n in r.notify if n not in notifiers and n not in errors}),
        "broken_targets": {n: e for n, e in errors.items() if n in used},
        "used_targets": used, "fallback": fallback,
        "email_targets": sorted(n for n in used if getattr(notifiers.get(n), "type", "") == "email"),
        "smtp_host": smtp.host,
        "tests": await repository.latest_target_tests(used, now - TEST_LOOKBACK),
        "report_targets": (await report_config.load())["targets"],
        "tls": {"enabled": tls.enabled, "days_left": tls.days_left,
                "errors": [text for level, text in tls.problems if level == "error"]},
        "plain_pcs": sorted(a["host"] for a in agents if a.get("last_transport") in ("plain", "web")),
        "ingest_plain": settings.ingest_plain,
        "offline_pcs": sorted(a["host"] for a in agents if a["silent_sec"] > settings.heartbeat_stale_sec),
        "silent_streams": len(await repository.silent_streams(now)),
        "coverage_gaps": coverage.gaps(rules, await coverage.current(rules, now)),
        "retention_warnings": partitions.retention_warnings(),
        "backup": await backup_status(now),
        "replica": settings.replica,
        "weakened": [v for v in await repository.report_config_changes(now - CHANGE_LOOKBACK, now) if v["weakened"]],
    }


def judge(f: dict[str, Any]) -> list[Item]:
    items: list[Item] = []
    add = items.append

    # ------------------------------------------------------------ 계정
    admins = f["admins"]
    temp = [a["username"] for a in admins if a["must_change_password"]]
    add(Item("admin_password", "계정", "첫 관리자 비밀번호",
             "bad" if temp else "ok",
             f"임시 비밀번호를 아직 바꾸지 않은 관리자: {_names(temp)}" if temp else "임시 비밀번호를 쓰는 관리자가 없습니다",
             "#/users", "AIRGAP.md §7.3"))
    personal = [a["username"] for a in admins if a["username"] != "admin"]
    add(Item("personal_admins", "계정", "담당자별 관리자 계정",
             "ok" if personal else "warn",
             f"개인 관리자 계정 {len(personal)}개 ({_names(personal)}) — 공용 admin 은 비상용으로"
             if personal else "관리자가 공용 admin 하나뿐입니다 — 누가 했는지 감사로그로 가릴 수 있게 담당자별 계정을 만드세요",
             "#/users", "AIRGAP.md §7.3, ISMS 2.5.1"))
    if f["mfa_required"] != "off" and not f["secret_key"]:
        status, detail = "bad", "WLM_SECRET_KEY 가 없어 2단계 인증을 쓸 수 없습니다 (.env)"
    elif f["mfa_required"] == "off":
        status, detail = "warn", "2단계 인증이 필수가 아닙니다 (WLM_MFA_REQUIRED=off) — 관리자는 켜 두세요"
    else:
        missing = [a["username"] for a in admins if a["mfa_enabled_at"] is None]
        status = "warn" if missing else "ok"
        detail = (f"아직 등록하지 않은 관리자: {_names(missing)} (다음 로그인 때 등록 화면)" if missing
                  else f"관리자 {len(admins)}명 모두 등록 (필수: {f['mfa_required']})")
    add(Item("mfa", "계정", "2단계 인증", status, detail, "#/users", "ADR-049, ISMS 2.5.x"))

    # ------------------------------------------------------------ 알림
    h = f["health"]
    add(Item("alerting", "알림", "알림 기능 상태",
             {"down": "bad", "warn": "warn"}.get(h["status"], "ok"),
             "; ".join(p["text"] for p in h["problems"][:3]) or "평가·전송이 정상입니다", "#/alerts", "AIRGAP.md §9 7-1"))
    if not f["enabled_rules"] or not f["used_targets"]:
        add(Item("targets", "알림", "알림 받는 곳", "bad", "켜진 규칙이나 받는 곳이 없습니다 — 알림이 아무에게도 가지 않습니다",
                 "#/alerts/rules", "PROJECT.md §6"))
    else:
        problems = []
        if f["unknown_targets"]:
            problems.append(("bad", f"규칙이 쓰는데 없는 받는 곳: {_names(f['unknown_targets'])}"))
        for name, error in sorted(f["broken_targets"].items()):
            problems.append(("bad", f"'{name}' 을(를) 쓸 수 없음: {error[:120]}"))
        failed = sorted(n for n, t in f["tests"].items() if not t["ok"])
        never = sorted(n for n in f["used_targets"] if n not in f["tests"])
        if failed:
            problems.append(("bad", f"마지막 시험 전송이 실패한 곳: {_names(failed)}"))
        if never:
            problems.append(("warn", f"8일 안에 시험 전송한 적 없는 곳: {_names(never)} — 알림 > 알림 대상 > 테스트 발송"))
        status = "bad" if any(level == "bad" for level, _ in problems) else "warn" if problems else "ok"
        add(Item("targets", "알림", "알림 받는 곳 시험", status,
                 "; ".join(text for _, text in problems) or f"받는 곳 {len(f['used_targets'])}곳 모두 8일 안에 시험 전송 성공",
                 "#/alerts/targets", "AIRGAP.md §9 7, B-34"))
    if f["email_targets"]:
        add(Item("smtp", "알림", "메일 서버", "ok" if f["smtp_host"] else "bad",
                 f"메일 서버 {f['smtp_host']}" if f["smtp_host"]
                 else f"메일 서버가 없는데 수신 그룹({_names(f['email_targets'])})으로 알림을 보냅니다",
                 "#/settings/smtp", "AIRGAP.md §9 6"))
    add(Item("fallback", "알림", "알림 기능 문제를 받을 곳", "ok" if f["fallback"] else "warn",
             f"{_names(f['fallback'])} — 엔진 멈춤·전송 실패를 여기로" if f["fallback"]
             else "없습니다 — 메일이 멈춘 것을 메일로는 알 수 없으니 메신저 웹훅 하나를 settings.fallback_notify 나 점검 보고서 받는 곳에",
             "#/settings/reports", "ADR-045"))
    add(Item("report", "알림", "점검 보고서 받는 곳", "ok" if f["report_targets"] else "warn",
             _names(f["report_targets"]) if f["report_targets"] else "정한 곳이 없어 일간·주간 보고서가 아무에게도 가지 않습니다",
             "#/settings/reports", "ISMS 2.9.5"))

    # ------------------------------------------------------------ 수집
    t = f["tls"]
    if not t["enabled"]:
        status, detail = "warn", "화면·수집이 평문입니다 (WLM_TLS=off) — 사내망이라도 비밀번호·로그가 그대로 흐릅니다"
    elif t["errors"]:
        status, detail = "bad", "; ".join(t["errors"][:2])
    elif t["days_left"] is not None and t["days_left"] < CERT_BAD_DAYS:
        status, detail = "bad", f"서버 인증서가 {t['days_left']}일 뒤 만료됩니다 — tls-renew"
    elif t["days_left"] is not None and t["days_left"] < CERT_WARN_DAYS:
        status, detail = "warn", f"서버 인증서가 {t['days_left']}일 뒤 만료됩니다 — tls-renew"
    elif f["plain_pcs"] and f["ingest_plain"]:
        status, detail = "warn", (f"아직 평문으로 보내는 PC {len(f['plain_pcs'])}대: {_names(f['plain_pcs'])} — 새 설치 묶음으로 다시 설치한 뒤"
                                  " WLM_INGEST_PLAIN=off")
    else:
        status, detail = "ok", "화면·수집 모두 TLS" + (f" (인증서 D-{t['days_left']})" if t["days_left"] is not None else "")
    add(Item("tls", "수집", "전송 구간 암호화 (TLS)", status, detail, "#/agents", "AIRGAP.md §7.5, ISMS 2.7.1"))
    gaps = f["coverage_gaps"]
    add(Item("coverage", "수집", "규칙이 보는 데이터", "warn" if gaps else "ok",
             "; ".join(f"{g['channel']} 을(를) 보내지 않는 PC {g['total']}대 ({_names(g['hosts'], 3)})" for g in gaps[:3])
             or "켜진 규칙이 보는 채널을 모든 대상 PC 가 보냅니다", "#/alerts/rules", "ISMS.md '수집 측 권장 설정', B-37"))
    agent_problems = []
    if f["offline_pcs"]:
        agent_problems.append(f"연락이 끊긴 PC {len(f['offline_pcs'])}대 ({_names(f['offline_pcs'], 3)})")
    if f["silent_streams"]:
        agent_problems.append(f"늘 오던 로그가 끊긴 채널 {f['silent_streams']}개")
    add(Item("agents", "수집", "수집 PC", "warn" if agent_problems else "ok",
             "; ".join(agent_problems) or "최근 7일 수집 PC 가 모두 들어오고 있습니다", "#/agents", "AIRGAP.md §9 4"))

    # ------------------------------------------------------------ 보관
    add(Item("retention", "보관", "법정 보관기간", "bad" if f["retention_warnings"] else "ok",
             "; ".join(f["retention_warnings"]) or "로그·감사로그 보관기간이 법정 최소 이상입니다",
             "#/settings/retention", "ISMS.md 법령 근거, ADR-040"))
    b = f["backup"]
    backup_problems = [p for p in b["problems"] if "복제" not in p]
    add(Item("backup", "보관", "DB 백업·복구 시험", "bad" if backup_problems else "ok",
             "; ".join(backup_problems[:2]) or "백업과 복구 시험이 정상입니다", "#/settings/retention", "AIRGAP.md §11, ISMS 2.9.3"))
    replica_problems = [p for p in b["problems"] if "복제" in p]
    if not f["replica"]:
        status, detail = "warn", "백업·보관 파일이 이 서버 디스크에만 있습니다 — 서버 장애·랜섬웨어 때 같이 잃습니다 (WLM_REPLICA=on)"
    else:
        status, detail = ("bad", "; ".join(replica_problems[:2])) if replica_problems else ("ok", "외부 저장소 복제가 정상입니다")
    add(Item("replica", "보관", "외부 저장소 복제", status, detail, "#/settings/retention", "AIRGAP.md §11, ADR-047"))

    # ------------------------------------------------------------ 변경 감시
    weak = f["weakened"]
    add(Item("weakened", "변경 감시", "탐지를 약하게 한 변경 (7일)", "warn" if weak else "ok",
             f"판본 {len(weak)}개 — {_names([f'#{v['id']} {v['actor']}' for v in weak], 3)}. 의도한 변경인지 확인하세요"
             if weak else "최근 7일 동안 탐지를 약하게 한 설정 변경이 없습니다", "#/audit?action=alerts.config.", "ADR-043"))
    return items


async def checklist(now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    items = judge(await collect(now))
    summary = {s: sum(1 for i in items if i.status == s) for s in ("bad", "warn", "ok")}
    return {"checked_at": now, "summary": summary, "items": [asdict(i) for i in items]}
