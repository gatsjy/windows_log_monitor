"""접속기록 점검 결과서 (BACKLOG B-72 3단계, ISMS 2.9.5, ADR-060).

점검 보고서(ADR-032)는 숫자를 모아 보내고 '확인' 한 번만 남는다. 접속기록 점검은 항목마다 적정·부적정·해당 없음과 조치를 남기고
점검자 서명 → 책임자 승인을 받아야 증적이 된다(권한 검토와 같은 방식, ADR-058).

- 시작하면 기간(기본: 지난달, 표시 시간대)의 항목별 근거를 모아 스냅샷으로 둔다(inspections.items) — 나중에 숫자가 바뀌어도 그때 무엇을
  보고 판단했는지가 남는다. 근거는 다른 화면·보고서가 쓰는 원천 그대로(보관기간 경고·위·변조 상태·내려받기 사유·감사로그).
- 결과·서명·승인·반려는 inspection_entries 에 한 줄씩(고칠 수 없음, 마이그레이션 036). 상태는 줄을 차례로 읽어 정한다(state).
- 주기는 내부 관리계획의 값(WLM_ACCESS_LOG_INSPECTION_DAYS, 기본 31 = 월 1회) — 마지막 승인한 점검의 기간 끝에서 한 주기가 지나
  다음 회차를 점검할 수 있게 된 뒤 여유(grace_days)까지 지나면 '계획 대비 빠진 회차'로 운영 준비도·점검 보고서가 알린다.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from . import backups, db, integrity, partitions, repository
from .config import display_zone, settings
from .csvexport import weak_reason

RESULTS = {"ok": "적정", "issue": "부적정", "na": "해당 없음"}
STATUS_LABELS = {"open": "진행 중", "signed": "서명 — 승인 대기", "approved": "승인됨"}
WORK_HOURS = (8, 19)          # 업무시간 (표시 시간대 08~19시, 평일) — 밖의 로그인은 '업무시간 외'
MASS_VIEWS = 300              # 기간에 개인정보 조회 접속기록이 이만큼 넘는 사람은 '대량 조회' 후보
MIN_PERIOD = timedelta(days=1)   # 이보다 짧은 기간은 한 회차로 치지 않는다 (한 시간짜리 점검을 승인해 주기 경고를 끄지 못하게)
_START_LOCK = 727_006            # 같은 기간의 점검을 두 사람이 동시에 시작해도 하나만

# (key, 항목, 근거 조항) — 화면·CSV·결과서가 같은 순서로
CHECKLIST = (
    ("retention", "접속기록 보관기간", "안전성 확보조치 기준 제8조①, ISMS 2.9.4"),
    ("integrity", "접속기록 위·변조 방지 (해시 체인·수집 로그 다이제스트·백업)", "제8조②, ISMS 2.9.4"),
    ("downloads", "개인정보 내려받기와 사유", "제8조②, ISMS 2.9.4"),
    ("off_hours", "업무시간 외 접속", "제8조②"),
    ("auth_failures", "인증 실패·계정 잠금", "ISMS 2.5.4"),
    ("privilege", "권한 부여·변경·말소 내역", "제5조, ISMS 2.5.6"),
    ("mass_access", "개인정보 대량·반복 조회", "제8조②"),
    ("accounts", "접속한 계정 (외부 업체·서비스 계정 포함)", "ISMS 2.5.5"),
)
ITEM_KEYS = tuple(k for k, _, _ in CHECKLIST)


class InspectionError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.message, self.status = message, status


def grace_days(days: int) -> int:
    """한 회차가 끝난 뒤 점검·서명·승인에 주는 여유 — 월 1회면 14일, 주 1회면 3일."""
    return min(14, max(1, days // 2))


def month_title(start: datetime) -> str:
    """기본 제목 — 표시 시간대의 달 (브라우저 시간대로 정하면 서쪽 PC 에서 지난지난달 이름이 영구 기록에 남는다)."""
    local = start.astimezone(display_zone())
    return f"{local.year}년 {local.month}월 접속기록 점검"


def last_month(now: datetime) -> tuple[datetime, datetime]:
    """지난달 (표시 시간대의 1일 0시 ~ 이번 달 1일 0시)."""
    zone = display_zone()
    local = now.astimezone(zone)
    end = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start = (end - timedelta(days=1)).replace(day=1)
    return start.astimezone(UTC), end.astimezone(UTC)


# 위·변조 방지 항목: 기간 안의 기록 중 문제인 것 (동작 → 문구). 지금 상태(integrity.status)만 보면 기간 안에 있었다가 풀린
# 검증 실패·보관 때 다이제스트 불일치(30일 뒤 상태에서 빠짐)가 가려져 '정상'으로 남는다 — 검토에서 재현
_PERIOD_PROBLEMS = {
    "integrity.verify": "감사로그·수집 로그 위·변조 검증 실패",
    "integrity.events_mismatch": "보관 파일로 옮긴 로그가 다이제스트와 다름",
    "integrity.anchor_failed": "감사로그 체인 앵커 실패",
    "retention.purge_audit_refused": "감사로그 만료 삭제 멈춤 (체인과 맞지 않음)",
    "retention.archive_failed": "보관 파일 만들기 실패",
    "backup.failed": "백업 실패",
    "backup.verify": "복구 시험 실패",
    "backup.replicate": "외부 저장소 복제 실패",
    "backup.restore": "DB 를 백업으로 복원함 (그 사이 감사로그는 백업 시점으로 돌아감)",
}
_OK_WHEN = {"integrity.verify", "backup.verify", "backup.replicate"}   # detail.ok 가 참이면 문제가 아니다
_RUNS = (("integrity.verify", "위·변조 검증", integrity.STALE_AFTER), ("integrity.anchor", "체인 앵커", integrity.STALE_AFTER),
         ("backup.create", "백업", backups.BACKUP_STALE))


def _integrity_period(rows: list[dict[str, Any]], start: datetime, end: datetime) -> dict[str, Any]:
    """기간의 위·변조 검증·앵커·백업 기록 → 횟수·문제(실패·빈 구간). DB 없이 — 시험이 표로 본다."""
    problems: list[dict[str, str]] = []
    for r in rows:
        if r["action"] in _PERIOD_PROBLEMS and not (r["action"] in _OK_WHEN and (r["detail"] or {}).get("ok") is True):
            first = ((r["detail"] or {}).get("problems") or [(r["detail"] or {}).get("error") or (r["detail"] or {}).get("reason") or ""])[0]
            text = _PERIOD_PROBLEMS[r["action"]] + (f" ({r['target']})" if r["target"] and r["action"] != "integrity.verify" else "")
            problems.append({"at": r["at"].isoformat(), "action": r["action"], "text": text + (f": {str(first)[:160]}" if first else "")})
    runs = {}
    for action, label, stale in _RUNS:
        times = [r["at"] for r in rows if r["action"] == action and not (action == "integrity.verify" and (r["detail"] or {}).get("ok") is not True)]
        runs[action] = len(times)
        if not times:
            problems.append({"at": start.isoformat(), "action": action, "text": f"기간에 {label} 기록이 없습니다"})
            continue
        # 빈 구간: 기록 사이와 마지막 기록 → 기간 끝. 기간 시작 → 첫 기록은 보지 않는다(기간 중에 설치한 경우)
        for a, b in zip(times, [*times[1:], end], strict=True):
            if b - a > stale:
                problems.append({"at": a.isoformat(), "action": action,
                                 "text": f"{label} 기록이 {int((b - a).total_seconds() // 3600)}시간 비었습니다 ({a.astimezone(display_zone()):%m-%d %H:%M} 뒤)"})
                break
    return {"runs": runs, "problems": problems}


async def evidence(start: datetime, end: datetime, now: datetime) -> list[dict[str, Any]]:
    """항목마다 근거 숫자와 한 줄 요약 — 점검자가 보고 판단한다(판단은 사람이). 시작할 때 한 번 모아 스냅샷으로."""
    warnings = partitions.retention_warnings()
    chain = await integrity.status(now)
    backup = await backups.backup_status(now)
    period = _integrity_period(await repository.integrity_records(start, end, [*_PERIOD_PROBLEMS, *(a for a, _, _ in _RUNS)]),
                               start, end)
    current = [n["text"] for n in chain["notices"]] + backup["problems"]
    runs = period["runs"]
    exports = await repository.audit_exports(start, end)
    weak = [e for e in exports if weak_reason(e["reason"])]
    stats = await repository.inspection_access_stats(start, end, display_zone().key, *WORK_HOURS)
    counts = await repository.audit_action_counts(start, end)
    privilege = {a: n for a, n in counts.items() if a.startswith(("user.", "user_group.", "auth.mfa.reset", "auth.mfa.disable",
                                                                    "access_review."))}
    off = [r for r in stats["logins"] if r["off_hours"]]
    mass = [r for r in stats["views"] if r["n"] >= MASS_VIEWS]
    raw = {
        "retention": ({"log_days": settings.retention_days, "db_days": settings.db_retention_days,
                       "audit_days": settings.audit_retention_days, "warnings": warnings},
                      " · ".join(warnings) or f"로그 {settings.retention_days}일(DB {settings.db_retention_days}일)·감사로그 "
                                               f"{settings.audit_retention_days}일 보관 — 법정 최소 이상"),
        "integrity": ({"runs": runs, "problems": period["problems"][:30], "problem_count": len(period["problems"]),
                       "notices": chain["notices"], "backup_problems": backup["problems"]},
                      (f"기간 중 문제 {len(period['problems'])}건 — " + " · ".join(p["text"] for p in period["problems"][:3])
                       if period["problems"] else
                       f"기간 중 위·변조 검증 {runs['integrity.verify']}회·체인 앵커 {runs['integrity.anchor']}회·백업 "
                       f"{runs['backup.create']}회 — 실패·빈 구간 없음")
                      + (" / 지금: " + " · ".join(current) if current else "")),
        "downloads": ({"total": len(exports), "weak": [{"at": e["at"].isoformat(), "actor": e["actor"], "action": e["action"],
                                                        "reason": e["reason"] or "", "rows": e["rows"]} for e in weak[:30]]},
                      f"내려받기 {len(exports)}건" + (f", 사유가 짧은 것 {len(weak)}건 — 확인 필요" if weak else ", 모두 사유 있음")),
        "off_hours": ({"logins": [{"actor": r["actor"], "n": r["n"], "off_hours": r["off_hours"]} for r in off[:30]],
                       "work_hours": list(WORK_HOURS)},
                      (f"업무시간({WORK_HOURS[0]}~{WORK_HOURS[1]}시, 평일) 밖 로그인 {sum(r['off_hours'] for r in off)}건 — "
                       + ", ".join(f"{r['actor']} {r['off_hours']}건" for r in off[:5])) if off else "업무시간 밖 로그인 없음"),
        "auth_failures": ({"failed": stats["failed"], "locked": stats["locked"], "failed_ips": stats["failed_ips"]},
                          f"로그인 실패 {stats['failed']}건(보낸 곳 {stats['failed_ips']}곳)·계정 잠금 {stats['locked']}건"),
        "privilege": ({"actions": privilege},
                      f"권한·계정 관리 작업 {sum(privilege.values())}건" + (" — " + ", ".join(f"{a} {n}" for a, n in
                                                                                sorted(privilege.items())[:6]) if privilege else "")),
        "mass_access": ({"views": [{"actor": r["actor"], "n": r["n"]} for r in stats["views"]], "threshold": MASS_VIEWS},
                        (f"개인정보 조회 {MASS_VIEWS}회 넘은 사람: " + ", ".join(f"{r['actor']} {r['n']}회" for r in mass))
                        if mass else f"개인정보 조회가 {MASS_VIEWS}회를 넘은 사람 없음"),
        "accounts": ({"logins": [{"actor": r["actor"], "n": r["n"], "first_at": r["first_at"].isoformat(),
                                  "last_at": r["last_at"].isoformat()} for r in stats["logins"]]},
                     f"로그인한 계정 {len(stats['logins'])}개 — " + (", ".join(r["actor"] for r in stats["logins"][:10]) or "없음")
                     + " (외부 업체·서비스 계정이 정해진 시간·목적대로 썼는지 확인)"),
    }
    return [{"key": k, "label": label, "basis": basis, "evidence": raw[k][0], "summary": raw[k][1]} for k, label, basis in CHECKLIST]


def state(inspection: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    """줄을 차례로 읽어 지금 상태 (DB 없이 — 시험이 표로 본다). 반려하면 다시 진행 중."""
    status, results = "open", {}
    signed = approved = rejected = None
    for e in entries:
        if e["kind"] == "result":
            results[e["item"]] = {"result": e["result"], "note": e["note"], "author": e["author"], "at": e["at"]}
        elif e["kind"] == "sign":
            status, signed = "signed", e
        elif e["kind"] == "reject":
            status, rejected, signed = "open", e, None
        elif e["kind"] == "approve":
            status, approved = "approved", e
    keys = [i["key"] for i in inspection["items"]]
    return {"status": status, "results": results, "signed": signed, "approved": approved, "rejected": rejected,
            "missing": [k for k in keys if k not in results],
            "issues": [k for k in keys if (results.get(k) or {}).get("result") == "issue"]}


async def start(title: str, start_at: datetime, end_at: datetime, actor: str, now: datetime) -> int:
    # 근거는 지금까지의 기록으로 모은다 — 끝이 미래면 그 뒤는 비어 있는 채 '한 회차'가 된다 (몇 분 차이는 시계 차이로 봐준다)
    if not (start_at + MIN_PERIOD <= end_at <= now + timedelta(minutes=5)):
        raise InspectionError("점검 기간이 올바르지 않습니다 (하루 이상, 끝은 지금까지)", 422)
    items = await evidence(start_at, end_at, now)
    async with db.pool().connection() as conn, conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(%s)", (_START_LOCK,))
        cur = await conn.execute(
            "SELECT i.id FROM inspections i WHERE i.kind = 'access_log' AND i.period_start = %s AND i.period_end = %s"
            " AND NOT EXISTS (SELECT 1 FROM inspection_entries e WHERE e.inspection_id = i.id AND e.kind = 'approve') LIMIT 1",
            (start_at, end_at))
        if dup := await cur.fetchone():
            # 점검 행은 지울 수 없다 — 겹쳐 시작한 것은 영영 '진행 중'으로 남는다
            raise InspectionError(f"같은 기간의 점검이 진행 중입니다 (#{dup['id']}) — 그 점검을 이어서 하세요")
        cur = await conn.execute(
            "INSERT INTO inspections (kind, title, period_start, period_end, started_by, items) VALUES ('access_log', %s, %s, %s, %s, %s::jsonb)"
            " RETURNING id", (title, start_at, end_at, actor, json.dumps(items, ensure_ascii=False, default=str)))
        return (await cur.fetchone())["id"]


async def _load(conn: Any, inspection_id: int, lock: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cur = await conn.execute("SELECT id, kind, title, period_start, period_end, started_by, started_at, items FROM inspections"
                             " WHERE id = %s" + (" FOR UPDATE" if lock else ""), (inspection_id,))
    inspection = await cur.fetchone()
    if inspection is None:
        raise InspectionError("점검이 없습니다", 404)
    cur = await conn.execute("SELECT id, kind, item, result, note, author, at FROM inspection_entries WHERE inspection_id = %s"
                             " ORDER BY id", (inspection_id,))
    return inspection, await cur.fetchall()


async def get(inspection_id: int) -> dict[str, Any]:
    async with db.pool().connection() as conn:
        inspection, entries = await _load(conn, inspection_id, lock=False)
    st = state(inspection, entries)
    for item in inspection["items"]:
        item["result"] = st["results"].get(item["key"])
    return {**inspection, "entries": entries, **{k: v for k, v in st.items() if k != "results"}}


async def add(inspection_id: int, kind: str, actor: str, *, item: str | None = None, result: str | None = None,
              note: str = "") -> dict[str, Any]:
    """결과·서명·승인·반려 한 줄 — 점검 행을 잠근 채 상태를 다시 읽어 판단(두 사람이 같이 눌러도 한쪽만)."""
    note = note.strip()[:2000]
    async with db.pool().connection() as conn, conn.transaction():
        inspection, entries = await _load(conn, inspection_id, lock=True)
        st = state(inspection, entries)
        if kind == "result":
            if st["status"] != "open":
                raise InspectionError("서명한 점검은 결과를 바꿀 수 없습니다 — 책임자가 반려하면 다시 바꿀 수 있습니다")
            if item not in {i["key"] for i in inspection["items"]}:
                raise InspectionError("이 점검에 없는 항목입니다", 422)
            if result not in RESULTS:
                raise InspectionError(f"결과는 {', '.join(RESULTS)} 중 하나", 422)
            if result == "issue" and len(note) < 2:
                raise InspectionError("부적정은 조치 내용을 적으세요", 422)
        elif kind == "sign":
            if st["status"] != "open":
                raise InspectionError("이미 서명했거나 승인한 점검입니다")
            if st["missing"]:
                raise InspectionError(f"결과를 정하지 않은 항목 {len(st['missing'])}개", 422)
        elif kind in ("approve", "reject"):
            if st["status"] != "signed":
                raise InspectionError("서명한(승인 대기) 점검만 승인·반려합니다")
            if st["signed"]["author"] == actor:
                raise InspectionError("서명한 사람이 아닌 다른 사람이 승인·반려합니다 (2단계 결재)", 403)
            if kind == "reject" and len(note) < 2:
                raise InspectionError("반려 사유를 적으세요", 422)
        else:
            raise InspectionError("알 수 없는 동작", 422)
        cur = await conn.execute(
            "INSERT INTO inspection_entries (inspection_id, kind, item, result, note, author) VALUES (%s, %s, %s, %s, %s, %s)"
            " RETURNING id, kind, item, result, note, author, at",
            (inspection_id, kind, item if kind == "result" else None, result if kind == "result" else None, note, actor))
        return {"entry": await cur.fetchone(), "title": inspection["title"]}


async def list_inspections() -> list[dict[str, Any]]:
    rows = await db.fetch_all("SELECT id, kind, title, period_start, period_end, started_by, started_at, items FROM inspections"
                              " ORDER BY period_end DESC, id DESC LIMIT 100")
    entries = await db.fetch_all("SELECT inspection_id, id, kind, item, result, note, author, at FROM inspection_entries"
                                 " WHERE inspection_id = ANY(%s) ORDER BY id", ([r["id"] for r in rows],))
    by: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        by.setdefault(e["inspection_id"], []).append(e)
    out = []
    for r in rows:
        st = state(r, by.get(r["id"], []))
        out.append({"id": r["id"], "title": r["title"], "period_start": r["period_start"], "period_end": r["period_end"],
                    "started_by": r["started_by"], "started_at": r["started_at"], "status": st["status"],
                    "items": len(r["items"]), "done": len(r["items"]) - len(st["missing"]), "issues": len(st["issues"]),
                    "signed_by": st["signed"] and st["signed"]["author"], "approved_by": st["approved"] and st["approved"]["author"],
                    "approved_at": st["approved"] and st["approved"]["at"]})
    return out


def judge(items: list[dict[str, Any]], now: datetime, days: int) -> dict[str, Any]:
    """list_inspections 의 결과로 판단 (DB 없이 — 시험이 날짜 표로 본다).

    기한 = 마지막 승인한 점검의 기간 끝 + 한 주기(다음 회차가 끝나 점검할 수 있게 되는 때) + 여유. 기간 끝에서 한 주기만 재면
    지난달 점검은 그달이 끝난 뒤 1~4일 안에 승인까지 마쳐야 했다(검토에서 재현)."""
    approved = [i for i in items if i["status"] == "approved"]
    last = max(approved, key=lambda i: i["period_end"], default=None)
    age = (now - last["period_end"]).days if last else None
    due = last["period_end"] + timedelta(days=days + grace_days(days)) if last and days else None
    # 이미 승인한 기간까지 덮인 진행 중 점검(겹쳐 시작했거나 버려진 것)은 빼고 보여 준다 — 지울 수 없으므로
    covered = last["period_end"] if last else None
    return {"days": days, "grace_days": grace_days(days) if days else 0, "last_title": last and last["title"],
            "last_period_end": last and last["period_end"].isoformat(), "age_days": age, "due": due and due.isoformat(),
            "overdue": bool(days) and (last is None or now > due),
            "in_progress": [i["title"] for i in items if i["status"] != "approved"
                            and (covered is None or i["period_end"] > covered)][:3]}


async def overview(now: datetime, days: int) -> dict[str, Any]:
    """운영 준비도·점검 보고서용: 마지막 승인한 점검의 기간 끝, 지난 날수, 계획 대비 빠짐(기한 넘김), 진행 중."""
    return judge(await list_inspections(), now, days)


def attention(o: dict[str, Any] | None) -> list[dict[str, str]]:
    """점검 필요 문구 — 점검 보고서·운영 준비도 공용."""
    if not o or not o["overdue"]:
        return []
    when = (f"마지막 승인한 점검의 기간 끝이 {o['age_days']}일 전('{o['last_title']}')" if o["age_days"] is not None
            else "승인한 접속기록 점검이 없습니다")
    grace = f" + 여유 {o['grace_days']}일" if o.get("grace_days") else ""   # 옛 보고서에는 없다
    return [{"level": "warn", "text": f"접속기록 점검 주기({o['days']}일{grace})를 넘겼습니다 — {when}. 점검 보고서 > 접속기록 점검"}]
