"""감사로그 위·변조 증명 (BACKLOG B-71, ADR-050): 해시 체인 검증과 DB 밖 앵커.

마이그레이션 022 의 트리거가 감사로그 행마다 앞 행의 해시를 넣은 SHA-256 을 남긴다. 여기서는 그것을 **파이썬으로 따로** 다시 계산해
맞춰 본다(같은 DB 함수로 다시 계산하면 함수를 바꾼 변조를 못 잡는다).
- 가운데 행을 고치거나 지우거나 끼워 넣으면: 그 행의 해시 또는 다음 행의 앞 해시가 어긋난다. 트리거를 끄고 넣은 행은 해시가 없다.
- 앞부분을 지우면: 남은 첫 행의 앞 해시가 체인 시작도, 믿을 만한 보관기간 만료 기록(retention.purge_audit)의 해시도 아니다.
- 끝을 지우거나 체인을 통째로 다시 쓰면: **DB 밖 앵커**가 잡는다 — 매일 보관 폴더의 integrity-YYYY-MM-DD.json(외부 저장소 복제로
  NAS·WORM 에 한 벌 더, B-17)과 점검 보고서(메일)에 마지막 번호·해시·시각을 남긴다. 보관기간 안의 앵커가 가리키는 행은 있어야 하고
  다시 계산한 해시가 같아야 한다.
DB 슈퍼유저는 이 서버의 앵커 파일까지 지울 수 있다 — 그때의 근거는 복제본·메일의 앵커다(`cli verify-chain --anchors <복제 폴더>`).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import db, eventdigest, repository
from .config import display_zone, settings

log = logging.getLogger(__name__)

BATCH = 5000
PROBLEMS_SHOWN = 20
VERIFY_EVERY = timedelta(hours=20)
STALE_AFTER = timedelta(hours=50)            # 매일 하는 검증·앵커가 이보다 오래 없으면 경고 (하루 + 여유)
FUTURE_SLACK = timedelta(minutes=5)          # 트리거가 시각을 정하므로 미래 행은 트리거를 끄고 넣은 것
BACKWARD_SLACK = timedelta(hours=1)          # 시계를 크게 되돌린 것이 아니면 시각은 번호 순서로 늘어난다
EXPIRY_SLACK = timedelta(days=1)
RESTORE_NOTICE = timedelta(days=30)          # 복원으로 대조하지 않은 앵커는 이 기간 동안 경고로 알린다 (가짜 복원 기록도 같은 모양이다)
MIN_MARK_RETENTION_DAYS = 365                # 이보다 짧은 보관기간을 적은 만료 기록으로는 앵커가 가리키는 행의 삭제를 설명하지 않는다
ANCHOR_PREFIX = "integrity-"
MARK_ACTION = "retention.purge_audit"
RESTORE_ACTION = "backup.restore"


def _field(value: Any) -> str:
    if value is None:
        return "N"
    text = str(value)
    return f"{len(text)}:{text}"


def canonical(prev: str | None, row_id: int, at_us: int, actor: str | None, ip: str | None, action: str | None,
              target: str | None, detail: str | None) -> str:
    """마이그레이션 022 의 audit_log_canonical 과 한 글자도 같아야 한다 (칸마다 NULL 은 'N', 아니면 '글자 수:값', | 로)."""
    return "|".join([_field(prev), str(row_id), str(at_us), _field(actor), _field(ip), _field(action), _field(target),
                     _field(detail)])


def row_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Chain:
    """번호 순서로 받은 행을 이어 맞춘다 — 검증(verify)과 만료 삭제 전 확인(repository.purge_audit)이 같이 쓴다.
    해시가 없는 행(트리거를 끄고 넣은 행)은 이어짐에서 빼고 그것만 알린다 — 앞뒤 행은 그대로 이어져 있다."""

    def __init__(self, now: datetime | None = None, backfill_max_id: int = 0) -> None:
        self.now = now or datetime.now(UTC)
        self.backfill_max_id = backfill_max_id
        self.problems: list[str] = []
        self.first: dict[str, Any] | None = None     # 처음 받은 행 (해시가 없어도)
        self.start: dict[str, Any] | None = None     # 처음 이어진 행 (체인의 시작을 맞춰 볼 행)
        self.last: dict[str, Any] | None = None      # 마지막으로 이어진 행
        self.rows = 0

    def problem(self, text: str) -> None:
        if len(self.problems) < PROBLEMS_SHOWN:
            self.problems.append(text)
        elif not self.problems[-1].startswith("그 밖에도"):
            self.problems[-1] = f"그 밖에도 문제가 있습니다 (앞의 {PROBLEMS_SHOWN - 1}개만 보임)"

    def feed(self, r: dict[str, Any]) -> bool:
        """행 하나 — 내용이 해시와 맞고 앞 행과 이어지면 True."""
        self.rows += 1
        self.first = self.first or r
        rid = r["id"]
        if r["row_hash"] is None:
            self.problem(f"#{rid} 해시가 없습니다 — 체인 트리거를 끈 채 넣은 행일 수 있습니다 ({r['action']})")
            return False
        ok = True
        if r["at_us"] is None:
            self.problem(f"#{rid} 시각이 올바르지 않습니다 — 고쳐진 행 ({r['action']})")
            ok = False
        elif row_hash(canonical(r["prev_hash"], rid, r["at_us"], r["actor"], r["actor_ip"], r["action"], r["target"],
                                r["detail"])) != r["row_hash"]:
            self.problem(f"#{rid} 내용이 해시와 다릅니다 — 고쳐진 행 ({r['action']})")
            ok = False
        if self.last is not None and r["prev_hash"] != self.last["row_hash"]:
            self.problem(f"#{rid} 앞 행(#{self.last['id']})과 이어지지 않습니다 — 그 사이 행이 지워지거나 끼워졌습니다")
            ok = False
        if r["at"] is not None:
            if r["at"] > self.now + FUTURE_SLACK:
                self.problem(f"#{rid} 시각이 미래입니다 ({r['at']:%Y-%m-%d %H:%M}) — 체인 트리거를 끄고 넣은 행")
                ok = False
            elif (rid > self.backfill_max_id and self.last is not None and self.last.get("at") is not None
                  and r["at"] < self.last["at"] - BACKWARD_SLACK):
                # 022 이후 행은 트리거가 시각을 정한다(잠금 순서) — 거꾸로 가면 트리거를 끄고 과거 시각으로 넣은 행
                self.problem(f"#{rid} 시각({r['at']:%Y-%m-%d %H:%M})이 앞 행보다 이릅니다 — 체인 트리거를 끄고 넣은 행이거나 서버 시계를 크게 되돌림")
                ok = False
        self.start = self.start or r
        self.last = r
        return ok


def anchor_dir() -> Path:
    return Path(settings.archive_dir)


def _parse_at(value: Any) -> datetime | None:
    try:
        at = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return at if at.tzinfo else None


def list_anchors(extra_dirs: Iterable[Path | str] = ()) -> list[dict[str, Any]]:
    """보관 폴더(와 덧붙인 폴더 — 외부 복제본)의 앵커. 덧붙인 폴더의 것은 이름 앞에 폴더를 붙여 구별한다."""
    out = []
    dirs = [(anchor_dir(), "")] + [(Path(d), f"{Path(d)}/") for d in extra_dirs]
    for folder, label in dirs:
        paths = sorted(folder.glob(f"{ANCHOR_PREFIX}*.json"))
        if label and not paths:
            # 덧붙인 폴더(복제본)는 대조하려고 일부러 준 것 — 경로를 틀리면 아무것도 대조하지 않고 '정상'이 나왔다
            out.append({"file": str(folder), "error": "폴더가 없거나 앵커(integrity-*.json)가 하나도 없습니다"})
        for path in paths:
            name = label + path.name
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                out.append({"file": name, "audit_last_id": int(data["audit_last_id"]),
                            "audit_last_hash": str(data["audit_last_hash"]), "at": _parse_at(data.get("at")),
                            "audit_last_at": _parse_at(data.get("audit_last_at"))})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                out.append({"file": name, "error": f"읽을 수 없음: {exc}"})
    return out


def _mark(r: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    """믿을 만한 보관기간 만료 기록: 시스템이 남겼고, 적은 보관기간·기준 시각이 그 행의 시각과 맞고, 보관기간이 너무 짧지 않다.
    아무나 넣은 '만료 기록' 하나로 앞부분 삭제가 통과했다(검토에서 재현) — 내용이 해시와 맞는 행만 여기에 온다."""
    try:
        d = json.loads(r["detail"] or "{}")
        days, upto, last_hash = int(d["retention_days"]), int(d["upto_id"]), d["last_hash"]
        cutoff = _parse_at(d["cutoff"])
    except (ValueError, KeyError, TypeError):
        return None
    if (r["actor"] != "system" or not last_hash or cutoff is None or r["at"] is None or r["at"] > now + FUTURE_SLACK
            or days < min(MIN_MARK_RETENTION_DAYS, settings.audit_retention_days)
            or abs(r["at"] - timedelta(days=days) - cutoff) > EXPIRY_SLACK):
        return None
    return {"id": r["id"], "upto_id": upto, "last_hash": last_hash, "cutoff": cutoff}


def _result(now: datetime, problems: list[str], **kw: Any) -> dict[str, Any]:
    base = {"ok": not problems, "checked_at": now, "rows": 0, "first_id": None, "last_id": None, "last_hash": None,
            "problems": problems, "anchors_checked": 0, "anchors_expired": 0, "superseded": [], "events_hours": 0}
    return base | kw


async def verify(now: datetime | None = None, anchor_dirs: Iterable[Path | str] = (),
                 events_window: timedelta | None = None) -> dict[str, Any]:
    """체인 전체를 한 시점에서 맞춰 본다 → {ok, rows, first_id, last_id, last_hash, problems, anchors_checked, anchors_expired, superseded,
    events_hours}. 끝에 수집 로그의 시간별 다이제스트(2단계)도 최근 events_window 만큼 다시 계산해 본다."""
    now = now or datetime.now(UTC)
    anchors = list_anchors(anchor_dirs)
    wanted = {a["audit_last_id"] for a in anchors if "error" not in a}
    seen: dict[int, str | None] = {}        # 앵커가 가리키는 번호 → 다시 계산해 맞은 해시 (고쳐진 행이면 None)
    marks: list[dict[str, Any]] = []
    restores: list[dict[str, Any]] = []
    async with repository.audit_snapshot() as snap:
        head = await snap.head()
        if head is None:
            return _result(now, ["체인 머리(audit_chain)가 없습니다 — 지워졌거나 마이그레이션 022 가 적용되지 않았습니다"])
        chain = Chain(now, head["backfill_max_id"])
        after = 0
        while batch := await snap.rows(after, BATCH):
            for r in batch:
                before = chain.last
                ok = chain.feed(r)
                if r["id"] in wanted:
                    seen[r["id"]] = r["row_hash"] if ok else None
                if ok and r["action"] == MARK_ACTION and (m := _mark(r, now)):
                    marks.append(m)
                elif ok and r["action"] == RESTORE_ACTION and r["actor"] == "system":
                    restores.append({"id": r["id"], "at": r["at"], "target": r["target"],
                                     "prev_at": before.get("at") if before else None})
            after = batch[-1]["id"]
    first, start, last = chain.first, chain.start, chain.last
    if last is None:
        # 만료 삭제는 같은 트랜잭션에 기록을 남기므로 정상이라면 이어진 행이 늘 하나는 있다 (처음 설치해 아직 아무 기록도 없을 때만 0)
        if head["last_id"] > 0:
            chain.problem(f"체인 머리는 #{head['last_id']} 인데 이어진 감사로그가 없습니다 — 지워졌습니다")
    else:
        # 같은 시점이라 마지막 행은 머리와 같아야 한다 — 다르면 끝이 지워졌거나 머리를 되돌려 그 뒤에 행을 끼웠다
        if (last["id"], last["row_hash"]) != (head["last_id"], head["last_hash"]):
            chain.problem(f"마지막 행(#{last['id']})이 체인 머리(#{head['last_id']})와 다릅니다 — 끝쪽 행이 지워졌거나 머리가 고쳐졌습니다")
        if start["prev_hash"] != head["start_hash"] and not any(
                m["last_hash"] == start["prev_hash"] and m["upto_id"] < start["id"] for m in marks):
            chain.problem(f"#{start['id']} 체인의 시작이 맞지 않습니다 — 앞쪽 행이 보관기간 만료가 아닌 방법으로 지워졌습니다")
    checked, expired, superseded = _check_anchors(anchors, seen, marks, restores, first, now, chain)
    event_problems, event_hours = await eventdigest.check_recent(now, events_window)
    for text in event_problems:
        chain.problem(text)
    return _result(now, chain.problems, rows=chain.rows, first_id=first["id"] if first else None, events_hours=event_hours,
                   last_id=last["id"] if last else None, last_hash=last["row_hash"] if last else None,
                   anchors_checked=checked, anchors_expired=expired, superseded=superseded)


def _check_anchors(anchors: list[dict[str, Any]], seen: dict[int, str | None], marks: list[dict[str, Any]],
                   restores: list[dict[str, Any]], first: dict[str, Any] | None, now: datetime,
                   chain: Chain) -> tuple[int, int, list[dict[str, Any]]]:
    """DB 밖 앵커: 보관기간 안이면 그 번호의 행이 있고, 다시 계산한 해시가 앵커와 같아야 한다.
    - 맞지 않아도 그 앵커가 백업으로 되돌린 시점(복원 기록 바로 앞 행의 시각)과 복원 사이에 남긴 것이면 버려진 갈래 — 따로 알린다
      (복원 기록 없이는 늘 대조한다. 복원 한 번으로 검증이 영영 실패했다 — 실제 pg_restore 로 재현).
    - 가리키는 행의 시각이 보관기간을 넘었으면 만료(지워졌거나 곧 지워짐)로 센다. 그 전의 행이 없으면, 보관기간을 그 사이 늘렸을 때만
      믿을 만한 만료 기록으로 설명된다 — 아무 만료 기록이나 앞부분 삭제를 덮지 못하게(검토에서 재현)."""
    checked = expired = 0
    superseded: list[dict[str, Any]] = []
    horizon = now - timedelta(days=settings.audit_retention_days) + EXPIRY_SLACK
    for a in anchors:
        if "error" in a:
            chain.problem(f"앵커 {a['file']}: {a['error']}")
            continue
        aid, row_at = a["audit_last_id"], a["audit_last_at"] or a["at"]
        stored = seen.get(aid, "missing")
        if stored == a["audit_last_hash"]:
            checked += 1
            continue
        gone = next((r for r in reversed(restores) if a["at"] is not None and a["at"] < r["at"]
                     and (r["prev_at"] is None or a["at"] > r["prev_at"])), None)
        if gone is not None:
            superseded.append({"file": a["file"], "restore_id": gone["id"], "restore_at": gone["at"], "backup": gone["target"]})
            continue
        if row_at is not None and row_at < horizon:
            expired += 1
            continue
        if stored == "missing" and first is not None and aid < first["id"] and row_at is not None and any(
                m["upto_id"] >= aid and m["cutoff"] > row_at for m in marks):
            expired += 1
            continue
        if stored == "missing":
            chain.problem(f"앵커 {a['file']} 의 #{aid} 가 없습니다 — 보관기간 안인데 지워졌습니다")
        elif stored is None:
            chain.problem(f"앵커 {a['file']} 의 #{aid} 가 고쳐졌습니다")
        else:
            chain.problem(f"앵커 {a['file']} 의 #{aid} 가 다릅니다 — 그 뒤로 감사로그가 지워지거나 다시 쓰였습니다")
    return checked, expired, superseded


async def write_anchor(now: datetime | None = None) -> dict[str, Any] | None:
    """오늘(표시 시간대)의 앵커 파일 — 이미 있으면 두지 않는다. 보관 폴더라 외부 저장소 복제(B-17)가 NAS 로 옮긴다."""
    now = now or datetime.now(UTC)
    head = await repository.audit_chain_head()
    if head is None:
        return None
    path = anchor_dir() / f"{ANCHOR_PREFIX}{now.astimezone(display_zone()):%Y-%m-%d}.json"
    body = {"version": 2, "at": now.isoformat(), "audit_last_id": head["last_id"], "audit_last_hash": head["last_hash"],
            "audit_last_at": head["last_at"].isoformat() if head["last_at"] else None, "start_hash": head["start_hash"]}
    data = json.dumps(body, ensure_ascii=False, indent=1).encode()
    tmp = path.with_suffix(".json.part")
    try:
        if path.exists():       # 폴더를 읽을 수 없어도 여기서 잡는다 (try 밖이면 매일 검증까지 멈췄다)
            return None
        anchor_dir().mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except OSError as exc:
        log.error("위·변조 증명 앵커를 쓰지 못함: %s", exc)
        last = (await repository.latest_audit_by_id(["integrity.anchor_failed"])).get("integrity.anchor_failed")
        if last is None or datetime.now(UTC) - last["at"] >= timedelta(hours=23):   # 시간마다 다시 시도하지만 기록은 하루 한 번
            await db.audit("system", "integrity.anchor_failed", str(path), {"error": str(exc)[:300]})
        return None
    await db.audit("system", "integrity.anchor", path.name,
                   {"audit_last_id": head["last_id"], "audit_last_hash": head["last_hash"],
                    "sha256": hashlib.sha256(data).hexdigest()})
    return body


async def daily(now: datetime | None = None) -> None:
    """정기 정리(1시간마다, 기동 직후는 제외)에서: 오늘 앵커가 없으면 남기고, 마지막 검증이 20시간보다 오래면 다시 검증한다.
    둘은 따로 — 앵커를 못 써도 검증은 한다."""
    now = now or datetime.now(UTC)
    try:
        await write_anchor(now)
    except Exception:
        log.exception("위·변조 증명 앵커 작업 실패")
    try:
        await eventdigest.digest_closed_hours(now)     # 수집 로그 시간별 다이제스트 (2단계) — 매시간
    except Exception:
        log.exception("수집 로그 다이제스트 실패")
    try:
        last = (await repository.latest_audit_by_id(["integrity.verify"])).get("integrity.verify")
        if last is None or not (now - VERIFY_EVERY < last["at"] <= now + FUTURE_SLACK):
            await record_verify(now, "system")
    except Exception:
        log.exception("위·변조 증명 정기 검증 실패")


async def record_verify(now: datetime | None = None, actor: str = "system", ip: str | None = None,
                        anchor_dirs: Iterable[Path | str] = (), events_window: timedelta | None = None) -> dict[str, Any]:
    """검증하고 감사로그(integrity.verify)에 남긴다. 검증이 예외로 멈춰도 실패로 남긴다 — 예전 '정상'이 그대로 보이지 않게."""
    now = now or datetime.now(UTC)
    try:
        result = await verify(now, anchor_dirs, events_window)
    except Exception as exc:
        log.exception("감사로그 위·변조 검증 중 오류")
        result = _result(now, [f"검증하지 못했습니다 — {type(exc).__name__}: {str(exc)[:200]}"])
    await db.audit(actor, "integrity.verify", "audit_log",
                   {"ok": result["ok"], "rows": result["rows"], "last_id": result["last_id"], "last_hash": result["last_hash"],
                    "problems": result["problems"][:5], "anchors_checked": result["anchors_checked"],
                    "anchors_expired": result["anchors_expired"], "events_hours": result["events_hours"],
                    "superseded": [{"file": s["file"], "restore_id": s["restore_id"],
                                    "restore_at": s["restore_at"].isoformat() if s["restore_at"] else None}
                                   for s in result["superseded"]][:20]},
                   actor_ip=ip)
    if not result["ok"]:
        log.error("감사로그 위·변조 검증 실패: %s", "; ".join(result["problems"][:3]))
    return result


async def purge_check(now: datetime | None = None) -> Chain:
    """만료 삭제 전 확인용(repository.purge_audit 의 check)."""
    head = await repository.audit_chain_head()
    return Chain(now, head["backfill_max_id"] if head else 0)


async def status(now: datetime | None = None) -> dict[str, Any]:
    """화면·점검 보고서·운영 준비도가 같이 쓰는 상태 — 머리, 마지막 검증·앵커, 그리고 판단(notices: level·text)."""
    now = now or datetime.now(UTC)
    head = await repository.audit_chain_head()
    latest = await repository.latest_audit_by_id(["integrity.verify", "integrity.anchor", "integrity.anchor_failed", eventdigest.MISMATCH_ACTION,
                                                  "retention.purge_audit_refused", MARK_ACTION])
    verify_row, anchor_row = latest.get("integrity.verify"), latest.get("integrity.anchor")
    failed, refused, purged = (latest.get("integrity.anchor_failed"), latest.get("retention.purge_audit_refused"),
                               latest.get(MARK_ACTION))
    notices: list[dict[str, str]] = []
    if head is None:
        notices.append({"level": "bad", "text": "감사로그 체인 머리가 없습니다 — 감사로그를 남길 수 없습니다 (마이그레이션 022 확인)"})
    if verify_row and not verify_row["detail"].get("ok"):
        first = (verify_row["detail"].get("problems") or ["문제"])[0]
        notices.append({"level": "bad", "text": f"감사로그 위·변조 검증 실패: {first} — python -m app.cli verify-chain 으로 확인"})
    if refused and (purged is None or refused["id"] > purged["id"]):
        first = (refused["detail"].get("problems") or ["문제"])[0]
        notices.append({"level": "bad", "text": f"감사로그 만료 삭제를 멈췄습니다 (지울 행이 체인과 맞지 않음): {first}"})
    mismatch = latest.get(eventdigest.MISMATCH_ACTION)
    if mismatch and now - mismatch["at"] < RESTORE_NOTICE:
        # 보관 파일을 만들 때 그 달의 로그가 다이제스트와 달랐다 — 파티션은 지워졌으므로 그 뒤 매일 검증에는 다시 나오지 않는다
        first = (mismatch["detail"].get("problems") or ["문제"])[0]
        notices.append({"level": "bad", "text": f"보관 파일로 옮긴 {mismatch['target']} 의 로그가 다이제스트와 다릅니다: {first}"})
    restored = [s for s in ((verify_row["detail"].get("superseded") or []) if verify_row else [])
                if (at := _parse_at(s.get("restore_at"))) and now - at < RESTORE_NOTICE]
    if restored:
        # 정상적인 백업 복원과 가짜 복원 기록(끝을 지우고 넣은 것)은 같은 모양이다 — 한 달 동안 사람에게 확인을 묻는다
        notices.append({"level": "warn", "text": f"DB 복원 기록(#{restored[0]['restore_id']}) 전에 남긴 앵커 {len(restored)}개를 대조하지 "
                                                 "않았습니다 — 그 무렵 백업으로 되돌린 적이 없다면 위·변조를 의심하세요"})
    started = head["started_at"] if head else now
    if now - started > STALE_AFTER:
        if verify_row is None or not (now - STALE_AFTER < verify_row["at"] <= now + FUTURE_SLACK):
            notices.append({"level": "warn", "text": "감사로그 위·변조 검증이 이틀 넘게 없습니다 — 정기 정리(1시간마다)가 도는지 확인"})
        if anchor_row is None or now - anchor_row["at"] > STALE_AFTER:
            text = "감사로그 체인 앵커를 이틀 넘게 남기지 못했습니다"
            if failed and (anchor_row is None or failed["id"] > anchor_row["id"]):
                text += f" — {failed['detail'].get('error', '')[:120]}"
            notices.append({"level": "warn", "text": text + " (보관 폴더 쓰기 권한·디스크 확인)"})
    return {"head": head, "last_verify": verify_row, "last_anchor": anchor_row, "anchors": len(list_anchors()),
            "replica": settings.replica, "notices": notices}
