"""로그 보관 파일(archive): DB 보관기간이 지난 월 파티션을 압축 파일로 옮기고, 필요하면 다시 불러온다.

파일 형식 (WLM_ARCHIVE_DIR, 기본 ./archive):
  events_2026_06.jsonl.gz        한 줄에 이벤트 하나 (JSON). 컬럼 전부 + 원본(raw) — 보관 등급에 맞지 않은 로그 (기본)
  events_2026_06.meta.json       {partition, from, to, rows, sha256, bytes, created_at, format, tiers, skipped}
  events_2026_06.<등급>.jsonl.gz  보관 등급(B-70, app/retention.py)에 맞은 로그 — 메타에 tier·keep_days·query
기본 메타는 늘 맨 나중에 쓴다 — '이 달은 보관을 마쳤다'는 표시(is_archived). 기본 기간(WLM_RETENTION_DAYS)이 이미 지난 달(더 긴 등급
때문에 보관하는 달)은 기본 파일 없이 메타만(file 없음 = 표시), 기본 파일이 먼저 만료돼도 그 달의 등급 파일이 남아 있는 동안은 메타를 표시로 남긴다.
표시가 없으면 다시 만든다(만들다 멈춘 달). 표시 없이 지나간 달을 복원했다가 보존 기간이 끝나면 지금 설정으로 다시 보관해 등급 파일을 덮어써
행이 사라지고 약속한 기간이 줄었다(검토에서 재현).
형식 v2 부터 공통 필드(category·username·src_ip, 마이그레이션 007)도 넣는다. v1 파일에는 없었다 — 복원한 달에서
user:/ip:/분류 검색이 0건이 되고 분류로 범위를 정한 사용자에게 보이지 않았다. v1 을 복원할 때는 원본에서 다시 구한다
(normalizers.derive_common, 정규화와 같은 값).
SHA-256 은 .gz 파일 전체의 해시. 만들 때 audit_log 에도 남기므로 나중에 위·변조 여부를 대조할 수 있다 (ISMS 2.9.4).

대용량 파티션도 메모리를 쓰지 않도록 서버 쪽 커서로 5천 건씩 읽고, 압축·파일 쓰기는 스레드에서 한다.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from psycopg import sql

from . import db, retention
from .config import settings
from .normalizers import derive_common, windows

log = logging.getLogger(__name__)

FORMAT = "wlm-events-jsonl-v2"
COLUMNS = ("id", "received_at", "ts", "host", "source", "category", "channel", "provider", "event_id", "level",
           "username", "src_ip", "message", "raw")
COMMON = ("category", "username", "src_ip")   # v1 보관 파일에는 없다
FETCH = 5000


class ArchiveError(Exception):
    pass


def archive_dir() -> Path:
    return Path(settings.archive_dir)


def data_path(partition: str, tier: str | None = None) -> Path:
    return archive_dir() / f"{partition}{'.' + tier if tier else ''}.jsonl.gz"


def meta_path(partition: str, tier: str | None = None) -> Path:
    return archive_dir() / f"{partition}{'.' + tier if tier else ''}.meta.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_meta(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def is_archived(partition: str) -> bool:
    """이 달의 보관을 마쳤나 — 기본 메타(완료 표시)가 있고, 기본 파일이 있다고 적혀 있으면 그 파일도 있다."""
    meta = _read_meta(meta_path(partition))
    return meta is not None and (meta.get("file") is None or data_path(partition).exists())


def list_archives(config: retention.Config | None = None, markers: bool = False) -> list[dict[str, Any]]:
    """보관 파일(메타)마다: 메타 + exists·tier·keep_days·expires_at (만료는 지금 등급 설정까지 보고).
    markers: 파일 없는 완료 표시(기본 파일 없이 등급 파일만 있는 달)도 — 화면·검증·복원에는 넣지 않는다."""
    config = config or retention.Config()
    items = []
    for meta in sorted(archive_dir().glob("events_*.meta.json")):
        data = _read_meta(meta)
        if data is None:
            continue
        data["tier"] = data.get("tier")
        if "file" in data and data["file"] is None:
            if markers:
                items.append({**data, "marker": True})
            continue
        data["file"] = data.get("file") or data_path(data["partition"], data["tier"]).name
        data["exists"] = (archive_dir() / data["file"]).exists()
        data["keep_days"] = retention.keep_days(data, config)
        data["expires_at"] = retention.expires_at(data, config).isoformat()
        items.append(data)
    return items


class _Group:
    """보관 파일 하나(기본 또는 등급)를 쓰는 중 — 첫 줄이 올 때 연다."""

    def __init__(self, partition: str, tier: retention.Tier | None):
        self.tier, self.rows, self.sha256 = tier, 0, ""
        self.final = data_path(partition, tier.id if tier else None)
        self.tmp = self.final.with_name(self.final.name + ".tmp")
        self.fh = gzip.open(self.tmp, "wt", encoding="utf-8", compresslevel=6)   # noqa: SIM115 - 묶음 여러 번에 걸쳐 쓴다 (닫기는 호출하는 쪽)

    def discard(self) -> None:
        self.fh.close()
        self.tmp.unlink(missing_ok=True)


def _row_json(row: dict) -> str:
    out = {}
    for key in COLUMNS:
        value = row[key]
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return json.dumps(out, ensure_ascii=False, default=str)


async def archive_partition(partition: str, start: datetime, end: datetime,
                            config: retention.Config | None = None) -> dict[str, Any]:
    """파티션 → 압축 파일(기본 + 보관 등급마다). 성공하면 기본 메타데이터(dict, tiers 에 등급 파일) 반환. 파티션은 지우지 않는다 (호출하는 쪽에서).
    쓰면서 시간별 다이제스트(B-71 2단계)를 모아, 그 달에 남긴 다이제스트와 맞춰 본다 — 파티션을 지우기 전 그 달 전체를 볼 마지막 기회.
    다르면 보관은 그대로 하되(파일 = 지금 DB) 감사로그 integrity.events_mismatch 로 남겨 화면·점검 보고서에 빨갛게 보인다.
    만들 때 이미 기간이 끝난 등급(기간이 DB 보관기간보다 짧은 등급 등)의 로그는 파일에 쓰지 않고 센다(skipped)."""
    from . import eventdigest  # repository·partitions 와 순환 import 를 피해 여기서

    config = config or retention.Config()
    if config.error:
        raise ArchiveError(f"보관 등급 설정 오류: {config.error}")
    now = datetime.now(UTC)
    expired = {t.id for t in config.tiers if end + timedelta(days=t.keep_days) <= now}
    if end + timedelta(days=settings.retention_days) <= now:
        expired.add(None)
    acc = eventdigest.Hours()
    archive_dir().mkdir(parents=True, exist_ok=True)
    groups: dict[str | None, _Group] = {}
    skipped: dict[str, int] = {}
    rows = 0

    def write(batch: list[dict]) -> None:
        lines: dict[str | None, list[str]] = {}
        for r in batch:
            tier = retention.classify(config.tiers, r)
            key = tier.id if tier else None
            if key in expired:
                skipped[key or "default"] = skipped.get(key or "default", 0) + 1
                continue
            if key not in groups:
                groups[key] = _Group(partition, tier)
            lines.setdefault(key, []).append(_row_json(r))
        for key, out in lines.items():
            groups[key].fh.write("\n".join(out) + "\n")
            groups[key].rows += len(out)
        acc.add_many(batch)

    try:
        if None not in expired:
            await asyncio.to_thread(lambda: groups.setdefault(None, _Group(partition, None)))   # 기본 파일은 0건이어도
        async with await db.connect_autocommit() as conn:
            async with conn.transaction(), conn.cursor(name=f"archive_{partition}") as cur:
                await cur.execute(sql.SQL("SELECT {} FROM {} ORDER BY received_at, id").format(
                    sql.SQL(", ").join(map(sql.Identifier, COLUMNS)), sql.Identifier(partition)))
                while batch := await cur.fetchmany(FETCH):
                    await asyncio.to_thread(write, batch)
                    rows += len(batch)
            expected = (await (await conn.execute(
                sql.SQL("SELECT count(*) AS n FROM {}").format(sql.Identifier(partition)))).fetchone())["n"]
        for g in groups.values():
            await asyncio.to_thread(g.fh.close)
    except BaseException:
        for g in groups.values():
            g.discard()
        raise
    if rows != expected:
        for g in groups.values():
            g.discard()
        raise ArchiveError(f"{partition}: 기록한 행 수({rows})와 파티션 행 수({expected})가 다릅니다")

    created = datetime.now(UTC).isoformat()
    base = {"partition": partition, "from": start.isoformat(), "to": end.isoformat(), "created_at": created, "format": FORMAT}
    tiers = []
    for key, g in sorted(groups.items(), key=lambda kv: kv[0] or ""):
        await asyncio.to_thread(os.replace, g.tmp, g.final)
        # 같은 이름을 다시 만들면(복원한 달을 기간을 늘린 뒤 다시 보관) 앞의 지운 표시를 치운다 — 남으면 외부 복제가 새 파일을 건너뛰고 복제본을 지웠다
        tombstone_path(g.final.name).unlink(missing_ok=True)
        g.sha256 = await asyncio.to_thread(sha256_file, g.final)
        if key is None:
            continue
        keep = g.tier.keep_days
        if (old := _read_meta(meta_path(partition, key))) is not None:
            # 만들다 멈춘 달을 다시 만들 때 — 앞서 약속한 기간보다 줄이지 않는다
            keep = max(keep, int(old.get("keep_days") or 0))
        tier_meta = {**base, "rows": g.rows, "sha256": g.sha256, "bytes": g.final.stat().st_size, "file": g.final.name,
                     "tier": key, "tier_name": g.tier.name, "keep_days": keep, "query": g.tier.query}
        meta_path(partition, key).write_text(json.dumps(tier_meta, ensure_ascii=False, indent=2), encoding="utf-8")
        tiers.append({k: tier_meta[k] for k in ("tier", "file", "rows", "sha256", "keep_days")})
        log.warning("보관 파일 생성: %s (%s건, 등급 %s %s일)", g.final.name, g.rows, key, g.tier.keep_days)
    default = groups.get(None)
    meta = {**base, "rows": default.rows if default else 0, "sha256": default.sha256 if default else None,
            "bytes": default.final.stat().st_size if default else 0, "file": default.final.name if default else None,
            "total_rows": rows, "tiers": tiers, "skipped": skipped}
    want = await eventdigest.recorded(start, end)
    problems = eventdigest.compare(acc, want)
    meta["digest_hours"], meta["digest_problems"] = len(want), len(problems)
    meta_path(partition).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")   # 완료 표시 (기본 파일이 없어도)
    log.warning("보관: %s (기본 %s건, 등급 파일 %s개, 기간이 끝나 쓰지 않음 %s건)", partition, meta["rows"], len(tiers),
                sum(skipped.values()))
    if problems:
        log.error("보관한 %s 의 로그가 다이제스트와 다름: %s", partition, "; ".join(problems[:3]))
        await db.audit("system", eventdigest.MISMATCH_ACTION, partition, {"hours": len(want), "problems": problems[:20]})
    return meta


def verify(partition: str, tier: str | None = None) -> dict[str, Any]:
    """보관 파일의 SHA-256 을 다시 계산해 메타데이터와 비교."""
    meta = json.loads(meta_path(partition, tier).read_text(encoding="utf-8"))
    path = data_path(partition, tier)
    if not path.exists():
        return {**meta, "ok": False, "problem": "파일 없음"}
    actual = sha256_file(path)
    return {**meta, "ok": actual == meta["sha256"], "actual_sha256": actual,
            "problem": None if actual == meta["sha256"] else "해시 불일치 (파일이 바뀌었을 수 있음)"}


async def restore(partition: str, hold_days: int, actor: str) -> int:
    """보관 파일 → DB 파티션 (조사용). 그 달의 기본·등급 파일을 모두 한 트랜잭션에 (기본 파일이 먼저 만료됐으면 남은 등급 파일만).
    hold_days 동안 자동 정리에서 제외한다."""
    metas = [m for m in list_archives() if m["partition"] == partition]
    if not metas:
        raise ArchiveError(f"{partition}: 보관 파일이 없습니다")
    checks = [await asyncio.to_thread(verify, partition, m["tier"]) for m in metas]
    for checked in checks:
        if not checked["ok"]:
            raise ArchiveError(f"{checked['file']}: {checked['problem']} — 복원하지 않습니다")
    start, end = datetime.fromisoformat(checks[0]["from"]), datetime.fromisoformat(checks[0]["to"])
    restored = derived = 0
    async with await db.connect_autocommit() as conn:
        await conn.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} PARTITION OF events FOR VALUES FROM ({}) TO ({})").format(
            sql.Identifier(partition), sql.Literal(start), sql.Literal(end)))
        existing = (await (await conn.execute(
            sql.SQL("SELECT count(*) AS n FROM {}").format(sql.Identifier(partition)))).fetchone())["n"]
        if existing:
            raise ArchiveError(f"{partition} 파티션에 이미 {existing}건이 있습니다 (이미 복원됨?)")
        async with conn.transaction():
            # 같은 행이 두 파일에 있을 수 있다(만들다 멈춘 달을 등급 이름을 바꾼 뒤 다시 만듦 — 검토에서 재현) — 임시 표에 모은 뒤 겹치는 것은 한 번만
            staging = sql.Identifier(f"restore_{partition}")
            await conn.execute(sql.SQL("CREATE TEMP TABLE {} (LIKE events INCLUDING DEFAULTS) ON COMMIT DROP").format(staging))
            async with conn.cursor() as cur, cur.copy(sql.SQL("COPY {} ({}) FROM STDIN").format(
                    staging, sql.SQL(", ").join(map(sql.Identifier, COLUMNS)))) as copy:
                for checked in checks:
                    with gzip.open(archive_dir() / checked["file"], "rt", encoding="utf-8") as fh:
                        for line in fh:
                            row = json.loads(line)
                            _add_windows_names(row)
                            if any(c not in row for c in COMMON):   # v1: 원본에서 다시 구한다
                                row["category"], row["username"], row["src_ip"] = derive_common(
                                    row.get("source"), row.get("channel"), row.get("provider"), row.get("event_id"),
                                    row.get("message"), row.get("raw"))
                                derived += 1
                            row["raw"] = json.dumps(row["raw"], ensure_ascii=False)
                            await copy.write_row([row[c] for c in COLUMNS])
            cols = sql.SQL(", ").join(map(sql.Identifier, COLUMNS))
            cur = await conn.execute(sql.SQL("INSERT INTO {} ({}) SELECT {} FROM {} ON CONFLICT DO NOTHING").format(
                sql.Identifier(partition), cols, cols, staging))
            restored = cur.rowcount
            await conn.execute(
                "INSERT INTO partition_holds (name, hold_until, reason, created_by) VALUES (%s, now() + make_interval(days => %s), %s, %s)"
                " ON CONFLICT (name) DO UPDATE SET hold_until = EXCLUDED.hold_until, created_by = EXCLUDED.created_by",
                (partition, hold_days, "보관 파일 복원", actor))
    await db.audit(actor, "retention.restore_archive", partition,
                   {"rows": restored, "hold_days": hold_days, "sha256": checks[0]["sha256"],
                    "format": checks[0].get("format"), "common_fields_derived": derived,
                    "files": [{"file": c["file"], "rows": c["rows"], "sha256": c["sha256"]} for c in checks]})
    return restored


def _add_windows_names(row: dict) -> None:
    """ADR-038 이전에 저장한 Windows 이벤트에는 서버가 붙인 이름(raw.winevtlog.EventData)이 없다 — 복원한 달에서도
    f.EventData.<이름> 규칙·검색이 맞게 수집 때와 같은 방법으로 붙인다 (원본 키는 건드리지 않음)."""
    raw = row.get("raw")
    if row.get("source") != windows.SOURCE or not isinstance(raw, dict) or windows.SOURCE in raw:
        return
    derived = windows.derived_event_data(raw, row.get("event_id"))
    if derived:
        row["raw"] = {**raw, windows.SOURCE: {"EventData": derived}}


def tombstone_path(file: str) -> Path:
    """지운 등급 파일의 표시 — 외부 복제본은 이것(또는 감사로그)이 있을 때만 지운다. DB 를 백업으로 되돌리면 감사로그의 파기 기록은 사라지지만
    이 파일은 남는다(검토에서 재현: 복제본이 영영 '만료 전에 사라진 원본'으로 남음). 작아서 지우지 않는다."""
    return archive_dir() / file.replace(".jsonl.gz", ".destroyed.json")


async def delete_expired(now: datetime, config: retention.Config) -> list[str]:
    """보관기간이 지난 보관 파일 삭제. 파기 기록(감사로그)을 **먼저** 남기고(남기지 못하면 지우지 않고 다음 주기에) 지운다 — 기록 없이 지우면
    외부 복제본이 지워지지 않고 증적도 없다. 기본 파일은 WLM_RETENTION_DAYS, 등급 파일은 만들 때 기간과 지금 설정 중 긴 쪽(retention.keep_days).
    기본 파일이 지워져도 그 달의 등급 파일이 남아 있으면 기본 메타는 완료 표시로 남긴다(복원했다가 다시 보관하지 않게)."""
    if config.error:
        return []
    deleted = []
    metas = list_archives(config, markers=True)
    for meta in metas:
        if meta.get("marker") or datetime.fromisoformat(meta["expires_at"]) > now:
            continue
        try:
            await db.audit("system", "retention.delete_archive", meta["file"],
                           {"rows": meta["rows"], "sha256": meta["sha256"], "retention_days": meta["keep_days"],
                            **({"tier": meta["tier"], "tier_name": meta.get("tier_name")} if meta["tier"] else {})}, required=True)
        except Exception:
            log.exception("파기 기록을 남기지 못해 %s 을(를) 지우지 않습니다 (다음 주기에 다시)", meta["file"])
            continue
        partition, tier = meta["partition"], meta["tier"]
        try:
            data_path(partition, tier).unlink(missing_ok=True)   # 먼저 지워 자리를 비운다 (디스크가 찼을 때 표시 쓰기가 막지 않게)
            if tier:
                meta_path(partition, tier).unlink(missing_ok=True)
        except OSError:
            log.exception("보관 파일 %s 을(를) 지우지 못했습니다 — 다음 주기에 다시", meta["file"])
            continue
        meta["deleted"] = True
        deleted.append(meta["file"])
        log.warning("보관기간 만료 보관 파일 삭제: %s", meta["file"])
        if tier:
            try:   # 외부 복제용 표시 — 못 써도 감사로그의 파기 기록으로 복제본을 지운다
                tombstone_path(meta["file"]).write_text(json.dumps(
                    {"file": meta["file"], "sha256": meta["sha256"], "tier": tier, "keep_days": meta["keep_days"],
                     "destroyed_at": now.isoformat()}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                log.exception("지운 표시 %s 를 쓰지 못했습니다 (외부 복제는 감사로그로 판단)", tombstone_path(meta["file"]).name)
    # 기본 메타(완료 표시): 그 달의 등급 파일이 남아 있는 동안은 남긴다
    left = {m["partition"] for m in metas if m["tier"] and not m.get("deleted")}
    for meta in metas:
        if meta["tier"] or not (meta.get("marker") or meta.get("deleted")):
            continue
        try:
            if meta["partition"] in left:
                if meta.get("deleted"):
                    raw = _read_meta(meta_path(meta["partition"])) or {}
                    meta_path(meta["partition"]).write_text(json.dumps(
                        {**raw, "file": None, "expired_default": {k: raw.get(k) for k in ("rows", "sha256", "bytes", "file")}},
                        ensure_ascii=False, indent=2), encoding="utf-8")
            else:
                meta_path(meta["partition"]).unlink(missing_ok=True)
        except OSError:
            log.exception("완료 표시 %s 를 고치지 못했습니다 — 다음 주기에 다시", meta_path(meta["partition"]).name)
    return deleted
