"""로그 보관 파일(archive): DB 보관기간이 지난 월 파티션을 압축 파일로 옮기고, 필요하면 다시 불러온다.

파일 형식 (WLM_ARCHIVE_DIR, 기본 ./archive):
  events_2026_06.jsonl.gz        한 줄에 이벤트 하나 (JSON). 컬럼 전부 + 원본(raw)
  events_2026_06.meta.json       {partition, from, to, rows, sha256, bytes, created_at, format}
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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psycopg import sql

from . import db
from .config import settings

log = logging.getLogger(__name__)

FORMAT = "wlm-events-jsonl-v1"
COLUMNS = ("id", "received_at", "ts", "host", "source", "channel", "provider", "event_id", "level", "message", "raw")
FETCH = 5000


class ArchiveError(Exception):
    pass


def archive_dir() -> Path:
    return Path(settings.archive_dir)


def data_path(partition: str) -> Path:
    return archive_dir() / f"{partition}.jsonl.gz"


def meta_path(partition: str) -> Path:
    return archive_dir() / f"{partition}.meta.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def list_archives() -> list[dict[str, Any]]:
    items = []
    for meta in sorted(archive_dir().glob("events_*.meta.json")):
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        data["exists"] = data_path(data["partition"]).exists()
        items.append(data)
    return items


def _row_json(row: dict) -> str:
    out = {}
    for key in COLUMNS:
        value = row[key]
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return json.dumps(out, ensure_ascii=False, default=str)


async def archive_partition(partition: str, start: datetime, end: datetime) -> dict[str, Any]:
    """파티션 → 압축 파일. 성공하면 메타데이터(dict) 반환. 파티션은 지우지 않는다 (호출하는 쪽에서)."""
    folder = archive_dir()
    folder.mkdir(parents=True, exist_ok=True)
    tmp = folder / f"{partition}.jsonl.gz.tmp"
    rows = 0
    fh = await asyncio.to_thread(gzip.open, tmp, "wt", encoding="utf-8", compresslevel=6)
    try:
        async with await db.connect_autocommit() as conn:
            async with conn.transaction(), conn.cursor(name=f"archive_{partition}") as cur:
                await cur.execute(sql.SQL("SELECT {} FROM {} ORDER BY received_at, id").format(
                    sql.SQL(", ").join(map(sql.Identifier, COLUMNS)), sql.Identifier(partition)))
                while batch := await cur.fetchmany(FETCH):
                    text = "\n".join(_row_json(r) for r in batch) + "\n"
                    await asyncio.to_thread(fh.write, text)
                    rows += len(batch)
            expected = (await (await conn.execute(
                sql.SQL("SELECT count(*) AS n FROM {}").format(sql.Identifier(partition)))).fetchone())["n"]
        await asyncio.to_thread(fh.close)
    except BaseException:
        fh.close()
        tmp.unlink(missing_ok=True)
        raise
    if rows != expected:
        tmp.unlink(missing_ok=True)
        raise ArchiveError(f"{partition}: 기록한 행 수({rows})와 파티션 행 수({expected})가 다릅니다")

    final = data_path(partition)
    await asyncio.to_thread(os.replace, tmp, final)
    digest = await asyncio.to_thread(sha256_file, final)
    meta = {
        "partition": partition, "from": start.isoformat(), "to": end.isoformat(), "rows": rows,
        "sha256": digest, "bytes": final.stat().st_size, "created_at": datetime.now(UTC).isoformat(),
        "format": FORMAT, "file": final.name,
    }
    meta_path(partition).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    log.warning("보관 파일 생성: %s (%s건, %s bytes)", final.name, rows, meta["bytes"])
    return meta


def verify(partition: str) -> dict[str, Any]:
    """보관 파일의 SHA-256 을 다시 계산해 메타데이터와 비교."""
    meta = json.loads(meta_path(partition).read_text(encoding="utf-8"))
    path = data_path(partition)
    if not path.exists():
        return {**meta, "ok": False, "problem": "파일 없음"}
    actual = sha256_file(path)
    return {**meta, "ok": actual == meta["sha256"], "actual_sha256": actual,
            "problem": None if actual == meta["sha256"] else "해시 불일치 (파일이 바뀌었을 수 있음)"}


async def restore(partition: str, hold_days: int, actor: str) -> int:
    """보관 파일 → DB 파티션 (조사용). hold_days 동안 자동 정리에서 제외한다."""
    checked = await asyncio.to_thread(verify, partition)
    if not checked["ok"]:
        raise ArchiveError(f"{partition}: {checked['problem']} — 복원하지 않습니다")
    start, end = datetime.fromisoformat(checked["from"]), datetime.fromisoformat(checked["to"])
    restored = 0
    async with await db.connect_autocommit() as conn:
        await conn.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} PARTITION OF events FOR VALUES FROM ({}) TO ({})").format(
            sql.Identifier(partition), sql.Literal(start), sql.Literal(end)))
        existing = (await (await conn.execute(
            sql.SQL("SELECT count(*) AS n FROM {}").format(sql.Identifier(partition)))).fetchone())["n"]
        if existing:
            raise ArchiveError(f"{partition} 파티션에 이미 {existing}건이 있습니다 (이미 복원됨?)")
        async with conn.transaction():
            async with conn.cursor() as cur, cur.copy(sql.SQL("COPY {} ({}) FROM STDIN").format(
                    sql.Identifier(partition), sql.SQL(", ").join(map(sql.Identifier, COLUMNS)))) as copy:
                with gzip.open(data_path(partition), "rt", encoding="utf-8") as fh:
                    for line in fh:
                        row = json.loads(line)
                        row["raw"] = json.dumps(row["raw"], ensure_ascii=False)
                        await copy.write_row([row[c] for c in COLUMNS])
                        restored += 1
            await conn.execute(
                "INSERT INTO partition_holds (name, hold_until, reason, created_by) VALUES (%s, now() + make_interval(days => %s), %s, %s)"
                " ON CONFLICT (name) DO UPDATE SET hold_until = EXCLUDED.hold_until, created_by = EXCLUDED.created_by",
                (partition, hold_days, "보관 파일 복원", actor))
    await db.audit(actor, "retention.restore_archive", partition,
                   {"rows": restored, "hold_days": hold_days, "sha256": checked["sha256"]})
    return restored


async def delete_expired(cutoff: datetime) -> list[str]:
    """전체 보관기간이 지난 보관 파일 삭제 (파기 기록을 audit_log 에)."""
    deleted = []
    for meta in list_archives():
        if datetime.fromisoformat(meta["to"]) > cutoff:
            continue
        data_path(meta["partition"]).unlink(missing_ok=True)
        meta_path(meta["partition"]).unlink(missing_ok=True)
        deleted.append(meta["partition"])
        log.warning("보관기간 만료 보관 파일 삭제: %s", meta["file"])
        await db.audit("system", "retention.delete_archive", meta["file"],
                       {"rows": meta["rows"], "sha256": meta["sha256"], "retention_days": settings.retention_days})
    return deleted
