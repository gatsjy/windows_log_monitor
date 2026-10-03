"""관리 명령 (서버 컨테이너 안에서 실행). 관리자가 잠겼거나 비밀번호를 잊었을 때 복구용.

  docker compose exec api python -m app.cli list-users
  docker compose exec api python -m app.cli reset-password admin
  docker compose exec api python -m app.cli create-user kim.minsu --role admin --name 김민수
  docker compose exec api python -m app.cli retention-status          # DB 파티션·보관 파일 현황
  docker compose exec api python -m app.cli verify-archives           # 보관 파일 SHA-256 무결성 확인
  docker compose exec api python -m app.cli restore-archive events_2026_06 --hold-days 14
  docker compose exec api python -m app.cli rotate-now                # 로그 로테이션 즉시 실행

모든 작업은 actor='cli' 로 audit_log 에 남는다.
"""

from __future__ import annotations

import argparse
import asyncio

from . import archive, db, partitions
from .auth import service
from .config import settings


async def _run(args: argparse.Namespace) -> None:
    await db.migrate()
    await db.open_pool()
    try:
        if args.command == "list-users":
            for u in await service.list_users():
                state = "활성" if u["is_active"] else "비활성"
                print(f"{u['id']:>4}  {u['username']:<20} {u['role']:<7} {state}  마지막 로그인 {u['last_login_at'] or '-'}")
        elif args.command == "reset-password":
            row = await db.fetch_one("SELECT id FROM users WHERE username = %s",
                                     (service.normalize_username(args.username),))
            if row is None:
                raise SystemExit(f"사용자 없음: {args.username}")
            username, temp = await service.reset_password(row["id"], "cli", None)
            print(f"{username} 의 임시 비밀번호: {temp}  (잠금 해제됨, 첫 로그인 때 변경 필요)")
        elif args.command == "create-user":
            _, temp = await service.create_user(args.username, args.name or "", args.role, "cli", None)
            print(f"{args.username} 생성 ({args.role}) — 임시 비밀번호: {temp}  (첫 로그인 때 변경 필요)")
        elif args.command == "retention-status":
            print(f"정책: DB {settings.db_retention_days}일 → 보관 파일 → 전체 {settings.retention_days}일 후 삭제"
                  f" (파일 보관 {'사용' if partitions.archiving_enabled() else '안 함'})")
            async with await db.connect_autocommit() as conn:
                for p in await partitions.list_partitions(conn):
                    hold = f"  보존 연장 ~{p['hold_until']:%Y-%m-%d}" if p["hold_until"] else ""
                    print(f"  DB   {p['name']}  약 {p['rows_estimate']:>12,}건  {p['bytes'] / 1e6:>10,.1f} MB{hold}")
            for a in archive.list_archives():
                print(f"  파일 {a['file']}  {a['rows']:>12,}건  {a['bytes'] / 1e6:>10,.1f} MB  sha256 {a['sha256'][:16]}…")
        elif args.command == "verify-archives":
            bad = 0
            for a in archive.list_archives():
                result = archive.verify(a["partition"])
                bad += not result["ok"]
                print(f"  {'정상' if result['ok'] else '문제'}  {a['file']}  {result['problem'] or ''}")
            await db.audit("cli", "retention.verify_archives", None, {"files": len(archive.list_archives()), "bad": bad})
            if bad:
                raise SystemExit(f"무결성 문제 {bad}건")
        elif args.command == "restore-archive":
            rows = await archive.restore(args.partition, args.hold_days, "cli")
            print(f"{args.partition}: {rows:,}건 복원. {args.hold_days}일 동안 자동 정리에서 제외됩니다")
        elif args.command == "rotate-now":
            await partitions.run_maintenance()
            print("로그 로테이션 실행 완료 (결과는 retention-status / 감사 로그)")
    except service.AuthError as exc:
        raise SystemExit(exc.message) from exc
    except archive.ArchiveError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        await db.close_pool()


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Log Monitor 관리 명령")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list-users", help="사용자 목록")
    reset = sub.add_parser("reset-password", help="임시 비밀번호 발급 + 잠금 해제")
    reset.add_argument("username")
    create = sub.add_parser("create-user", help="사용자 추가")
    create.add_argument("username")
    create.add_argument("--role", choices=service.ROLES, default="viewer")
    create.add_argument("--name", default="")
    sub.add_parser("retention-status", help="DB 파티션과 보관 파일 현황")
    sub.add_parser("verify-archives", help="보관 파일 SHA-256 무결성 확인")
    restore = sub.add_parser("restore-archive", help="보관 파일을 DB 로 다시 불러오기 (조사용)")
    restore.add_argument("partition", help="예: events_2026_06")
    restore.add_argument("--hold-days", type=int, default=14, help="자동 정리에서 제외할 일수")
    sub.add_parser("rotate-now", help="로그 로테이션(보관·삭제) 즉시 실행")
    asyncio.run(_run(parser.parse_args()))


if __name__ == "__main__":
    main()
