"""관리 명령 (서버 컨테이너 안에서 실행). 관리자가 잠겼거나 비밀번호를 잊었을 때 복구용.

  docker compose exec api python -m app.cli list-users
  docker compose exec api python -m app.cli reset-password admin
  docker compose exec api python -m app.cli create-user kim.minsu --role admin --name 김민수
  docker compose exec api python -m app.cli retention-status          # DB 파티션·보관 파일 현황
  docker compose exec api python -m app.cli verify-archives           # 보관 파일 SHA-256 무결성 확인
  docker compose exec api python -m app.cli restore-archive events_2026_06 --hold-days 14
  docker compose exec api python -m app.cli rotate-now                # 로그 로테이션 즉시 실행

모든 작업은 actor='cli' 로 audit_log 에 남는다.

인증서 명령(B-06, ADR-036)은 DB 없이 돈다 — 폐쇄망 설치가 api 를 띄우기 전에 일회성 컨테이너(--network none)로 부른다.
CA 개인키는 api 컨테이너에 마운트하지 않는 폴더(tls-ca/)에만 둔다 (docs/AIRGAP.md §7.5).

  python -m app.cli tls-init --out /out --ca-dir /ca --name logmon.corp.local [--ip 10.0.0.10]
  python -m app.cli tls-renew --dir /out --ca-dir /ca [--name 새이름] [--ip 새IP]   # 2년마다, 에이전트 재배포 없음
  python -m app.cli tls-status [--dir /app/tls]                                      # 이름·만료·CA 지문·문제
"""

from __future__ import annotations

import argparse
import asyncio
import os
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from . import archive, db, partitions, tlsutil
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
        elif args.command == "delete-user":
            # 퇴사자·점검용 계정 정리. 실수 방지를 위해 비활성 계정만 지운다 (먼저 화면에서 비활성화)
            row = await db.fetch_one("SELECT id, username, is_active FROM users WHERE username = %s",
                                     (service.normalize_username(args.username),))
            if row is None:
                raise SystemExit(f"사용자 없음: {args.username}")
            if row["is_active"]:
                raise SystemExit(f"{row['username']} 은(는) 활성 계정입니다. 먼저 비활성화하세요 (사용자 화면 > 수정)")
            await db.fetch_one("DELETE FROM users WHERE id = %s RETURNING id", (row["id"],))
            await db.audit("cli", "user.delete", row["username"], {"reason": args.reason})
            print(f"{row['username']} 삭제 (세션·그룹 소속도 함께 삭제, 감사 로그 기록은 유지)")
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
            # 화면의 확인(routers/settings.retention_verify)과 같은 형식: bad = 문제 파일 이름 목록 (점검 보고서가 읽는다)
            bad = []
            for a in archive.list_archives():
                result = archive.verify(a["partition"])
                if not result["ok"]:
                    bad.append(a["file"])
                print(f"  {'정상' if result['ok'] else '문제'}  {a['file']}  {result['problem'] or ''}")
            await db.audit("cli", "retention.verify_archives", None, {"files": len(archive.list_archives()), "bad": bad})
            if bad:
                raise SystemExit(f"무결성 문제 {len(bad)}건")
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
    delete = sub.add_parser("delete-user", help="비활성 사용자 삭제 (감사 로그에 기록)")
    delete.add_argument("username")
    delete.add_argument("--reason", default="", help="삭제 사유 (감사 로그에 남음)")
    sub.add_parser("retention-status", help="DB 파티션과 보관 파일 현황")
    sub.add_parser("verify-archives", help="보관 파일 SHA-256 무결성 확인")
    restore = sub.add_parser("restore-archive", help="보관 파일을 DB 로 다시 불러오기 (조사용)")
    restore.add_argument("partition", help="예: events_2026_06")
    restore.add_argument("--hold-days", type=int, default=14, help="자동 정리에서 제외할 일수")
    sub.add_parser("rotate-now", help="로그 로테이션(보관·삭제) 즉시 실행")
    init = sub.add_parser("tls-init", help="자체 CA + 서버 인증서 만들기 (DB 없이)")
    init.add_argument("--out", default="/app/tls", help="server.crt·server.key·ca.crt 를 둘 폴더 (api 가 읽는 tls/)")
    init.add_argument("--ca-dir", required=True, help="CA 개인키를 둘 폴더 — api 에 마운트하지 않는 곳 (tls-ca/)")
    init.add_argument("--name", action="append", default=[], help="서버 DNS 이름 (여러 번). DNS 에 없는 이름이어도 됨")
    init.add_argument("--ip", action="append", default=[], help="서버 IP (여러 번, 브라우저가 IP 로 접속할 때)")
    init.add_argument("--days", type=int, default=tlsutil.SERVER_DAYS, help="서버 인증서 유효일 (기본 730)")
    init.add_argument("--force", action="store_true", help="CA 가 이미 있어도 새로 만듦 — 모든 에이전트 재배포 필요")
    renew = sub.add_parser("tls-renew", help="같은 CA 로 서버 인증서 갱신 (에이전트 재배포 없음)")
    renew.add_argument("--dir", default="/app/tls")
    renew.add_argument("--ca-dir", required=True)
    renew.add_argument("--name", action="append", default=[], help="더할 DNS 이름")
    renew.add_argument("--ip", action="append", default=[], help="더할 IP")
    renew.add_argument("--days", type=int, default=tlsutil.SERVER_DAYS)
    st = sub.add_parser("tls-status", help="서버 인증서 이름·만료·CA 지문·문제 (오류가 있으면 종료 코드 1)")
    st.add_argument("--dir", default=None, help="기본: WLM_TLS_*_FILE")
    args = parser.parse_args()
    if args.command.startswith("tls-"):
        try:
            raise SystemExit(_tls(args))
        except tlsutil.TlsError as exc:
            raise SystemExit(f"오류: {exc}") from exc
    asyncio.run(_run(args))


def _write_atomic(path: Path, data: bytes, mode: int, group: int | None = None) -> None:
    """임시 파일 → 권한 → 이름 바꾸기. 쓰는 도중에 api 가 반쯤 쓴 키를 읽거나, 실패해 옛 키를 잃지 않게."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, mode)
        if group is not None and os.geteuid() == 0:
            try:
                os.fchown(fd, 0, group)
            except OSError as exc:   # macOS 바인드 마운트 등
                print(f"  경고: {path.name} 의 그룹을 {group} 으로 바꾸지 못했습니다 ({exc}). api(uid 10001)가 읽는지 확인하세요.")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


API_GID = 10001   # server/Dockerfile 의 wlm 계정 — 키는 0640 root:10001


def _write_server(out: Path, key, cert, ca) -> None:
    out.mkdir(parents=True, exist_ok=True)
    _write_atomic(out / "server.key", tlsutil.key_pem(key), 0o640, API_GID)
    # 리프 + CA: 중간 CA 가 없는 자체 CA 라 CA 를 붙여 두면 브라우저·에이전트가 연쇄를 바로 만든다
    _write_atomic(out / "server.crt", tlsutil.cert_pem(cert) + tlsutil.cert_pem(ca), 0o644)
    _write_atomic(out / "ca.crt", tlsutil.cert_pem(ca), 0o644)


def _print_status(st: tlsutil.TlsStatus) -> None:
    print(f"  이름(DNS) {', '.join(st.dns_names) or '-'}   IP {', '.join(st.ip_names) or '-'}")
    if st.not_after:
        print(f"  만료 {st.not_after:%Y-%m-%d} (D-{st.days_left})")
    print(f"  CA SHA-256 {st.ca_sha256 or '-'}  ({'서버 인증서와 이어짐' if st.ca_ok else '서버 인증서와 이어지지 않음'})")
    for level, text in st.problems:
        print(f"  {'[오류]' if level == 'error' else '[주의]'} {text}")


def _tls(args: argparse.Namespace) -> int:
    if args.command == "tls-status":
        s = settings
        if args.dir:
            d = Path(args.dir)
            s = replace(settings, tls_cert_file=str(d / "server.crt"), tls_key_file=str(d / "server.key"),
                        tls_ca_file=str(d / "ca.crt"))
        st = tlsutil.status(replace(s, tls_mode="on"))
        _print_status(st)
        return 1 if any(level == "error" for level, _ in st.problems) else 0

    ca_dir = Path(args.ca_dir)
    out = Path(args.out if args.command == "tls-init" else args.dir)
    if ca_dir.resolve() == out.resolve():
        raise tlsutil.TlsError("CA 개인키는 api 가 읽는 폴더(tls/)와 다른 곳(tls-ca/)에 두어야 합니다 — "
                               "서버가 뚫려도 가짜 인증서를 만들 수 없게.")
    if args.command == "tls-init":
        if (ca_dir / "ca.key").exists() and not args.force:
            raise tlsutil.TlsError(f"이미 CA 가 있습니다({ca_dir / 'ca.key'}). 새 CA 를 만들면 모든 에이전트를 다시 배포해야 합니다. "
                                   "서버 인증서만 새로 만들려면 tls-renew, 정말 새로 만들려면 --force.")
        ca_key, ca = tlsutil.issue_ca(args.name, args.ip)
        key, cert = tlsutil.issue_server(ca_key, ca, args.name, args.ip, days=args.days)
        ca_dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(ca_dir / "ca.key", tlsutil.key_pem(ca_key), 0o600)
        _write_atomic(ca_dir / "ca.crt", tlsutil.cert_pem(ca), 0o644)
        _write_server(out, key, cert, ca)
        print(f"자체 CA 와 서버 인증서를 만들었습니다: {out}/server.crt·server.key·ca.crt, CA 개인키 {ca_dir}/ca.key")
        print(f"  CA 개인키({ca_dir})는 오프라인 매체로 옮겨 따로 보관하세요 — 2년마다 tls-renew 에 필요합니다.")
    else:
        ca_key, ca = tlsutil.load_key(str(ca_dir / "ca.key")), tlsutil.load_certs(str(ca_dir / "ca.crt"))[0]
        deployed = out / "ca.crt"
        if deployed.exists() and tlsutil.load_certs(str(deployed))[0] != ca:
            raise tlsutil.TlsError(f"{deployed} 와 {ca_dir}/ca.crt 가 다른 CA 입니다. 에이전트가 믿는 CA 의 키로 갱신해야 합니다.")
        names, ips = list(args.name), list(args.ip)
        current = out / "server.crt"
        if current.exists():
            dns, addrs = tlsutil.san_names(tlsutil.load_certs(str(current))[0])
            names, ips = dns + names, addrs + ips
        key, cert = tlsutil.issue_server(ca_key, ca, names, ips, days=args.days)
        _write_server(out, key, cert, ca)
        print(f"서버 인증서를 갱신했습니다: {out}/server.crt (CA 는 그대로라 에이전트 재배포 없음)")
        print("  반영: docker compose -f docker-compose.yml restart api")
    # 공개 주소(WLM_PUBLIC_URL) 점검은 빼고 본다 — 설치 중의 일회성 컨테이너에는 .env 가 없고, 주소는 켤 때 바꾼다
    st = tlsutil.status(replace(settings, tls_mode="on", tls_cert_file=str(out / "server.crt"),
                                tls_key_file=str(out / "server.key"), tls_ca_file=str(out / "ca.crt"),
                                public_url=f"https://{tlsutil.san_names(cert)[0][0]}"),
                        now=datetime.now(UTC))
    _print_status(st)
    return 0


if __name__ == "__main__":
    main()
