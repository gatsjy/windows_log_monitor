"""에이전트 설치 묶음 내려받기 — 폐쇄망 PC 에 반입·배포하기 위한 zip 하나.

  log-monitor-agent-windows/
    install.cmd            관리자 권한으로 실행 (GPO·SCCM 은 install.cmd /quiet)
    install.ps1, fluent-bit.yaml, README.md
    settings.json          이 서버의 주소·수집 포트(6976)·API 키·선택 항목
    fluent-bit/            Fluent Bit 설치 파일 (반입 묶음의 agent-installers 에 있으면)
    설치방법.txt

API 키가 들어가므로 관리자만 받을 수 있고, 내려받을 때마다 감사로그에 남긴다(키 값은 기록하지 않음).
"""

from __future__ import annotations

import io
import json
import re
import shlex
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from .. import __version__, db
from ..auth.deps import client_ip, require_permission
from ..auth.service import User
from ..config import settings

router = APIRouter(tags=["agents"])

_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]{0,252}|\[?[0-9A-Fa-f:]{2,45}\]?")
INSTALLER_PATTERNS = {
    "windows": ("fluent-bit-*-win64.zip", "fluent-bit-*-win64.exe"),
    "linux": ("*.rpm", "*.deb"),
}


def _installers(os_name: str) -> list[Path]:
    """agent-installers 안의 설치 파일 (하위 폴더 windows/, linux/ 도 찾는다). 같은 종류는 최신 이름 하나만."""
    base = Path(settings.agent_installers_dir)
    found: list[Path] = []
    for pattern in INSTALLER_PATTERNS[os_name]:
        files = sorted({*base.glob(pattern), *base.glob(f"*/{pattern}")}, key=lambda p: p.name)
        if os_name == "windows" and files:
            found.append(files[-1])
        else:
            found.extend(files)
    return [f for f in found if f.is_file()]


def _guide(os_name: str, server: str, port: int, installers: list[Path]) -> str:
    fb = ", ".join(f.name for f in installers) or "없음 — Fluent Bit 을 먼저 설치하세요"
    if os_name == "windows":
        steps = [
            "1. 이 폴더를 PC 에 복사합니다 (예: C:\\Temp\\log-monitor-agent).",
            "2. install.cmd 를 마우스 오른쪽 단추 > '관리자 권한으로 실행'.",
            "   - 여러 대에 배포할 때(GPO 시작 스크립트·SCCM): install.cmd /quiet",
            "3. 30초 안에 Log Monitor 화면의 '수집 PC' 목록에 나타나면 끝입니다.",
        ]
    else:
        steps = [
            "1. 이 폴더를 서버에 복사합니다.",
            "2. sudo ./install-configured.sh",
            "   - packages/ 에 Fluent Bit 패키지가 있으면 먼저 설치합니다.",
            "3. 30초 안에 '수집 PC' 목록에 나타나면 끝입니다.",
        ]
    lines = [
        "Log Monitor 에이전트 설치 묶음",
        f"만든 시각: {datetime.now(UTC):%Y-%m-%d %H:%M} UTC · 서버 버전 {__version__}",
        f"보낼 곳: {server}:{port} (수집 전용 포트)",
        f"Fluent Bit 설치 파일: {fb}",
        "",
        *steps,
        "",
        "주의: settings.json(또는 install-configured.sh)에는 수집 API 키가 들어 있습니다. 배포가 끝나면 지우세요.",
        "방화벽: PC → 서버 TCP " + str(port) + " 이 열려 있어야 합니다.",
    ]
    return "\ufeff" + "\r\n".join(lines) + "\r\n"  # 메모장에서 한글이 깨지지 않도록 BOM + CRLF


@router.get("/api/agents/package/info")
async def package_info(admin: User = Depends(require_permission("agents.deploy"))):
    """내려받기 창에 보여 줄 정보: 기본 서버 주소·포트, 들어갈 설치 파일."""
    from urllib.parse import urlsplit

    return {
        "server": urlsplit(settings.public_url).hostname or "",
        "port": settings.ingest_public_port,
        "installers": {os_name: [f.name for f in _installers(os_name)] for os_name in INSTALLER_PATTERNS},
        "has_key": bool(settings.ingest_api_keys),
    }


@router.get("/api/agents/package")
async def agent_package(
    request: Request,
    os: str = Query("windows", pattern="^(windows|linux)$"),
    server: str = Query(..., min_length=1, max_length=255),
    port: int | None = Query(None, ge=1, le=65535),
    iis: bool = False,
    mssql: bool = False,
    admin: User = Depends(require_permission("agents.deploy")),
):
    server = server.strip()
    if not _HOST.fullmatch(server):
        raise HTTPException(422, "서버 주소는 호스트 이름 또는 IP 만 적습니다 (예: logmon.corp.local, 10.0.0.10)")
    if not settings.ingest_api_keys:
        raise HTTPException(409, "서버에 수집 API 키(WLM_INGEST_API_KEYS)가 설정되어 있지 않습니다")
    port = port or settings.ingest_public_port
    key = settings.ingest_api_keys[0]
    source = Path(settings.agent_dir) / os
    if not source.is_dir():
        raise HTTPException(500, f"에이전트 파일이 없습니다: {source}")
    installers = _installers(os)
    prefix = f"log-monitor-agent-{os}"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, f"{prefix}/{path.relative_to(source).as_posix()}")
        if os == "windows":
            conf = {"ServerHost": server, "ServerPort": port, "ApiKey": key, "Iis": iis, "MssqlErrorlog": mssql}
            zf.writestr(f"{prefix}/settings.json", json.dumps(conf, ensure_ascii=False, indent=2))
            for f in installers:
                zf.write(f, f"{prefix}/fluent-bit/{f.name}")
        else:
            script = (
                "#!/usr/bin/env bash\n# Log Monitor 서버에서 내려받은, 이 서버로 보내도록 설정된 설치 스크립트\n"
                "set -euo pipefail\ncd \"$(dirname \"$0\")\"\n"
                "if ! command -v fluent-bit >/dev/null 2>&1 && [ ! -x /opt/fluent-bit/bin/fluent-bit ]; then\n"
                "  for pkg in packages/*.rpm packages/*.deb; do\n"
                "    [ -e \"$pkg\" ] || continue\n"
                "    case \"$pkg\" in *.rpm) rpm -Uvh \"$pkg\" ;; *.deb) dpkg -i \"$pkg\" ;; esac\n"
                "    break\n  done\nfi\n"
                f"exec ./install.sh {shlex.quote(server)} {port} {shlex.quote(key)}\n"
            )
            info = zipfile.ZipInfo(f"{prefix}/install-configured.sh")
            info.external_attr = 0o755 << 16
            zf.writestr(info, script)
            for f in installers:
                zf.write(f, f"{prefix}/packages/{f.name}")
        zf.writestr(f"{prefix}/설치방법.txt", _guide(os, server, port, installers))

    await db.audit(admin.username, "agents.package.download", os,
                   {"server": server, "port": port, "iis": iis, "mssql": mssql,
                    "installers": [f.name for f in installers]}, actor_ip=client_ip(request))
    filename = f"{prefix}-{server}.zip"
    return Response(buffer.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})
