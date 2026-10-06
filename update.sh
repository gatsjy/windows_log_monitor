#!/usr/bin/env bash
# Log Monitor — 폐쇄망 패치 즉시 적용 스크립트 (빌드 없이 1초 완료)
set -e

echo "==> Log Monitor 패치를 적용합니다..."

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose up -d --no-build --pull never
    docker compose restart api
    echo ""
    echo "==> [성공] 최신 백엔드 로직과 웹 UI가 즉시 반영되었습니다!"
    echo "    웹 브라우저에서 'Ctrl + F5' (강력 새로고침)를 눌러 확인하세요."
else
    echo "[오류] docker compose 명령어를 실행할 수 없습니다." >&2
    exit 1
fi
