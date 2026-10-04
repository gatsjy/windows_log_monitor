#!/usr/bin/env bash
# 폐쇄망 서버 설치·업그레이드 — 반입 묶음을 푼 폴더에서 실행한다. 자세한 절차: docs/AIRGAP.md
#
#   처음 설치:  sudo ./deploy/airgap/install.sh --public-url http://logmon.corp.local:8080 [--syslog]
#   업그레이드: sudo ./deploy/airgap/install.sh --upgrade [--syslog]
#
#   --target DIR      설치 위치 (기본 /opt/log-monitor). 묶음 폴더와 달라도 된다.
#   --public-url URL  사용자가 접속하는 주소 (알림 메일의 링크). 처음 설치 때 필요
#   --port N          웹 화면 포트 (기본 8080, 사용자가 접속)
#   --ingest-port N   에이전트 로그 수집 전용 포트 (기본 6976, 수집 API 만 열림)
#   --syslog          syslog 수신기(514/udp·tcp, 1514/tcp)도 기동
#   --upgrade         기존 설치를 새 버전으로: DB 백업 → 이미지 → 프로그램 파일 교체 → 재기동
#                     .env, config/(화면에서 고친 대시보드·규칙), archive/ 는 그대로 둔다.
#
# 인터넷에 접속하지 않는다 (이미지는 묶음에서 불러오고, 기동 시 내려받기를 막는다).
set -euo pipefail

BUNDLE=$(cd "$(dirname "$0")/../.." && pwd)
TARGET=/opt/log-monitor
PUBLIC_URL=""
PORT=""
INGEST_PORT=""
SYSLOG=0
UPGRADE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET=$2; shift 2 ;;
    --public-url) PUBLIC_URL=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --ingest-port) INGEST_PORT=$2; shift 2 ;;
    --syslog) SYSLOG=1; shift ;;
    --upgrade) UPGRADE=1; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션: $1 (--help 참고)" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\n[중단] %s\n' "$*" >&2; exit 1; }
info() { sed -n "s/^$1=//p" "$BUNDLE/VERSION"; }
env_get() { sed -n "s/^$1=\([^ #]*\).*/\1/p" "$TARGET/.env" | tail -1; }
env_set() {  # 값에 | 가 없다는 전제 (무작위 hex·URL·이미지 이름만 넣는다)
  if grep -q "^$1=" "$TARGET/.env"; then sed -i "s|^$1=.*|$1=$2|" "$TARGET/.env"; else echo "$1=$2" >> "$TARGET/.env"; fi
}
rand_hex() { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

[ -f "$BUNDLE/VERSION" ] || die "묶음 폴더가 아닙니다 (VERSION 없음): $BUNDLE"
VERSION=$(info version)
PLATFORM=$(info platform)
API_IMAGE=$(info api_image)

# ------------------------------------------------------------------ 1. 사전 점검
step "1. 사전 점검 (버전 ${VERSION}, ${PLATFORM})"
command -v docker >/dev/null || die "docker 가 없습니다 — docs/AIRGAP.md 2단계(Docker 오프라인 설치)를 먼저 하세요"
docker compose version >/dev/null 2>&1 || die "docker compose 플러그인이 없습니다 — docs/AIRGAP.md 2단계"
docker info >/dev/null 2>&1 || die "Docker 데몬에 접속할 수 없습니다 (sudo 로 실행했는지, systemctl status docker 확인)"
case "$(uname -m)" in x86_64|amd64) HOST_ARCH=amd64 ;; aarch64|arm64) HOST_ARCH=arm64 ;; *) HOST_ARCH=$(uname -m) ;; esac
[ "linux/${HOST_ARCH}" = "$PLATFORM" ] || die "CPU 가 다릅니다: 서버 linux/${HOST_ARCH}, 묶음 ${PLATFORM} — make-bundle.sh --platform linux/${HOST_ARCH} 로 다시 만드세요"
if [ "$UPGRADE" = 1 ]; then
  [ -f "$TARGET/.env" ] || die "업그레이드할 설치가 없습니다: $TARGET/.env"
else
  [ ! -f "$TARGET/.env" ] || die "이미 설치되어 있습니다: $TARGET — 새 버전이면 --upgrade 를 붙이세요"
  [ -n "$PUBLIC_URL" ] || die "--public-url 이 필요합니다 (예: http://logmon.corp.local:8080)"
fi
echo "  Docker $(docker version --format '{{.Server.Version}}'), $(docker compose version --short 2>/dev/null || docker compose version)"

# ------------------------------------------------------------------ 2. 무결성
step "2. 파일 무결성 (SHA256SUMS)"
(cd "$BUNDLE" && sha256sum --quiet -c SHA256SUMS) || die "체크섬이 맞지 않습니다 — 반입 중 손상 또는 변조. 묶음을 다시 반입하세요"
echo "  모든 파일 일치"

# ------------------------------------------------------------------ 3. 이미지
step "3. 컨테이너 이미지 불러오기"
gunzip -c "$BUNDLE/images/images.tar.gz" | docker load
cat "$BUNDLE/images/IMAGES.txt"

# ------------------------------------------------------------------ 4. 프로그램 파일
compose() {
  local profile=()
  [ "$SYSLOG" = 1 ] && profile=(--profile syslog)
  (cd "$TARGET" && docker compose -f docker-compose.yml "${profile[@]}" "$@")
}

if [ "$UPGRADE" = 1 ]; then
  step "4. 업그레이드 전 DB 백업"
  mkdir -p "$TARGET/backups"
  BACKUP="$TARGET/backups/before-${VERSION}-$(date +%Y%m%d-%H%M%S).dump"
  if compose ps --status running --services 2>/dev/null | grep -qx db; then
    compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > "$BACKUP" \
      || die "DB 백업 실패 — 업그레이드를 멈춥니다 ($BACKUP)"
    echo "  $(du -h "$BACKUP" | cut -f1)  $BACKUP"
  else
    echo "  db 가 꺼져 있어 백업을 건너뜁니다 (볼륨은 그대로 남습니다)"
  fi
  echo "  이전 이미지: $(env_get WLM_API_IMAGE) (되돌릴 때 .env 의 WLM_API_IMAGE 를 이 값으로)"
fi

step "5. 프로그램 파일 → ${TARGET}"
mkdir -p "$TARGET"
if [ "$BUNDLE" != "$(cd "$TARGET" && pwd)" ]; then
  # 설정(config/)·.env·보관 파일·백업은 덮어쓰지 않는다. 이미지 파일은 이미 불러왔으므로 복사하지 않는다.
  (cd "$BUNDLE" && tar -cf - --exclude=./images --exclude=./config --exclude=./.env --exclude=./archive \
     --exclude=./backups --exclude=./SHA256SUMS .) | (cd "$TARGET" && tar -xf -)
fi
mkdir -p "$TARGET/config" "$TARGET/archive"
# 새 기본 설정: 없는 파일은 복사, 이미 있는데 내용이 다르면 *.new 로 옆에 둔다 (운영에서 고친 내용 보호)
NEWS=()
while IFS= read -r -d '' src; do
  rel=${src#"$BUNDLE/config/"}
  dst="$TARGET/config/$rel"
  mkdir -p "$(dirname "$dst")"
  if [ ! -e "$dst" ]; then
    cp "$src" "$dst"
  elif ! cmp -s "$src" "$dst"; then
    cp "$src" "$dst.new"
    NEWS+=("config/$rel.new")
  fi
done < <(find "$BUNDLE/config" -type f ! -path '*/oracle/*' -print0)
[ ${#NEWS[@]} -eq 0 ] || printf '  새 기본값과 다른 설정 (직접 비교·반영 후 *.new 삭제):\n%s\n' "$(printf '    %s\n' "${NEWS[@]}")"

# ------------------------------------------------------------------ 6. .env
step "6. 설정 파일 (.env)"
if [ "$UPGRADE" = 0 ]; then
  cp "$TARGET/.env.example" "$TARGET/.env"
  INGEST_KEY=$(rand_hex 24)
  env_set POSTGRES_PASSWORD "$(rand_hex 24)"
  env_set WLM_INGEST_API_KEYS "$INGEST_KEY"
  env_set WLM_COLLECTOR_API_KEY "$INGEST_KEY"
  env_set WLM_SECRET_KEY "$(rand_hex 32)"
  env_set WLM_PUBLIC_URL "$PUBLIC_URL"
  env_set WLM_API_DOCS false
  echo "  비밀번호·수집 API 키·암호화 키를 무작위로 만들었습니다 → $TARGET/.env (권한 600)"
  echo "  ※ .env 는 DB 백업과 따로 안전하게 보관하세요 (WLM_SECRET_KEY 를 잃으면 화면에서 넣은 비밀값을 다시 입력해야 함)"
fi
env_set WLM_API_IMAGE "$API_IMAGE"
[ -z "$PORT" ] || env_set WLM_PORT "$PORT"
[ -z "$INGEST_PORT" ] || env_set WLM_INGEST_PORT "$INGEST_PORT"
chmod 600 "$TARGET/.env"
LEFT=$(grep -E '^[A-Z_]+=change-me' "$TARGET/.env" | cut -d= -f1 | tr '\n' ' ' || true)
[ -z "$LEFT" ] || echo "  [확인 필요] 아직 예시 값: ${LEFT}"

# ------------------------------------------------------------------ 7. 권한
step "7. 폴더 권한"
if [ "$(id -u)" = 0 ]; then
  chown -R 10001:10001 "$TARGET/config" "$TARGET/archive"   # 컨테이너 사용자(uid 10001)가 화면 저장·보관 파일 기록
  if command -v getenforce >/dev/null && [ "$(getenforce)" = Enforcing ]; then
    chcon -R -t container_file_t "$TARGET/config" "$TARGET/archive" "$TARGET/collector"
    echo "  SELinux: 컨테이너가 읽고 쓸 수 있게 레이블 지정"
  fi
  echo "  config/, archive/ → uid 10001"
else
  echo "  [확인 필요] root 가 아니라 권한을 바꾸지 못했습니다: sudo chown -R 10001:10001 $TARGET/config $TARGET/archive"
fi

# ------------------------------------------------------------------ 8. 기동
step "8. 기동"
compose up -d --no-build --pull never --remove-orphans
printf '  상태 확인 '
for _ in $(seq 1 60); do
  if compose exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" >/dev/null 2>&1; then
    OK=1; break
  fi
  printf '.'; sleep 2
done
echo
[ "${OK:-0}" = 1 ] || die "2분 안에 기동하지 않았습니다 — (cd $TARGET && docker compose -f docker-compose.yml logs api db)"
compose ps

step "완료 — 버전 ${VERSION}"
PORT=$(env_get WLM_PORT); PORT=${PORT:-8080}
IPORT=$(env_get WLM_INGEST_PORT); IPORT=${IPORT:-6976}
echo "  웹 화면: $(env_get WLM_PUBLIC_URL)  (포트 ${PORT}, 사용자·관리자 PC 에서만 접근하도록 방화벽 권장)"
echo "  에이전트 수집 포트: ${IPORT}/tcp  (모든 PC·서버 → 이 서버)"
if [ "$UPGRADE" = 0 ]; then
  echo "  첫 로그인: 아이디 admin, 임시 비밀번호는 아래 한 줄 (첫 로그인 때 변경)"
  compose logs api 2>/dev/null | grep -m1 -o '임시 비밀번호 [^ ]*' | sed 's/^/    /' \
    || echo "    (로그에서 찾지 못함) docker compose -f docker-compose.yml exec api python -m app.cli reset-password admin"
  echo "  에이전트 배포: 화면 '수집 PC > 에이전트 설치' 에서 설정이 채워진 설치 묶음(zip)을 내려받아 PC 에 배포"
  echo "                 (Fluent Bit 설치 파일 포함: $(ls "$TARGET/agent-installers" 2>/dev/null | grep -v -e README -e sha256 | tr '\n' ' '))"
fi
echo "  다음: docs/AIRGAP.md 5단계(에이전트 배포)·6단계(설치 확인)"
