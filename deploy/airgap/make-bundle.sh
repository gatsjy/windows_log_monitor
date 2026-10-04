#!/usr/bin/env bash
# 폐쇄망 반입 묶음 만들기 — 인터넷이 되는 PC(Docker 설치)에서 실행한다. 자세한 절차: docs/AIRGAP.md
#
#   deploy/airgap/make-bundle.sh [--platform linux/amd64] [--out dist]
#
#   --platform  폐쇄망 서버의 CPU. 일반 서버는 linux/amd64(기본), ARM 서버는 linux/arm64.
#               Apple Silicon Mac 에서 만들어도 이 값으로 빌드·다운로드한다 (그냥 빌드하면 arm64 가 되어 서버에서 안 뜬다).
#   --out       결과 폴더 (기본 dist)
#   --no-agent-download  Fluent Bit Windows 설치 파일을 자동으로 받지 않음 (agent-installers 에 직접 넣은 것만 사용)
#   FLUENTBIT_VERSION=4.0.14  에이전트용 Fluent Bit 버전 (서버 수신기와 같은 4.0 계열 권장)
#
# 결과: <out>/log-monitor-<버전>-<arch>.tar.gz 와 .sha256
#   안에: 컨테이너 이미지(images/images.tar.gz), 실행 파일(compose·설정·에이전트·문서·소스), SHA256SUMS, VERSION
#   deploy/airgap/agent-installers/ 에 넣어 둔 Fluent Bit 설치 파일도 함께 묶는다.
set -euo pipefail

cd "$(dirname "$0")/../.."
PLATFORM=linux/amd64
OUT=dist
AGENT_DOWNLOAD=1
FLUENTBIT_VERSION=${FLUENTBIT_VERSION:-4.0.14}
while [ $# -gt 0 ]; do
  case "$1" in
    --platform) PLATFORM=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --no-agent-download) AGENT_DOWNLOAD=0; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션: $1 (--help 참고)" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
# macOS tar(bsdtar)는 Apple 확장 속성을 같이 담아 리눅스에서 경고가 쏟아진다 → 빼고 묶는다
TAR_OPTS=()
if tar --version 2>/dev/null | grep -q bsdtar; then TAR_OPTS=(--no-xattrs --no-mac-metadata); export COPYFILE_DISABLE=1; fi
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' server/app/__init__.py)
ARCH=${PLATFORM#linux/}
NAME="log-monitor-${VERSION}-${ARCH}"
API_IMAGE="log-monitor-api:${VERSION}"
STAGE="${OUT}/${NAME}"
[ -n "$VERSION" ] || { echo "server/app/__init__.py 에서 버전을 읽지 못함" >&2; exit 1; }

step "사전 점검"
docker version --format '  Docker {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
docker buildx version >/dev/null || { echo "docker buildx 가 필요합니다" >&2; exit 1; }
# compose 파일에 적힌 외부 이미지 (db, collector) — compose 를 바꾸면 자동으로 따라온다
EXT_IMAGES=$(docker compose -f docker-compose.yml --profile syslog config --images | grep -v '^log-monitor-api' | sort -u)
echo "  버전 ${VERSION}, 대상 ${PLATFORM}"
echo "  이미지: ${API_IMAGE} $(echo "$EXT_IMAGES" | tr '\n' ' ')"

step "API 이미지 빌드 (${PLATFORM})"
docker buildx build --platform "$PLATFORM" -f server/Dockerfile --target runtime -t "$API_IMAGE" --load .

step "외부 이미지 내려받기 (${PLATFORM})"
for image in $EXT_IMAGES; do
  docker pull --quiet --platform "$PLATFORM" "$image"
done

if [ "$AGENT_DOWNLOAD" = 1 ]; then
  step "에이전트용 Fluent Bit Windows 설치 파일 (${FLUENTBIT_VERSION})"
  # 폐쇄망 PC 에도 그대로 반입할 수 있게 묶음에 넣는다 → 서버 화면 '에이전트 설치 묶음' zip 에 자동 포함
  FB_DIR=deploy/airgap/agent-installers
  FB_ZIP="fluent-bit-${FLUENTBIT_VERSION}-win64.zip"
  mkdir -p "$FB_DIR"
  if [ ! -f "$FB_DIR/$FB_ZIP" ]; then
    curl -fL --retry 3 -o "$FB_DIR/$FB_ZIP.part" "https://packages.fluentbit.io/windows/$FB_ZIP"
    curl -fsSL --retry 3 -o "$FB_DIR/$FB_ZIP.sha256" "https://packages.fluentbit.io/windows/$FB_ZIP.sha256"
    mv "$FB_DIR/$FB_ZIP.part" "$FB_DIR/$FB_ZIP"
  fi
  (cd "$FB_DIR" && sha256 -c "$FB_ZIP.sha256") || { echo "Fluent Bit 설치 파일 해시가 맞지 않습니다 — 지우고 다시 실행하세요" >&2; exit 1; }
fi

step "묶음 폴더 만들기: ${STAGE}"
rm -rf "$STAGE"
mkdir -p "$STAGE/images"
# 운영에 필요한 파일만. 개발용 override, .env(비밀값), 보관 파일, 캐시는 넣지 않는다.
tar "${TAR_OPTS[@]}" -cf - \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' --exclude='.ruff_cache' --exclude='.DS_Store' \
  --exclude='config/oracle' --exclude='deploy/airgap/agent-installers' \
  docker-compose.yml .env.example .dockerignore README.md AGENTS.md \
  agent collector config docs server web deploy tools/simulate.py \
  | tar -xf - -C "$STAGE"
if [ -d deploy/airgap/agent-installers ] && [ -n "$(ls -A deploy/airgap/agent-installers | grep -v README.md || true)" ]; then
  mkdir -p "$STAGE/agent-installers"
  find deploy/airgap/agent-installers -type f ! -name README.md -exec cp {} "$STAGE/agent-installers/" \;
  echo "  에이전트 설치 파일: $(ls "$STAGE/agent-installers" | tr '\n' ' ')"
else
  echo "  (참고) deploy/airgap/agent-installers/ 가 비어 있음 — Fluent Bit 설치 파일은 따로 반입해야 합니다"
fi

step "이미지 저장 (${PLATFORM}만)"
# shellcheck disable=SC2086
docker save --platform "$PLATFORM" "$API_IMAGE" $EXT_IMAGES | gzip -6 > "$STAGE/images/images.tar.gz"
{
  echo "version=${VERSION}"
  echo "platform=${PLATFORM}"
  echo "api_image=${API_IMAGE}"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "built_on=$(uname -sm)"
} > "$STAGE/VERSION"
{
  for image in "$API_IMAGE" $EXT_IMAGES; do
    echo "${image} $(docker image inspect --format '{{.Id}}' "$image")"
  done
} > "$STAGE/images/IMAGES.txt"
# 이미지에 들어간 파이썬 패키지 버전 (requirements.txt 는 범위만 적혀 있어 빌드 시점마다 다를 수 있다 → 반입 기록용)
docker run --rm --platform "$PLATFORM" --entrypoint pip "$API_IMAGE" freeze --all > "$STAGE/images/PACKAGES.txt"
echo "  파이썬 패키지 $(wc -l < "$STAGE/images/PACKAGES.txt" | tr -d ' ')개 → images/PACKAGES.txt"

step "체크섬"
(cd "$STAGE" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's|^\./||' | while read -r f; do sha256 "$f"; done > SHA256SUMS)
tar "${TAR_OPTS[@]}" -czf "${OUT}/${NAME}.tar.gz" -C "$OUT" "$NAME"
(cd "$OUT" && sha256 "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256")
rm -rf "$STAGE"

step "완료"
ls -lh "${OUT}/${NAME}.tar.gz"
cat "${OUT}/${NAME}.tar.gz.sha256"
echo "  반입 신청서에 위 SHA-256 을 적고, 폐쇄망 서버에서 같은 값인지 확인한 뒤 설치합니다 (docs/AIRGAP.md 3·4단계)."
