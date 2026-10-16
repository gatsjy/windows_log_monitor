#!/usr/bin/env bash
# CI(B-06): agent/linux/install.sh 를 실제로 돌려 본다 (컨테이너 안, root, systemctl·Fluent Bit 은 흉내).
#   docker run --rm -v "$PWD:/repo:ro" -v /tmp/agent-render:/render:ro rockylinux/rockylinux:9 bash /repo/tools/ci/test_install_sh.sh
# /render 는 tools/ci/render_agent_configs.py 의 출력 — 설치 스크립트가 만든 설정이 그 재구현과 바이트까지 같아야 한다.
# openssl 이 있는 이미지(Rocky)와 없는 이미지(Debian slim) 둘 다에서 돈다.
set -euo pipefail

REPO=${REPO:-/repo}
RENDER=${RENDER:-/render}
FIX="$REPO/tools/ci/fixtures/ci-ca.crt"
WORK=$(mktemp -d)
fail() { echo "FAIL: $*" >&2; exit 1; }
same() { [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }   # cmp 가 없는 이미지도 있다 (Rocky 최소 이미지)

# 흉내: Fluent Bit 실행 파일, systemctl (서비스 등록은 확인하지 않는다)
mkdir -p /opt/fluent-bit/bin /etc/systemd/system
printf '#!/bin/sh\nexit 0\n' > /opt/fluent-bit/bin/fluent-bit
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl
chmod +x /opt/fluent-bit/bin/fluent-bit /usr/local/bin/systemctl
cp -r "$REPO/agent/linux" "$WORK/pkg"
cd "$WORK/pkg"
SHA=$(python3 "$REPO/tools/ci/render_agent_configs.py" --ca-sha256 "$FIX" 2>/dev/null || true)
if [ -z "$SHA" ]; then   # 이미지에 python3 가 없으면 같은 방법(첫 블록 base64 → sha256)으로
  SHA=$(sed -n '/BEGIN CERT/,/END CERT/p' "$FIX" | sed '1d;$d' | tr -d '\r\n' | base64 -d | sha256sum | cut -d' ' -f1)
fi
run() { env AGENT_HOST=ci-agent "$@" ./install.sh logmon.ci.local ${PORT_ARG[@]+"${PORT_ARG[@]}"} ci-test-key; }
reset() { rm -rf /etc/wlm-agent; }
HAS_OPENSSL=0
command -v openssl >/dev/null 2>&1 && HAS_OPENSSL=1
echo "== install.sh 실행 시험 (openssl: $HAS_OPENSSL)"

# 1) 평문: 렌더 스크립트의 linux.yaml 과 같다
reset; PORT_ARG=(6976)
run >/dev/null || fail "plain install"
same /etc/wlm-agent/fluent-bit.yaml "$RENDER/linux.yaml" || fail "plain config differs from linux.yaml"
[ ! -e /etc/wlm-agent/ca.crt ] || fail "plain install must not install a CA"

# 2) TLS (포트를 비우면 TLS 기본 6977, 지문 일치): linux-tls.yaml 과 같다
reset; PORT_ARG=("")
run TLS_CA_FILE="$FIX" TLS_SERVER_NAME=logmon.ci.internal TLS_CA_SHA256="$SHA" >/dev/null || fail "tls install"
same /etc/wlm-agent/fluent-bit.yaml "$RENDER/linux-tls.yaml" || fail "tls config differs from linux-tls.yaml"
same /etc/wlm-agent/ca.crt <(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$FIX" | tr -d '\r') \
  || fail "installed CA differs from the fixture certificate"
[ "$(stat -c %a /etc/wlm-agent/fluent-bit.yaml)" = 600 ] || fail "config must be 600 (API key)"
[ "$(stat -c %a /etc/wlm-agent/ca.crt)" = 644 ] || fail "CA must be 644"
# 같은 파일(설치된 CA)로 다시 실행해도 된다
run TLS_CA_FILE=/etc/wlm-agent/ca.crt TLS_SERVER_NAME=logmon.ci.internal >/dev/null || fail "re-run with the installed CA"

# 3) CA 파일에 개인키·CRLF 가 섞여도 PC 에는 인증서만
reset; PORT_ARG=(""); { cat "$FIX"; printf -- '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'; } | sed 's/$/\r/' > "$WORK/mixed.crt"
run TLS_CA_FILE="$WORK/mixed.crt" TLS_SERVER_NAME=logmon.ci.internal TLS_CA_SHA256="$SHA" >/dev/null || fail "mixed CA file"
! grep -q "PRIVATE KEY" /etc/wlm-agent/ca.crt || fail "private key copied to the PC"
! grep -q $'\r' /etc/wlm-agent/ca.crt || fail "CR left in the CA"

# 4) 실패해야 하는 경우 — 설정을 쓰지 않고 멈춘다
must_fail() {  # 이름 기대문구 env...
  local name=$1 want=$2; shift 2
  reset
  local out
  if out=$(run "$@" 2>&1); then fail "$name: must fail"; fi
  grep -q -- "$want" <<<"$out" || { echo "$out" >&2; fail "$name: wrong message (want '$want')"; }
  [ ! -e /etc/wlm-agent/fluent-bit.yaml ] || fail "$name: config written"
}
must_fail "다른 CA 지문" "서버가 묶어 준 것과 다릅니다" TLS_CA_FILE="$FIX" TLS_SERVER_NAME=logmon.ci.internal TLS_CA_SHA256="$(printf '0%.0s' {1..64})"
must_fail "PEM 아님" "PEM" TLS_CA_FILE=/etc/hostname TLS_SERVER_NAME=logmon.ci.internal
printf -- '-----BEGIN CERTIFICATE-----\n@@@@ not base64 @@@@\n-----END CERTIFICATE-----\n' > "$WORK/broken.crt"
must_fail "깨진 base64" "깨졌습니다" TLS_CA_FILE="$WORK/broken.crt" TLS_SERVER_NAME=logmon.ci.internal
reset
if out=$(env AGENT_HOST=ci-agent TLS_CA_FILE="$FIX" ./install.sh 10.0.0.10 "" ci-test-key 2>&1); then fail "IP host without TLS_SERVER_NAME must fail"; fi
grep -q "TLS_SERVER_NAME" <<<"$out" || fail "IP host: wrong message"
for bad in 'a|b.corp' 'a&b.corp' 'a\b.corp' 'x.corp; rm' '10.0.0.1' '*.corp.local' $'x.corp\n  tls: off'; do
  must_fail "이름 '$bad'" "DNS 이름이 아닙니다" TLS_CA_FILE="$FIX" TLS_SERVER_NAME="$bad"
done
if [ "$HAS_OPENSSL" = 1 ]; then
  # CA 가 아닌 인증서(server.crt 를 잘못 줌)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/leaf.key" -out "$WORK/leaf.crt" \
    -subj /CN=leaf -days 30 -addext basicConstraints=critical,CA:FALSE >/dev/null 2>&1
  must_fail "CA 아님" "CA 인증서가 아닙니다" TLS_CA_FILE="$WORK/leaf.crt" TLS_SERVER_NAME=logmon.ci.internal
else
  reset; PORT_ARG=("")
  out=$(run TLS_CA_FILE="$FIX" TLS_SERVER_NAME=logmon.ci.internal TLS_CA_SHA256="$SHA" 2>&1) || fail "tls install without openssl"
  grep -q "openssl 이 없어" <<<"$out" || fail "missing openssl must be reported"
fi
echo "install.sh 시험 통과"
