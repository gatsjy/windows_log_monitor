#!/usr/bin/env bash
# Log Monitor Linux 에이전트 설치 (Fluent Bit 을 wlm-agent systemd 서비스로 실행)
#   sudo ./install.sh <서버주소> <포트> <수집 API 키>
#   HTTPS(TLS): sudo TLS_CA_FILE=./ca.crt [TLS_SERVER_NAME=<인증서 DNS 이름>] ./install.sh <서버주소> <포트> <키>
#     설치 묶음의 install-configured.sh 는 서버가 TLS 를 켰으면 이 두 값을 채워서 부른다.
# 다시 실행하면 설정을 갱신하고 재시작한다.
set -euo pipefail

TLS_CA_FILE=${TLS_CA_FILE:-}           # 서버 인증서를 발급한 CA (PEM). 있으면 TLS 로 보낸다
TLS_SERVER_NAME=${TLS_SERVER_NAME:-}   # 서버 인증서의 DNS 이름. 비우면 서버 주소 (IP 면 필수)
if [ -n "$TLS_CA_FILE" ]; then DEFAULT_PORT=6977; else DEFAULT_PORT=6976; fi
SERVER_HOST=${1:?사용법: sudo ./install.sh <서버주소> <포트> <수집 API 키>}
SERVER_PORT=${2:-$DEFAULT_PORT}   # 서버의 수집 전용 포트 (평문 WLM_INGEST_PORT 6976, TLS WLM_INGEST_TLS_PORT 6977)
API_KEY=${3:?수집 API 키가 필요합니다}
FLUENT_BIT=${FLUENT_BIT:-/opt/fluent-bit/bin/fluent-bit}
AGENT_HOST=${AGENT_HOST:-$(hostname -s)}
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
  echo "root 권한이 필요합니다 (sudo)" >&2
  exit 1
fi
if [ ! -x "$FLUENT_BIT" ]; then
  echo "Fluent Bit 이 없습니다: $FLUENT_BIT" >&2
  echo "설치: https://docs.fluentbit.io/manual/installation/linux  (또는 FLUENT_BIT=/경로 지정)" >&2
  exit 1
fi
if [[ "$API_KEY" =~ [\|\&\\] ]]; then
  echo "API 키에 | & \\ 문자는 쓸 수 없습니다" >&2
  exit 1
fi

# TLS: 이름과 CA 를 설치 전에 확인한다. 잘못되면 Fluent Bit 이 뜨지 못하고 재시작만 반복한다(ca_file 오류는 기동 실패).
sed_tls=()
if [ -n "$TLS_CA_FILE" ]; then
  if [ ! -f "$TLS_CA_FILE" ] || ! grep -q -- "-----BEGIN CERTIFICATE-----" "$TLS_CA_FILE"; then
    echo "CA 인증서(PEM) 파일이 아닙니다: $TLS_CA_FILE" >&2
    exit 1
  fi
  if [ -z "$TLS_SERVER_NAME" ]; then
    # Fluent Bit 은 IP SAN 으로 이름을 검증하지 못한다 → 서버 주소가 IP 면 인증서의 DNS 이름을 따로 받는다
    if [[ "$SERVER_HOST" == *:* || ! "$SERVER_HOST" =~ [A-Za-z] ]]; then
      echo "서버 주소가 IP($SERVER_HOST)이면 TLS_SERVER_NAME 에 서버 인증서의 DNS 이름을 주세요" >&2
      exit 1
    fi
    TLS_SERVER_NAME=$SERVER_HOST
  fi
  # DNS 이름만 (영문자 1자 이상). 설정 파일과 sed 치환에 그대로 들어가므로 | & \ 등은 이 정규식에서 걸러진다
  name_re='^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
  if [ "${#TLS_SERVER_NAME}" -gt 253 ] || ! [[ "$TLS_SERVER_NAME" =~ $name_re ]] || ! [[ "$TLS_SERVER_NAME" =~ [A-Za-z] ]]; then
    echo "TLS_SERVER_NAME 이 DNS 이름이 아닙니다: $TLS_SERVER_NAME (영문자·숫자·-·. 만)" >&2
    exit 1
  fi
  if command -v openssl >/dev/null 2>&1; then
    if ! openssl x509 -in "$TLS_CA_FILE" -noout -subject -enddate -fingerprint -sha256; then
      echo "CA 인증서를 읽을 수 없습니다: $TLS_CA_FILE" >&2
      exit 1
    fi
    if ! openssl x509 -in "$TLS_CA_FILE" -noout -checkend 0 >/dev/null; then
      echo "CA 인증서가 만료되었습니다: $TLS_CA_FILE" >&2
      exit 1
    fi
  fi
  # 4칸 + '#' + 3칸으로 적힌 키 줄만 6칸 들여쓰기로 푼다 (install.ps1 Enable-Block 과 같은 결과, 설명 줄은 그대로)
  sed_tls=(-e '/# @@TLS_BEGIN/,/# @@TLS_END/ s/^\( *\)# \(  \)/\1\2/')
  echo "보낼 곳: ${SERVER_HOST}:${SERVER_PORT} (TLS, 인증서 이름 ${TLS_SERVER_NAME})"
else
  if [ -n "$TLS_SERVER_NAME" ]; then
    echo "경고: TLS_CA_FILE 이 없어 TLS_SERVER_NAME 은 쓰지 않습니다 (평문 HTTP)" >&2
  fi
  TLS_SERVER_NAME=""
  echo "보낼 곳: ${SERVER_HOST}:${SERVER_PORT} (평문 HTTP)"
fi

install -d -m 700 /etc/wlm-agent /var/lib/wlm-agent /var/lib/wlm-agent/buffer
if [ -n "$TLS_CA_FILE" ] && ! [ "$TLS_CA_FILE" -ef /etc/wlm-agent/ca.crt ]; then
  install -m 644 "$TLS_CA_FILE" /etc/wlm-agent/ca.crt   # 틀의 tls.ca_file 위치
fi
# sed_tls 는 비어 있을 수 있다: set -u 인 옛 bash(4.3 이하)에서도 되도록 ${배열[@]+...} 꼴로 편다
sed -e "s|@SERVER_HOST@|${SERVER_HOST}|g" \
    -e "s|@SERVER_PORT@|${SERVER_PORT}|g" \
    -e "s|@API_KEY@|${API_KEY}|g" \
    -e "s|@AGENT_HOST@|${AGENT_HOST}|g" \
    -e "s|@TLS_SERVER_NAME@|${TLS_SERVER_NAME}|g" \
    ${sed_tls[@]+"${sed_tls[@]}"} \
    "$HERE/fluent-bit.yaml" > /etc/wlm-agent/fluent-bit.yaml
chmod 600 /etc/wlm-agent/fluent-bit.yaml   # API 키 포함

cat > /etc/systemd/system/wlm-agent.service <<EOF
[Unit]
Description=Log Monitor agent (Fluent Bit)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${FLUENT_BIT} -c /etc/wlm-agent/fluent-bit.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now wlm-agent
systemctl restart wlm-agent
sleep 2
systemctl --no-pager --lines=5 status wlm-agent || true
echo "완료: 30초 안에 서버의 '수집 PC' 화면에 ${AGENT_HOST} 가 나타납니다."
