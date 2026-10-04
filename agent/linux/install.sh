#!/usr/bin/env bash
# Log Monitor Linux 에이전트 설치 (Fluent Bit 을 wlm-agent systemd 서비스로 실행)
#   sudo ./install.sh <서버주소> <포트> <수집 API 키>
# 다시 실행하면 설정을 갱신하고 재시작한다.
set -euo pipefail

SERVER_HOST=${1:?사용법: sudo ./install.sh <서버주소> <포트> <수집 API 키>}
SERVER_PORT=${2:-6976}   # 서버의 수집 전용 포트 (WLM_INGEST_PORT)
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

install -d -m 700 /etc/wlm-agent /var/lib/wlm-agent /var/lib/wlm-agent/buffer
sed -e "s|@SERVER_HOST@|${SERVER_HOST}|g" \
    -e "s|@SERVER_PORT@|${SERVER_PORT}|g" \
    -e "s|@API_KEY@|${API_KEY}|g" \
    -e "s|@AGENT_HOST@|${AGENT_HOST}|g" \
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
