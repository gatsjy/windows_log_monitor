# Linux 에이전트

Linux 서버에 Fluent Bit(Apache 2.0)를 `wlm-agent` 서비스로 설치합니다.

- 기본 수집 대상은 **systemd journal** 입니다. sshd 로그인, sudo, kernel, 각종 서비스 로그가 여기에 있습니다.
- 텍스트 로그 파일은 설정 파일의 `tail` 예시 주석을 풀어서 추가합니다.

## 설치

**권장 (폐쇄망 포함):** 화면 **수집 PC > 에이전트 설치** 에서 Linux 를 골라 설치 묶음을 받고, 압축을 푼 뒤 `sudo ./install-configured.sh`.
서버 주소·수집 포트·API 키가 채워져 있고, `packages/` 에 Fluent Bit 패키지가 있으면 먼저 설치합니다.
서버가 HTTPS 를 켰으면 묶음에 `ca.crt` 가 들어 있고, `install-configured.sh` 가 아래 TLS 변수를 채워 부릅니다(포트 6977).

```bash
# 수동: 1) Fluent Bit 설치 (배포판 패키지)  2) 이 폴더를 서버에 복사한 뒤
sudo ./install.sh 10.0.0.10 6976 <수집 API 키>     # 6976 = 서버의 수집 전용 포트 (WLM_INGEST_PORT)

# HTTPS(TLS): CA 인증서와 서버 인증서의 DNS 이름을 준다 (포트를 비우면 6977)
sudo TLS_CA_FILE=./ca.crt TLS_SERVER_NAME=logmon.corp.local [TLS_CA_SHA256=<CA 지문>] ./install.sh 10.0.0.10 6977 <수집 API 키>
```

| 환경변수 | 뜻 |
|---|---|
| `TLS_CA_FILE` | 서버 인증서를 발급한 CA 인증서(PEM). 주면 HTTPS 로 보내고 서버 인증서와 이름을 검증합니다(`tls.verify`, `tls.verify_hostname`) |
| `TLS_SERVER_NAME` | 서버 인증서의 **DNS 이름**. 비우면 서버 주소를 씁니다. 서버 주소가 IP 면 필수이고, DNS 에 등록되지 않은 이름이어도 됩니다 |
| `TLS_CA_SHA256` | 서버가 알려 준 CA 지문(첫 인증서 DER 의 SHA-256). 주면 `ca.crt` 와 대조해 다르면 멈춥니다 — 설치 묶음의 `install-configured.sh` 가 채웁니다 |

- `install.sh` 는 설치 전에 확인합니다: CA 파일이 깨지지 않은 PEM 인증서인지, 지문이 묶음과 같은지(openssl 없이도), 이름이 DNS 이름인지. `openssl` 이 있으면 CA 의 이름·만료일을 보여 주고 만료된 CA·CA 가 아닌 인증서(server.crt)는 거부, 아직 유효하지 않으면 시계를 확인하라고 알립니다. 없으면 만료·용도는 확인하지 못했다고 알립니다.
- PC 의 `/etc/wlm-agent/ca.crt` 에는 인증서만 들어갑니다(개인키·설명 글·CRLF 는 빠짐).
- 서버 주소가 IP 여도 이름은 `tls.vhost` 로 검증합니다. Fluent Bit 은 IP 로 인증서를 검증하지 못합니다.
- 검증을 끄는 옵션은 두지 않습니다. 오류는 `journalctl -u wlm-agent | grep -E 'X509|tls'` 로 봅니다. code 62 는 이름 불일치, 19·20·21 은 다른 CA, 10 은 만료입니다.

| 항목 | 위치 |
|---|---|
| 설정 | `/etc/wlm-agent/fluent-bit.yaml` (권한 600, API 키 포함) |
| CA 인증서 (TLS) | `/etc/wlm-agent/ca.crt` |
| 읽은 위치 / 장애 시 버퍼 | `/var/lib/wlm-agent/` |
| 서비스 | `systemctl status wlm-agent`, `journalctl -u wlm-agent` |

## 에이전트를 설치하지 않는 방법 (rsyslog 전달)

에이전트를 설치하기 어렵다면 rsyslog 전달 방식을 씁니다. 네트워크 장비도 같은 방식입니다.

1. 서버에서 syslog 수신기를 켭니다: `docker compose --profile syslog up -d`
2. 대상 서버의 rsyslog 에 아래 설정을 추가합니다.

```
# /etc/rsyslog.d/90-log-monitor.conf
*.* @@10.0.0.10:514     # @@ = TCP, @ = UDP
```

```bash
sudo systemctl restart rsyslog
```

## 제거

```bash
sudo systemctl disable --now wlm-agent
sudo rm -rf /etc/systemd/system/wlm-agent.service /etc/wlm-agent /var/lib/wlm-agent
sudo systemctl daemon-reload
```
