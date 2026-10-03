# Linux 에이전트

Linux 서버에 Fluent Bit(Apache 2.0)를 `wlm-agent` 서비스로 설치합니다.

- 기본 수집 대상은 **systemd journal** 입니다. sshd 로그인, sudo, kernel, 각종 서비스 로그가 여기에 있습니다.
- 텍스트 로그 파일은 설정 파일의 `tail` 예시 주석을 풀어서 추가합니다.

## 설치

```bash
# 1) Fluent Bit 설치 (공식 스크립트 또는 배포판 패키지)
#    https://docs.fluentbit.io/manual/installation/linux
# 2) 이 폴더를 서버에 복사한 뒤
sudo ./install.sh 10.0.0.10 8080 <수집 API 키>
```

| 항목 | 위치 |
|---|---|
| 설정 | `/etc/wlm-agent/fluent-bit.yaml` (권한 600, API 키 포함) |
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
