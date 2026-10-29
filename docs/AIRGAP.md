# 폐쇄망 배포 가이드

> 최종 갱신: 2026-10-16 · 버전 0.5.0 + 미출시(HTTPS·에이전트 TLS §7.5)
> 인터넷이 되지 않는 사내망 서버에 Log Monitor 를 설치·업그레이드하는 절차입니다.
> 스크립트: `deploy/airgap/make-bundle.sh`(묶음 만들기), `deploy/airgap/install.sh`(설치·업그레이드). 리허설 기록은 §13.

## 0. 한눈에 보기

```
 [인터넷 PC]                         [반입 절차]                  [폐쇄망]
 ① make-bundle.sh ─ 묶음(.tar.gz) ─┐  (Fluent Bit Windows 설치 파일 자동 포함)
 ② Docker 오프라인 설치 파일 ───────┼─▶ 해시·백신 검사·승인 ─▶ ④ 서버: Docker 설치 → install.sh
 ③ (Linux 에이전트용 패키지) ───────┘   (망연계/USB)          ⑤ 서버 화면에서 '에이전트 설치 묶음' zip 을 받아
                                                                 PC 에 배포 (PC 도 폐쇄망 — 인터넷 불필요)
                                                              ⑥ 설치 확인 체크리스트
```

| 단계 | 어디서 | 하는 일 | 결과물 |
|---|---|---|---|
| ① | 인터넷 PC (Docker 설치) | `make-bundle.sh` 실행 | `log-monitor-<버전>-amd64.tar.gz` + `.sha256` |
| ② | 인터넷 PC | 서버 OS 에 맞는 Docker Engine·Compose 설치 파일 받기 | `docker-*.tgz` 또는 `*.rpm` / `*.deb` |
| ③ | 인터넷 PC | (Linux 서버에도 설치할 때) Fluent Bit Linux 패키지 받기. Windows 용은 ①이 자동으로 받음 | `*.rpm` / `*.deb` |
| — | 반입 | 해시 확인, 백신 검사, 반입 승인·기록 | 반입 기록 (§6) |
| ④ | 폐쇄망 서버 | Docker 설치 → 묶음 풀기 → `install.sh` | 기동된 서비스 |
| ⑤ | 폐쇄망 PC·서버 | 서버 화면 '수집 PC > 에이전트 설치' 에서 zip 내려받기 → PC 에서 `install.cmd` | 수집 PC 화면에 나타남 |
| ⑥ | 폐쇄망 | 설치 확인 | 점검 기록 (§9) |

**인터넷이 필요 없는 이유:**
- 화면(UI)은 빌드·CDN·외부 글꼴 없이 서버가 그대로 제공합니다.
- 파이썬 패키지는 이미지 안에 들어 있고, 실행 중에 아무것도 내려받지 않습니다.
- Oracle 연동은 thin 모드라 Oracle Client 설치가 필요 없습니다.
- `install.sh` 는 이미지를 묶음에서 불러오고, 기동할 때 내려받기를 막습니다(`--pull never`).

## 1. 준비물 체크리스트

| 구분 | 항목 | 비고 |
|---|---|---|
| 반입 파일 | 반입 묶음 `log-monitor-<버전>-<arch>.tar.gz` (+ `.sha256`) | 약 260MB. 이미지 3개 + 설정·에이전트·문서·소스 + Fluent Bit Windows 설치 파일 |
| 반입 파일 | Docker Engine + Compose 플러그인 오프라인 설치 파일 | §4. 서버에 이미 있으면 생략 |
| 반입 파일 | (선택) Fluent Bit Linux 패키지 | §5. Windows 용은 묶음에 자동 포함 |
| 사내 정보 | 서버 IP·DNS 이름, 사용자가 접속할 주소(`--public-url`, https 권장) | 알림 메일 링크·TLS 인증서 이름(§7.5). DNS 에 등록하지 않은 이름이어도 됨 |
| 사내 정보 | (선택) 사내 PKI 서버 인증서·개인키·루트 CA | 없으면 install.sh 가 자체 CA 로 만듦 (§7.5) |
| 사내 정보 | 메일 릴레이(SMTP) 주소·포트·인증 방식 | 환경설정 화면에서 입력 |
| 사내 정보 | 사내 NTP 서버 | 모든 PC·서버 시각 일치 (ISMS 2.9.6) |
| 사내 정보 | (선택) Oracle 접속 정보: TNS 별칭 또는 SID/서비스 이름 | 환경설정 화면에서 입력 |
| 승인 | 방화벽 정책: 모든 PC → 서버 **6977/tcp**(로그 수집 TLS. 평문으로 운영 중이면 6976 도 전환 기간 동안), 사용자 PC → 서버 8080/tcp(화면 https), 장비 → 서버 514/udp·tcp, 1514/tcp | §2 |
| 승인 | 반입 승인 (정보보호 담당자) | §6 |

## 2. 서버 요구사항

| 항목 | 권장 |
|---|---|
| OS | Linux x86_64: RHEL·Rocky·AlmaLinux 8/9, Ubuntu 22.04/24.04 (커널 4.x 이상, systemd) |
| CPU 종류 | **묶음과 같아야 합니다.** 일반 서버는 `amd64`(x86_64). `uname -m` 으로 확인 |
| 사양 | PC 50대 기준 4코어 · 메모리 8GB · 디스크 100GB(SSD). 200대 이상은 8코어 · 16~32GB · 500GB+ ([PERFORMANCE.md](PERFORMANCE.md) §5) |
| 디스크 배치 | Docker 데이터(`/var/lib/docker`, DB 포함)와 `/opt/log-monitor/archive`(보관 파일)를 넉넉한 볼륨에 |
| 메모리 설정 | 기본값은 4GB 서버 기준. 8GB 이상이면 `.env` 의 `WLM_PG_*`·`WLM_*_MEM_LIMIT` 를 올림 (docs/PERFORMANCE.md §4). 기존 서버의 `.env` 는 업그레이드해도 그대로이니 직접 고칠 것 |

**포트 (방화벽):**

| 포트 | 방향 | 용도 | 필수 |
|---|---|---|---|
| **6977/tcp** (`WLM_INGEST_TLS_PORT`) | 모든 PC·서버(에이전트) → 서버 | 로그 수집 전용 **TLS** (`WLM_TLS=on`). `/api/ingest` 와 `/healthz` 만 열림 | TLS 운영 시 필수 |
| 6976/tcp (`--ingest-port`) | 모든 PC·서버(에이전트) → 서버 | 로그 수집 전용 평문. TLS 로 옮기는 동안만 — 다 옮기면 `WLM_INGEST_PLAIN=off` 로 닫음 (§7.5) | 평문 운영·전환 기간 |
| 8080/tcp (`--port`) | 사용자·관리자 PC → 서버 | 웹 화면 + API (`WLM_TLS=on` 이면 https 만). 관리 대역에서만 열 것을 권장 | 필수 |
| 514/udp, 514/tcp | 네트워크 장비·Linux → 서버 | syslog RFC3164 (`--syslog` 일 때) | 선택 |
| 1514/tcp | 장비 → 서버 | syslog RFC5424 (`--syslog` 일 때) | 선택 |
| 25/587/465 | 서버 → 사내 메일 릴레이 | 알림 메일 | 알림 사용 시 |
| 1521 등 | 서버 → 사내 Oracle | 알림을 Oracle 에 기록 | 선택 |

- DB(5432)는 밖으로 열지 않습니다(컨테이너 내부 통신만). 수집기(syslog)는 api 의 내부 포트 8003 으로 보내며 이것도 게시하지 않습니다.

## 3. [인터넷 PC] 반입 묶음 만들기

준비: Docker (Docker Desktop 또는 Linux Docker Engine) + buildx. 이 저장소 폴더에서 실행합니다.

```bash
./deploy/airgap/make-bundle.sh                        # 일반 서버 (linux/amd64)
./deploy/airgap/make-bundle.sh --platform linux/arm64 # ARM 서버일 때만
```

- **주의 (Apple Silicon Mac):** 그냥 `docker build` 하면 arm64 이미지가 되어 x86 서버에서 뜨지 않습니다. 스크립트는 기본으로 `linux/amd64` 로 빌드·다운로드합니다.
- 에이전트 설치 파일을 함께 넣으려면, 실행 전에 `deploy/airgap/agent-installers/` 에 넣어 둡니다(§5).
- Fluent Bit Windows 설치 파일(서버 수신기와 같은 4.0.14, `FLUENTBIT_VERSION` 로 변경)을 자동으로 받아 해시를 확인하고 묶음에 넣습니다.
  - 해시는 저장소에 고정한 `deploy/airgap/agent-installers/<zip>.sha256` 으로 확인합니다. 버전을 올리면 새 `.sha256` 을 확인해 커밋합니다(CI 윈도 작업도 같은 파일을 씁니다).
  - 이 파일이 서버 화면의 '에이전트 설치 묶음' zip 에 그대로 들어가므로, 폐쇄망 PC 에 따로 반입할 것이 없습니다.
  - 인터넷이 안 되는 빌드 PC 라면 `--no-agent-download` 로 끄고 `deploy/airgap/agent-installers/` 에 직접 넣습니다.
- 결과물 (`dist/`):

```
log-monitor-0.5.0-amd64.tar.gz          반입 파일
log-monitor-0.5.0-amd64.tar.gz.sha256   반입 신청서에 적을 해시
  └ 안에: images/images.tar.gz         컨테이너 이미지 3개 (api, postgres:17-alpine, fluent-bit:4.0)
          images/IMAGES.txt            이미지 ID
          images/PACKAGES.txt          이미지 안의 파이썬 패키지 버전 (소프트웨어 목록 증적)
          docker-compose.yml, .env.example, config/, collector/, agent/, docs/, server/(소스), deploy/
          agent-installers/            Fluent Bit Windows 설치 파일 (+ .sha256)
          VERSION, SHA256SUMS          버전·대상 CPU, 파일별 해시
```

- 넣지 않는 것: `.env`(비밀값), 개발용 `docker-compose.override.yml`, `archive/`, 캐시.

## 4. [인터넷 PC] Docker 오프라인 설치 파일

서버에 Docker Engine 과 Compose 플러그인이 없으면 준비합니다. 모두 오픈소스입니다(Moby·containerd·Compose: Apache 2.0).
Docker Desktop 은 서버에 쓰지 않습니다. 세 방법 중 하나를 고르고, 서버 OS 의 공식 설치 문서(docs.docker.com/engine/install)도 함께 확인합니다.

### 방법 A — 정적 바이너리 (OS 종류와 무관, 가장 단순)

인터넷 PC에서:
- `https://download.docker.com/linux/static/stable/x86_64/` → `docker-<버전>.tgz`
- `https://github.com/docker/compose/releases` → `docker-compose-linux-x86_64`

폐쇄망 서버에서:

```bash
sudo tar -xzf docker-*.tgz --strip-components=1 -C /usr/bin       # dockerd, containerd, runc 포함
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo install -m 755 docker-compose-linux-x86_64 /usr/local/lib/docker/cli-plugins/docker-compose
sudo tee /etc/systemd/system/docker.service >/dev/null <<'EOF'
[Unit]
Description=Docker Engine
After=network-online.target firewalld.service
Wants=network-online.target
[Service]
Type=notify
ExecStart=/usr/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
TimeoutStartSec=0
Delegate=yes
KillMode=process
Restart=always
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now docker
docker version && docker compose version
```

### 방법 B — RPM (RHEL·Rocky·Alma 8/9)

인터넷 PC에서 **서버와 같은 OS 버전** 컨테이너로 받습니다:

```bash
docker run --rm -v "$PWD/docker-rpms:/out" rockylinux:9 bash -c '
  dnf -y install dnf-plugins-core &&
  dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo &&
  dnf download --resolve --destdir /out docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'
```

폐쇄망 서버에서:

```bash
sudo dnf install --disablerepo='*' ./docker-rpms/*.rpm
sudo systemctl enable --now docker
```

- 의존성이 모자라다는 오류가 나면, 그 패키지를 OS 설치 DVD(로컬 저장소)에서 함께 설치합니다.

### 방법 C — DEB (Ubuntu 22.04/24.04)

```bash
docker run --rm -v "$PWD/docker-debs:/out" ubuntu:24.04 bash -c '
  apt-get update && apt-get install -y ca-certificates curl &&
  install -m 0755 -d /etc/apt/keyrings &&
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc &&
  echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" > /etc/apt/sources.list.d/docker.list &&
  apt-get update && apt-get install -y --download-only docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin &&
  cp /var/cache/apt/archives/*.deb /out/'
```

- 22.04 는 이미지 `ubuntu:22.04`, 저장소 이름 `jammy` 로 바꿉니다.
- 폐쇄망 서버에서: `sudo apt install ./docker-debs/*.deb && sudo systemctl enable --now docker`

## 5. [인터넷 PC] 에이전트 설치 파일

| 대상 | 준비 |
|---|---|
| Windows PC·서버 | **할 일 없음.** `make-bundle.sh` 가 Fluent Bit Windows zip(4.0.14)을 받아 해시를 확인하고 묶음에 넣습니다 |
| Linux 서버 | 배포판별 `fluent-bit` 패키지(`.rpm`/`.deb`)를 packages.fluentbit.io 에서 받아 `deploy/airgap/agent-installers/` 에 넣고 `make-bundle.sh` 실행 |

- 서버 수신기와 같은 **4.0 계열**을 씁니다(개발·검증 기준 4.0.14).
- 묶음의 `agent-installers/` 는 서버에서 `/opt/log-monitor/agent-installers` 가 되고, 화면의 '에이전트 설치 묶음' zip 에 자동으로 들어갑니다.

## 6. 반입 절차 (망연계·USB)

1. 인터넷 PC에서 해시를 확인합니다: `shasum -a 256 -c log-monitor-<버전>-amd64.tar.gz.sha256`
2. 사내 규정에 따라 백신 검사를 하고, 반입 승인을 받습니다.
3. 폐쇄망 쪽에서 다시 해시를 확인합니다: `sha256sum -c log-monitor-<버전>-amd64.tar.gz.sha256`
4. 아래 기록을 남깁니다. ISMS 2.8.6(운영환경 이관)·2.10.x 증적이 됩니다.

| 반입 일시 | 반입자 | 승인자 | 파일명 | SHA-256 | 버전 | 용도 |
|---|---|---|---|---|---|---|
| 2026-10-__ | | | log-monitor-0.5.0-amd64.tar.gz | (`.sha256` 내용) | 0.5.0 | 신규 설치 / 업그레이드 |

- 묶음 안의 `images/PACKAGES.txt`, `images/IMAGES.txt` 를 기록에 첨부하면 '어떤 소프트웨어가 들어갔는가' 를 증명할 수 있습니다.

## 7. [폐쇄망 서버] 설치

### 7.1 Docker 확인

```bash
docker version && docker compose version && uname -m      # x86_64 이면 amd64 묶음
```

### 7.2 묶음 풀고 설치

```bash
sha256sum -c log-monitor-0.5.0-amd64.tar.gz.sha256
tar -xzf log-monitor-0.5.0-amd64.tar.gz
cd log-monitor-0.5.0-amd64
sudo ./deploy/airgap/install.sh --public-url https://logmon.corp.local:8080 --syslog
# 사용자가 IP 로 접속: --public-url https://10.0.0.10:8080 (인증서 이름 logmon.internal + IP 로 자동)
# 사내 PKI 인증서: ... --tls-cert server.crt --tls-key server.key --tls-ca root-ca.crt
```

| 옵션 | 설명 |
|---|---|
| `--public-url` | 사용자가 접속하는 주소. 알림 메일의 "자세히 보기" 링크 (처음 설치 때 필수). **https 면 TLS 로 설치**하고 평문 수집은 닫힙니다 |
| `--tls-name N` / `--tls-ip IP` | 자체 CA 로 만들 서버 인증서의 DNS 이름·IP (여러 번). 기본은 https 주소의 호스트 (§7.5) |
| `--tls-cert F --tls-key F --tls-ca F` | 사내 PKI 의 서버 인증서(리프+중간)·개인키·루트 CA 를 그대로 씀 |
| `--port N` | 웹 화면 포트 (기본 8080). 서버에 이미 쓰는 포트가 있을 때 |
| `--ingest-port N` | 에이전트 수집 포트 (기본 6976) |
| `--syslog` | syslog 수신기(514, 1514)도 기동. 업그레이드 때도 똑같이 붙입니다 |
| `--target DIR` | 설치 위치 (기본 `/opt/log-monitor`) |

**install.sh 가 하는 일:**
1. 사전 점검: Docker·Compose 확인, **서버 CPU 와 묶음 CPU 일치** 확인, 중복 설치 방지
2. `SHA256SUMS` 로 모든 파일 무결성 확인 (하나라도 다르면 중단)
3. 이미지 불러오기 (`docker load`)
4. 프로그램 파일을 `/opt/log-monitor` 로 복사
5. `.env` 생성: DB 비밀번호·수집 API 키·암호화 키(`WLM_SECRET_KEY`)를 **무작위로** 만들고 권한 600. API 문서(`/docs`)는 숨김
6. (TLS) 인증서 준비: 자체 CA 로 만들거나(이미 있으면 갱신) 사내 인증서를 `tls/` 로 복사, api 계정으로 읽히는지 확인. 새 설치면 `WLM_TLS=on`·`WLM_INGEST_PLAIN=off`. 업그레이드면 인증서만 준비하고 켜지 않음 (§7.5)
7. `config/`, `archive/` 소유자를 컨테이너 사용자(uid 10001)로, SELinux Enforcing 이면 레이블 지정
8. 인터넷 없이 기동 (`--no-build --pull never`), 상태 확인 (`python -m app.healthcheck` — TLS 면 https)
9. 첫 관리자(`admin`) 임시 비밀번호를 한 번 보여 줍니다. TLS 면 인증서 이름·만료일(D-n)·CA 지문과 CA 배포 안내

### 7.3 첫 로그인과 환경설정

1. `https://<서버>:8080` (평문 설치면 http) → `admin` + 임시 비밀번호 → 비밀번호 변경. 자체 CA 면 먼저 `tls/ca.crt` 를 브라우저 신뢰에 넣습니다(§7.5)
   - 임시 비밀번호를 놓쳤으면: `cd /opt/log-monitor && sudo docker compose -f docker-compose.yml exec api python -m app.cli reset-password admin`
2. **사용자** 화면: 담당자별 개인 계정을 만들고, 공용 `admin` 은 비상용으로만 씁니다(ISMS 2.5.x).
3. **환경설정 > 메일 서버**: 사내 릴레이 입력 → 테스트 메일.
4. **환경설정 > 수신자·수신 그룹**: 기본 그룹 '운영팀'에 담당자를 넣습니다(알림 규칙이 이 그룹으로 보냄).
5. (선택) **환경설정 > 외부 연동**: Oracle(TNS/SID/서비스) 또는 사내 메신저 웹훅 → 테스트.
6. `.env` 를 안전한 곳에 따로 백업합니다. 이 파일에는 암호화 키가 들어 있습니다.

### 7.4 방화벽·SELinux

```bash
# firewalld (RHEL 계열)
sudo firewall-cmd --permanent --add-port=6977/tcp                       # 에이전트 로그 수집 TLS (모든 PC)
sudo firewall-cmd --permanent --add-port=6976/tcp                       # 평문 수집 — 평문 운영·전환 기간에만 (§7.5)
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.10.0/24 port port=8080 protocol=tcp accept'  # 화면은 관리 대역만 (예시)
sudo firewall-cmd --permanent --add-port=514/udp --add-port=514/tcp --add-port=1514/tcp   # --syslog 일 때
sudo firewall-cmd --reload
# ufw (Ubuntu)
sudo ufw allow 6977/tcp && sudo ufw allow from 10.0.10.0/24 to any port 8080 proto tcp && sudo ufw allow 514 && sudo ufw allow 1514/tcp
```

- Docker 가 게시한 포트는 iptables 규칙을 직접 넣기 때문에, 호스트 방화벽과 별도로 **네트워크 방화벽**에서도 출발지 대역을 제한합니다.
- SELinux Enforcing 에서 화면 저장이 안 되면: `sudo chcon -R -t container_file_t /opt/log-monitor/config /opt/log-monitor/archive /opt/log-monitor/collector` (install.sh 가 root 로 실행되면 자동).

### 7.5 HTTPS·에이전트 TLS (ISMS 2.7.1, ADR-036)

api 가 직접 TLS 를 처리합니다(별도 프록시 이미지 없음). 켜면 화면 8080 은 https 만, 에이전트는 **6977**(TLS)로 보내고
서버 인증서를 **CA 와 이름으로 확인**합니다(끌 수 없음). 평문 6976 은 옮기는 동안만 열어 둡니다.

**인증서 요건**
- 서버 인증서 SAN 에 **DNS 이름이 꼭 있어야** 합니다. 에이전트는 IP 로 접속하더라도 이 이름으로 서버를 확인합니다(Fluent Bit 은 IP 로 확인하지 못함). DNS 에 등록하지 않은 이름이어도 됩니다(예: `logmon.internal`). 사용자가 IP 로 접속하면 IP 도 넣습니다.
- `tls/server.crt`(리프 먼저, 중간 CA 포함) · `tls/server.key`(암호 없는 PEM, **소유자 uid 10001·0600**) · `tls/ca.crt`(루트 CA — 에이전트 설치 묶음에 들어감). `tls/` 는 `10001:root 0750`.
- 확인: `sudo docker compose -f docker-compose.yml exec api python -m app.cli tls-status` — 이름·만료(D-n)·CA 지문·문제 (오류면 종료 코드 1). 에이전트와 같은 OpenSSL 로 **실제 핸드셰이크**를 해 봅니다(CA·중간 CA·만료·용도·이름 제한·키 짝). 여기서 [오류]가 나는 인증서로는 설치 묶음을 만들지 않습니다.
- `tls/ca.crt` 에는 루트 CA 인증서만 둡니다(맨 앞이 루트). 중간(발급) CA 는 `server.crt` 에 리프 다음으로 넣습니다. 개인키가 섞인 파일(full.pem 등)은 오류로 알리고, 설치 묶음에는 늘 인증서만 다시 써서 넣습니다.

**자체 CA** (사내 PKI 가 없을 때. install.sh `--tls-name`·`--tls-ip` 가 같은 일을 함)

```bash
cd /opt/log-monitor && sudo mkdir -p tls tls-ca && sudo chmod 700 tls-ca
IMG=$(sudo sed -n 's/^WLM_API_IMAGE=//p' .env)   # .env 는 root 만 읽는다(600)
sudo docker run --rm --network none --user 0 -v "$PWD/tls:/out" -v "$PWD/tls-ca:/ca" --entrypoint python "$IMG" \
  -m app.cli tls-init --out /out --ca-dir /ca --name logmon.corp.local --ip 10.0.0.10
sudo chown 10001:0 tls && sudo chmod 750 tls
```

- CA 는 10년, **이름 제한**: 준 DNS 이름(과 하위 도메인)·IP 만(`--ip` 를 안 주면 모든 IP 금지), 메일 주소 금지, 용도는 서버 인증만(EKU). GPO 로 루트에 배포한 CA 의 키가 새도 다른 이름·IP 의 서버나 메일·코드 서명에 쓰지 못하게 피해 범위를 좁힙니다. 서버 인증서는 2년.
- **CA 개인키 `tls-ca/`** 는 api 에 마운트하지 않습니다. 오프라인 매체로 옮겨 `.env` 처럼 DB 백업과 따로 보관합니다. 잃으면 새 CA 와 **전체 에이전트 재배포**가 필요합니다. `tls-init`·`install.sh` 는 배포된 CA(`tls/ca.crt`)가 있으면 새로 만들지 않습니다 — 갱신할 때 `tls-ca/` 를 되돌려 놓고 실행합니다(새 CA 로 바꾸려면 `tls/` 를 비우거나 `--force`).
- 브라우저 신뢰: `tls/ca.crt` 를 GPO(컴퓨터 구성 > 정책 > Windows 설정 > 보안 설정 > 공개 키 정책 > **신뢰할 수 있는 루트 인증 기관**)로 배포합니다. 켜기 전에 끝냅니다.

**사내 PKI:** `install.sh --tls-cert … --tls-key … --tls-ca …` 또는 위 세 파일을 `tls/` 에 둡니다. SAN 에 DNS 이름이 있는지 `tls-status` 로 확인합니다.

**평문으로 운영 중인 설치를 옮기는 순서**

| 단계 | 할 일 |
|---|---|
| 0 | 이 버전으로 업그레이드(TLS 는 꺼진 채라 동작이 같음). 수집 PC 화면 **'연결'** 칸이 채워지는지 하루 봅니다. **'평문(화면 포트)'** 인 PC(0.4 이전 묶음 — 8080 으로 보냄)는 TLS 를 켜기 **전에** 새 묶음으로 다시 설치합니다. 8080 이 https 로 바뀌는 순간 끊깁니다. 설정 버전으로는 0.4 와 0.5 묶음이 구별되지 않습니다(둘 다 0.2.0/0.1.0) |
| 1 | 인증서 (위) — 업그레이드에 `--tls-name` 등을 주면 인증서만 준비하고 켜지 않습니다 |
| 2 | 브라우저 신뢰 (자체 CA 면 GPO) |
| 3 | **네트워크 방화벽**: 모든 PC → 서버 6977/tcp 허용. 6976 은 그대로 |
| 4 | `.env`: `WLM_TLS=on`, `WLM_PUBLIC_URL=https://<인증서 이름>:8080`, `WLM_INGEST_API_KEYS=<새키>,<옛키>` → `sudo docker compose -f docker-compose.yml up -d api` (**restart 는 .env 를 다시 읽지 않습니다**). 사용자에게 https 로 접속하라고 알립니다(http 북마크는 빈 화면) |
| 5 | 수집 PC > 에이전트 설치에서 새 묶음(TLS·새 키·`ca.crt`·6977)을 받아 몇 대 시범 설치 → GPO·SCCM `install.cmd /quiet`. 다시 설치해도 버퍼·읽은 위치가 남아 유실·중복이 없습니다. 옛 평문 zip(옛 키)은 지웁니다 |
| 6 | 수집 PC 화면의 **'평문으로 보내는 PC N대'** 가 0 이 될 때까지. 오래 꺼진 PC 는 따로 다시 설치하거나 목록에서 삭제 |
| 7 | 평문 닫기: `WLM_INGEST_PLAIN=off`, `WLM_INGEST_API_KEYS=<새키>` → `sudo docker compose -f docker-compose.yml up -d api`. syslog 수신기를 쓰면(`--syslog` 설치) **`WLM_COLLECTOR_API_KEY=<새키>`** 도 바꾸고(빠뜨리면 syslog 가 401) `… --profile syslog up -d api collector` — 프로필 없이 collector 를 부르면 `--syslog` 없이 설치한 서버에도 514 수신기가 뜹니다. 방화벽에서 6976 삭제. 늦게 남은 PC 는 버퍼(최대 1GB)에 쌓았다가 다시 설치하면 이어서 보냅니다 |
| 8 | (선택) HSTS: DNS 이름 접속이 안정되면 `WLM_HSTS_MAX_AGE=86400` → 1주 뒤 `15552000`(비워 두면 보내지 않음). 그 이름의 **모든 포트**에 걸립니다. 되돌릴 때는 `WLM_HSTS_MAX_AGE=0` 으로 바꿔 `max-age=0` 을 보내고(브라우저가 기억을 지움), 사용자가 https 로 한 번씩 들어온 뒤 TLS 를 끕니다 |

- **되돌리기 (4~6 사이):** `WLM_TLS=off`, `WLM_PUBLIC_URL=http://…` → `up -d api`. 6976 이 열려 있어 옛 PC 는 그대로이고, TLS 묶음 PC 는 버퍼에 쌓았다가 다시 켜면 이어서 보냅니다.
- **새 설치:** `install.sh --public-url https://…` 면 처음부터 TLS, 평문 수집 닫힘, 방화벽은 6977 만.
- **인증서 갱신 (2년마다):** `tls-ca/` 를 가져와 같은 `docker run … tls-renew --dir /out --ca-dir /ca` → `sudo docker compose -f docker-compose.yml restart api` (인증서 파일만 바꿨으면 restart 로 됨). CA 가 그대로라 **에이전트 재배포 없음**. 만료 30일 전부터 서버 로그에 매일 경고, 설치 묶음 창에 D-n, install.sh 업그레이드 때 60일 이하 경고. **만료되면 모든 에이전트가 보내지 못합니다**(버퍼에만 쌓임) — 운영 달력에 넣습니다.
- **앞에 리버스 프록시(L7)가 이미 있으면:** 프록시 IP 를 `WLM_TRUSTED_PROXIES` 에 적습니다. X-Forwarded-For/Proto 는 그 주소에서 온 것만 믿습니다(`*`·`0.0.0.0/0` 은 기동 거부). L4 로드밸런서(SNAT)는 접속 IP 를 가립니다.
- 장비 → 수신기(514) syslog 는 평문으로 남습니다(장비가 지원하면 TLS syslog 는 다음 단계).

## 8. [폐쇄망] 에이전트 배포 (PC 도 폐쇄망)

PC 에 반입·배포할 것은 **서버 화면에서 내려받는 zip 하나**입니다.

1. 관리자로 로그인 → **수집 PC > 에이전트 설치**
2. 대상(Windows/Linux), **서버 주소**(PC 에서 보이는 이름·IP), 수집 포트(TLS 6977, 평문 서버면 6976), TLS 면 **인증서 이름**, 웹 서버면 IIS·DB 서버면 SQL Server 를 고르고 **설치 묶음 내려받기**
   - TLS 서버는 TLS 묶음만 만듭니다. 서버 인증서가 만료됐거나 `ca.crt` 와 이어지지 않으면 묶음을 만들지 않고 이유를 보여 줍니다
3. zip 안에 들어 있는 것:

| 파일 | 내용 |
|---|---|
| `install.cmd` | 관리자 권한으로 실행. 여러 대는 `install.cmd /quiet` 를 GPO 시작 스크립트·SCCM 으로 |
| `install.ps1`, `fluent-bit.yaml` | 에이전트 설치 스크립트·설정 틀 |
| `settings.json` | 서버 주소·수집 포트·**수집 API 키**·IIS/MSSQL 선택. TLS 면 `CaFile`·`TlsServerName`(인증서 이름)·`CaSha256`(CA 지문 — 설치 스크립트가 대조) |
| `ca.crt` | TLS 면: 서버 인증서를 확인할 루트 CA (공개값). 설치 스크립트가 지문(`CaSha256`, Linux 는 `TLS_CA_SHA256`)을 대조하고 인증서만 `C:\ProgramData\wlm-agent\ca.crt`(Linux `/etc/wlm-agent/ca.crt`)에 둡니다 |
| `fluent-bit/fluent-bit-4.0.14-win64.zip` | Fluent Bit (PC 에 없으면 자동 설치 — `C:\Program Files\fluent-bit`) |
| `설치방법.txt` | 위 절차 요약 |

4. 사내 파일 서버·배포 도구로 PC 에 복사 → `install.cmd` 실행 → 30초 안에 '수집 PC' 에 나타남

- **보안:** zip 에 수집 API 키가 들어 있습니다. 내려받기는 관리자(또는 '에이전트 배포' 권한 그룹)만 할 수 있고 감사 로그에 남습니다. 배포가 끝나면 복사본을 지웁니다.
  - PC 에 설치된 설정 파일(`C:\ProgramData\wlm-agent`)은 SYSTEM·Administrators 만 읽을 수 있습니다. 설치 스크립트가 파일을 쓰기 전에 폴더의 소유자·권한을 다시 잡습니다(미리 만들어 둔 폴더 대비).
- 웹 서버·DB 서버·일반 PC 용 zip 을 따로 받아 두면 배포 그룹별로 나눠 쓸 수 있습니다.
- **Linux:** 같은 화면에서 Linux 를 고르면 `install-configured.sh` 가 들어 있습니다. `packages/` 에 Fluent Bit 패키지가 있으면 먼저 설치합니다.
- **네트워크 장비:** syslog 대상을 `서버:514`(UDP/TCP)로 지정합니다(`--syslog` 로 설치한 경우).
- 수동 설치: `install.ps1 -ServerHost <서버> -ApiKey <키> -CaFile ca.crt -TlsServerName <인증서 이름>` (TLS 면 포트 기본 6977, 평문 6976) — [agent/windows/README.md](../agent/windows/README.md)

## 9. 설치 확인 체크리스트

| # | 확인 | 방법 | 기대 결과 |
|---|---|---|---|
| 1 | 서비스 상태 | `sudo docker compose -f docker-compose.yml ps` (in `/opt/log-monitor`) | db·api healthy, backup·collector Up |
| 2 | 상태 API | TLS: `sudo curl -sS --cacert tls/ca.crt --resolve <인증서 이름>:8080:<서버 IP> https://<인증서 이름>:8080/healthz`, 같은 꼴로 `:6977` (인증서 이름이 DNS 에 없어도 `--resolve` 로. 평문 설치: `curl -s http://<서버>:8080/healthz`, `:6976`) | 둘 다 `{"status":"ok",…}`. `…:6977/` 은 404 (수집 전용). TLS 면 `http://<서버>:8080` 은 빈 응답 |
| 2-1 | 인증서 | `sudo docker compose -f docker-compose.yml exec api python -m app.cli tls-status` | 이름·만료 D-n·'서버 인증서와 이어짐', [오류] 없음 |
| 3 | 로그인·비밀번호 변경 | 화면 | 대시보드 표시 |
| 4 | 에이전트 수신 | 시험 PC 에 설치 묶음으로 설치 → **수집 PC** 화면 | 30초 안에 '온라인', **'연결' 칸이 TLS**. PC 에서 `Test-NetConnection <서버> -Port 6977` 성공 |
| 5 | syslog | Linux 에서 `logger -n <서버> -P 514 -T "airgap test"` | 이벤트 검색에 표시 |
| 6 | 알림 메일 | 환경설정 > 메일 서버 > 테스트 | 메일 수신 |
| 7 | 알림 대상 | 알림 화면 > 알림 대상 > 테스트 발송 | 전송됨 |
| 7-1 | 알림 기능 상태 | 알림 화면 상태 띠, `curl -s http://<서버>:8080/healthz/alerts` (TLS 면 위 2번처럼) | '알림 엔진 동작 중', `"status":"ok"`. 병원 감시 도구(Zabbix·PRTG 등)가 있으면 이 주소를 등록 — 멈추면 503 (ADR-045) |
| 8 | 감사 로그 | 감사 로그 화면 | 로그인·설정 변경 기록 |
| 9 | 시각 | 이벤트의 발생 시각과 수신 시각 차이 | 수 초 이내 (NTP) |
| 10 | 백업·복구 시험 | §11 의 `backup.sh backup` → `backup.sh verify` 1회 | 환경설정 > 로그 보관에 '백업과 복구 시험이 정상입니다', `backups/wlm-*.dump` 생성 |

## 10. 업그레이드와 되돌리기

**업그레이드** (새 버전 묶음을 §3·§6 대로 반입한 뒤):

```bash
tar -xzf log-monitor-0.6.0-amd64.tar.gz && cd log-monitor-0.6.0-amd64
sudo ./deploy/airgap/install.sh --upgrade --syslog        # 처음 설치와 같은 --syslog / --target
```

- 업그레이드 전에 DB 를 `/opt/log-monitor/backups/before-<버전>-<시각>.dump` 로 자동 백업합니다(실패하면 중단).
- `.env`, `archive/`, **화면에서 고친 `config/`(대시보드·알림 규칙)** 는 그대로 둡니다.
  - 새 버전의 기본 설정이 다르면 `config/<파일>.new` 로 옆에 둡니다. 비교해서 필요한 부분만 반영하고 `.new` 를 지웁니다.
- DB 구조 변경(마이그레이션)은 기동할 때 자동 적용됩니다.
- **TLS:** 업그레이드는 TLS 설정을 바꾸지 않습니다. 평문으로 운영 중이면 완료 출력에 '[확인 필요] 평문 운영'이 나옵니다 — §7.5 순서로 옮깁니다. `tls/`·`tls-ca/` 는 덮어쓰지 않습니다.
- **보관기간 (ADR-040):** 이 버전부터 감사로그·점검 보고서는 기본 3년(`WLM_AUDIT_RETENTION_DAYS`·`WLM_REPORT_RETENTION_DAYS`), 알림 이력은 로그와 같은 기간입니다. `.env` 에 없으면 기본값이 적용됩니다. 진료정보(민감정보) 처리 시스템의 접속기록이면 `WLM_RETENTION_DAYS=730` 과 `WLM_SENSITIVE_ACCESS_LOG=on`(2년 미달 경고)으로 둡니다. 업그레이드 뒤 로그 보관 화면의 '기록 종류별 보관기간'에 빨간 줄이 없는지 확인합니다.
- **에이전트는 서버 다음에:** 새 서버로 올린 뒤에 PC 에 새 설치 묶음을 배포합니다. 설치 묶음은 서버의 에이전트 틀로 만들어지므로 화면에서 받으면 자연히 이 순서가 됩니다.
  - 설정 버전 **0.4.0**(SQL Server ERRORLOG 여러 줄 묶기, ADR-037)을 옛 서버에 보내면 묶인 레코드의 시각·오류 번호를 읽지 못합니다. 저장소 파일로 직접 설치할 때 주의합니다.
  - 다시 설치해도 읽은 위치(`tail-*.sqlite`)와 버퍼가 남아 유실·중복이 없습니다. 바꿀 PC 찾기: 수집 PC 화면의 설정 버전이 0.3.0 이하이면서 ERRORLOG 를 수집하는 DB 서버.
  - 서버를 되돌려야 하는데 0.4.0 PC 가 있으면, 되돌리기 **전에** 그 PC 들의 ERRORLOG 묶기를 끕니다. 새 서버는 0.4.0 묶음만 만들므로 둘 중 하나로 합니다.
    - 업그레이드 전에 받아 둔 옛 설치 묶음(DB 서버용)으로 다시 설치.
    - 또는 PC 에서 `C:\ProgramData\wlm-agent\fluent-bit.yaml` 의 `multiline.parser: mssql_errorlog` 줄을 지우고 `Restart-Service knuh-agent` (다음 설치 때 원래대로 돌아옵니다).
  - IIS 열 순서 표 `iis_layouts` 는 옛 서버가 무시하므로 그대로 둬도 됩니다.
- **IIS 사용자 지정 열 순서 사이트:** 이 버전으로 올린 직후에는 저장된 열 순서가 없어, 다음 로그 파일(하루 단위면 09:00 KST)까지 원문으로 남습니다(IIS 대시보드·규칙에 안 잡힘). 09:00 KST 직전에 올리면 공백이 짧습니다(ADR-037).

**되돌리기:**

```bash
cd /opt/log-monitor
# 1) 이전 이미지로 (이전 버전 이미지는 docker 에 남아 있음: docker images log-monitor-api)
sudo sed -i 's|^WLM_API_IMAGE=.*|WLM_API_IMAGE=log-monitor-api:0.5.0|' .env
# 2) DB 도 업그레이드 전으로 되돌려야 할 때만 (업그레이드 이후 수집된 로그는 사라짐)
sudo docker compose -f docker-compose.yml stop api collector
sudo docker compose -f docker-compose.yml run --rm backup restore before-0.6.0-<시각>.dump --yes   # 해시 확인 후 복원
# 3) 기동
sudo docker compose -f docker-compose.yml --profile syslog up -d --no-build --pull never
```

- 마이그레이션은 '추가만' 하므로(컬럼·테이블 추가) 대부분은 1)만으로 이전 버전이 동작합니다. 2)는 새 버전에서 데이터 문제가 생겼을 때만 합니다.

## 11. 백업 (운영)

`backup` 서비스(db 와 같은 `postgres:17-alpine` 이미지, `deploy/backup/backup.sh`)가 자동으로 합니다(ADR-031).

- **매일** `WLM_BACKUP_TIME`(기본 02:30)이 지나면 그날 한 번 `backups/wlm-<시각>.dump` + `.sha256` + 설정 묶음(`config/`)을 만들고, 최근 `WLM_BACKUP_KEEP`(기본 14, **1 이상**)개만 남깁니다.
  - 서버가 꺼져 있어 시각을 놓쳤으면 켜진 뒤 그날 바로 합니다. 마지막으로 한 날짜는 `backups/.last-run` 에 남아 같은 날 두 번 하지 않습니다.
  - 매시간 유지보수(00:00 UTC 전후에 새 달 파티션 생성)와 겹쳐도 수집은 멈추지 않습니다. 파티션 작업이 잠금을 5초만 기다리고 다음 주기로 미룹니다.
- **매주** `WLM_BACKUP_VERIFY_WEEKDAY`(기본 7 = 일요일) 백업 뒤 임시 DB 에 실제로 복원해 해시·마이그레이션 버전·행 수(백업과 정확히 같은지)를 확인합니다.
  - DB 크기 + 1GB 의 여유 디스크가 필요합니다. 모자라면 시험하지 않고 '실패(공간 부족)'로 남깁니다 — 디스크를 늘리거나 0 으로 끄고 시험 서버에서 수동으로 합니다.
- 결과는 감사로그(DB 백업 / DB 백업 실패 / 백업 복구 시험 / 백업으로 DB 복원)와 **환경설정 > 로그 보관** 화면에 남습니다. 백업이 36시간 넘게 없거나 복구 시험이 실패하면 화면에 경고합니다.
  - 실패한 복구 시험은 **같은 백업이나 더 새 백업**의 시험이 성공해야 경고에서 빠집니다.

```bash
cd /opt/log-monitor
sudo docker compose -f docker-compose.yml exec backup backup.sh backup        # 지금 백업
sudo docker compose -f docker-compose.yml exec backup backup.sh verify        # 가장 최근 백업 복구 시험 (임시 DB)
sudo docker compose -f docker-compose.yml exec backup backup.sh list          # 목록
sudo docker compose -f docker-compose.yml run --rm backup selftest            # 백업 스크립트 자체 시험 (시험용 DB 만 씀)
# 장애 복구: 운영 DB 를 백업으로 되돌린다 (그 뒤 수집된 로그는 운영 DB 에서 빠짐)
sudo docker compose -f docker-compose.yml stop api
sudo docker compose -f docker-compose.yml run --rm backup restore wlm-<시각>.dump --yes
sudo docker compose -f docker-compose.yml start api
```

- 복원은 운영 DB 에 연결된 세션이 있으면 거부합니다(api 를 먼저 멈춤). 지금 DB 를 `backups/before-restore-<시각>.dump` 로 남긴 뒤, 임시 DB 에 복원이 끝나면 이름을 바꿔 끼웁니다. 복원이 실패하면 운영 DB 는 그대로입니다.
  - 파일을 잘못 골랐으면 그 안전 사본으로 다시 `restore before-restore-<시각>.dump --yes` 합니다.
  - DB 가 망가져 지금 DB 를 덤프할 수 없을 때만 끝에 `--no-safety-dump` 를 붙입니다.
- 백업·복구 시험 중에 `docker compose stop`·재부팅하면 만들던 파일(`*.part`)과 임시 DB 를 지우고 멈춥니다. 남은 것은 다음 기동 때 정리합니다.

- `backups/` 와 `archive/` 를 **다른 매체**(NAS·외장 디스크)로 복사합니다(ISMS 2.9.3, 복제 자동화는 BACKLOG B-17).
- `.env`(암호화 키)는 백업에 넣지 않습니다. **따로** 안전한 곳에 보관합니다 — 백업만 유출되어도 화면에서 넣은 비밀값을 풀 수 없게(ISMS 2.7.2).
- 백업 파일 권한은 600(소유자만), `backups/` 는 700 입니다. 로그·계정 정보가 들어 있습니다. SELinux(Enforcing)에서는 설치 스크립트가 `backups/` 에 컨테이너 레이블을 붙입니다.

## 12. 문제 해결

| 증상 | 원인 | 조치 |
|---|---|---|
| `CPU 가 다릅니다` 로 중단 | arm64 묶음을 x86 서버에 (또는 반대) | 인터넷 PC에서 `--platform linux/amd64` 로 다시 만들기 |
| `exec format error` | 위와 같음 (스크립트 없이 수동 설치한 경우) | 위와 같음 |
| `체크섬이 맞지 않습니다` | 반입 중 손상·변조 | 원본 해시와 비교, 다시 반입 |
| 기동 시 `pull access denied` / 인터넷 접속 시도 | `--pull never` 없이 수동으로 `docker compose up` | `up -d --no-build --pull never` 로 기동 |
| api 가 DB 인증 실패 | 예전 설치의 DB 볼륨(`log-monitor_pgdata`)이 남아 비밀번호가 다름 | 새 설치라면 `docker volume rm log-monitor_pgdata` 후 다시 (데이터 삭제됨, 주의) |
| 화면에서 대시보드·규칙 저장 실패 | `config/` 권한 또는 SELinux | §7.4, `sudo chown -R 10001:10001 config archive` |
| 첫 관리자 비밀번호를 모름 | 로그를 놓침 | §7.3 의 `reset-password admin` |
| 에이전트가 '오프라인' | 방화벽(6977/6976), API 키, 서버 주소 | PC에서 `Test-NetConnection 서버 -Port 6977`(평문이면 6976), 서버 로그의 `[401]`. 예전 묶음(8080)으로 설치했다면 새 묶음으로 다시 설치 |
| api 가 뜨지 않고 로그에 `기동 중단:` | TLS 설정 오류(인증서·키 없음·짝 안 맞음·암호 걸린 키, `WLM_TLS` 오타, `WLM_TRUSTED_PROXIES` 에 `*`·호스트 비트가 있는 대역 `10.0.0.5/24`) | 로그의 안내대로 고친 뒤 `up -d api`. 키는 암호 없이, 소유자 uid 10001·0600 |
| 수집 PC '연결' 이 '평문(화면 포트)' | 0.4 이전 설치 묶음이 8080 으로 보냄 | TLS 를 켜기 전에 새 묶음으로 다시 설치 (§7.5 0단계) |
| TLS 에이전트가 보내지 못함 (`C:\ProgramData\wlm-agent\fluent-bit.log`, Linux `journalctl -u wlm-agent`) | `X509 code: 62` 이름 불일치 · `19`/`20`/`21` 다른 CA(또는 server.crt 에 중간 CA 누락) · `2` ca.crt 에 중간 CA 를 루트로 둠 · `26` 서버 인증 용도(EKU) 아님 · `79` 중간 인증서가 CA 아님 · `47` CA 이름 제한 밖 · `10` 인증서(서버·CA) 만료 · `9` 아직 유효하지 않음(시계) · `unexpected EOF` 평문 포트(6976)에 TLS 로 | 서버에서 `tls-status` 가 같은 번호로 알려 줍니다(같은 OpenSSL 확인). 62: 묶음의 인증서 이름이 서버 인증서에 있는지. 19~21·2: `tls/ca.crt` 가 루트 CA 인지, 묶음의 `ca.crt` 와 같은지. 26·79·47: 인증서를 다시 발급. 10: `tls-renew`. 9: NTP. 포트: 6977 로 |
| Fluent Bit 서비스가 계속 다시 시작 | `tls.ca_file` 파일 없음 (설정 검사는 통과하지만 실행 때 종료) | 설치 스크립트로 다시 설치(CA 를 `C:\ProgramData\wlm-agent\ca.crt` 로 복사) |
| http 북마크로 화면이 빈 응답 | TLS 를 켠 뒤 화면은 https 만 받음 | `https://<인증서 이름>:8080` 으로 |
| 로그인했는데 바로 로그인 화면 / 'HTTPS 주소로 접속하세요' | `WLM_COOKIE_SECURE=true` 인데 http 로 접속 | https 로 접속 (https 요청은 자동으로 Secure 쿠키라 보통 이 값은 false 로 둠) |
| 알림 메일이 안 옴 | 릴레이 주소·포트·인증 | 환경설정 > 메일 서버 > 테스트의 오류 문구 확인 |

## 13. 검증 기록 (2026-10-04, 개발 PC 리허설)

### 2026-10-16 HTTPS·에이전트 TLS (B-06, 개발 PC — 실기 설치는 B-25·B-28)

- 인증서: `tls-init` 으로 자체 CA(이름 제한 critical, pathlen 0) + 서버 인증서(DNS `logmon.dev.internal`·`localhost`, IP `127.0.0.1`, 730일). api 계정(uid 10001·gid 999)으로 키를 읽고 CA 키는 못 읽음(리눅스 파일시스템). Docker Desktop 바인드 마운트에서도 읽힘(chmod 불필요).
- 서버(`WLM_TLS=on`): 리스너 '화면 8000(TLS) · 수집 8001(평문) · 수집 8002(TLS) · 내부 수집 8003(평문)', 상태 healthy(HEALTHCHECK 가 https). `curl --cacert` 로 8080·6977 `/healthz` 200, 6977 `/` 404, http 8080 은 빈 응답, CA 없이 https 는 신뢰 실패.
- 프로토콜: TLS 1.1(클라이언트 보안 수준 0)·TLS 1.2 CBC 거부, TLS 1.2 GCM·TLS 1.3 연결.
- Fluent Bit 4.0 컨테이너(`tls.verify`·`verify_hostname`·`vhost`·`ca_file`): 서비스 이름·IP+이름·호스트 게시 6977 → 200 이고 이벤트·하트비트 저장(`last_transport=tls`). 다른 이름 → X509 62, 다른 CA → 19, 평문 포트에 TLS → unexpected EOF — 모두 저장 안 됨.
- 평문 닫기(`WLM_INGEST_PLAIN=off`): 6976 연결 리셋, syslog 는 수집기 → 8003 으로 계속 저장, TLS 에이전트 계속 200. HSTS 60초 설정 시 https 응답에 `max-age=60`(includeSubDomains 없음), 기본 0 이면 없음.
- 핸드셰이크 부하: 연결마다 새 TLS + 하트비트 POST 를 초당 200회 30초 — 오류 0, p95 27ms, 화면 `/healthz` p95 18ms (PERFORMANCE.md §2.3).
- 종단(서버 설치 묶음 → 설치 스크립트 → 실제 Fluent Bit): https 로 로그인(Secure 쿠키)해 받은 Linux 묶음을 Rocky Linux 9 컨테이너에서 `install-configured.sh` 로 설치 → 만든 설정 그대로 Fluent Bit 4.0 기동 → 6977 로 200, `last_transport=tls`·설정 버전 0.2.0. Windows 묶음은 `install.ps1 -RenderOnly`(pwsh 7)로 TLS 블록(6977·`verify_hostname`·`vhost`·`ca_file`) 확인, `ca.crt` 를 다른 CA 로 바꾸면 지문 불일치로 중단. Windows PowerShell 5.1·서비스는 B-28.
- 화면: 수집 PC '연결' 칸(TLS·평문), 'TLS 를 켠 서버에서 평문 PC N대' 안내, 설치 창의 TLS 상태·인증서 이름 선택·거절 사유 표시, 휴대폰 폭 카드. 브라우저 확인은 같은 설정의 평문 리스너로(내장 브라우저가 자체 서명 인증서를 열지 않음).

- **묶음:** Apple Silicon Mac 에서 `make-bundle.sh` → `linux/amd64` 묶음 224MB, 약 1분 30초.
  - 저장된 이미지 3개의 OS/CPU 가 모두 `linux/amd64` 인지 확인했습니다.
- **오프라인 설치:** 네트워크를 끊은 격리 Docker(dind) 안에서 같은 스크립트로 시험했습니다. CPU 를 맞추려고 리허설용 arm64 묶음을 썼습니다.
  - 변조 감지: 묶음의 파일 하나를 바꾸면 설치가 중단됩니다.
  - 설치: 이미지 로드 → 무작위 비밀값으로 `.env` 생성 → 기동 → 첫 관리자 로그인·비밀번호 변경까지 정상. 개발용 기본 API 키는 거부됩니다.
  - 수집: Windows 이벤트(API), syslog(UDP 514) → 분류·사용자·IP 추출 정상. `/docs` 숨김.
  - 업그레이드: 백업 생성, 운영에서 고친 `alerts.yaml` 보존 + `.new` 생성, 데이터 유지.
  - 복원: 백업에서 DB 를 다시 만들어 이벤트·사용자·감사로그·마이그레이션 복원 확인.
- **발견해 고친 것:**
  - `.env.example` 의 `WLM_ADMIN_INITIAL_PASSWORD=    # 설명` 줄을 compose 가 설명문을 비밀번호로 읽었습니다(공개된 문구가 첫 관리자 비밀번호가 됨).
    - 설명을 윗줄로 옮겼고, 서버도 `#` 로 시작하는 값은 무시하도록 막았습니다.
  - macOS tar 의 확장 속성 때문에 리눅스에서 경고가 쏟아지던 것을 묶을 때 빼도록 했습니다.
- **아직 실제 사내 서버(x86, RHEL/Ubuntu)와 사내 Docker 설치 파일로는 시험하지 않았습니다.** 첫 설치 때 §9 체크리스트 결과를 여기에 추가합니다.

### 2026-10-04 추가 검증 (0.5.0)

- 수집 전용 포트: 6976 으로 수집·`/healthz` 정상, 화면·로그인·조회 API 는 404. 8080 은 그대로 동작.
- syslog 수신기는 내부 수집 포트(8001)로 보내도록 바꾼 뒤 수신 확인.
- 에이전트 설치 묶음: zip 구성(설정·Fluent Bit·설명서)과 입력 검증·감사 기록을 자동 테스트로 확인.
  - PowerShell(컨테이너)에서 `install.ps1` 문법 검사 통과, `settings.json` 읽기와 Fluent Bit zip 자동 설치까지 실행 확인
    (실제 서비스 등록은 Windows 가 필요해 사내 시험 PC 에서 확인 필요 — BACKLOG B-25).

### 2026-10-05 설치 리허설 (0.5.0 묶음, 네트워크를 끊은 격리 Docker)

- 변조 감지: 묶음 안 파일 하나를 바꾸면 설치 중단. 압축 해제 경고 없음(macOS 확장 속성 제거 확인).
- 처음 설치: 이미지 로드 → 무작위 비밀값 `.env` → 기동(`python -m app.serve`, 8080·6976) → 첫 관리자 로그인·비밀번호 변경.
- 포트: 8080·6976 `/healthz` 200, 6976 의 화면(`/`)·로그인 API 는 404.
- 수집: 6976 으로 Windows·SQL Server 이벤트, 514/udp syslog(수신기 → 내부 8001) 저장 확인.
- 에이전트 설치 묶음: Fluent Bit 4.0.14 zip 포함, `settings.json` 에 이 서버의 무작위 키·포트 6976·선택 항목.
- 규칙 관리(추가·SID 자동·끄기·미리보기), 사용자 그룹(DB팀 → MSSQL 로그만, 규칙 변경 403), 감사 로그 기록 — 15개 항목 모두 통과.
- 업그레이드: DB 백업 생성, 화면에서 추가한 규칙이 남은 `alerts.yaml` 보존 + `alerts.yaml.new`, 이벤트·그룹 유지.
- 복원: 백업으로 DB 를 다시 만들어 이벤트·사용자·그룹·마이그레이션(8개) 복원, 정상 기동.
