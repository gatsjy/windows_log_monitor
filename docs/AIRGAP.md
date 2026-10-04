# 폐쇄망 배포 가이드

> 최종 갱신: 2026-10-04 · 버전 0.5.0
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
| 사내 정보 | 서버 IP·DNS 이름, 사용자가 접속할 주소(`--public-url`) | 알림 메일 링크에 쓰임 |
| 사내 정보 | 메일 릴레이(SMTP) 주소·포트·인증 방식 | 환경설정 화면에서 입력 |
| 사내 정보 | 사내 NTP 서버 | 모든 PC·서버 시각 일치 (ISMS 2.9.6) |
| 사내 정보 | (선택) Oracle 접속 정보: TNS 별칭 또는 SID/서비스 이름 | 환경설정 화면에서 입력 |
| 승인 | 방화벽 정책: 모든 PC → 서버 **6976/tcp**(로그 수집), 사용자 PC → 서버 8080/tcp(화면), 장비 → 서버 514/udp·tcp, 1514/tcp | §2 |
| 승인 | 반입 승인 (정보보호 담당자) | §6 |

## 2. 서버 요구사항

| 항목 | 권장 |
|---|---|
| OS | Linux x86_64: RHEL·Rocky·AlmaLinux 8/9, Ubuntu 22.04/24.04 (커널 4.x 이상, systemd) |
| CPU 종류 | **묶음과 같아야 합니다.** 일반 서버는 `amd64`(x86_64). `uname -m` 으로 확인 |
| 사양 | PC 50대 기준 4코어 · 메모리 8GB · 디스크 100GB(SSD). 200대 이상은 8코어 · 16~32GB · 500GB+ ([PERFORMANCE.md](PERFORMANCE.md) §5) |
| 디스크 배치 | Docker 데이터(`/var/lib/docker`, DB 포함)와 `/opt/log-monitor/archive`(보관 파일)를 넉넉한 볼륨에 |
| 메모리 설정 | 8GB 가 아니면 설치 후 `.env` 의 `WLM_PG_*` 를 조정 (shared_buffers ≈ 메모리 25%) |

**포트 (방화벽):**

| 포트 | 방향 | 용도 | 필수 |
|---|---|---|---|
| **6976/tcp** (`--ingest-port`) | 모든 PC·서버(에이전트) → 서버 | 로그 수집 전용. `/api/ingest` 와 `/healthz` 만 열림 (화면·로그인 불가) | 필수 |
| 8080/tcp (`--port`) | 사용자·관리자 PC → 서버 | 웹 화면 + API. 관리 대역에서만 열 것을 권장 | 필수 |
| 514/udp, 514/tcp | 네트워크 장비·Linux → 서버 | syslog RFC3164 (`--syslog` 일 때) | 선택 |
| 1514/tcp | 장비 → 서버 | syslog RFC5424 (`--syslog` 일 때) | 선택 |
| 25/587/465 | 서버 → 사내 메일 릴레이 | 알림 메일 | 알림 사용 시 |
| 1521 등 | 서버 → 사내 Oracle | 알림을 Oracle 에 기록 | 선택 |

- DB(5432)는 밖으로 열지 않습니다(컨테이너 내부 통신만).

## 3. [인터넷 PC] 반입 묶음 만들기

준비: Docker (Docker Desktop 또는 Linux Docker Engine) + buildx. 이 저장소 폴더에서 실행합니다.

```bash
./deploy/airgap/make-bundle.sh                        # 일반 서버 (linux/amd64)
./deploy/airgap/make-bundle.sh --platform linux/arm64 # ARM 서버일 때만
```

- **주의 (Apple Silicon Mac):** 그냥 `docker build` 하면 arm64 이미지가 되어 x86 서버에서 뜨지 않습니다. 스크립트는 기본으로 `linux/amd64` 로 빌드·다운로드합니다.
- 에이전트 설치 파일을 함께 넣으려면, 실행 전에 `deploy/airgap/agent-installers/` 에 넣어 둡니다(§5).
- Fluent Bit Windows 설치 파일(서버 수신기와 같은 4.0.14, `FLUENTBIT_VERSION` 로 변경)을 자동으로 받아 해시를 확인하고 묶음에 넣습니다.
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
sudo ./deploy/airgap/install.sh --public-url http://logmon.corp.local:8080 --syslog
```

| 옵션 | 설명 |
|---|---|
| `--public-url` | 사용자가 접속하는 주소. 알림 메일의 "자세히 보기" 링크 (처음 설치 때 필수) |
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
6. `config/`, `archive/` 소유자를 컨테이너 사용자(uid 10001)로, SELinux Enforcing 이면 레이블 지정
7. 인터넷 없이 기동 (`--no-build --pull never`), 상태 확인
8. 첫 관리자(`admin`) 임시 비밀번호를 한 번 보여 줍니다

### 7.3 첫 로그인과 환경설정

1. `http://<서버>:8080` → `admin` + 임시 비밀번호 → 비밀번호 변경
   - 임시 비밀번호를 놓쳤으면: `cd /opt/log-monitor && sudo docker compose -f docker-compose.yml exec api python -m app.cli reset-password admin`
2. **사용자** 화면: 담당자별 개인 계정을 만들고, 공용 `admin` 은 비상용으로만 씁니다(ISMS 2.5.x).
3. **환경설정 > 메일 서버**: 사내 릴레이 입력 → 테스트 메일.
4. **환경설정 > 수신자·수신 그룹**: 기본 그룹 '운영팀'에 담당자를 넣습니다(알림 규칙이 이 그룹으로 보냄).
5. (선택) **환경설정 > 외부 연동**: Oracle(TNS/SID/서비스) 또는 사내 메신저 웹훅 → 테스트.
6. `.env` 를 안전한 곳에 따로 백업합니다. 이 파일에는 암호화 키가 들어 있습니다.

### 7.4 방화벽·SELinux

```bash
# firewalld (RHEL 계열)
sudo firewall-cmd --permanent --add-port=6976/tcp                       # 에이전트 로그 수집 (모든 PC)
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.10.0/24 port port=8080 protocol=tcp accept'  # 화면은 관리 대역만 (예시)
sudo firewall-cmd --permanent --add-port=514/udp --add-port=514/tcp --add-port=1514/tcp   # --syslog 일 때
sudo firewall-cmd --reload
# ufw (Ubuntu)
sudo ufw allow 6976/tcp && sudo ufw allow from 10.0.10.0/24 to any port 8080 proto tcp && sudo ufw allow 514 && sudo ufw allow 1514/tcp
```

- Docker 가 게시한 포트는 iptables 규칙을 직접 넣기 때문에, 호스트 방화벽과 별도로 **네트워크 방화벽**에서도 출발지 대역을 제한합니다.
- SELinux Enforcing 에서 화면 저장이 안 되면: `sudo chcon -R -t container_file_t /opt/log-monitor/config /opt/log-monitor/archive /opt/log-monitor/collector` (install.sh 가 root 로 실행되면 자동).

## 8. [폐쇄망] 에이전트 배포 (PC 도 폐쇄망)

PC 에 반입·배포할 것은 **서버 화면에서 내려받는 zip 하나**입니다.

1. 관리자로 로그인 → **수집 PC > 에이전트 설치**
2. 대상(Windows/Linux), **서버 주소**(PC 에서 보이는 이름·IP), 수집 포트(기본 6976), 웹 서버면 IIS·DB 서버면 SQL Server 를 고르고 **설치 묶음 내려받기**
3. zip 안에 들어 있는 것:

| 파일 | 내용 |
|---|---|
| `install.cmd` | 관리자 권한으로 실행. 여러 대는 `install.cmd /quiet` 를 GPO 시작 스크립트·SCCM 으로 |
| `install.ps1`, `fluent-bit.yaml` | 에이전트 설치 스크립트·설정 틀 |
| `settings.json` | 서버 주소·수집 포트·**수집 API 키**·IIS/MSSQL 선택 |
| `fluent-bit/fluent-bit-4.0.14-win64.zip` | Fluent Bit (PC 에 없으면 자동 설치 — `C:\Program Files\fluent-bit`) |
| `설치방법.txt` | 위 절차 요약 |

4. 사내 파일 서버·배포 도구로 PC 에 복사 → `install.cmd` 실행 → 30초 안에 '수집 PC' 에 나타남

- **보안:** zip 에 수집 API 키가 들어 있습니다. 내려받기는 관리자(또는 '에이전트 배포' 권한 그룹)만 할 수 있고 감사 로그에 남습니다. 배포가 끝나면 복사본을 지웁니다.
  - PC 에 설치된 설정 파일(`C:\ProgramData\wlm-agent`)은 SYSTEM·Administrators 만 읽을 수 있습니다.
- 웹 서버·DB 서버·일반 PC 용 zip 을 따로 받아 두면 배포 그룹별로 나눠 쓸 수 있습니다.
- **Linux:** 같은 화면에서 Linux 를 고르면 `install-configured.sh` 가 들어 있습니다. `packages/` 에 Fluent Bit 패키지가 있으면 먼저 설치합니다.
- **네트워크 장비:** syslog 대상을 `서버:514`(UDP/TCP)로 지정합니다(`--syslog` 로 설치한 경우).
- 수동 설치: `install.ps1 -ServerHost <서버> -ApiKey <키>` (포트 기본 6976) — [agent/windows/README.md](../agent/windows/README.md)

## 9. 설치 확인 체크리스트

| # | 확인 | 방법 | 기대 결과 |
|---|---|---|---|
| 1 | 서비스 상태 | `sudo docker compose -f docker-compose.yml ps` (in `/opt/log-monitor`) | db·api healthy, collector Up |
| 2 | 상태 API | `curl -s http://<서버>:8080/healthz`, `curl -s http://<서버>:6976/healthz` | 둘 다 `{"status":"ok","version":"0.5.0"}`. `http://<서버>:6976/` 은 404 (수집 전용) |
| 3 | 로그인·비밀번호 변경 | 화면 | 대시보드 표시 |
| 4 | 에이전트 수신 | 시험 PC 에 설치 묶음으로 설치 → **수집 PC** 화면 | 30초 안에 '온라인'. PC 에서 `Test-NetConnection <서버> -Port 6976` 성공 |
| 5 | syslog | Linux 에서 `logger -n <서버> -P 514 -T "airgap test"` | 이벤트 검색에 표시 |
| 6 | 알림 메일 | 환경설정 > 메일 서버 > 테스트 | 메일 수신 |
| 7 | 알림 대상 | 알림 화면 > 알림 대상 > 테스트 발송 | 전송됨 |
| 8 | 감사 로그 | 감사 로그 화면 | 로그인·설정 변경 기록 |
| 9 | 시각 | 이벤트의 발생 시각과 수신 시각 차이 | 수 초 이내 (NTP) |
| 10 | 백업 | §11 백업 명령 1회 실행 | `.dump` 파일 생성 |

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

**되돌리기:**

```bash
cd /opt/log-monitor
# 1) 이전 이미지로 (이전 버전 이미지는 docker 에 남아 있음: docker images log-monitor-api)
sudo sed -i 's|^WLM_API_IMAGE=.*|WLM_API_IMAGE=log-monitor-api:0.5.0|' .env
# 2) DB 도 업그레이드 전으로 되돌려야 할 때만 (업그레이드 이후 수집된 로그는 사라짐)
sudo docker compose -f docker-compose.yml stop api collector
sudo docker compose -f docker-compose.yml exec -T db sh -c 'dropdb -U "$POSTGRES_USER" "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" "$POSTGRES_DB"'
sudo docker compose -f docker-compose.yml exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --exit-on-error' < backups/before-0.6.0-<시각>.dump
# 3) 기동
sudo docker compose -f docker-compose.yml --profile syslog up -d --no-build --pull never
```

- 마이그레이션은 '추가만' 하므로(컬럼·테이블 추가) 대부분은 1)만으로 이전 버전이 동작합니다. 2)는 새 버전에서 데이터 문제가 생겼을 때만 합니다.

## 11. 백업 (운영)

```bash
cd /opt/log-monitor
sudo docker compose -f docker-compose.yml exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > backups/daily-$(date +%F).dump
```

- cron 으로 매일 실행하고, `backups/`, `archive/`, `.env` 를 **다른 매체**로 복사합니다(ISMS 2.9.3).
- 분기마다 §10 의 복원 절차를 시험 서버에서 실제로 해 보고 기록합니다. 자동화는 [BACKLOG.md](BACKLOG.md) B-16.

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
| 에이전트가 '오프라인' | 방화벽(6976), API 키, 서버 주소 | PC에서 `Test-NetConnection 서버 -Port 6976`, 서버 로그의 `[401]`. 예전 묶음(8080)으로 설치했다면 새 묶음으로 다시 설치 |
| 알림 메일이 안 옴 | 릴레이 주소·포트·인증 | 환경설정 > 메일 서버 > 테스트의 오류 문구 확인 |

## 13. 검증 기록 (2026-10-04, 개발 PC 리허설)

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
