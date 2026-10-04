# Windows 에이전트

각 Windows PC/서버에 [Fluent Bit](https://fluentbit.io) (Apache 2.0)를 서비스로 설치해서 이벤트 로그를 서버로 보냅니다.
웹 서버(IIS)·DB 서버(SQL Server)에서는 스위치 하나로 IIS 접속 로그와 SQL Server ERRORLOG 도 함께 보냅니다.

## 설치 (권장: 서버에서 받은 설치 묶음 — 폐쇄망 PC 도 그대로)

1. Log Monitor 화면 **수집 PC > 에이전트 설치** 에서 설치 묶음(zip)을 내려받습니다 (관리자 또는 '에이전트 배포' 권한).
   - 서버 주소·수집 포트(6976)·API 키가 `settings.json` 에, Fluent Bit 설치 파일이 `fluent-bit\` 에 들어 있습니다.
2. PC 에 복사해서 압축을 풀고 `install.cmd` 를 **관리자 권한으로 실행**합니다.
   - 여러 대: `install.cmd /quiet` 를 GPO 시작 스크립트·SCCM·사내 배포 도구로 실행합니다.
   - Fluent Bit 이 없으면 묶음의 zip 을 `C:\Program Files\fluent-bit` 에 풀어 설치합니다. 인터넷이 필요 없습니다.
3. 배포가 끝나면 묶음 복사본(API 키 포함)을 지웁니다.

## 설치 (수동)

1. Fluent Bit Windows 설치 파일(64bit, 4.0 계열)을 설치합니다. 기본 경로는 `C:\Program Files\fluent-bit\bin\fluent-bit.exe` 입니다.
2. 이 폴더(`agent/windows`)를 PC로 복사하고 **관리자 PowerShell**에서 실행합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -ServerHost 10.0.0.10 -ApiKey <수집 API 키>
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `-ServerHost` | `settings.json` | Log Monitor 서버 주소 |
| `-ServerPort` | **6976** | 서버의 **수집 전용 포트** (`.env` 의 `WLM_INGEST_PORT`). 화면 포트(8080)와 다릅니다 |
| `-ApiKey` | `settings.json` | 서버 `.env` 의 `WLM_INGEST_API_KEYS` 중 하나 |
| `-Channels` | System, Application, Security, PowerShell/Operational, Windows Defender/Operational, TerminalServices-LocalSessionManager/Operational | 수집할 이벤트 로그 채널 (콤마로 구분, 없는 채널은 무시) |
| `-Iis` | 끔 | IIS W3C 접속 로그 수집 |
| `-IisLogPath` | `C:\inetpub\logs\LogFiles\W3SVC*` 자동 탐색 | IIS 로그 파일 패턴 (콤마로 구분, 예: `D:\logs\W3SVC1\*.log`) |
| `-MssqlErrorlog` | 끔 | SQL Server ERRORLOG 수집 (UTF-16) |
| `-MssqlErrorlogPath` | `C:\Program Files\Microsoft SQL Server\**\ERRORLOG` 자동 탐색 | ERRORLOG 경로 (콤마로 구분, 이름 있는 인스턴스 여러 개 가능) |
| `-FluentBitExe` | C:\Program Files\fluent-bit\bin\fluent-bit.exe | Fluent Bit 실행 파일 경로 |
| `-Settings` | 스크립트 옆 `settings.json` | 설치 묶음의 설정 파일. 명령줄 값이 우선 |

30초 안에 웹 화면의 **수집 PC** 목록에 나타납니다(하트비트 주기).

## 수집 채널 추가 예시

```powershell
.\install.ps1 -ServerHost 10.0.0.10 -ApiKey <키> -Channels "System,Application,Security,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
```

- 채널 이름은 `이벤트 뷰어 > 로그 속성 > 전체 이름` 또는 `wevtutil el` 로 확인합니다.
- 없는 채널은 무시됩니다(`ignore_missing_channels: true`).
- Sysmon을 쓰고 있다면 `Microsoft-Windows-Sysmon/Operational` 을 추가합니다.

## IIS·SQL Server 로그

```powershell
# 웹 서버
.\install.ps1 -ServerHost 10.0.0.10 -ApiKey <키> -Iis
# DB 서버
.\install.ps1 -ServerHost 10.0.0.10 -ApiKey <키> -MssqlErrorlog
```

- **IIS:** 사이트별 `W3SVC<n>` 폴더를 찾아 tail 합니다. 로그 형식은 **W3C** 여야 합니다(IIS 관리자 > 로깅).
  - 열 구성을 바꿔도 됩니다. 서버가 파일의 `#Fields:` 머리줄을 읽어 맞춥니다.
  - W3C 시각은 UTC 로 기록되므로 그대로 해석합니다.
  - 화면: 분류 '웹 서버 (IIS)', 이벤트 = HTTP 상태, 5xx 는 오류, 401·403·429 는 경고. 대시보드 '웹 서버 (IIS)'.
- **SQL Server:** ERRORLOG 는 UTF-16 이라 `unicode.encoding: UTF-16LE` 로 읽습니다.
  - 로그인 실패(18456)·심각한 오류는 Windows **응용 프로그램** 로그에도 남으므로, 스위치 없이도 분류 'DB (MSSQL)' 로 들어옵니다. ERRORLOG 는 더 자세한 내용이 필요할 때 켭니다.
  - SQL Server 의 '로그인 감사' 를 '실패한 로그인만' 이상으로 둡니다.
- 두 스위치는 `fluent-bit.yaml` 의 `# @@IIS_BEGIN` ~ `# @@IIS_END`, `# @@MSSQL_BEGIN` ~ `# @@MSSQL_END` 블록의 주석을 풀어 경로를 채웁니다. 수동으로 켤 때도 같은 블록을 고칩니다.
- 나중에 켜려면 같은 명령을 스위치와 함께 다시 실행합니다(설정을 다시 만들고 서비스를 재시작, 읽은 위치는 유지).

## 동작 방식

| 항목 | 내용 |
|---|---|
| 서비스 이름 | `wlm-agent` (자동 시작, 비정상 종료 시 자동 재시작) |
| 설정/데이터 | `C:\ProgramData\wlm-agent\` (SYSTEM, Administrators 만 접근 가능. API 키가 들어 있음) |
| 읽은 위치 기록 | `winevtlog.sqlite`, `tail-iis.sqlite`, `tail-mssql.sqlite` (재시작해도 중복/누락 없음) |
| 이벤트 필드 | `event_data_as_map: true` — EventData 를 이름 있는 맵으로 보냄 (서버가 사용자·IP 를 뽑고 `f.EventData.LogonType` 처럼 검색) |
| 장애 대비 | 서버에 연결할 수 없으면 `buffer\` 에 디스크로 쌓아 두었다가 복구되면 전송 |
| 시작 시점 | 설치 이후 발생한 이벤트부터 수집 (`read_existing_events: false`) |

## 이벤트 로그 크기와 로테이션 (중요)

Windows 이벤트 로그는 정해진 크기가 차면 오래된 이벤트부터 덮어씁니다. 기본 보안 로그는 20MB 라 몇 시간이면 찹니다.

- 에이전트는 실시간 구독이라 평소에는 문제가 없습니다.
- 다음 상황에서는 크기가 작으면 읽기 전에 덮어써져 **유실**됩니다.
  - 에이전트가 멈춰 있거나 PC가 서버와 오래 끊긴 경우
  - 로그온 실패 폭주처럼 이벤트가 한꺼번에 몰리는 경우

GPO로 크기를 충분히 키웁니다. 경로는 `컴퓨터 구성 > 정책 > 관리 템플릿 > Windows 구성 요소 > 이벤트 로그 서비스` 입니다.

| 로그 | 최대 크기 (권장) | 로그가 가득 찼을 때 |
|---|---|---|
| 보안(Security) | 1~4 GB (서버·DC 는 크게) | 필요 시 이벤트 덮어쓰기 |
| 시스템 / 응용 프로그램 | 256 MB 이상 | 필요 시 이벤트 덮어쓰기 |
| PowerShell/Operational 등 추가 채널 | 128 MB 이상 | 필요 시 이벤트 덮어쓰기 |

```powershell
# 현재 설정 확인 / 한 대만 바꿀 때 (관리자)
wevtutil gl Security
wevtutil sl Security /ms:1073741824      # 1GB
```

- **덮어쓰기를 쓰는 이유:** '가득 차면 보관(archive)'이나 '덮어쓰지 않음'은 디스크가 차거나, 로그가 멈춰 감사 이벤트를 잃게 할 수 있습니다.
- **장기 보관:** 서버(Log Monitor)의 로그 로테이션이 맡습니다. DB 90일 + 압축 보관 파일 1년이며, 자세한 내용은 docs/PROJECT.md §9 에 있습니다.
- **에이전트 쪽 보호:**
  - 서버와 끊긴 동안 받은 이벤트는 `buffer\` 에 최대 1GB 까지 디스크로 쌓아 두었다가 보냅니다(`storage.total_limit_size`).
  - 읽은 위치는 `winevtlog.sqlite` 에 기록하므로, 서비스를 재시작해도 이어서 읽습니다.

## 문제 해결

```powershell
Get-Service wlm-agent
# 콘솔에서 직접 실행해서 오류 보기 (서비스를 먼저 중지)
Stop-Service wlm-agent
& "C:\Program Files\fluent-bit\bin\fluent-bit.exe" -c C:\ProgramData\wlm-agent\fluent-bit.yaml
```

- 서버 쪽 로그 `[401]`: API 키가 틀렸습니다.
- 연결 실패: 방화벽에서 서버 수집 포트(**6976**) 아웃바운드를 허용합니다. `Test-NetConnection <서버> -Port 6976` 으로 확인합니다.
- 예전 설치(8080 으로 보내던 PC)도 계속 수집됩니다. 화면 포트와 방화벽을 나누려면 새 묶음으로 다시 설치합니다.

## 제거

```powershell
.\uninstall.ps1             # 서비스만 제거
.\uninstall.ps1 -RemoveData # 설정·버퍼까지 삭제
```

## 대량 배포

`install.ps1` 은 같은 인자로 다시 실행해도 안전합니다(설정 갱신 후 재시작).

- 여러 대에 배포할 때는 GPO 시작 스크립트, SCCM/Intune, Ansible(`win_shell`) 등으로 같은 명령을 실행합니다.
- 설정 파일을 바꾸면 `config_version` 을 올립니다. 그러면 웹 화면에서 어떤 PC가 옛 설정을 쓰는지 보입니다.
