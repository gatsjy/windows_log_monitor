# 변경 내역

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/) 를 따르고, 버전은 [유의적 버전](https://semver.org/lang/ko/) 을 씁니다.
버전 번호는 `server/app/__init__.py` 의 `__version__` 이 기준입니다(화면 로그인 창, `/healthz`, 폐쇄망 묶음 이름에 쓰임).

## [0.5.0] - 2026-10-04

### 추가
- **알림 규칙 관리 화면 (Snort 방식):** 규칙 묶음 목록 + 규칙 표(SID·사용 스위치·검색), 묶음 단위 켜기/끄기.
  - 입력 양식 편집기: Snort 식 한 줄 규칙 문장·우리말 요약이 실시간으로 바뀌고, 최근 24시간 **미리보기**(예상 알림 횟수)를 제공합니다.
  - 저장 시 `config/alerts.yaml` 에서 그 규칙 블록만 바꿉니다(다른 규칙·주석 유지). 규칙에 `sid`·`group` 항목 추가.
- **사용자 그룹:** DB팀·보안팀·의료정보과처럼 묶어 **기능 권한**(알림 규칙 관리, 대시보드 편집, 환경설정, 감사 로그, 에이전트 배포)과 **볼 수 있는 범위**(분류·PC 패턴)를 줍니다. 서버 API 에서 적용. 마이그레이션 `008_user_groups`.
- **수집 전용 포트 6976:** 에이전트·syslog 수신기는 6976(`WLM_INGEST_PORT`)으로 보냅니다. 이 포트는 수집과 `/healthz` 만 열립니다. 화면은 8080.
- **폐쇄망 PC 용 에이전트 설치 묶음:** 화면 '수집 PC > 에이전트 설치' 에서 서버 주소·포트·API 키·Fluent Bit 이 들어간 zip 을 내려받아 `install.cmd` 하나로 설치(인터넷 불필요).
  - `make-bundle.sh` 가 Fluent Bit Windows 설치 파일(4.0.14)을 자동으로 받아 해시를 확인하고 반입 묶음에 넣습니다.
- 알림 화면 탭(이력·규칙 관리·알림 대상).

### 변경
- **화면 디자인 개편:** Pretendard 글꼴(로컬 포함, SIL OFL 1.1), 새 색 체계·로고(그라데이션), 사이드바·버튼·입력창·로그인 화면.
- **반응형:** 1000px 미만은 상단 바 + 왼쪽에서 열리는 메뉴, 카드는 줄 단위로 2열/1열 재배치, 700px 미만은 표를 카드로(이벤트 표 전용 배치), 터치 화면은 누르는 영역 확대.
- 검색 조건 막대를 묶음 단위로 재구성 (좁은 화면에서 2열 정렬).
- 운영 실행을 `python -m app.serve`(두 포트) 로, 개발은 `watchfiles` 재시작으로 바꿨습니다.
- 에이전트 기본 포트 8080 → 6976 (`install.ps1 -ServerPort`, `install.sh` 두 번째 인자). 이미 8080 으로 보내는 PC 도 계속 수집됩니다.

### 수정
- 규칙 편집기에서 입력 칸 사이가 크게 벌어지던 문제, 좁은 화면에서 메뉴 닫기 버튼이 넓은 화면에도 보이던 문제.

## [0.4.0] - 2026-10-04

### 추가
- **IIS·SQL Server 로그 수집과 해석.** Windows 에이전트 설치 스위치 `-Iis`, `-MssqlErrorlog`.
  - 서버가 IIS W3C(`#Fields:` 머리줄 반영)와 SQL Server ERRORLOG 를 해석합니다.
  - 웹 서버(IIS)·DB(MSSQL) 대시보드를 추가했습니다.
- **분류(category) 13종과 공통 필드(사용자·접속 IP).** 마이그레이션 `007_fields`. 검색·대시보드·알림 규칙에서 `category`, `user`, `ip` 를 씁니다.
- Windows 에이전트가 EventData 를 이름 있는 필드로 보냅니다(`event_data_as_map`). 예: `f.EventData.LogonType`.
- 기본 수집 채널에 PowerShell/Operational, Windows Defender/Operational, TerminalServices-LocalSessionManager/Operational 를 추가했습니다.
- **보안 탐지 규칙 20개**와 규칙 태그(MITRE ATT&CK, ISMS 항목). 알림 메시지와 화면에 표시합니다. 규칙 `group_by: ip | user` 를 지원합니다.
- 메시지 검색에서 `a|b`(OR)를 지원합니다.
- **폐쇄망 배포:** `deploy/airgap/make-bundle.sh`(반입 묶음), `deploy/airgap/install.sh`(설치·업그레이드), 가이드 `docs/AIRGAP.md`.
  - `.env` 의 `WLM_API_IMAGE` 로 이미지 태그를 고정합니다.
- 문서: `docs/COMPARISON.md`(Wazuh·Graylog·ELK·Loki 비교), `docs/BACKLOG.md`(개발 예정), `LICENSE`(MIT), `SECURITY.md`, `CONTRIBUTING.md`.
- 통합 테스트 `test_api_events.py` (수집 → 정규화 → 검색).

### 변경
- 새 로고·파비콘: 로그 세 줄 + 실시간 신호.
- 검색 필터의 '소스' 선택을 '분류' 선택으로 바꿨습니다. 소스는 칩으로 표시합니다.
- 상위 값 목록(`top`)에서 사용자·IP 는 값 없는 이벤트를 세지 않습니다.
- 알림 규칙 요약 문구를 한국어로 표시합니다(분류 이름, '출발지 IP별' 등).

### 수정
- **보안:** `.env.example` 의 `WLM_ADMIN_INITIAL_PASSWORD=    # 설명` 줄을 docker compose 가 설명문을 값으로 읽었습니다.
  - 그 결과 공개된 문구가 첫 관리자 비밀번호가 될 수 있었습니다.
  - 설명을 윗줄로 옮겼고, 서버도 `#` 로 시작하는 값은 무시합니다.
  - 이전 `.env.example` 로 설치했다면 `admin` 비밀번호가 바뀌었는지 확인하세요.
- SQL Server ERRORLOG 의 `Error:` 머리줄과 본문 줄이 둘 다 세어져 로그인 실패가 2배로 집계되던 문제를 고쳤습니다.
- 좁은 화면(900px 이하)에서 내용이 짧으면 상단 메뉴 막대가 세로로 늘어나던 문제를 고쳤습니다.

## [0.3.0] - 2026-10-03

Phase 1(수집·저장·화면)과 Phase 2(알림·인증·환경설정·로그 로테이션)를 묶은 첫 정리 버전입니다.

### 추가
- 수집: Fluent Bit 에이전트(Windows 이벤트 로그, Linux journald/파일), syslog 수신기(RFC3164/5424), 하트비트로 PC 상태 판정.
- 저장: PostgreSQL 17 월별 파티션, 원본 JSONB 보존, 메시지 부분일치 인덱스(pg_trgm).
- 화면: 대시보드(JSON 정의, 화면 편집, SSE 실시간 반영), 실시간 로그, 이벤트 검색, 수집 PC, 필드 탐색.
- 알림: YAML 규칙 → 메일(수신 그룹)·웹훅·Oracle, 재시도, 쿨다운, 받을 최소 수준, 알림 화면.
- 인증: 개인 계정·역할, scrypt, 비밀번호 정책·잠금·세션 만료, CSRF, 수정 불가 감사 로그(CSV).
- 환경설정: 수신자·그룹, 웹훅, Oracle(TNS 이름/SID/서비스/접속 문자열)·조회 쿼리, 메일 서버. 비밀값은 Fernet 암호화.
- 로그 로테이션: DB(90일) → 압축 보관 파일(SHA-256) → 삭제(365일), 복원·무결성 확인.
- 성능: 500만 건 벤치마크(`tools/bench`), PostgreSQL 설정 튜닝.

[0.5.0]: https://github.com/gatsjy/windows_log_monitor/releases/tag/v0.5.0
[0.4.0]: https://github.com/gatsjy/windows_log_monitor/releases/tag/v0.4.0
[0.3.0]: https://github.com/gatsjy/windows_log_monitor/releases/tag/v0.3.0
