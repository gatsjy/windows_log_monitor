# 변경 내역

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/) 를 따르고, 버전은 [유의적 버전](https://semver.org/lang/ko/) 을 씁니다.
버전 번호는 `server/app/__init__.py` 의 `__version__` 이 기준입니다(화면 로그인 창, `/healthz`, 폐쇄망 묶음 이름에 쓰임).

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

[0.4.0]: https://github.com/gatsjy/windows_log_monitor/releases/tag/v0.4.0
[0.3.0]: https://github.com/gatsjy/windows_log_monitor/releases/tag/v0.3.0
