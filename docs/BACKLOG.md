# 개발 백로그 — 앞으로 만들 것

> 최종 갱신: 2026-10-04 (버전 0.4.0 기준)
> 이 문서는 **아직 만들지 않은 것**만 적습니다. 만든 것은 PROJECT.md 로 옮기고 여기서 지웁니다.
> 출처: [COMPARISON.md](COMPARISON.md)(Wazuh·Graylog·ELK·Loki 비교), PROJECT.md §15 알려진 한계, ISMS.md 의 '계획' 칸, 개발 중 발견한 문제.

## 작업 규칙 (사람·AI 에이전트 공통)

1. 항목을 시작하면 아래 요약 표의 **상태**를 `진행 중`으로 바꾸고, 끝나면 항목을 지우고 PROJECT.md·DECISIONS.md 에 반영합니다.
2. 각 항목의 **완료 기준**을 모두 만족해야 끝난 것입니다. 공통 완료 기준(테스트·린트·브라우저 확인·문서)은 [AGENTS.md](../AGENTS.md) 를 따릅니다.
3. 새 의존성은 OSI 승인 라이선스만 씁니다(AGENTS.md 절대 규칙 1). 항목에 적힌 후보 라이선스도 도입 전에 다시 확인합니다.
4. DB 변경은 새 마이그레이션 파일(`008_…` 부터)로만 합니다.
5. 새로 할 일을 발견하면 여기에 **번호를 이어서** 추가합니다. 번호는 재사용하지 않습니다.

**우선순위:** P1 = 다음에 바로 / P2 = 운영해 보며 필요해지면 / P3 = 규모·요구가 생기면
**규모:** S = 하루 이내 / M = 2~4일 / L = 1주 이상

## 요약

| ID | 항목 | 우선 | 규모 | 근거 | 상태 |
|---|---|---|---|---|---|
| B-01 | 검색 언어 (`필드:값`, 제외, 따옴표) | P1 | M | 비교 §2 | 대기 |
| B-02 | 알림 처리 기록 (확인·해결·메모) | P1 | M | ISMS 2.11.5 | 대기 |
| B-03 | 알림 무음 (silence)·점검 시간대 | P1 | S | 비교 §2 | 대기 |
| B-04 | 메신저 프리셋 (Slack·Teams·두레이·잔디) | P1 | S | 비교 §2 | 대기 |
| B-05 | 정기 점검 보고서 (일간·주간) | P1 | M | ISMS 2.9.5 | 대기 |
| B-06 | 운영 HTTPS (리버스 프록시) + 에이전트 TLS | P1 | S | ISMS 2.7.1, §15 | 대기 |
| B-07 | 대시보드 위젯 편집 폼 | P2 | M | 비교 §2 | 대기 |
| B-08 | IIS 열 순서 영속화, MSSQL 여러 줄 합치기 | P2 | S | ADR-020 | 대기 |
| B-09 | 시간별 집계 테이블 (긴 기간 대시보드) | P2 | L | PERFORMANCE.md §5 | 대기 |
| B-10 | 자주 쓰는 원본 필드 인덱스 | P2 | S | PERFORMANCE.md | 대기 |
| B-11 | 에이전트 중앙 관리 (설정 버전·배포) | P2 | L | 비교 §2 | 대기 |
| B-12 | 사내 SSO (AD/LDAP, OIDC) | P2 | M | ISMS 2.5.x, ADR-013 | 대기 |
| B-13 | 순서 기반 상관 규칙 | P2 | M | 비교 §2 | 대기 |
| B-14 | Sigma 규칙 가져오기 | P3 | L | 비교 §2 | 대기 |
| B-15 | git 저장소화 + CI (테스트·린트·이미지 점검) | P1 | S | ISMS 2.8.5, 2.10.x | 대기 |
| B-16 | 백업 자동화 + 복구 시험 기록 | P1 | S | ISMS 2.9.3 | 대기 |
| B-17 | 보관 파일 외부 저장소 복제 | P2 | S | ISMS 2.9.4 | 대기 |
| B-18 | 개인정보 마스킹 (수집 단계) | P2 | M | ISMS-P 3.x | 대기 |
| B-19 | 읽기 전용 API 토큰 (외부 연계) | P3 | S | 확장 | 대기 |
| B-20 | 다중 워커 (실시간 스트림·머리줄 기억 DB화) | P3 | M | ADR-006 | 대기 |
| B-21 | OpenTelemetry(OTLP) 로그 수신 | P3 | M | 확장 | 대기 |
| B-22 | Windows 성능 메트릭 (CPU·메모리·디스크) | P3 | L | 로드맵 Phase 4 | 대기 |
| B-23 | 기술 부채 모음 | P2 | S | 개발 중 발견 | 대기 |
| B-24 | 사내 컨테이너 레지스트리 배포 (Harbor) | P3 | M | ADR-022 | 대기 |
| B-25 | 폐쇄망 첫 설치 실측 (사내 x86 서버) | P1 | S | AIRGAP.md §13 | 대기 |
| B-26 | 사용자 그룹 ↔ 알림 수신 그룹 연결 (팀별 알림) | P2 | M | 사용자 그룹 | 대기 |
| B-27 | 요약 숫자(PC 수·수집 속도·알림 수)에도 조회 범위 적용 | P3 | S | ADR-025 | 대기 |
| B-28 | Windows 에이전트 설치 묶음 실기 시험 (서비스 등록·GPO /quiet) | P1 | S | AIRGAP.md §13 | 대기 |

---

## P1 — 다음에 바로

### B-01 검색 언어
- **왜:** 지금은 입력 칸 조합(AND)과 메시지 OR(`a|b`)만 됩니다. 조사할 때 "이 IP 인데 이 계정은 빼고" 같은 조건을 한 줄로 쓸 수 없습니다.
- **문법 (안):**
  - `event_id:4625 ip:10.0.0.5 -user:svc_backup level:오류,심각 "잘못된 암호"`
  - 키는 검색 파라미터와 같습니다: `host channel provider source category user ip level event_id` + `f.<경로>`.
  - `-키:값` 제외, `키:a,b` 여러 값(OR), 따옴표는 메시지 구문, 그냥 단어는 메시지 부분일치(AND).
- **구현 방향:**
  - 서버: `server/app/filters.py` 에 `parse_query(text) -> EventFilter` 추가. 제외 조건을 담을 `EventFilter.excludes` 필드 추가.
  - SQL: `repository.py` 의 `where_clause` 에 `NOT IN` / `IS DISTINCT FROM` 처리. 원본 필드 제외는 `NOT (raw @> …)`.
  - 화면: 이벤트 검색·실시간 화면 상단에 입력 한 줄. 기존 드롭다운과 양방향 동기화(드롭다운을 바꾸면 문장이 바뀜).
  - 실시간: `web/js/livefilter.js` 에 같은 파서. **서버·화면 파서를 같은 테스트 케이스 표로 검증합니다**(AGENTS.md 함정: 둘 다 고쳐야 함).
  - 알림 규칙: `match.query: "…"` 키로 같은 문법을 받습니다.
- **완료 기준:** 파서 단위 테스트(정상·오류 문장 20개 이상), 잘못된 문장은 어디가 틀렸는지 한국어로 표시, URL 공유 시 같은 결과, 500만 건 벤치에서 기존 검색 대비 느려지지 않음.

### B-02 알림 처리 기록 (확인·해결·메모)
- **왜:** ISMS 2.11.5(사고 대응)는 "인지 → 조치 → 종료" 기록을 요구합니다. 지금은 발생·전송 이력만 있습니다.
- **구현 방향:**
  - 마이그레이션: `alerts` 에 `status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acked','resolved'))`, `acked_by`, `acked_at`, `resolved_by`, `resolved_at`. 메모는 별도 테이블 `alert_notes(alert_id, at, by, text)` (수정·삭제 불가, 감사 성격).
  - API: `POST /api/alerts/{id}/ack`, `/resolve`, `/notes` (관리자·조회자 모두? → 역할 정책 결정 필요, 기본안: 조회자도 확인·메모 가능, 해결은 관리자). 모두 `db.audit`.
  - 화면: 알림 이력에 상태 칩·필터('처리 안 됨'), 알림 상세에 버튼과 메모 타임라인. 사이드바 숫자를 '처리 안 된 알림 수'로.
  - 같은 규칙·대상으로 재발하면 열린 알림에 횟수만 더할지(묶기) 결정 → DECISIONS.md 에 기록.
- **완료 기준:** 상태 전이 테스트, 감사로그 기록 확인, CSV 내보내기에 처리자·처리 시각 포함, ISMS.md 증적 목록 갱신.

### B-03 알림 무음 (silence)
- **왜:** 점검·배포 중 예상된 오류로 알림이 쏟아지면 진짜 알림을 놓칩니다.
- **구현 방향:**
  - 테이블 `alert_silences(id, rule NULL, group_key NULL, starts_at, ends_at, reason, created_by)`.
  - `engine.py` 에서 발생 기록은 남기되 전송만 `skipped`(사유: 무음)로. 발생 자체를 숨기지 않아야 감사 증적이 남습니다.
  - 화면: 알림 상세에서 "이 규칙·대상 1시간/하루 무음", 환경설정에 무음 목록.
- **완료 기준:** 기간 경계 테스트, 무음 생성·삭제 감사로그, 무음 중 발생한 알림이 이력에 '무음' 표시.

### B-04 메신저 프리셋
- **왜:** 지금 웹훅은 `json`(자체 형식)과 `text`(Slack 호환)뿐이라 Teams·두레이·잔디는 받는 쪽에서 변환이 필요합니다.
- **구현 방향:**
  - 웹훅 연동의 `format` 값에 `slack`, `teams`, `dooray`, `jandi` 추가(`app/alerts/notifiers.py` WebhookNotifier). DB 스키마 변경은 없습니다(config JSON).
  - 형식별 본문: Slack Block Kit, Teams Adaptive Card(Workflows 웹훅), 두레이 `{botName, text, attachments}`, 잔디 `{body, connectColor, connectInfo}`.
  - 심각도 색은 `message.py` 의 색 표를 함께 씁니다.
  - 환경설정 화면에 형식 선택과 '예시 미리보기'.
- **완료 기준:** 형식별 본문 스냅샷 테스트, 실제 각 서비스 테스트 채널로 테스트 발송 1회씩(결과를 PROJECT.md §6.5 검증 기록에 추가).

### B-05 정기 점검 보고서
- **왜:** ISMS 2.9.5 는 "정기적으로 로그를 점검하고 결과를 남길 것"을 요구합니다. 지금은 사람이 대시보드를 열어 봐야 합니다.
- **구현 방향:**
  - 설정: 환경설정에 보고서(일간 09:00 / 주간 월요일 09:00, 받을 그룹·연동, 포함 항목).
  - 내용: 기간 내 수준별 건수와 추이, 상위 오류 PC, 보안 이벤트 요약(로그온 실패·계정 변경·로그 삭제), 알림 발생·처리 현황(B-02), 연락 끊긴 PC, 로그 보관 상태(파티션·보관 파일·무결성).
  - 엔진: 알림 엔진처럼 앱 내부 작업 + advisory lock. 보낸 보고서는 `reports(id, period, sent_at, payload)` 에 저장(증적).
  - 형식: 메일 HTML(기존 `message.py` 스타일), 메신저는 요약 + 링크.
- **완료 기준:** 보고서 생성 테스트(고정 데이터), Mailpit 수신 확인, '보고서 이력' 화면에서 과거 보고서 열람, ISMS.md 증적 목록 갱신.

### B-06 운영 HTTPS + 에이전트 TLS
- **왜:** 수집·화면 모두 평문 HTTP 입니다(PROJECT.md §15). 운영 전 필수입니다.
- **구현 방향:**
  - `deploy/caddy/` 예시: Caddy(Apache 2.0) 리버스 프록시, 사내 인증서 또는 내부 CA. Nginx(BSD) 예시도 함께.
  - compose 프로필 `--profile https`, `WLM_COOKIE_SECURE=true`, `api` 포트는 내부 망에만.
  - 에이전트: `fluent-bit.yaml` 의 `tls: on`, `tls.verify`, 사내 CA 배포 방법(install.ps1 `-CaFile`).
  - 접근 IP 제한(관리 화면은 사내 대역만) 예시.
- **완료 기준:** 개발 환경에서 자체 서명 인증서로 에이전트→서버 TLS 수집 확인, 운영 배포 절차(README) 갱신, ISMS.md 2.7.1 상태 '구현됨'.

### B-15 git 저장소화 + CI
- **왜:** 지금 폴더는 git 저장소가 아닙니다. ISMS 2.8.5(소스 관리)·변경 이력 증적(대시보드·규칙 파일 변경)을 위해 필요합니다.
- **구현 방향:**
  - `git init`, `.gitignore`(.env, archive/, pgdata, __pycache__), 브랜치 보호 규칙.
  - CI(사내 GitLab CI 또는 GitHub Actions): `ruff check`, `pytest`(PostgreSQL 서비스 컨테이너), 에이전트 설정 `fluent-bit --dry-run`, 이미지 취약점 점검 Trivy(Apache 2.0).
- **완료 기준:** 메인 브랜치에 CI 통과 필수, ISMS.md 2.8.5 상태 갱신.

### B-16 백업 자동화 + 복구 시험 기록
- **왜:** 지금은 `pg_dump` 절차만 문서에 있습니다(PROJECT.md §13). ISMS 2.9.3 은 정기 백업과 복구 시험 기록을 봅니다.
- **구현 방향:**
  - compose 에 백업 작업(매일 `pg_dump -Fc`, 보관 N개, `.env`·`archive/` 함께 묶기) 또는 `tools/backup.sh` + cron 예시.
  - `python -m app.cli verify-backup <파일>`: 임시 DB 에 복원해 행 수 확인 → 결과를 audit_log 에 기록.
  - 환경설정 > 로그 보관 화면에 마지막 백업·복구 시험 시각 표시.
- **완료 기준:** 백업→복원 시험 자동 테스트, 감사로그 기록, 운영 문서 갱신.

---

## P2 — 운영해 보며 필요해지면

### B-07 대시보드 위젯 편집 폼
- **왜:** 지금은 JSON 편집입니다. 운영자가 위젯 하나 추가하려면 형식을 알아야 합니다.
- **구현 방향:** `views/dashboard.js` 편집 모드에 위젯 목록(순서 끌어 옮기기), 위젯별 폼(종류·제목·너비·조건·필드). 조건 입력은 B-01 문장을 재사용. 저장은 기존 `PUT /api/dashboards/{name}`(JSON 그대로) — **파일 형식은 바꾸지 않습니다**.
- **완료 기준:** 폼으로 만든 JSON 과 손으로 쓴 JSON 이 같은 결과, 잘못된 값은 저장 전 표시, 새 대시보드 만들기·복제·삭제(감사로그).

### B-08 IIS 열 순서 영속화, MSSQL 여러 줄 합치기
- **왜 (IIS):** `#Fields:` 기억이 프로세스 메모리라 서버 재시작 직후 사용자 지정 열 순서 파일이 기본 순서로 잘못 읽힐 수 있습니다(ADR-020).
- **왜 (MSSQL):** ERRORLOG 의 스택·덤프 같은 여러 줄 메시지가 줄마다 따로 저장됩니다.
- **구현 방향:**
  - IIS: `iis_layouts(host, file, fields, updated_at)` 테이블에 저장하고 시작 시 읽기. 또는 에이전트에서 머리줄을 매 레코드에 붙이는 방식 비교 후 결정.
  - MSSQL: Fluent Bit `multiline.parser`(시작 줄 = 날짜 정규식)로 에이전트에서 묶는 방안이 우선. 묶인 레코드도 기존 정규화기가 첫 줄 기준으로 처리하게 테스트.
  - 기존 머리줄 합치기(`_pending`)는 B-20 과 함께 정리.
- **완료 기준:** 재시작 시나리오 테스트, 실제 ERRORLOG 샘플(여러 줄 포함)로 회귀 테스트, 에이전트 `--dry-run` 통과.

### B-09 시간별 집계 테이블
- **왜:** 30일 이상 집계는 행 수에 비례해 느려집니다(PERFORMANCE.md: 하루 수백만 건부터 체감).
- **구현 방향:** `events_hourly(hour, host, category, source, channel, event_id, level, n)` 를 매 5분 증분 갱신(마지막 처리 `received_at` 기억). `repository.py` 의 count/timeseries/top 이 기간 ≥ 7일이고 조건이 집계 열만 쓰면 집계 테이블을 씁니다(원본 필드·메시지 조건이면 원본). 로테이션 때 집계는 원본보다 오래 보관(추세용 1~3년).
- **완료 기준:** 벤치(`tools/bench`)로 30일·90일 화면 전후 비교를 PERFORMANCE.md 에 기록, 집계와 원본 결과 일치 테스트.

### B-10 자주 쓰는 원본 필드 인덱스
- **왜:** `f.EventData.LogonType` 같은 원본 필드 조건은 jsonb 전체를 훑습니다(7일 0.3초, 기간이 길면 증가).
- **구현 방향:** 자주 쓰는 경로에 표현식 인덱스(마이그레이션). 후보: `raw->'EventData'->>'LogonType'`, `raw->'iis'->>'uri_stem'`, `raw->'mssql'->>'error'`. 필드 탐색 화면에 "자주 검색됨" 표시(감사로그의 검색 조건 집계)로 후보를 고릅니다.
- **완료 기준:** 벤치 전후 기록(ADR-017 처럼 느려지면 기각 기록), 수집 처리량 저하 5% 이내.

### B-11 에이전트 중앙 관리
- **왜:** PC 가 많아지면 설정 변경(채널 추가, IIS 켜기)을 PC 마다 해야 합니다.
- **구현 방향 (단계):**
  1. 수집 PC 화면에 에이전트 설정 버전·Fluent Bit 버전·수집 채널 표시(하트비트 `meta` 확장), 기준 버전과 다르면 표시.
  2. GPO/SCCM/Ansible 배포 가이드와 스크립트(`install.ps1` 무인 설치 옵션 정리).
  3. (필요 시) 서버가 설정 파일을 내려주고 에이전트 쪽 작은 갱신 작업(예약 작업)이 가져가는 방식. 보안 검토 필수(설정 위조 = 수집 중단).
- **완료 기준:** 1·2단계 완료로 일단 종료, 3단계는 DECISIONS.md 에 결정 기록 후 착수.

### B-12 사내 SSO
- **왜:** 개인 계정을 따로 만들고 퇴사자 처리를 따로 해야 합니다(ISMS 2.5.x).
- **구현 방향:** AD/LDAP 바인드 인증(ldap3, LGPL-3.0) 또는 OIDC(Keycloak 등, Apache 2.0)와 연동. 역할은 AD 그룹 → 관리자/조회자 매핑. 로컬 관리자 1개는 비상용으로 유지. 세션·감사로그는 기존 그대로.
- **완료 기준:** 그룹 매핑 테스트, 비상 계정 절차 문서, ISMS.md 2.5.x 갱신, ADR-013 개정.

### B-13 순서 기반 상관 규칙
- **왜:** "로그온 실패 N회 후 성공(계정 탈취 의심)", "새 계정 생성 직후 관리자 그룹 추가" 같은 탐지는 건수 규칙으로 못 합니다.
- **구현 방향:** `rules.py` 의 `RULE_KINDS` 에 `sequence` 추가. 형식(안): `steps: [{match, threshold}, {match}]`, `within: 10m`, `same: [ip]` 또는 `[user]`. `engine.py` 에서 단계별 집계를 `same` 키로 조인(SQL 한 문장). 기본 규칙 2~3개 추가(MITRE T1110 + 성공, T1136 → T1098).
- **완료 기준:** 순서·시간 경계 테스트, 시뮬레이터에 시나리오 추가(`tools/simulate.py`), 규칙 팩 문서 갱신.

### B-17 보관 파일 외부 저장소 복제
- **왜:** `archive/` 가 같은 서버 디스크에만 있습니다. 서버 장애·랜섬웨어 시 같이 잃습니다(ISMS 2.9.4).
- **구현 방향:** rclone(MIT)로 NAS·S3 호환 저장소에 복제하는 예시 + 복제 후 원격 해시 확인. 가능하면 WORM(객체 잠금) 설정 안내.
- **완료 기준:** 복제·검증 스크립트, 로그 보관 화면에 마지막 복제 시각, ISMS.md 갱신.

### B-18 개인정보 마스킹
- **왜:** 응용 로그·IIS 쿼리 문자열에 주민등록번호·전화번호·이메일이 섞여 들어올 수 있습니다(ISMS-P 개인정보 처리 단계 요구사항).
- **구현 방향:** 수집 단계(정규화 직후) 마스킹 규칙(환경설정: 정규식 + 적용 소스). 원본 보존 원칙과 충돌하므로 **마스킹된 값을 원본으로 저장**하는 예외를 DECISIONS.md 에 기록. 기본 규칙: 주민번호(`\d{6}-[1-4]\d{6}`), 휴대전화, 카드번호(Luhn 확인).
- **완료 기준:** 오탐·미탐 테스트, 마스킹 규칙 변경 감사로그, 수집 처리량 저하 측정.

### B-23 기술 부채 모음
- `starlette.testclient` 의 httpx 사용 경고(StarletteDeprecationWarning) — FastAPI/Starlette 권장 방식으로 테스트 클라이언트 교체.
- 마이그레이션 007 의 기존 데이터 분류(UPDATE) 공급자 목록에 `SQLBrowser`·`SQLWriter` 가 없음(새 데이터는 `classify()` 가 처리). 다음 마이그레이션에서 보정 UPDATE.
- 필드 경로의 점(.) 구분 한계: 키 이름에 점이 있으면 `f.` 필터 불가(PROJECT.md §15). 이스케이프 문법(예: `f.a\.b`) 검토.
- PRI 없는 syslog 줄을 수신기가 버림 — collector 에 원문 보관 경로(`log_source: file`) 추가 검토.
- 시뮬레이터(`tools/simulate.py`)는 백그라운드 장시간 실행용이 아님 — `--duration` 옵션 추가.
- `requirements.txt` 가 버전 범위만 적혀 있어 빌드 시점마다 패키지 버전이 달라짐 — 잠금 파일(`requirements.lock`, pip-tools BSD) 도입. 지금은 묶음의 `images/PACKAGES.txt` 로 기록만 함.
- 종단 기능 검증 스크립트(2026-10-04 에 122개 항목으로 수동 실행)를 `tools/smoke_test.py` 로 저장소에 넣고, 설치 확인(AIRGAP.md §9)에 활용.

---

## P3 — 규모·요구가 생기면

### B-24 사내 컨테이너 레지스트리 배포
- **왜:** 서버가 여러 대(운영·DR·시험)이거나 다른 시스템도 컨테이너를 쓰면, 매번 묶음을 반입·로드하는 것보다 사내 레지스트리 하나에 올리는 편이 관리가 쉽습니다.
- **구현 방향:** Harbor(Apache 2.0) 또는 Docker Distribution(Apache 2.0)에 `make-bundle.sh` 결과를 `docker load` → `docker push`. compose 의 이미지 이름을 `registry.corp.local/log-monitor/...` 로 바꿀 수 있게 `.env` 변수화. 이미지 서명(cosign, Apache 2.0) 검토.
- **완료 기준:** AIRGAP.md 에 레지스트리 방식 절 추가, 시험 서버에서 pull 설치 확인.

### B-25 폐쇄망 첫 설치 실측
- **왜:** 리허설은 개발 PC 의 격리 Docker(arm64)에서 했습니다. 실제 사내 x86 서버·사내 Docker 설치 파일·SELinux·방화벽 조합은 아직 시험하지 않았습니다.
- **할 일:** 시험 서버에 AIRGAP.md 절차 그대로 설치 → §9 체크리스트 10개 결과 기록 → 막힌 부분을 문서·스크립트에 반영. 업그레이드·되돌리기(§10)도 1회 시험.
- **완료 기준:** AIRGAP.md §13 에 실측 기록 추가.

### B-26 사용자 그룹 ↔ 알림 수신 그룹 연결
- **왜:** 지금 알림 수신 그룹(메일 받는 사람)과 로그인 사용자 그룹이 따로 있습니다. "DB팀 규칙은 DB팀에게" 를 한 번에 설정하고 싶을 수 있습니다.
- **구현 방향:** 수신 그룹에 '사용자 그룹 구성원에게도 보내기' 옵션 (사용자에 이메일 칸 추가) 또는 규칙 묶음 → 기본 받는 곳 지정.
- **완료 기준:** 화면에서 연결, 메일 수신 시험, 감사로그.

### B-28 Windows 에이전트 설치 묶음 실기 시험
- **왜:** PowerShell 문법·설정 읽기·Fluent Bit 압축 해제까지는 리눅스 PowerShell 로 확인했지만, 서비스 등록과 GPO `/quiet` 배포는 Windows 에서만 확인할 수 있습니다.
- **할 일:** Windows 10/11, Server 2019/2022 시험 PC 에서 zip 설치 → 서비스·하트비트 확인 → GPO 시작 스크립트 배포 1회 → 결과를 AIRGAP.md §13 에 기록.

### B-14 Sigma 규칙 가져오기
- **왜:** 공개 탐지 규칙(SigmaHQ, DRL 1.1)을 쓰면 규칙 팩을 직접 만들 필요가 줄어듭니다.
- **구현 방향:** `tools/sigma_import.py` 가 Sigma YAML(windows 범주)을 `config/alerts.yaml` 규칙으로 변환. 필드 매핑 표(Sigma `TargetUserName` → `user`, `IpAddress` → `ip`, 그 외 → `f.EventData.*`). 변환 못 하는 조건(정규식 수정자, 집계)은 건너뛰고 보고서로 출력. pySigma(LGPL-2.1) 사용 검토.
- **완료 기준:** 대표 규칙 30개 변환 성공률 보고, 변환 규칙에 `tags`(MITRE) 자동 부착, B-01·B-13 완료 후 착수.

### B-19 읽기 전용 API 토큰
- **왜:** 다른 시스템(사내 포털, BI)이 검색 API 를 쓰려면 지금은 로그인 세션이 필요합니다.
- **구현 방향:** `api_tokens(id, name, hash, scopes, expires_at, created_by)`, 헤더 `Authorization: Bearer`. 조회 전용 범위만. 모든 호출 감사로그. 사용자 화면에서 발급·폐기(값은 발급 때 한 번만 표시).
- **완료 기준:** 만료·폐기 테스트, CSRF 예외 범위 검토, ISMS.md 접근통제 갱신.

### B-20 다중 워커
- **왜:** 실시간 스트림, IP 로그인 제한, IIS·MSSQL 머리줄 기억이 프로세스 메모리라 uvicorn 워커가 1개여야 합니다(ADR-006).
- **구현 방향:** 실시간은 PostgreSQL `LISTEN/NOTIFY`(또는 수집 배치 id 폴링), 로그인 제한·머리줄은 DB 테이블. 수집 처리량이 한 프로세스(초당 약 9,800건)를 넘을 때 착수.
- **완료 기준:** 워커 4개로 벤치, 실시간 화면 누락·중복 없음 확인, ADR-006 개정.

### B-21 OpenTelemetry 로그 수신
- **왜:** 사내 응용 프로그램(.NET, Java)이 OTel SDK 로 로그를 보낼 수 있으면 파일 tail 없이 받습니다.
- **구현 방향:** `POST /v1/logs`(OTLP/HTTP JSON) 수신 → `normalizers/otlp.py`(resource 속성 → host·category, severityNumber → level). protobuf 는 opentelemetry-proto(Apache 2.0).
- **완료 기준:** OTel Collector 로 보내는 예시 설정, 정규화 테스트.

### B-22 Windows 성능 메트릭
- **왜:** 장애 분석 때 로그와 함께 CPU·메모리·디스크 추세를 보고 싶다는 요구가 생길 수 있습니다(PROJECT.md 범위 밖 → 로드맵 Phase 4).
- **구현 방향:** Fluent Bit `windows_exporter_metrics` 입력 → 별도 테이블 `metrics(ts, host, name, value)` (이벤트와 분리, 짧은 보관) → 대시보드 `metric` 위젯. 대안으로 Prometheus(Apache 2.0) + 기존 대시보드는 링크만.
- **완료 기준:** DECISIONS.md 에 방식 결정 기록 후 착수.
