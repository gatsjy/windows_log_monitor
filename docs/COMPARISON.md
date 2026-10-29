# 다른 모니터링 시스템과 비교 — 벤치마킹 (2026-10-29)

> 목적: 비슷한 일을 하는 오픈소스·상용 시스템이 **어떻게** 하는지 보고, 우리에게 빠진 것과 틀린 것을 찾아 [BACKLOG.md](BACKLOG.md) 의 계획으로 옮긴다.
> 2026-10-04 판(Wazuh·Graylog·ELK·Loki 기능표)을 대신한다. 그때 남긴 B-01~B-05 는 대부분 끝났다(PROJECT.md, CHANGELOG.md).
> 제품·라이선스·법령 정보는 조사 시점(2026-10) 공개 자료 기준이다. 도입하거나 인용하기 전에 원문에서 다시 확인한다(§7).

## 1. 목적과 방법

**6 묶음으로 나눠 조사했습니다** (발견 111건, 발견마다 동작 원리·우리 상태·출처 URL).

| 묶음 | 본 시스템 | 발견 |
|---|---|---|
| SIEM 오픈소스 | Wazuh, Security Onion, OpenSearch Security Analytics, Elastic Security, Sigma, MITRE ATT&CK | 22 |
| 로그 관리 UX | Graylog, Seq, Grafana Loki·Explore, Kibana, Datadog Logs | 17 |
| 알림·에이전트 운영 | Alertmanager, Grafana Alerting·OnCall, Zabbix, PagerDuty, Graylog Sidecar, Elastic Fleet, osquery·Fleet, Fluent Bit, OpAMP | 18 |
| Windows 탐지 | Sigma·SigmaHQ·pySigma, Hayabusa, Chainsaw, DeepBlueCLI, Microsoft WEF·Appendix L, Sysmon 설정 | 20 |
| 저장·성능 | VictoriaLogs, ClickHouse·ClickStack, Loki, Elasticsearch·OpenSearch, Parquet·DuckDB, TimescaleDB·Citus, PostgreSQL 17·18 | 15 |
| 국내 상용·법령 | Splunk ES, Microsoft Sentinel, Logpresso, 이지서티, 피앤피시큐어, ManageEngine, 안전성 확보조치 기준, ISMS-P, 의료법 | 19 |

**진행 순서:**
1. 조사: 묶음마다 공개 문서와 소스를 읽고 발견을 적었습니다.
2. 로드맵: 중복을 합쳐 항목 약 50개로 정리했습니다(기존 BACKLOG 8개 포함).
3. 적대적 검토 두 번: 판정자와 누락 비평가가 코드·개발 DB 로 각 항목을 반박하고 재현했습니다. 이미 고쳐진 것, 원인을 잘못 짚은 것, 빠진 것(13건)을 찾았습니다.
4. 결과를 이 문서와 BACKLOG(B-34~B-83, 기존 항목 보강)에 옮겼습니다.

**자료 원칙:**
- 공개 문서와 공개 소스를 읽었습니다. 소스는 동작을 확인하는 데만 썼고(Wazuh `eventinfo.c`·Graylog·Kibana 위험 점수 등 MIT 가 아닌 소스 포함), 가져온 코드는 없습니다.
- **이 저장소(MIT)에는 아이디어만 다시 구현합니다.** 새 의존성은 OSI 승인 라이선스만 씁니다(AGENTS.md 절대 규칙 1).
- Sigma 규칙(SigmaHQ)은 DRL 1.1 입니다(OSI 소프트웨어 라이선스가 아님). 규칙을 들여오면(B-14) 저자·출처를 규칙과 알림에 표시합니다. 우리가 직접 쓰는 규칙은 조건만 참고합니다.
- 시험 표본은 직접 캡처한 것(윈도 CI)이나 OTRF Security-Datasets(MIT)만 씁니다. EVTX-ATTACK-SAMPLES(GPL-3.0)는 저장소에 넣지 않습니다.
- 그 밖의 MIT 자료(Palantir WEF·sysmon-modular 등)는 고지를 지키면 고쳐 쓸 수 있습니다(BACKLOG 작업 규칙 6).

**판단 기준:** 1~2명이 운영하는 병원 폐쇄망 서버 한 대에서 유지할 수 있는가. PostgreSQL 하나, 빌드 없는 UI, 원본 보존, 추가만 하는 마이그레이션 원칙을 지키는가.

## 2. 비교 대상

| 시스템 | 성격 | 라이선스 | 우리가 참고한 것 |
|---|---|---|---|
| **Wazuh 4.14** | 오픈소스 SIEM·XDR | GPLv2 | 빈도·순서 규칙(`if_matched_sid`), CDB 목록, 처음 보는 값(FTS), 중앙 설정 체크섬, wazuh-logtest |
| **Security Onion 2.4** | 보안 관제 배포판 | ELv2 | 탐지 튜닝·운영 메모, Rule Mismatch, 알림 대기열 묶어 보기, 케이스, 플레이북 |
| **Elastic Security 9.x** | SIEM | ELv2·SSPL·AGPL | threshold+cardinality, EQL sequence, new terms, 알림 억제, 예외·값 목록, 위험 점수, 규칙 실행 감시 |
| **OpenSearch Security Analytics 3.x** | SIEM 플러그인 | Apache-2.0 | finding 과 trigger 분리, 상관 규칙·ATT&CK 자동 상관 |
| **Sigma 2.1 · SigmaHQ · pySigma** | 규칙 형식·규칙집·변환기 | 명세 public domain, 규칙 DRL 1.1, pySigma LGPL-2.1 | 상관 규칙(value_count·temporal), 수정자, 회귀 표본(regression_data) |
| **Hayabusa · Chainsaw · DeepBlueCLI** | Windows EVTX 분석 도구 | AGPL-3.0 · GPL-3.0 · GPL-3.0 | 스프레이 카운터, 한 줄 요약(default_details), noisy 목록, EventRecordID 누락 찾기 |
| **MITRE ATT&CK · Navigator** | 공격 기법 체계 | MITRE 이용 조건(표시) · Apache-2.0 | 기법 태그, 범위 지도(레이어 v4.5). 버전 변경은 §7 확인 필요 |
| **Microsoft WEF 지침·Appendix L, NSA·Palantir WEF** | Windows 수집 지침 | 문서 · CC0 · MIT | 감사 정책 기준선, XPath 수집, USB·출력 이벤트, 이벤트 중요도 |
| **Prometheus · Alertmanager** | 규칙 평가·알림 라우팅 | Apache-2.0 | 상태 기계(`keep_firing_for`), 묶음 전송, 라벨 무음, 복구 통지, Watchdog(늘 울리는 알림) |
| **Grafana Alerting · OnCall** | 알림·당직 | AGPL-3.0 (OnCall OSS 는 2026-03 보관 처리) | NoData·Error 상태, 반복 무음 시간, 에스컬레이션 체인 |
| **Zabbix 7** | 인프라 감시 | AGPL-3.0 | 점검 기간, 트리거 의존성, 복구 식, `nodata()`, 시계 오차(`fuzzytime`) |
| **PagerDuty** | 사고 대응 SaaS | 상용 | Events v2 `dedup_key`, 에스컬레이션·확인 시간 초과 |
| **Elastic Fleet · Graylog Sidecar · osquery/Fleet · OpAMP** | 에이전트 관리 | ELv2 · SSPL · Apache-2.0/MIT · Apache-2.0 | 설정 해시 비교, 에이전트별 등록 키, 상태 모델, 서명 갱신(TUF), 원격 설정 보안 지침 |
| **Fluent Bit 4.0.14 / 5.1** | 우리 에이전트 | Apache-2.0 | 내부 지표, `event_data_as_map`(5.1), 청크·재시도 동작 |
| **Graylog Open 6·7** | 로그 관리 | SSPL | 앞뒤 메시지, 조회표, 스트림별 보관 |
| **Seq** | 구조화 로그 서버 | 독점 | 저장 검색(시그널) 재사용, First of Type, 보존 정책 |
| **Grafana Loki 3 · Explore** | 로그 저장·탐색 | AGPL-3.0 | 패턴(Drain), Show context, 스트림별 보관 |
| **Kibana Discover · AIOps** | 검색·시각화 | ELv2·SSPL·AGPL | 앞뒤 문서, 값 자동완성, 필드 상위 값, 로그 빈도 분석 |
| **Datadog Logs** | SaaS | 독점 | 패턴, Transactions(세션 묶기), Saved Views, 이상치 감시 |
| **VictoriaLogs** | 로그 DB | Apache-2.0 | 일 파티션, 단어·접두 검색, 디스크 한도 |
| **ClickHouse · ClickStack** | 컬럼형 DB·관측 | Apache-2.0 · MIT | 증분 집계(MV), 건너뛰기 색인, 속성 역색인 |
| **TimescaleDB · Citus · Hydra** | PostgreSQL 확장 | 해당 기능 TSL · AGPL | 실시간 집계, 증분 rollup — 개념만, **도입 불가**(§6) |
| **PostgreSQL 17·18 내장 기능** | 우리 저장소 | PostgreSQL | BRIN, TOAST lz4, 'simple' 텍스트 검색, GIN `jsonb_path_ops` |
| **Splunk ES · Microsoft Sentinel** | 상용 SIEM | 독점 | 위험 기반 알림, 자산·신원 목록, 종료 분류, 개체 페이지, 데이터 무결성 해시 |
| **Logpresso Sonar** | 국산 SIEM | 독점 | 소명 절차, 직원 정보, 보고서 hwpx, 연동 앱 |
| **이지서티 · 피앤피시큐어 · 이글루 SPiDER TM** | 국산 접속기록·DB 접근제어·관제 | 독점 | 접속기록 5항목, 월간 점검 리포트, 권한 검토 |
| **ManageEngine ADAudit Plus · EventLog Analyzer** | AD 감사·로그 관리 | 독점 | 계정 잠금 원인 추적, 규정별 보고서 |
| **안전성 확보조치 기준 · ISMS-P · 의료법** | 규정 | — | 보관기간, 접속기록 항목, 점검 증적 (개정 내용은 §7 확인 필요) |

## 3. 우리 쪽 강점 (유지할 것)

- **검색 문장 하나.** 검색·실시간·알림 규칙·대시보드가 같은 문장을 쓰고, 서버·화면 의미를 케이스 표·교차 퍼징·SQL 스냅샷으로 고정합니다(ADR-033). Kibana 는 KQL·Lucene·ES|QL 로, Grafana 는 LogQL 과 Drilldown 으로 나뉩니다.
  → 예외·목록·플레이북·대시보드 변수도 별도 DSL 없이 이 문장을 재사용합니다.
- **고칠 수 없는 증적.** `audit_log`·`alert_notes`·`reports` 는 DB 트리거로 UPDATE·DELETE·TRUNCATE 를 막고, 보관 파일 SHA-256 을 감사로그에 남깁니다. 비교한 제품의 사건 이력은 대부분 애플리케이션 수준 기록입니다. 다음 단계는 해시 체인(B-71)입니다.
- **수신 시각 기준 평가(ADR-011).** 장애 뒤 몰아 받은 로그도 평가합니다. Wazuh 는 재시작하면 빈도 상태를 잃고, Loki·VictoriaLogs 는 오래된 표본을 버립니다. 대가(몰아 받은 로그의 건수 오탐)는 B-35 에서 표시합니다.
- **무음 중에도 기록.** 발생은 남기고 전송만 건너뛰며, 사유·설정자·해제 이력이 남습니다(ADR-029). Alertmanager 는 무음된 알림을 기록하지 않습니다.
- **규칙 미리보기.** 최근 24시간에 맞는 건수와, 재알림 간격을 반영한 예상 알림 수를 대상별로 보여 줍니다.
- **조회 범위를 서버에서.** 사용자 그룹의 분류·PC 범위를 이벤트·통계·실시간·알림·무음까지 LIMIT 전에 적용합니다(ADR-025). 상단 요약 숫자 일부는 아직 전체 기준입니다(B-27).
- **수집 전용 에이전트.** 명령 실행 채널이 없어 서버를 탈취해도 전 PC 명령으로 번지지 않습니다. TLS 이름 확인은 끌 수 없고 CA 지문을 대조하며, 서버는 묶음을 만들기 전에 에이전트와 같은 OpenSSL 핸드셰이크로 검증합니다(ADR-036).
- **단순한 운영.** PostgreSQL 하나와 컨테이너 3~4개, 해시가 붙은 폐쇄망 묶음, 업그레이드 전 자동 백업, 매주 실제 복원 시험. JVM 검색 클러스터·MongoDB·GB 당 과금이 없습니다.
- **원본 보존 + 한 트랜잭션 수집.** raw JSONB 를 그대로 두고 서버 해석은 `raw.<소스>.*` 에 덧붙입니다. 이벤트·agents·field_stats·iis_layouts 가 한 트랜잭션이라 집계 표(B-09)도 같은 트랜잭션에 덧붙일 수 있습니다.
  → 분류·사용자·IP 는 공통 열(`category`·`username`·`src_ip`, ADR-019)로 뽑아 Windows·IIS·MSSQL·SSH 를 가로질러 찾습니다. Wazuh·Graylog·Elastic(ECS)도 이런 공통 스키마를 둡니다.
- **웹훅 보안 기본값.** 30x 넘김 거부, 오류 문구의 토큰 가림, 클라우드 메신저 https 강제, 주소별 전송 간격, CSV 수식 주입 방지.
- **한국 환경·ISMS-P.** 규칙마다 ISMS 항목, 보안 규칙에는 MITRE 태그, 한국어 UI, 두레이·잔디, Oracle(TNS/SID), 일간·주간 점검 보고서와 '점검 확인', '지난주 같은 요일' 비교.
- **IIS·SQL Server 해석.** IIS W3C 열 순서 DB 영속·값 모양 검사, ERRORLOG 여러 줄 묶기(ADR-037). EVTX 전용 도구·Loki·Seq 는 이것을 하지 않습니다.
- **화면 조회 보호.** 시간 상한 30초·동시 6자리로 수집·알림 연결을 지키고(ADR-035), keyset 커서라 깊은 페이지 제한이 없습니다.

## 4. 조사 기간에 찾아 고친 것

| 무엇이 틀렸나 | 영향 | 고친 것 | 근거 |
|---|---|---|---|
| 에이전트(Fluent Bit 4.0.14)는 EventData 이름 없이 StringInserts 만 보냄 | 기본 규칙 1000007·1000009 와 보안 대시보드 RDP 위젯이 실제 PC 에서 맞을 수 없었음. 시험·시뮬레이터가 이름을 넣어 보내 통과 | 서버가 (공급자, ID, 버전) 템플릿으로 `raw.winevtlog.EventData` 를 덧붙이고 `f.EventData.*` 는 별칭. 시험은 윈도 CI 실측 모양 | ADR-038 · 98f6ba3 |
| 서버에 못 보내는 동안 하트비트 조각(256KB 선점)이 쌓임 | PC 메모리가 장애 하루에 약 720MB 늘어남 | 하트비트 전용 출력(재시도 2번 뒤 버림), 윈도 CI 메모리 시험 | ADR-039 · 8622351 (업그레이드는 B-33) |
| 보관기간 설정 하나로 모든 기록을 같은 날 지움. 보관 파일에 공통 필드 누락 | 권한 변경 감사로그가 1년 만에 사라짐(제5조 3년). 복원한 달의 `user:`·`ip:` 검색이 0건 | 기록 종류별 보관기간(감사로그·보고서 3년), 법정 최소 미달 경고, 보관 파일 v2 | ADR-040 · 513d3b9 |
| 규칙이 건수만 셈 | 패스워드 스프레이와 교대 근무 오타를 가를 수 없음 | `distinct` 규칙 + 기본 규칙 3개(1000021~23) | ADR-041 · cb24543 |
| `group_by` ip·user 규칙이 값 없는 이벤트를 '' 한 묶음으로 셈 | 1000006 이 출발지·표본 없이 울림(개발 DB 후보 1위가 이 묶음 3,610건). distinct 를 더하면 병원 전체 오타가 스프레이로 셈 | 알림 후보·미리보기에서 `<키> IS NOT NULL` | ADR-041 3-1 · aeb38bf |
| 레코드 하나의 NUL 이 psycopg 오류로 요청 전체를 500 으로 만듦 | 에이전트·수집기가 같은 청크를 끝없이 재전송(장비 이름 하나로 수집기의 모든 장비 로그가 멈춤) | 정규화 단계에서 Event 의 모든 글자 칸과 저장 단계의 `agents.last_ip`·field_stats 에서 NUL 제거 | aeb38bf. 남은 것: 레코드 격리·거절 장부(B-40) |
| 이 시스템의 접속기록: 상세 조회에 정보주체 없음, 사용자·IP 상위 값 조회 미기록, 기록 실패해도 조회 진행, CSV 사유 없음 | 누구의 기록을 봤는지·개인정보 통계를 누가 봤는지 증명 불가 | `events.view` 에 username·src_ip·category, `events.stats`(10분 묶음), 검색·상세·상위 값·CSV 는 기록 실패 시 503, CSV 사유 필수 | ADR-042 · 31d61df. 남은 것: B-38 |
| 규칙·대시보드의 `f.EventData` 이름을 검사하지 않음 | 이름 오타·그 이벤트에 없는 이름이 실제 PC 에서 영영 안 맞음(1000007·1000009 사례) | 이름이 그 이벤트의 **실측 확인된** 템플릿에 있는지 정적 검사(`test_rule_fields.py`) | 08a315b. 남은 것: 규칙별 표본(B-45) |
| 민감정보 처리 시스템의 접속기록 2년(제8조)은 안내만, v1 보관 파일 복원 시 Windows 이름 없음 | 1년으로 둔 채 넘어가도 경고 없음, 복원한 달의 `f.EventData.*` 규칙·위젯 0건 | `WLM_SENSITIVE_ACCESS_LOG=on` 이면 730일 미만 경고, v1 복원 때 `win_templates` 로 이름 덧붙임 | ADR-040 보완 · 207fb42 |
| 서버에서 `config/alerts.yaml` 을 직접 고치면 로그 한 줄만 남기고 바로 적용, 깨진 파일로 시작하면 규칙 0개 | 탐지를 끈 사실이 아무 데도 남지 않음. 화면에서 규칙을 꺼도 그 알림을 받던 사람은 모름 | 설정 판본(`alert_config_versions`)과 감사로그 `alerts.config.apply`. 약해지는 변경·넓은 무음은 내장 알림 '알림 설정 변경'으로 바뀌기 전 받는 곳에. 깨진 파일이면 마지막 판본으로 감시 | ADR-043 (B-36 1단계). 남은 것: 다른 관리 작업 알림(B-36) |

**검토가 바로잡은 로드맵 안:**
- 규칙을 위치 번호(`f.StringInserts.N`)로 고치는 안 → 버전마다 위치가 바뀌어 기각(ADR-038). 남은 일은 규칙 표본 게이트(B-45)입니다.
- 감사로그를 동작 접두어별로 다르게 보관 → 분류 실수는 되돌릴 수 없어 전체 3년(ADR-040).
- 엔진 '평가 공백 따라잡기' → 서버가 멈추면 수집도 멈추므로 공백의 실제 원인은 **전송을 기다리느라 주기가 멈추는 것**. 전송 분리로 바꿈(B-34).
- 해결하면 재알림 간격을 무시 → 창 안에 남은 같은 이벤트로 바로 다시 울림. **해결 시각 뒤 새 이벤트**가 있을 때만으로(B-35).
- 보안 건수 규칙의 자동 해소 → 사람이 검토하지 않은 알림이 '해결됨'으로 남음. 운영 규칙만(B-35 2단계).
- 내려받기 사유 모달 중심 → 실제 빈 곳은 통계 조회 미기록·정보주체 없는 상세 조회·기록 실패 시 진행. 이 범위로 ADR-042 에 반영했습니다.
- EventRecordID 누락 10분 대기 → Fluent Bit 재시도 백오프보다 짧아 거짓 누락. 하트비트 기준 대기·DB 커서로(B-56, P2).
- 에이전트 지표를 remote_write(gzip)로 → 규격은 snappy. 하트비트 값부터(B-57).
- ATT&CK 태그·개정 고시·의료법 날짜 → 1차 출처를 확인하기 전에는 바꾸지 않음(§7).

## 5. 영역별 차이와 로드맵

- 표의 '우리 상태': ✅ 있음 · △ 일부 · ❌ 없음 (2026-10-29 코드 기준).
- 'BACKLOG' 칸은 [BACKLOG.md](BACKLOG.md) 항목 번호입니다. 우선순위는 BACKLOG 요약 표를 따릅니다.
- **다음 순서(P1):** B-36 탐지 약화 변경 감시(1단계 완료, ADR-043) → B-34 엔진 감시·전송 분리 → B-40 수집 견고성 → B-35 알림 수명주기 1단계 → B-37 수집 완전성 1단계 → B-39 EMR 접속기록 조사·결정(0단계 완료, ADR-048 — 병원 답변 대기) → B-17 외부 복제(완료, ADR-047).
  - B-40 은 운영(병원) 첫 설치 전에 끝냅니다.
  - 자체 접속기록은 핵심을 ADR-042 로 끝냈고 남은 것은 B-38(P2)입니다.

### 5.1 탐지 규칙·상관

| 항목 | 다른 제품의 방식 | 우리 상태 | BACKLOG |
|---|---|---|---|
| 서로 다른 값 수 | Elastic threshold 의 cardinality, Sigma `value_count`: 묶음마다 서로 다른 값 수가 기준 이상일 때 | ✅ `distinct`(ADR-041), 기본 규칙 3개. 여러 키로 묶기는 없음 | B-13 에서 이어서 |
| 순서·부재 상관 | Elastic EQL `sequence`(maxspan·by·until·부재, 키마다 대기 시퀀스 1개), Sigma `temporal_ordered`(규칙 이름 참조·aliases) | ❌ 건수·`agent_silent` 규칙만 | B-13 |
| 처음 보는 값 | Elastic new terms(이력 창에 없던 값), Wazuh FTS, Sentinel UEBA FirstTime*(30~180일 기준선) | ❌ | B-47 (선행 B-54) |
| 규칙 예외 | Elastic exceptions·공유 목록(작성자·만료), Security Onion 튜닝·운영 메모, Sigma `filter_optional_*` | △ 규칙 문장에 `-user:` 를 직접 씀. 무음은 (규칙, 대상) 30일 이내 | B-46 |
| 값 목록·자산 | Wazuh CDB 목록, Sentinel watchlist(퇴직자·중요 자산·내부 대역), Splunk ES asset & identity 우선순위 | ❌ 검색 문장의 인라인 OR(`ip:a,b`)뿐 | B-53, B-55 |
| 계정 표기 통일 | Splunk ES identity(한 사람의 여러 계정), Sentinel Identity Correlation | ❌ `clean_user` 는 원문 그대로(`kim`, `HOSP\kim`, UPN 이 섞일 수 있음) | B-54 |
| 기본 규칙 표본 시험 | SigmaHQ `regression_data`(규칙마다 표본·기대 건수), Hayabusa sample-evtx, wazuh-logtest | △ 템플릿 34개 중 실측 확인 11개(윈도 CI), 나머지 23개는 문서 기반 — 그중 기본 규칙이 기대는 것: 4698·4719·4740·4771·1102. `f.EventData` 이름은 정적 검사(`test_rule_fields.py`), 실측 모양 시험은 규칙 6개만 | B-45, B-28 |
| 규칙 시험기·관찰 모드 | wazuh-logtest 단계별 출력, Hayabusa proven/noisy, SigmaHQ 패키지 단계 | △ 24시간 미리보기(예상 알림 수)만 | B-52 |
| 기본 팩과 현장 수정 | Wazuh `ruleset/` 와 `local_rules.xml`+overwrite, Elastic 사전 규칙 3-way 비교 | △ 한 파일(`alerts.yaml`). 업그레이드 때 `alerts.yaml.new` 를 손으로 합침 | B-51 |
| 탐지 내용 | SigmaHQ windows builtin(Kerberoasting·DCSync·4719 하위 범주·xp_cmdshell), Microsoft Appendix L, Hayabusa 의 Defender 등급 분할 | △ 규칙 23개. Kerberoasting·DCSync 같은 DC 공격·AD 객체 변경(5136) 탐지 없음, Defender 1116/1117 모두 critical, 4719 전체에 울림, Linux 는 SSH 하나 | B-48, B-49, B-50 |
| Sigma 가져오기 | Sigma taxonomy·modifiers, pySigma 처리 파이프라인, Hayabusa 변환기의 4688/Sysmon 이중 규칙 | ❌ 계획만 | B-14 (P3) |
| 신호·위험 점수 | Elastic building block·entity risk score, Splunk RBA(개체별 24시간 점수 합) | ❌ 규칙마다 바로 알림 | B-78 (P3) |
| ATT&CK 범위 | Elastic MITRE coverage, Wazuh MITRE 모듈, Navigator 레이어 v4.5 | △ 태그 문자열만(`MITRE T1070.001`) | B-73, 태그 갱신은 B-48 (§7) |

### 5.2 알림 수명주기·운영

| 항목 | 다른 제품의 방식 | 우리 상태 | BACKLOG |
|---|---|---|---|
| 엔진 자체 감시 | Prometheus 규칙별 health·lastError·evaluationTime, Grafana Error·NoData 상태, Elastic 규칙 실행 기록 | △ 엔진 상태가 전체 하나(마지막 실행·오류). 규칙 실패는 로그 한 줄, 후보 `LIMIT 100` 이 넘쳐도 표시 없음, `/healthz` 는 DB `SELECT 1` 만 | B-34 |
| 전송과 평가 분리 | Alertmanager dispatcher: 평가와 별도 대기열·전송 기록(nflog) | ❌ 평가 루프가 알림마다 전송을 기다림(대상당 최대 30초), 재시도도 같은 주기 | B-34 |
| 알림 경로 고장 감지 | Alertmanager Watchdog(항상 울리는 알림, dead man's switch) | ❌ 사람이 누르는 시험 전송만 | B-34 |
| 억제 건수 | Elastic 알림 억제: 억제된 문서 수, 닫으면 억제 초기화 | ❌ 재알림 간격 동안 들어온 건수·마지막 시각을 남기지 않음 | B-35 |
| 해결 뒤 재발 | Elastic(닫으면 억제 초기화), Zabbix 복구 식 | ❌ `last_alert` 가 처리 상태를 읽지 않아 해결 직후 재발도 간격(5분~2시간) 동안 침묵 | B-35 |
| 지연 수신분 | Loki·VictoriaLogs 는 오래된 표본을 버림, Elastic 은 gap 채우기 | △ 받아서 평가하지만, 몰려 들어온 몇 시간치가 창 하나에 세어져 오탐 | B-35 |
| 자동 해소·복구 통지 | Prometheus `keep_firing_for`, Alertmanager `send_resolved`, Zabbix 복구, PagerDuty `dedup_key` | ❌ 해결은 사람만, `agent_silent` 회복도 기록 없음, 외부 티켓용 고정 키 없음 | B-35 2단계 |
| 묶음 전송 | Alertmanager `group_wait`·`group_interval`, Grafana 알림 정책 | ❌ 대상 키마다 한 통(300대면 300통) | B-41 |
| 반복 점검·라벨 무음 | Alertmanager `time_interval`·라벨 매처 무음, Grafana mute timing, Zabbix 점검 기간 | △ 1회성 무음(30일 이내, 규칙·대상 단위) | B-42 |
| 에스컬레이션 | PagerDuty 에스컬레이션 정책·확인 시간 초과, Zabbix 액션 단계 | ❌ | B-43 |
| 받는 곳 경로 | Alertmanager route 트리(matchers·continue) | △ 규칙마다 `notify` 목록 | B-26 |
| 대기열·종료 분류 | Security Onion Alerts(Group By·ack/escalate), Sentinel 종료 분류(TP/BP/FP) | △ 발생마다 한 행, 같은 규칙·대상 함께 해결 | B-44 |
| 탐지 약화 변경 | (검토에서 도출 — 조사 자료에 대응 제품 기능 없음) | △ 알림 설정은 판본·약화 알림(ADR-043): 화면 저장·서버 파일 직접 수정·꺼져 있는 동안의 수정을 판본으로 남기고, 약해지는 변경·넓은 무음은 바뀌기 전 받는 곳에 알림. 수신 그룹 구성원·보관 파일 삭제·권한 부여 같은 다른 관리 작업은 감사로그에만 | B-36 |
| 운영 준비도 | (조사 종합 — 단일 제품 기능 아님) | △ 신호가 여러 화면·로그에 흩어짐 | B-75 |
| 메신저 형식 | Alertmanager·Grafana 기본 통합 | ✅ Slack·Teams·두레이·잔디(ADR-030), 실채널 확인만 남음 | B-04 |

### 5.3 수집·에이전트

| 항목 | 다른 제품의 방식 | 우리 상태 | BACKLOG |
|---|---|---|---|
| PC×채널 끊김 | Zabbix `nodata()`, Grafana NoData, Elastic Fleet 상태 | △ `agent_silent` 는 PC 전체가 조용할 때만, 보고서는 전체 0건·절반 이하만 | B-37 |
| 규칙별 데이터 유무 | Elastic Required fields·'Matched indices 0', Security Onion Rule Mismatch, ATT&CK Data Components | ❌ 필요한 감사 정책은 ISMS.md 문서에만 | B-37 |
| 레코드 누락·해석 품질 | Chainsaw `analyse gaps`(EventRecordID), Hayabusa 이벤트 ID 별 지표 | ❌ catalog 는 EventRecordID 를 '누락 확인에 사용'이라 설명하지만 확인 코드 없음 | B-56 |
| 문제 레코드 격리 | dead letter queue(처리 못 한 레코드 보관함) 개념(Fluent Bit 4.0 에는 없음, ADR-039) | △ NUL 은 막음(aeb38bf). 정규화 예외·DB 데이터 오류는 여전히 요청 전체 실패 | B-40 |
| 거절한 요청 기록 | (검토에서 도출. 참고: Graylog Sidecar·OpAMP 는 에이전트가 스스로 상태 보고) | ❌ 401·413 은 응답만, 서버에 남지 않음 | B-40 |
| 에이전트 상태 신호 | Fluent Bit `fluentbit_metrics`(dropped_records_total), OpAMP ComponentHealth, Zabbix `fuzzytime` | ❌ 하트비트는 설정 버전 하나, 하트비트 발생 시각(`date`)은 버림 | B-57 |
| 설정 차이·중앙 관리 | Wazuh merged.mg 체크섬, Elastic Fleet 정책 revision, Graylog Sidecar ETag·검증 명령, OpAMP RemoteConfigStatus | △ 손으로 올리는 설정 버전 상수 하나 표시 | B-11 |
| 상태 모델·기대 일정 | Elastic Fleet Offline/Inactive, Fleet(fleetd) 호스트별 기대 간격 | △ 전역 90초/900초. 퇴근 때 끈 PC 도 보고서의 '연락이 끊긴 PC' | B-11 |
| 에이전트 신원 | Elastic Fleet 등록 토큰 → 에이전트별 키, osquery `enroll_secret` → `node_key` | ❌ 공용 수집 키, PC 이름은 레코드가 스스로 주장 | B-58 |
| 배포 무결성 | Fleet(fleetd) TUF·되돌리기 방지, Elastic 단계 업그레이드 | △ 반입 묶음 SHA-256·CA 지문 고정. 설치 스크립트 서명 없음 | B-58 |
| 감사 정책 기준선·XPath | Microsoft WEF Appendix A·C, Fluent Bit `event_query`, NSA·Palantir WEF 구독 | ❌ 채널 단위 수집, 기준선은 문서만 | B-59 |
| Windows 이름 필드 | Fluent Bit 5.1 `event_data_as_map`(PR #12082) | ✅ 서버가 이름을 붙임(ADR-038). 원본에 중복(저장 +6~39%) | B-33 |
| 수집 대상 대조 | Sentinel watchlist(High Value Assets), Elastic Fleet 등록 목록(개념) | ❌ 한 번이라도 보낸 PC 만 보임 | B-55 |
| 에이전트 없는 수집 | Windows Event Forwarding → WEC | ❌ PC 마다 에이전트. `pick_host` 가 `agent_host` 를 먼저 써서 WEC 로 모으면 모두 WEC 서버 것으로 보임 | B-80 (P3) |

### 5.4 조사 UX

| 항목 | 다른 제품의 방식 | 우리 상태 | BACKLOG |
|---|---|---|---|
| 앞뒤 로그 | Kibana View surrounding documents, Graylog Show surrounding messages, Grafana Show context | ❌ 검색을 다시 짜야 함 | B-61 |
| 통계 표 | Seq SQL(group by·distinct·행 상한), Datadog Log Analytics | △ 위젯(top·timeseries·stat)으로만. 이벤트 CSV 없음 | B-62 |
| 로그온 세션 | Datadog Transactions(공통 키로 묶어 지속 시간) | ❌ 4624 를 하나씩 봄 | B-63 |
| 저장한 검색 | Seq signals(공유·보호, 보존·알림·대시보드 재사용), Kibana saved queries | △ '링크 복사'(절대 구간)만 | B-64 |
| 값 자동완성·필드 패널·열 | Kibana 값 제안·필드 상위 값·히스토그램 끌기, Grafana Loki label browser | △ 키·미리 받은 목록만 자동완성, 표 열 6개 고정 | B-65 |
| 조사 플레이북 | Security Onion Guided Analysis(질문 + 알림 값으로 채운 검색), Elastic investigation guides | ❌ 규칙 설명 한 줄, 최근 이벤트 5건·검색 링크 | B-66 |
| 개체 페이지·관련 알림 | Sentinel entity pages, OpenSearch 자동 상관, Elastic Insights > Correlations | △ `user:`·`ip:`·`host:` 검색, 같은 규칙·대상의 미해결 알림만 | B-67 |
| 이벤트 한 줄 요약 | Hayabusa `default_details`·data_mapping, ADAudit Plus 잠금 원인·변경 전후 값 | △ Windows 렌더 메시지(서버 언어마다 다름), 필드 설명 일부 | B-68 |
| 대시보드 편집·변수 | Seq Add to Dashboard, Kibana Lens, Grafana 대시보드 변수 | △ JSON 편집 | B-07 |
| 한국어 2글자 검색 | VictoriaLogs 단어·접두 검색, PostgreSQL 'simple' 텍스트 검색 | △ trigram 이 안 돼 30일 28.8초(PERFORMANCE.md §2.1) | B-29 |
| 사고(케이스) | Security Onion Cases, Graylog Security Investigations, DFIR-IRIS | ❌ 알림 단위 처리만 | B-77 (P3) |
| 로그 패턴 | Drain3(MIT), Loki pattern ingester, Datadog Patterns, Kibana log rate analysis | ❌ | B-79 (P3) |

### 5.5 저장·성능

| 항목 | 다른 제품의 방식 | 우리 상태 | BACKLOG |
|---|---|---|---|
| 시간별 집계 | ClickHouse 증분 MV + SummingMergeTree, TimescaleDB 실시간 집계(양 끝은 원본) | ❌ 30일 이상 집계는 행 수에 비례 | B-09 (같은 트랜잭션 덧붙이기로 변경) |
| 원본 필드 색인 | ClickStack 속성 역색인, PostgreSQL GIN `jsonb_path_ops` | ❌ `f.` 경로 조건은 기간 안 행을 모두 읽음 | B-10 (사전 필터로 변경) |
| 디스크 예산 | VictoriaLogs `maxDiskUsagePercent`, OpenSearch ISM 크기 전이 | △ 기간 기준 보관만. 볼륨이 차면 쓰기가 멈춤 | B-69 |
| 저장 기본값 | PostgreSQL TOAST lz4·BRIN·insert-vacuum | △ 기본값 그대로 | B-69 |
| 보관 계층 | Elastic logsdb index sort·ILM warm, VictoriaLogs 일 파티션, Parquet+DuckDB | △ 월 파티션 → gzip JSONL 보관 파일(v2) | B-81 (P3) |
| 저장소 교체 판정 | (ADR-004 전환 신호) VictoriaLogs·ClickHouse·OpenSearch | ✅ PostgreSQL 하나가 지금 규모에 맞음. 전환 신호가 오면 VictoriaLogs 를 1순위로 재평가 | B-69 (ADR 갱신) |

### 5.6 국내 규정·증적

| 항목 | 다른 제품의 방식 | 우리 상태 | BACKLOG |
|---|---|---|---|
| 응용(EMR) 접속기록 | 국내 접속기록 솔루션(이지서티 UBI SAFER-PSM 등)의 5항목 스키마, Logpresso Sonar 소명 | ❌ 수집 대상 아님 — 법정 보관 장비는 EMR 이력관리 장비(ADR-048) | B-39 (0단계 완료, 병원 답변 대기), B-76 |
| PACS 열람 기록 | IHE ATNA(ITI-20): DICOM 감사 메시지를 syslog 로 | ❌ | B-60 |
| 이 시스템의 접속기록 | Logpresso 보고서 내려받기 권한, DBSAFER 다운로드 사유 | △ 검색 조건·상세(정보주체 포함)·사용자·IP 상위 값·CSV(사유 필수) 기록, 실패 시 거부(ADR-042). 실시간 스트림·보고서 열람·감사로그 목록·사용자별 시계열은 미기록 | B-38 |
| 기록 종류별 보관 | Seq retention policies, Loki `retention_stream`, Graylog index sets | △ 로그·알림·감사로그·보고서별(ADR-040), 민감정보 표식이면 2년 미달 경고. 이벤트 안의 등급(접속기록 2년·웹 요청 짧게)은 없음 | B-70 |
| 위·변조 증명 | Splunk data integrity control(slice SHA-256 → l1/l2 해시), 국내 권고(별도 장치의 MAC·WORM) | △ 트리거로 수정 금지, 보관 파일 SHA-256. DB 슈퍼유저 우회·DB 밖 앵커 없음 | B-71 |
| 외부 복제 | 국내 권고(분리 저장·WORM), rclone(MIT) | ✅ NAS 폴더 복제, 새 파일만·덮어쓰지 않음·만료만 삭제(ADR-047) | B-17(완료) |
| 접속기록 점검 결과서 | 피앤피시큐어 INFOSAFER 월간 점검 리포트, ISMS-P 2.9.5 확인사항 | △ 일간·주간 운영 보고서 + 1회 점검 확인 | B-72 |
| 권한 검토·장기 미사용 | DBSAFER IM 권한 검토·인사 연계, Sentinel IsDormantAccount | △ 사용자 화면(마지막 로그인·잠금) | B-72 |
| 심사 증적 묶음 | Wazuh 컴플라이언스 모듈, ManageEngine EventLog Analyzer 규정별 보고서 | △ ISMS.md 목록, 사람이 화면·CSV 를 모음 | B-73 |
| 관리자 2단계 인증 | RFC 6238 TOTP(표준) | ❌ | B-74 |
| 한글 문서 | Logpresso 보고서 hwpx, OWPML(KS X 6101) | ❌ HTML·인쇄만 | B-83 (P3) |
| 국산 보안 제품 | Logpresso Store 연동 앱, 이글루 SPiDER TM | ❌ 장비 syslog 원문만, 백신 규칙은 Defender 만 | B-82 (P3) |

## 6. 하지 않기로 한 것

| 안 | 이유 |
|---|---|
| 자동 대응(Wazuh Active Response 식 IP 차단·계정 잠금) | 명령 채널이 없는 것이 보안상 장점. 오탐으로 응급실 공용 계정이 잠기면 진료 중단. 필요하면 사람이 승인하는 '조치 요청' 웹훅만 검토 |
| 해시 기준선 FIM·취약점 탐지(CVE 피드) | 에이전트 권한·폐쇄망 피드 반입 부담, '수집 전용' 원칙과 충돌. 중요 파일 변경은 SACL + 4663(B-59) |
| 화면에서 고치는 수집 파이프라인(Graylog 식 정규식·grok) | 정규식 ReDoS·CPU 예산·시뮬레이터까지 소규모 팀이 유지하기 어려움. 마스킹은 B-18 |
| 검색 문장 안의 파이프 집계(`\| stats … by`) | 서버·화면 두 파서 동기화(ADR-033) 부담. 통계 탭(B-62)·세션(B-63)으로 |
| 규칙 전용 YAML 탐지 언어(Sigma 식 selection·condition) | '한 문장' 강점과 케이스 표·교차 퍼징이 두 벌이 됨. 수정자는 B-29, Sigma 는 그 문법으로 변환 |
| UEBA 동료 그룹 비교(Sentinel peer) | 데이터·설명 가능성 부족, 1~2명이 튜닝 불가. 처음 보는 값(B-47)·개인 기준선(B-78)만 |
| TimescaleDB 연속 집계·컬럼스토어, Citus/Hydra columnar | TSL·AGPL 이라 절대 규칙 1 위반, Hydra 는 유지보수 종료. B-09·B-81 로 |
| host·channel 사전 인코딩(ClickHouse LowCardinality 식) | 실제 Windows 행에서 절감 1~2%, repository 전반 수정 비용이 큼 |
| 지금 PostgreSQL 을 VictoriaLogs·ClickHouse·OpenSearch 로 교체 | 증적 트리거·트랜잭션 수집·조회 범위가 PostgreSQL 위에 있음. 전환 신호가 오면 ADR-004 갱신(B-69) |
| Hayabusa·Chainsaw·DeepBlueCLI 규칙·매핑 파일 재사용, EVTX-ATTACK-SAMPLES 포함 | AGPL·GPL(일부 불명). 조건·임계값만 다시 쓰고 표본은 직접 캡처·OTRF(MIT) |
| Grafana OnCall·Alertmanager 를 별도 서비스로 추가 | OnCall OSS 보관 처리(AGPL), 컨테이너·저장소 증가. 의미만 엔진에 재구현(B-41~B-43) |
| Fluent Bit `in_calyptia_fleet` 흉내 원격 설정 서버 | 비공개 상용 API, 설정 파일 통째 배포는 서버 탈취 시 수집 중단. B-11 3단계는 허용 매개변수만 |
| Sysmon 바이너리·SwiftOnSecurity 설정을 묶음에 포함 | Sysmon 은 재배포 금지 독점, 설정은 CC-BY-4.0. 채널 수집 + sysmon-modular(MIT) 참고 안내만 |
| pg_bigm 등을 넣은 자체 PostgreSQL 이미지(지금) | 폐쇄망 묶음·백업·Trivy·업그레이드가 모두 바뀜. 내장 'simple' 텍스트 검색(B-29) 먼저 |
| 실시간 원격 질의(osquery·Fleet 분산 쿼리) | 서버 → 전 PC 질의 경로 자체가 큰 공격 면. 고정 스크립트의 로컬 점검(B-59) |
| Bloom 필터로 '처음 보는 유형'(Seq First of Type) | 드물게 놓침. PostgreSQL `ON CONFLICT … RETURNING (xmax = 0)` 이 정확·간단(B-47) |
| 인터넷이 필요한 기능(위협 인텔 피드, AI 보고서, 런타임 CDN·규칙 동기화) | 폐쇄망 원칙 위반. IOC 는 받은 목록을 값 목록(B-53)으로, 규칙·ATT&CK 데이터는 make-bundle 때 반입 |

## 7. 법령·외부 근거 확인 메모

조사의 근거 일부는 블로그·기사·해설 같은 2차 출처입니다. 아래는 **1차 출처로 확인하기 전에는 코드·ISMS.md·규칙 태그를 바꾸지 않습니다.**

| 주장 (조사 내용) | 영향 받는 항목 | 조사 때 본 곳 | 확인할 곳 | 상태 |
|---|---|---|---|---|
| 2025-10-31 개정 안전성 확보조치 기준: 접속기록 보관 대상이 '개인정보처리시스템에 접속한 자(정보주체 제외)'로 넓어짐(외부 유지보수 계정 포함), 제8조② 의 '월 1회 이상 점검'이 '내부 관리계획으로 정한 주기·방법·사후조치'로 바뀜, 제4조 내부 관리계획에 출력·복사 안전조치 추가, 일부 조항 1년 유예 뒤 2026-10-31 적용 | B-38, B-72, B-74 | https://byline.network/2025/10/31-281/ , https://intothesec.com/149 , https://www.kimchang.com/ko/insights/detail.kc?sch_section=4&idx=33291 | https://www.law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000281400&chrClsCd=010201 (현행 제2026-9호), 부칙 <제2025-9호> | **확인함 (2026-10-30, ADR-048)** — 고시 제2025-9호(현행은 제2026-9호, 제8조는 같음). 유예 조항 제4조①12·13, 제5조①⑥, 제6조②, 제8조①② 는 '발령한 날의 1년 후' = 2026-10-31. 제8조② 에서 '다운로드 사유 반드시 확인'도 빠짐. **고침:** '외부 유지보수 계정 포함'은 원문에 없는 해설(개정이유의 예시는 '오픈마켓 판매자 등'), 김앤장의 '2025. 7. 21.'은 행정예고일 |
| 접속기록 1년 이상, 5만 명 이상·고유식별·민감정보 처리 시스템은 2년 이상(제8조①). 권한 부여·변경·말소 내역 3년(제5조) | ADR-040(반영됨), B-70 | http://www.boannews.com/news/articleView.html?idxno=126907 , https://intothesec.com/149 | https://www.law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000281400&chrClsCd=010201 | **확인함 (2026-10-30)** — 제8조① 1·2호, 제5조③ 원문 일치. 1년/2년 구분은 2021 판본부터(2023 은 기간통신사업자 3호만 추가). 항목은 '**식별자**, 접속일시, 접속지 정보, 처리한 정보주체 정보, 수행업무'(제2조제3호, '계정'은 2021 문구). 병원 EMR 이 2호(민감정보)라는 것은 추론 |
| 의료법 시행규칙 개정안: EMR '단순 열람'도 접속기록을 이력관리 장비에 별도 보관, 2026-12-10 시행 예정(입법예고 단계, 보관기간·항목 미확정) | B-39, B-60, B-76 | https://dailymedi.com/news/news_view.php?ca_id=&wr_id=940408 , https://medicaltimes.com/Main/News/NewsView.html?ID=1170738 , https://akomnews.com/68358 , https://dentalnews.or.kr/news/article.html?no=33516 | https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=286719&efYd=20261210 , https://opinion.lawmaking.go.kr/gcom/ogLmPp/88448 , https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=286963 | **확인함 (2026-10-30, ADR-048)** — **법률은 확정**(제23조④, 법률 제21776호, 2026-06-09 공포, 2026-12-10 시행, 제90조 벌금 500만원 이하). 시행규칙은 입법예고(공고 제2026-696호)만, 공포 전. 항목은 어디에도 없음. 고시 개정안의 보관기간(진료기록 보존기간과 같게, 최대 10년)은 다시 확인하지 못해 **2차 수준**. B-76 은 P3 유지(병원 답변 대기) |
| 공공시스템(시행령 제30조의2): 접근권한의 인사정보 연계(고시 제16조), 접속기록 자동 분석·소명(제17조), 권한 밖 접근 시 정보주체 통지 | B-53, B-76 | https://hs.ac.kr/bbs/kor/2157/54638/download.do , https://www.nepla.ai/wiki/it-정보-방송통신/개인정보-위치정보-신용정보/개인정보의-안전성-확보조치-w5dnz70m9e6k | https://www.law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000281400&chrClsCd=010201 , https://www.law.go.kr/LSW/lsInfoP.do?lsiSeq=289537 | **확인함 (2026-10-30)** — 원문 일치. 단 보호위원회가 **지정한** 공공시스템(공공기관 운영)에만 적용. 병원의 지정 여부는 **병원 확인 필요**(B-39). 2026-9 개정으로 공공시스템 연 1회 취약점 점검·침투테스트(제18조, 2027-01-01) |
| ISMS-P 실효성 강화(2026-04): 서류 심사에서 현장 실증·모의침투로, 2027 의무화 예고 | B-30, B-74, B-75 | https://v.daum.net/v/20260410082534799 , https://news.mtn.co.kr/news-detail/2026030915535171389 | 과기정통부·개인정보위·KISA 공고 | **확인 필요** |
| ATT&CK v19(2026-04-28): Defense Evasion 이 Stealth·Defense Impairment 로 나뉨, 'Clear Windows Event Logs'(T1070.001)·'Disable Windows Event Logging'(T1562.002)이 T1685 아래로 revoke. 최신 STIX 는 enterprise-attack 20.0(2026-10-13) | B-48(1000013·1000014 태그), B-73 | https://attack.mitre.org/resources/updates/updates-april-2026/ , https://attack.mitre.org/techniques/T1685/ , https://github.com/mitre-attack/attack-stix-data | 공식 STIX 묶음 diff | **확인 필요** — 확인 전 태그를 바꾸지 않음 |
| Sigma 규칙 DRL 1.1: 저자·출처 표시 조건 | B-14 | https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md | 라이선스 원문 | 도입 전 확인 |
| Fluent Bit: `event_data_as_map` 은 5.1.0 부터(PR #12082), winevtlog 렌더 실패 누수·이중 해제 수정은 4.2.8·5.0.10·5.1.0 부터 | B-33 | https://github.com/fluent/fluent-bit/pull/12082 | 릴리스 노트·소스 | 확인함(ADR-038·ADR-039 조사, 소스) |

## 8. 주요 출처 (영역별)

- **탐지 규칙·상관:** https://www.elastic.co/docs/solutions/security/detect-and-alert/threshold · https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html · https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax · https://github.com/SigmaHQ/sigma/blob/master/regression_data/README.md · https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- **알림 수명주기·운영:** https://prometheus.io/docs/alerting/latest/alertmanager/ · https://prometheus.io/docs/alerting/latest/configuration/ · https://www.elastic.co/guide/en/security/current/alert-suppression.html · https://docs.pagerduty.com/developer/send-alert-event · https://www.zabbix.com/documentation/current/en/manual/config/notifications/action/escalations
- **수집·에이전트:** https://opentelemetry.io/docs/specs/opamp/ · https://fleetdm.com/guides/fleetd-updates · https://github.com/nsacyber/Event-Forwarding-Guidance · https://github.com/palantir/windows-event-forwarding · https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
- **조사 UX:** https://datalust.co/docs/query-syntax · https://docs.securityonion.net/en/2.4/alerts.html · https://learn.microsoft.com/en-us/azure/sentinel/entity-pages · https://github.com/Yamato-Security/hayabusa-rules/blob/main/config/default_details.txt
- **저장·성능:** https://docs.victoriametrics.com/victorialogs/ · https://www.postgresql.org/docs/17/textsearch-controls.html
- **국내 규정·증적:** https://docs.logpresso.com/en/sonar/5.0/ui/section-explanation · https://docs.logpresso.com/en/sonar/5.0/ui/section-report · https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/audit-activity-in-splunk-enterprise/manage-data-integrity · https://itwiki.kr/w/ISMS-P_%EC%9D%B8%EC%A6%9D_%EA%B8%B0%EC%A4%80_2.9.5.%EB%A1%9C%EA%B7%B8_%EB%B0%8F_%EC%A0%91%EC%86%8D%EA%B8%B0%EB%A1%9D_%EC%A0%90%EA%B2%80 · https://profiles.ihe.net/ITI/TF/Volume2/ITI-20.html · https://dicom.nema.org/medical/dicom/current/output/chtml/part15/sect_A.5.html
