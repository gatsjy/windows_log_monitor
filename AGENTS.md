# AGENTS.md — AI 에이전트 작업 안내

이 저장소에서 작업하는 모든 AI 에이전트(Claude Code, Codex, Cursor 등)는 이 파일을 먼저 읽습니다.
상세 스펙은 [docs/PROJECT.md](docs/PROJECT.md), 설계 결정 이력은 [docs/DECISIONS.md](docs/DECISIONS.md),
**앞으로 만들 것(우선순위·완료 기준)은 [docs/BACKLOG.md](docs/BACKLOG.md)** 에 있습니다. 새 작업을 고를 때는 BACKLOG 의 P1 부터 봅니다.

## 한 줄 요약

Fluent Bit 에이전트가 보낸 Windows 이벤트 로그, IIS·SQL Server 로그, syslog, journald, 파일 로그를 FastAPI가 받아서 정규화(분류·사용자·IP 포함)한 뒤 PostgreSQL에 저장합니다. 빌드 없는 순수 JS UI가 이를 실시간으로 시각화합니다.

- **알림:** 엔진이 규칙(`config/alerts.yaml`)에 맞으면 수신 그룹(메일), 웹훅, Oracle 로 보냅니다. 대상은 환경설정 화면(DB)에서 관리합니다.
  - 알림마다 처리 상태(처리 안 됨 → 확인함 → 해결됨)와 고칠 수 없는 처리 기록이 남고, 점검 중에는 무음으로 전송만 건너뜁니다(ADR-029).
- **인증:** 로그인·역할(관리자/조회자)·감사로그가 있습니다.
- **전송 구간:** `WLM_TLS=on` 이면 api 가 직접 TLS(화면 https, 수집 6977). 에이전트는 CA·인증서 이름으로 서버를 확인합니다(ADR-036).
- **로그 로테이션:** DB → 압축 보관 파일 → 삭제 순서로 정리합니다.

## 절대 규칙

1. **오픈소스만 사용합니다.** 새 의존성은 OSI 승인 라이선스(MIT, BSD, Apache 2.0, PostgreSQL, LGPL, MPL)만 씁니다.
   - 추가하면 `docs/PROJECT.md` 의 라이선스 표와 `docs/DECISIONS.md` 를 갱신합니다.
   - SSPL, Elastic License, BSL 등 소스 공개형 비오픈소스는 금지입니다.
2. **원본 보존.** 에이전트가 보낸 레코드는 `events.raw` (JSONB)에 가공 없이 저장합니다.
   - 정규화는 컬럼을 *추가로 뽑아내는 것*일 뿐, 원본을 바꾸지 않습니다.
   - 서버가 텍스트 줄을 해석한 값은 원본 키를 덮지 말고 `raw.<소스>.*` (예: `raw.iis.status`, `raw.mssql.error`) 아래에 덧붙입니다.
3. **마이그레이션은 추가만 합니다.** `server/migrations/` 에 이미 있는 파일은 수정하지 않습니다.
   - 변경이 필요하면 `002_설명.sql` 처럼 새 파일을 만듭니다.
   - 서버 시작 시 자동 적용됩니다(`app/db.py: migrate`).
4. **이벤트 관련 SQL은 `server/app/repository.py` 에만 둡니다.** 라우터에 SQL을 쓰지 않습니다.
   - 저장소를 ClickHouse/OpenSearch로 바꿀 때 이 파일만 교체하기 위해서입니다.
5. **UI는 빌드 단계를 두지 않습니다.** 프레임워크와 npm 없이 ES 모듈을 그대로 씁니다.
   - 외부 차트 라이브러리도 넣지 않습니다(`web/js/charts.js` 사용).
   - 수정 후 새로고침만 하면 반영되어야 합니다.
6. **비밀값(비밀번호, 토큰, 웹훅 주소)은 평문으로 저장하지 않고 응답에도 내보내지 않습니다.**
   - 화면에서 입력하는 값은 `app/secrets.py` 로 암호화해서 DB 에 저장합니다.
   - 서버 기동 설정은 `.env` 에 둡니다.
   - API 응답에는 `has_secret` 같은 설정 여부만 넣습니다.
7. **보안·감사 관련 변경은 `docs/ISMS.md` 를 함께 갱신합니다.**
   - 로그 보관, 접근통제, 감사로그가 여기에 해당합니다.
8. **UI 문구는 한국어, 코드 식별자는 영어**로 씁니다. 주석은 한국어로 쓰되 "왜"를 적습니다.
   - 예외: PowerShell 스크립트는 영어만 씁니다(PS 5.1 인코딩 문제).

## 구조

```
server/app/
  rejects.py         수집 거절 장부 (메모리에 모아 30초마다 ingest_rejections 에, B-40)
  main.py            앱 진입점, 시작 시 마이그레이션·파티션 준비, 정적 UI 제공, 수집 포트 제한(IngestPortGuard), 보안 헤더(HSTS 선택)
  serve.py           운영 실행: 한 프로세스에 리스너 넷 — 8000 화면·API(TLS 면 https), 8001 평문 수집(6976), 8002 TLS 수집(6977), 8003 수집기 전용 내부
  tlsutil.py         ★ TLS: uvicorn TLS 설정(1.2+, ECDHE+AEAD), 기동 전 점검, 인증서 상태(만료·이름·CA), 자체 CA·서버 인증서 발급 (ADR-036)
  healthcheck.py     상태 확인(HEALTHCHECK·install.sh): config 만 읽고 TLS 면 https
  config.py          환경변수(WLM_*) 설정
  db.py              연결 풀, 마이그레이션 실행기, audit()
  partitions.py      events 월별 파티션 생성 / 보관기간 만료 삭제
  repository.py      ★ 이벤트 저장·조회 SQL 전부
  filters.py         검색 조건 파싱 + 실시간 매칭 (백엔드 무관)
  querylang.py       ★ 검색 문장 파서·정규형 (표준 라이브러리만, web/js/querylang.js 와 한 줄씩 같은 알고리즘, ADR-033)
  live.py            실시간 스트림(SSE) 브로드캐스터, 수집 속도
  normalizers/       ★ 소스별 정규화: windows / iis / mssql / syslog(+journald) / generic
                       categories.py = 분류(category) 규칙, base.py = Event·clean_ip/clean_user
  alerts/            ★ 알림: rules(YAML 검증) · ruleedit(규칙 블록 편집) · message(문구) · notifiers(메일/웹훅/Oracle) · targets(DB의 수신자·그룹·연동) · engine(평가·무음·설정 판본·규칙 상태) · dispatcher(전송 대기열·재시도) · health(알림 기능 상태 판단) · watchdog(멈춘 작업 다시 시작·내장 시스템 알림) · adminwatch(받는 곳 약화·관리 권한 부여 알림) · coverage(규칙별 데이터 유무) · builtin(내장 알림 이름) · configdiff(판본 차이·탐지 약화 판단) · visibility(조회 범위) · messenger(웹훅 형식: Slack·Teams·두레이·잔디)
  auth/              ★ 인증: passwords(scrypt·정책) · service(로그인·세션·사용자) · groups(사용자 그룹·권한·조회 범위) · deps(require_user/require_admin/require_permission/CSRF)
  reports/           ★ 점검 보고서: config(일정·받는 곳) · builder(내용 모으기) · render(메일·화면·인쇄 공용 HTML, 메신저 공지) · scheduler(정기 실행·보내기)
  backups.py         DB 백업·복구 시험 상태 (backup 서비스가 남긴 audit_log 로) — 로그 보관 화면·점검 보고서 공용
  oracle.py          Oracle 접속(TNS/SID/서비스/접속문자열)·조회 전용 쿼리·SQL 실행
  secrets.py         환경설정 비밀값 암호화 (WLM_SECRET_KEY)
  csvexport.py       CSV 내려받기 공용 (BOM, 엑셀 수식 주입 방지) — 감사로그·알림 이력
  archive.py         로그 보관 파일 만들기·검증·복원
  cli.py             관리 명령 (사용자 복구, 로그 보관 상태·무결성·복원, 인증서 tls-init·tls-renew·tls-status — DB 없이)
  routers/           ingest · query · dashboards · alerts · auth · users(+사용자 그룹) · audit · settings · agentpkg(에이전트 설치 묶음)
server/migrations/   번호순 SQL
server/tests/        pytest (DB 없이 도는 단위 테스트)
web/js/
  main.js            해시 라우터 (#/화면/하위?파라미터)
  views/             화면: dashboard, live, events, alerts, agents, fields, reports(점검 보고서), users·audit·settings(관리자)
  auth.js            로그인·비밀번호 변경 화면, 현재 사용자 (main.js 가 init)
  widgets/           ★ 대시보드 위젯: stat, timeseries, top, events, hosts, text, alerts (live() = 실시간 갱신)
  querylang.js       ★ 검색 문장 파서·매처·옛 링크 접기·문장 편집 (import·DOM 없음 — node 로 시험)
  querybox.js        검색 문장 입력 칸 (해석·오류 위치·빠른 고침·도움말·자동완성)
  filterbar.js       검색·실시간 필터 막대 (문장이 정본, 드롭다운·수준 칩은 문장을 고치는 창)
  livefilter.js      대시보드 실시간 갱신용 조건 판단 (querylang.compileQuery 에 맡김)
  responsive.js      좁은 화면 보정: 표 칸에 data-label(모바일 카드), 카드 격자 줄 단위 재배치 (MutationObserver)
  ruleform.js        알림 규칙 편집 패널 (Snort 식 규칙 문장·우리말 요약·미리보기)
  alertdetail.js     알림 상세 패널(확인·해결·메모·무음), 전송·처리 상태 칩, 규칙 요약 문구
  charts.js          SVG 차트 (누적 막대, 가로 막대, 스파크라인)
  catalog.js         필드·이벤트 ID 한글 설명 사전
config/dashboards/   대시보드 정의 JSON (UI 편집기로 저장하면 이 파일이 바뀜)
config/alerts.yaml   알림 규칙·알림 대상 (UI '규칙 편집'으로 저장하면 이 파일이 바뀜, 자동 반영)
agent/windows|linux/ 에이전트 설정 + 설치 스크립트
collector/           syslog 수신기 설정
tools/simulate.py    가짜 PC 로그 생성기 (표준 라이브러리만)
tools/bench/         검색 성능 벤치마크 (별도 DB, docs/PERFORMANCE.md)
deploy/airgap/       폐쇄망 배포: make-bundle.sh(인터넷 PC) · install.sh(서버 설치·업그레이드) — docs/AIRGAP.md
deploy/backup/       backup.sh — compose 의 backup 서비스(postgres 이미지): 매일 백업·주간 복구 시험·복원 (ADR-031)
```

## 실행과 검증

```bash
docker compose up -d --build               # 개발 모드 (server/app, web 이 마운트되어 즉시 반영)
python3 tools/simulate.py --once           # 테스트 데이터 (과거 24시간)
docker compose exec api python -m pytest   # 단위 + 통합 테스트 (통합은 <DB>_test 를 만들어 쓰고, Oracle 은 시험 컨테이너가 있을 때만)
docker compose exec api ruff check --no-cache app tests
docker compose run --rm backup selftest     # 백업·복구 시험·복원 스크립트 자체 시험 (시험용 DB 만 씀)
node --test 'server/tests/js/*.test.mjs'    # 검색 문장 화면 쪽 시험 + node·python3 교차 퍼징 (npm 없음, 개발 PC 에서)
python3 tools/ci/render_agent_configs.py out  # 에이전트 설정 틀을 채워 보기 (CI 가 fluent-bit --dry-run 에 씀)
docker run --rm --network none -v "$PWD:/repo:ro" -v "$PWD/out:/render:ro" rockylinux/rockylinux:9 bash /repo/tools/ci/test_install_sh.sh   # install.sh 실행 시험
docker run --rm --network none -v "$PWD:/repo:ro" -v "$PWD/out:/render:ro" mcr.microsoft.com/powershell:lts-alpine-3.20 pwsh -File /repo/tools/ci/test_install_ps1.ps1 -RenderDir /render -CaSha256 $(python3 tools/ci/render_agent_configs.py --ca-sha256 tools/ci/fixtures/ci-ca.crt) -Work /tmp/w   # install.ps1 (CI 는 5.1)
tools/ci/test_fluentbit_mssql.sh out/windows.yaml   # ERRORLOG 묶음(multiline)을 Fluent Bit 컨테이너로 실제 실행 (기대값 다시 만들기: --update)
python tools/ci/agent_memory.py --fluent-bit <fluent-bit.exe> --baseline tools/ci/fixtures/windows-agent-0.4.0.yaml   # 윈도 전용: 서버 장애 중 에이전트 메모리 (관리자)
curl -s localhost:8080/healthz
# TLS 로 띄워 보기 (개발, .env 는 그대로): 인증서 → WLM_TLS=on 으로 up → https 확인 → 그냥 up 으로 평문 복귀 (AIRGAP.md §13)
docker compose run --rm --no-deps --user 0 -v "$PWD/tls:/out" -v "$PWD/tls-ca:/ca" api python -m app.cli tls-init --out /out --ca-dir /ca --name logmon.dev.internal --name localhost --ip 127.0.0.1
WLM_TLS=on WLM_PUBLIC_URL=https://localhost:8080 docker compose up -d api && curl -s --cacert tls/ca.crt https://localhost:8080/healthz
```

**완료 기준:**
- 테스트와 린트가 통과합니다. 검색·필터 규칙(querylang·filters·livefilter)을 바꿨으면 node 시험도 통과합니다.
- 관련 화면을 브라우저(http://localhost:8080)에서 직접 열어 확인했습니다.
- 브라우저 콘솔에 오류가 없습니다.
- 문서(이 파일, PROJECT.md, DECISIONS.md, ISMS.md 중 해당하는 것)를 갱신했습니다.

## 자주 하는 작업

| 작업 | 방법 |
|---|---|
| 새 로그 소스 | `normalizers/새소스.py` 작성 → `normalizers/__init__.py` 의 `BY_SOURCE` 등록 → 에이전트에서 `log_source: 새소스` 부착 → 테스트 추가 |
| 새 위젯 | `web/js/widgets/이름.js` (`render(body, cfg, ctx)`, 실시간이면 `live(body, cfg, ctx, events)` 도) → `widgets/index.js` 등록 → `server/app/routers/dashboards.py` 의 `WIDGET_TYPES` 추가 → `views/dashboard.js` 의 REFERENCE 설명 추가 |
| 알림 규칙 추가 | `config/alerts.yaml` 의 `rules` (형식: docs/PROJECT.md §6.1). `tests/test_alerts.py::test_shipped_config_is_valid` 가 검증 |
| 새 메신저(웹훅 형식) | `alerts/messenger.py` 에 `build_<이름>` + `FORMATS` 한 줄(호스트·필수 헤더·https·전송 간격) → `tests/test_messenger.py` 스냅샷 생성(`WLM_UPDATE_SNAPSHOTS=1`) → PROJECT.md §6.2 표. 형식은 공식 문서로 확인한 것만 |
| 새 알림 대상 종류 | `app/alerts/notifiers.py` (Notifier 상속, `send()` 실패 시 예외) → `channels.type` CHECK 마이그레이션 → `targets.py` 의 `build_channel`/`_clean_channel_config` → `views/settings.js` → 테스트 |
| 새 API | 라우터를 `main.py` 에 등록할 때 `dependencies=[Depends(require_user)]` 로 로그인 필수, 변경 작업은 엔드포인트에 `Depends(require_admin)` + `db.audit(...)` |
| 관리자 화면 | `main.js` 의 `ADMIN_VIEWS` + 메뉴 링크에 `data-admin` (서버도 `require_admin` 으로 막을 것) |
| 새 화면 | `web/js/views/이름.js` (`mount(root, params, sub)` → cleanup 함수 반환) → `main.js` 의 `VIEWS` → `index.html` 메뉴 |
| 새 API | `routers/` 에 엔드포인트, SQL 은 `repository.py` 에 함수로 |
| DB 변경 | `server/migrations/00N_설명.sql` 추가 |
| 이벤트 ID 설명 | `web/js/catalog.js` 의 `EVENT_DOCS` (IIS 는 `HTTP_STATUS`) |
| 검색 키 추가 | 케이스 표에 줄 먼저 → `querylang.py`·`querylang.js` 의 SYNC(키·힌트) → `EventFilter`(필드·merged·matches) → `repository.where_clause`(포함·`_EXCLUDE_COLUMNS`) → `querylang.js`(INCLUDE_FIELD·compileFilter) → `querybox.js` KEY_LABELS → PROJECT.md §4.1 |
| 분류 추가·변경 | `normalizers/categories.py` 의 `classify()` + `web/js/levels.js` 의 `CATEGORY_LABELS` + 기존 데이터 UPDATE 마이그레이션 |
| 사용자·IP 추출 추가 | 정규화기에서 `Event.username`/`src_ip` 채우기 (`clean_user`/`clean_ip` 통과). Windows 는 `windows.py` 의 `USER_FIELDS`·`IP_FIELDS`·`STRING_INSERT_POSITIONS` |
| 알림 규칙 태그 | 규칙의 `tags: [MITRE Txxxx, ISMS 2.x.x]` — ISMS.md 의 '알림 규칙과 ISMS 항목' 표도 맞춤 |

## 알려진 함정

- `events` 의 파티션 키는 **`received_at`(서버 수신 시각)** 입니다. 시간 검색은 `ts`(발생 시각)로 합니다(ADR-003).
- PK는 `(id, received_at)` 입니다. 단건 조회는 `id` 로만 해도 됩니다.
- 실시간 스트림은 프로세스 메모리 기반이라 **uvicorn 워커가 1개**여야 합니다(ADR-006).
- jsonb는 `\u0000` 을, TEXT는 NUL 문자를 저장하지 못합니다. 정규화와 저장 단계에서 제거합니다.
- 보안 로그 `Level` 은 대부분 0이라 정보(4)로 들어옵니다. Keywords의 감사 실패 비트가 있으면 경고(3)로 올립니다(ADR-008).
- 개발 포트는 UI 8080, **수집 6976**(평문)·6977(TLS, `WLM_TLS=on` 일 때만 받음), DB 15432(127.0.0.1), Mailpit 8025(127.0.0.1)입니다. 수집기는 api 내부 8003 으로 보냅니다(게시 안 함). 5432와 8000은 다른 로컬 프로젝트가 쓰고 있습니다.
- 개발 중 알림 메일은 밖으로 나가지 않습니다. Mailpit(http://localhost:8025)에서 확인합니다.
- **검색 규칙은 세 곳에 있습니다:** `server/app/querylang.py`·`filters.py`(서버·알림), `web/js/querylang.js`(화면·대시보드 실시간), 케이스 표 `server/tests/querylang_cases.json`. **표에 줄을 먼저 추가**하고 두 언어를 같이 고칩니다(ADR-033).
  - 상수·오류 문구는 두 파일의 SYNC(`@sync` 블록)에 두고 pytest(`test_querylang_sync.py`)가 비교합니다. JS 는 `Array.from` 코드 포인트, Python 은 str 인덱스 — 위치는 코드 포인트.
  - 제외는 값이 없는 이벤트를 남깁니다: SQL `(포함식) IS NOT TRUE`, 매처는 None 이면 통과. `NOT IN`·`<> ALL` 을 쓰지 않습니다.
  - 기존 파라미터의 SQL 은 바뀌면 안 됩니다(`test_where_snapshot.py`). 일부러 바꿨다면 `WLM_UPDATE_SNAPSHOTS=1` 로 다시 만들고 이유를 커밋에 적습니다.
  - 검색 파라미터 `user`·`ip` 는 컬럼 `username`·`src_ip` 로 매핑됩니다(`repository.COLUMN_EXPR`, `livefilter.FIELD_OF`).
  - 상위 값 목록에서 `user`·`ip` 의 빈 값 제외도 두 곳입니다(`repository.TOP_SKIP_EMPTY`, `widgets/top.js` 의 `SKIP_EMPTY`).
- 알림 규칙이 감시하는 분류는 `Rule.categories`(match.category + match.query 의 `category:`)입니다. 조회 범위 판단(`alerts/visibility.py`)은 이것만 봅니다.
- **새 API 의 권한:** 관리자만이면 `require_admin`, 그룹으로 위임할 수 있는 기능이면 `require_permission("권한")`(auth/groups.py PERMISSIONS 에 추가). 화면은 `auth.can("권한")` 으로 버튼을 숨긴다.
- **이벤트를 돌려주는 새 API 는 반드시 `routers/query._filter(request)` 로 필터를 만든다.** 그래야 사용자 그룹의 조회 범위(`scopes`)가 붙는다. 단건 조회는 `filters.scopes_allow` 로 확인.
  - 시간 상한도 걸어야 한다: `routers/query.py` 라우터의 GET 은 자동, 다른 라우터나 POST 로 읽는 API 는 엔드포인트에 `dependencies=[Depends(read_time_limit)]`(ADR-035). 의존성은 async 여야 컨텍스트 변수가 엔드포인트로 넘어간다. 시험 `test_search_routes_have_time_limit` 에 경로를 더한다.
  - 상한이 걸린 조회는 `db.SEARCH_SLOTS`(6)개 연결까지만 동시에 쓴다. 풀 크기(`db.POOL_MAX`)를 바꾸면 수집 몫(4개 이상)이 남는지 본다.
  - 알림·무음을 돌려주거나 바꾸는 API 는 `alerts/visibility.py`(`alert_visible`·`silence_visible`·`count_by_status`)로 범위를 확인한다. 알림 수를 새로 셀 때도 마찬가지.
- 알림 처리 기록(`alert_notes`)은 `audit_log` 처럼 트리거로 수정·삭제·TRUNCATE 를 막는다(알림이 보관기간 만료로 지워질 때만 함께 삭제). 테스트에서도 지울 수 없다.
- 웹훅 오류·연결 실패 문구는 `WebhookNotifier.redact()` 를 거친다(받는 쪽이 토큰이 든 경로를 돌려준다). 새 전송기도 오류 문구에 주소를 그대로 넣지 않는다.
- 웹훅은 `notifiers._OPENER`(넘김 거부)로 보낸다. `urllib.request.urlopen` 을 직접 쓰면 30x 를 따라가 인증 헤더가 새고 실패가 '전송됨'이 된다.
- **CSV 를 내보내는 새 API 는 `app/csvexport.csv_response` 를 쓴다.** 로그에서 온 값(syslog 호스트 이름 등)이 엑셀 수식으로 실행되지 않게 한다.
- 셸 스크립트(`*.sh`)는 `.gitattributes` 로 LF 고정이다. 윈도 PC 에서 이 줄 이전에 받은 저장소는 `.sh` 를 지우고 `git checkout -- <파일>` 로 다시 받는다 — CRLF 면 `backup` 이 `set: illegal option -` 로 재시작을 반복한다.
- 윈도 PC 의 개발 컨테이너에서 ruff 는 `EXE002` 를 많이 낸다(마운트한 파일이 모두 실행 권한으로 보임). CI(리눅스)에서는 나지 않으므로 개발 PC 에서는 `--ignore EXE002` 로 본다.
- 백업은 api 가 아니라 `backup` 서비스(postgres 이미지, busybox sh)가 한다. 결과는 `audit_log` 의 `backup.*` 로만 api 에 전달된다. `backup.sh` 를 고치면 `selftest` 로 확인한다.
  - busybox `date` 는 `-d '+1 month'`·`'-N days'` 를 모른다(GNU 만). 날짜 계산은 `YYYY-MM-DD` 와 초(`date +%s`) 산술로 — 자체 시험에서 그 값으로 만든 파일 이름이 비지 않는지도 본다.
  - 외부 저장소 복제(B-17)는 새 파일만 복사하고 덮어쓰지 않는다. 지우는 규칙(만료)을 바꾸면 '원본이 사라져도 복제본은 남는다' 시험을 지킨다.
- 점검 보고서(`reports`)는 트리거로 내용 수정·삭제·TRUNCATE 를 막는다(확인은 한 번, 전송 결과만 나중에 채움, 보관기간 정리만 `SET LOCAL wlm.report_purge`). 보고서 HTML 에는 로그에서 온 값이 들어가므로 `render.py` 에서 반드시 `escape` 한다(화면은 같은 출처 iframe).
- 테스트에서는 `WLM_REPORT_SCHEDULER=off`(conftest)라 정기 실행이 돌지 않는다. 정기 실행 시험은 `scheduler.tick(now)` 을 직접 부른다.
- 표시 시간대는 `config.display_zone()` 으로 얻는다(`ZoneInfo(settings.display_tz)` 를 직접 부르지 않는다 — 이름이 틀리면 UTC 로).
- 점검 보고서 `payload` 는 고칠 수 없으므로 렌더러(`reports/render.py`)는 예전 형식도 그려야 한다. 전송 기록(`deliveries`)은 덮어쓰지 말고 `repository.add_report_deliveries` 로 덧붙인다.
- **자동 해결 (B-35 2단계):** `alert_deliveries` 의 키는 `(alert_id, notifier, action)` 이다(action = trigger·resolve, 마이그레이션 019). 행을 고치는 새 SQL 은 action 까지 조건에 넣는다.
  자동 해결은 `resolve: auto` 규칙·끊김 규칙만, `repository.auto_resolve` 한 트랜잭션(상태·처리 기록·못 보낸 알림 건너뜀 → 해소 통지 순서). 사람이 다시 연(reopen 기록) 알림은 건드리지 않는다.
  - 해소 통지는 넣을 때가 아니라 **보낼 때** 다시 본다(`dispatcher._stale`: 다시 열림·사람이 해결·같은 대상의 새 알림·그 곳에 알림이 전해지지 않음). 같은 dedup_key 라 늦은 해소가 새 사고를 닫았다(검토에서 재현).
- 무음은 행을 지우지 않는다. 해제 = `ends_at` 을 앞당김(시작 전이면 길이 0). 상태(적용 중·예정·끝남)는 `routers/alerts._silence_state` 가 정한다.
- 수집 포트(8001·8002·8003)로는 `/api/ingest`·`/healthz` 만 열린다(`main.INGEST_PORT_PATHS`·`INGEST_LISTEN_PORTS`). 에이전트용 새 경로가 필요하면 거기에 추가.
- **TLS (ADR-036):**
  - Fluent Bit 의 `tls.verify_hostname` 기본값은 **off** 다 — 에이전트 틀에 on 을 고정하고 CI 정적 검사가 막는다. `--dry-run` 은 없는 `tls.ca_file`·키 오타를 통과시킨다(실행 때 종료).
  - 에이전트는 IP SAN 으로 서버를 확인하지 못한다 → 서버 인증서에 DNS 이름 필수, 에이전트는 `tls.vhost`. 설치 묶음 API 는 확인할 수 없는 CA·이름·만료면 409/422.
  - 이미지의 `wlm` 은 uid 10001·**gid 999** — 키는 그룹이 아니라 소유자(10001, 0600)로 준다.
  - 인증서 판단은 `tlsutil.agent_handshake`(메모리 안 OpenSSL 핸드셰이크, STRICT·PARTIAL_CHAIN 끔 = Fluent Bit 기본). cryptography 의 검증기로 바꾸지 않는다 — 판정이 OpenSSL 과 달라 에이전트가 거부할 묶음을 통과시켰다(검토에서 재현).
  - 시험 인증서가 핸드셰이크를 거치면 **실제 시각** 기준으로 유효해야 한다(고정 날짜 NOW 로 만들면 그 날짜가 지나 깨진다).
  - `last_transport` 는 `tls`·`plain`·`web`(화면 포트로 온 평문 = 0.4 이전 묶음). 제약은 마이그레이션 013.
  - `WLM_HSTS_MAX_AGE` 는 비우면 안 보냄, `0` 은 `max-age=0`(지우기) — 0 과 빈 값을 섞지 않는다.
  - 화면 포트가 TLS 면 http 상태 확인은 실패한다 — 상태 확인은 `python -m app.healthcheck`(Dockerfile HEALTHCHECK·install.sh).
  - `.env` 를 바꾸면 `up -d`(restart 는 환경을 다시 읽지 않음), 인증서 파일만 바꾸면 `restart api`.
  - 프록시 헤더 신뢰는 `WLM_TRUSTED_PROXIES` 로만(serve.py 가 값을 직접 넘김). `FORWARDED_ALLOW_IPS` 환경변수는 효과가 없다.
  - CA 개인키(`tls-ca/`)는 api 에 마운트하지 않는다. `tls/`·`tls-ca/` 는 .gitignore·.dockerignore 에 있다.
  - 설치 스크립트를 고치면 `tools/ci/test_install_sh.sh`·`test_install_ps1.ps1` 로 실제로 돌린다(렌더 스크립트는 재구현이라 스크립트 회귀를 못 잡는다). CI 의 기대 지문은 `--ca-sha256` 으로 따로 계산한 값.
  - 윈도 CI 의 PowerShell 실행 본문은 영어만(5.1 이 임시 스크립트를 ANSI 로 읽을 수 있다). 파이썬은 `PYTHONUTF8=1`.
  - 내장 브라우저는 자체 서명 인증서를 열지 않는다 → TLS 화면은 같은 설정의 평문 리스너(개발 전용 `docker compose run -p 127.0.0.1:8090:8090 … uvicorn`)로 확인했다(AIRGAP.md §13).
- 알림 규칙을 화면에서 저장하면 그 규칙 블록만 다시 쓴다(`ruleedit.py`). 블록 안의 주석은 그 규칙을 화면에서 저장하면 사라진다(켜기/끄기만은 보존).
- UI 디자인 값은 `web/css/app.css` 의 토큰(`:root`)만 쓴다. 좁은 화면 기준: 1000px(상단 바), 700px(표→카드), 600px(휴대폰).
- 정규화기는 `None` 을 돌려 레코드를 저장하지 않을 수 있습니다(IIS `#Fields:` 머리줄). 그 외에는 버리지 않습니다.
- **수집 견고성 (ADR-044):** 수집은 `normalize_safely`(정규화 예외 → 일반 로그 + `raw._ingest.error`, `_ingest` 는 서버 예약 키)와 `insert_batch`(값 오류 → 한 트랜잭션·저장점으로 반씩 나눠 문제 레코드만 `ingest_quarantine`, 격리한 이벤트를 돌려줌, 시도 상한 `ISOLATE_BUDGET`)를 거친다. 새 '값 오류' 종류는 `repository._DATA_ERRORS` 에.
  - 알려진 값 오류는 격리까지 가지 않게 미리 막는다(`normalizers._scrub` 의 범위, 수집의 NaN·서로게이트). 새로 알게 된 것도 그쪽에 — 격리는 모르는 것을 위한 그물이다. 시험은 `_write` 에 DB 값 오류를 넣어 격리를 본다(`test_api_ingest_problems.poison`).
  - `_json` 은 홀수 개 역슬래시 뒤의 `\u0000` 만 지운다(글자 그대로의 `\u0000` 을 지우면 JSON 이 깨진다 — 재현). 짝 없는 서로게이트는 수집 본문에서 U+FFFD 로.
  - 수집 거절은 `rejects.note()` 로 메모리에 모았다가 30초마다 `ingest_rejections` 에(인증 전 요청을 요청마다 DB 에 쓰지 않는다). 시험은 `rejects.flush()` 를 직접 부른다.
- **수집 트랜잭션의 집계 (B-37, ADR-046):** `_write` 는 events COPY 뒤 agents → field_stats → agent_streams → agent_events → iis_layouts 순서로 쓴다(같은 표 안에서는 정렬). 새 집계를 더할 때 이 순서를 지키고, 줄마다 upsert 하지 말고 문장 하나(`unnest`)로 — 줄마다면 PC 가 많은 묶음에서 수집이 13% 느려졌다(PERFORMANCE.md §2.5).
- IIS 열 순서는 DB `iis_layouts` 가 정본입니다(ADR-037). `repository._IIS_FILE`·`_IIS_SITE` 캐시는 커밋한 뒤에만 채우고(`remember_iis_layouts`), 시험에서 '서버 재시작'은 `forget_iis_layouts()` 로 흉내 냅니다.
  - 그 파일의 순서(머리줄)는 서버 필드 모양만 봅니다(`iis.plausible` — 요청자 값으로 해석이 깨지지 않게). 추정한 순서(같은 폴더·기본)는 `iis.plausible_guess` 로 더 엄격히 봅니다 — 칸이 밀리면 요청자 값('-'·IP 모양 UA)이 서버 칸을 통과해 공격자가 `src_ip` 를 정할 수 있었습니다(검토에서 재현).
  - 모양 규칙(`_SHAPES`·`_ALWAYS`·`_REQUEST_SHAPES`·`_REQUESTER_TEXT`)을 바꾸면 `tests/test_iis_context.py` 의 고정 목록(ALWAYS·SHAPES·REQUESTER_TEXT)도 고칩니다. 목록마다 항목 하나를 빼면 그것만으로 실패하는 동작 시험이 있습니다 — 시험 매개변수를 모듈의 목록에서 만들지 않습니다(항목을 빼면 시험도 같이 사라짐).
  - `_is_ip` 캐시에는 64자 이하만 넣습니다(요청자가 정하는 긴 UA 가 캐시에 남아 메모리를 채움 — 검토에서 재현).
  - 수집 요청 하나에 들어온 값 때문에 SQL 이 실패하면 그 요청의 다른 이벤트까지 거절되고 에이전트가 끝없이 다시 보냅니다. 표에 넣는 값은 NUL·길이를 먼저 거릅니다(`iis._storable`).
- MSSQL `Error:` 머리줄 짝(`_pending`)만 프로세스 메모리입니다(워커 1개 전제, 키는 PC·파일·프로세스). 테스트에서 순서에 의존하는 경우 같은 `host`·파일을 씁니다. 여러 줄 레코드는 첫 줄로 해석합니다.
- **에이전트 multiline (ADR-037):** `multiline.parser` 이름 오타는 `--dry-run` 을 통과하고 기동 때 엔진 전체(윈도 이벤트 포함)가 멈춘다 → `render_agent_configs.check_multiline` 이 막는다. multiline tail 은 `storage.type: filesystem` 필수(서버가 꺼진 채 멈추면 묶던 것·못 보낸 것을 잃는다 — `tools/ci/test_fluentbit_mssql.sh` 가 재현).
- **에이전트 출력은 둘 (ADR-039):** 로그(`match_regex: '^(?!heartbeat$).*'`, 무한 재시도·디스크 버퍼)와 하트비트(`retry_limit: 2`, 메모리). 하트비트를 로그 출력에 다시 합치면 서버 장애 동안 256KB 조각이 쌓여 PC 메모리가 하루 약 720MB 씩 는다. 서버 주소·TLS 등 출력 키는 **두 출력 모두** 고친다 — `render_agent_configs.check_heartbeat_route`·`check_tls` 가 막고, 윈도 CI `tools/ci/agent_memory.py` 가 실제 Fluent Bit 로 메모리·라우팅을 잰다.
  - 틀의 `mssql_errorlog` 시작 정규식과 서버 `mssql._LINE` 은 같은 줄을 시각 줄로 봐야 한다(`tests/test_agent_sync.py`). 고정 자료 `tests/fixtures/mssql/fb-*.jsonl` 은 Fluent Bit 실제 출력 — Fluent Bit 을 올리면 `test_fluentbit_mssql.sh … --update` 후 서버 시험.
  - 에이전트 설정 버전 0.4.0 은 서버보다 먼저 배포하지 않는다(옛 서버는 묶인 레코드를 잘못 읽음).
- **Windows EventData 이름 (ADR-038):** 에이전트(Fluent Bit 4.0)는 EventData 를 보내지 않고 StringInserts 만 보낸다(LogonType 은 숫자). 서버가 `win_templates` 로 `raw.winevtlog.EventData` 를 붙이고, `f.EventData.X` 는 별칭(보낸 값 → 붙인 값)이다.
  - 별칭은 세 곳이 같아야 한다: `repository._raw_clause`(SQL COALESCE), `querylang.raw_field`, `web/js/querylang.js` 의 `rawField`(SYNC `raw_alias`). 케이스 표에 줄을 먼저.
  - Windows 시험 자료는 실제 에이전트 모양으로(`tests/fixtures/winevtlog/agent-fb4.0.14.jsonl`). EventData 맵을 넣은 레코드로만 시험하면 실제 PC 에서 안 맞는 규칙이 통과한다(실제로 그랬다). 시뮬레이터 기본값도 StringInserts 만.
  - 템플릿을 더하면 윈도 CI 의 실측 레코드로 길이를 확인한다(`test_win_templates.py`). 버전마다 필드가 중간에 끼기도 한다(4624 v3) — `VERSIONED`.
  - 기본 규칙·대시보드의 `f.EventData.<이름>` 은 그 이벤트의 **실측으로 확인한** 템플릿에 있어야 한다(`test_rule_fields.py`). 이름 오타는 검사 없이 통과하고 실제 PC 에서 영영 맞지 않는다.
- MSSQL ERRORLOG 의 `Error:` 머리줄은 번호 없이 '상세'(5)로 저장됩니다. 오류 번호로 세는 규칙·위젯은 본문 줄 기준입니다(이중 집계 방지).
- 알림 규칙의 `name` 이 쿨다운 키입니다. 이름을 바꾸면 이전 발생 기록과 연결이 끊깁니다.
- **알림 설정 판본 (ADR-043):** 설정을 적용하면 `engine.reload()` 가 `_pending` 을 두고 `await engine.record()` 가 판본(`alert_config_versions`, 추가만)·감사로그·약화 알림을 남긴다. 설정을 바꾸는 새 API 는 `routers/alerts._store` 를 거친다(쓰기 전 파일 직접 수정부터 기록 → `reload(force=True, source="ui", actor=…)`).
  - 내장 규칙 이름 `engine.CONFIG_RULE`('알림 설정 변경', kind `config`)은 무음을 건너뛴다. 받는 곳은 바뀌기 전 설정의 규칙들 — 새 약화 판단은 `configdiff._rule_changes` 와 `test_configdiff.py` 의 표에 함께.
  - 엔진은 프로세스에 하나라 시험 모듈마다 `conftest` 가 `engine.forget()`(처음 설치한 서버처럼)을 부른다. 시험에서 '서버 재시작'도 `engine.forget()`.
  - `record()` 는 잠금 안에서 비교·기록한다. 판본을 남긴 뒤의 감사로그·알림은 `_owed` 로 다시 시도 — 판본을 두 번 넣지 않는다. 파일이 깨졌거나 없으면(`engine.config_error`) 규칙 단위 저장은 409.
  - 받는 곳(수신자·수신 그룹·외부 연동·메일 서버)을 바꾸는 새 API 는 `async with adminwatch.watch_targets(actor, "무엇")` 로 감싼다 — 앞뒤 비교로 약해지면 알린다(B-36).
  - 서버에서 고친 것을 기록하지 못한 채 화면 저장이 덮지 않게 `_store` 는 `_record_versions(strict=True)`(실패하면 503). 파일 변경은 (mtime, ctime, 크기, inode) 서명으로 본다.
- 알림 엔진은 앱 안의 백그라운드 작업입니다. `uvicorn --reload` 로 재시작되면 다음 주기에 이어서 평가합니다.
- **평가와 전송은 따로 (ADR-045):** 엔진의 `fire()` 는 `alert_deliveries`(대기열)에 넣고 깨울 뿐 보내지 않는다. 보내기·재시도는 `alerts/dispatcher.py`(lock 727_004).
  - 시험에서는 전송기가 돌지 않는다(`WLM_ALERT_DISPATCHER=off`, conftest). 보낸 결과를 보려면 `client.portal.call(dispatcher.drain)`.
  - 결과는 `repository.finish_delivery` 로만 쓴다 — `claimed_at` 이 그대로일 때만 바뀐다(풀린 뒤 늦게 온 결과는 버림). 새 전송기 오류는 `NotifierError(target_down=…)` 로 받는 곳 문제인지 알린다.
  - 감시(`alerts/watchdog.py`)도 시험에서 돌지 않는다 — `watchdog.check(now)` 를 직접 부른다. 내장 알림 이름은 `alerts/builtin.py` 에만(규칙 이름으로 못 씀).
  - 정기 시험 전송은 시험에서 꺼져 있다(`WLM_ALERT_TEST_WEEKDAY=0`, conftest) — `watchdog.scheduled_tests(now)` 를 직접 부른다. 시험 기록은 감사로그
    (`repository.TARGET_TEST_ACTIONS`)가 정본이다: 받는 곳을 시험하는 새 API 를 만들면 그 동작 이름을 거기에 더한다(같은 주에 두 번 보내지 않게, `test_failed` 가 풀리게).
  - Oracle 을 부르는 새 코드는 `notifiers._in_oracle_pool`(전용 스레드 넷)로 — `asyncio.to_thread` 는 기본 풀을 써서 응답 없는 Oracle 이 로그인·메일까지 막는다.
  - 규칙 쿼리는 `db.background_time_limit`(조회 자리 SEARCH_SLOTS 를 쓰지 않음). 규칙 상태(`engine.runs`)·전송 상태(`dispatcher.targets`)는 메모리(워커 1개). 상태 판단은 `alerts/health.py` 한 곳 — 화면·`/healthz/alerts`·보고서가 같이 쓴다.
- 상태를 바꾸는 API 를 테스트할 때는 `X-WLM-CSRF: 1` 헤더가 있어야 합니다. 로그인 세션은 쿠키(`wlm_session`)로 유지합니다.
- **2단계 인증 (B-74, ADR-049):** 시험에서는 꺼져 있다(`WLM_MFA_REQUIRED=off`, conftest). 개발 서버는 기본 privileged 라 관리자 임시 계정도 등록해야 화면을 쓴다(코드는 `app.auth.totp.code_at`).
  - 의존성: `session_user`(코드 대기 세션도 통과 — 내 정보·로그아웃·코드 확인만) → `current_user`(코드 대기 세션 막음) → `require_user`(비밀번호 변경·필수 등록까지). 새 인증 API 는 맞는 단계를 고른다.
  - 실패 수(`failed_count`)는 정식 로그인이 끝날 때만 지운다(`service._complete_login`) — 비밀번호 단계에서 지우면 코드를 끝없이 맞혀 볼 수 있다.
- `audit_log` 는 DB 트리거로 UPDATE·DELETE·TRUNCATE 를 막습니다. 테스트나 마이그레이션에서 지우려 하면 실패합니다.
- 개발 DB 의 관리자 비밀번호는 저장소에 없습니다. `python -m app.cli reset-password admin` 으로 임시 비밀번호를 받습니다.
- `.env`·`.env.example` 에 `KEY=    # 설명` 처럼 빈 값 뒤 주석을 쓰지 않습니다. compose 가 설명문을 값으로 읽습니다(첫 관리자 비밀번호 사고 사례, docs/AIRGAP.md §13).
- 컨테이너 이미지·의존성·포트·볼륨을 바꾸면 `deploy/airgap/` 스크립트와 docs/AIRGAP.md 도 확인합니다. 폐쇄망은 인터넷 없이 `--pull never` 로 기동합니다.
  - 실행 중에 인터넷에서 무언가를 내려받는 코드(CDN, 외부 글꼴, pip install 등)를 넣지 않습니다.
- CI(`.github/workflows/ci.yml`)는 개발 이미지 안에서 시험한다(시험이 `/app/...` 배치를 전제). 외부 action 은 커밋 해시로 고정하고, ruff 는 `requirements-dev.txt` 에 버전을 고정한다 — 올릴 때 새 규칙 위반을 함께 고친다(ADR-034).
- 성능을 바꾸는 변경(인덱스, 쿼리 형태)은 `tools/bench/bench.py --skip-seed` 로 전후를 재고 docs/PERFORMANCE.md 에 기록합니다.
  - 예: 수신 시각 조건을 추가한 파티션 가지치기는 오히려 10배 느려져 기각했습니다(ADR-017).
