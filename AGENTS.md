# AGENTS.md — AI 에이전트 작업 안내

이 저장소에서 작업하는 모든 AI 에이전트(Claude Code, Codex, Cursor 등)는 이 파일을 먼저 읽습니다.
상세 스펙은 [docs/PROJECT.md](docs/PROJECT.md), 설계 결정 이력은 [docs/DECISIONS.md](docs/DECISIONS.md),
**앞으로 만들 것(우선순위·완료 기준)은 [docs/BACKLOG.md](docs/BACKLOG.md)** 에 있습니다. 새 작업을 고를 때는 BACKLOG 의 P1 부터 봅니다.

## 한 줄 요약

Fluent Bit 에이전트가 보낸 Windows 이벤트 로그, IIS·SQL Server 로그, syslog, journald, 파일 로그를 FastAPI가 받아서 정규화(분류·사용자·IP 포함)한 뒤 PostgreSQL에 저장합니다. 빌드 없는 순수 JS UI가 이를 실시간으로 시각화합니다.

- **알림:** 엔진이 규칙(`config/alerts.yaml`)에 맞으면 수신 그룹(메일), 웹훅, Oracle 로 보냅니다. 대상은 환경설정 화면(DB)에서 관리합니다.
- **인증:** 로그인·역할(관리자/조회자)·감사로그가 있습니다.
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
  main.py            앱 진입점, 시작 시 마이그레이션·파티션 준비, 정적 UI 제공, 수집 포트 제한(IngestPortGuard)
  serve.py           운영 실행: 8000(화면·API) + 8001(수집 전용, 호스트 6976) 두 리스너를 한 프로세스에서
  config.py          환경변수(WLM_*) 설정
  db.py              연결 풀, 마이그레이션 실행기, audit()
  partitions.py      events 월별 파티션 생성 / 보관기간 만료 삭제
  repository.py      ★ 이벤트 저장·조회 SQL 전부
  filters.py         검색 조건 파싱 + 실시간 매칭 (백엔드 무관)
  live.py            실시간 스트림(SSE) 브로드캐스터, 수집 속도
  normalizers/       ★ 소스별 정규화: windows / iis / mssql / syslog(+journald) / generic
                       categories.py = 분류(category) 규칙, base.py = Event·clean_ip/clean_user
  alerts/            ★ 알림: rules(YAML 검증) · ruleedit(규칙 블록 편집) · message(문구) · notifiers(메일/웹훅/Oracle) · targets(DB의 수신자·그룹·연동) · engine(평가·재시도)
  auth/              ★ 인증: passwords(scrypt·정책) · service(로그인·세션·사용자) · groups(사용자 그룹·권한·조회 범위) · deps(require_user/require_admin/require_permission/CSRF)
  oracle.py          Oracle 접속(TNS/SID/서비스/접속문자열)·조회 전용 쿼리·SQL 실행
  secrets.py         환경설정 비밀값 암호화 (WLM_SECRET_KEY)
  archive.py         로그 보관 파일 만들기·검증·복원
  cli.py             관리 명령 (사용자 복구, 로그 보관 상태·무결성·복원)
  routers/           ingest · query · dashboards · alerts · auth · users(+사용자 그룹) · audit · settings · agentpkg(에이전트 설치 묶음)
server/migrations/   번호순 SQL
server/tests/        pytest (DB 없이 도는 단위 테스트)
web/js/
  main.js            해시 라우터 (#/화면/하위?파라미터)
  views/             화면: dashboard, live, events, alerts, agents, fields, users·audit·settings(관리자)
  auth.js            로그인·비밀번호 변경 화면, 현재 사용자 (main.js 가 init)
  widgets/           ★ 대시보드 위젯: stat, timeseries, top, events, hosts, text, alerts (live() = 실시간 갱신)
  livefilter.js      서버 filters.py 와 같은 조건 판단 (대시보드 실시간 갱신용)
  responsive.js      좁은 화면 보정: 표 칸에 data-label(모바일 카드), 카드 격자 줄 단위 재배치 (MutationObserver)
  ruleform.js        알림 규칙 편집 패널 (Snort 식 규칙 문장·우리말 요약·미리보기)
  alertdetail.js     알림 상세 패널, 전송 상태 칩, 규칙 요약 문구
  charts.js          SVG 차트 (누적 막대, 가로 막대, 스파크라인)
  catalog.js         필드·이벤트 ID 한글 설명 사전
config/dashboards/   대시보드 정의 JSON (UI 편집기로 저장하면 이 파일이 바뀜)
config/alerts.yaml   알림 규칙·알림 대상 (UI '규칙 편집'으로 저장하면 이 파일이 바뀜, 자동 반영)
agent/windows|linux/ 에이전트 설정 + 설치 스크립트
collector/           syslog 수신기 설정
tools/simulate.py    가짜 PC 로그 생성기 (표준 라이브러리만)
tools/bench/         검색 성능 벤치마크 (별도 DB, docs/PERFORMANCE.md)
deploy/airgap/       폐쇄망 배포: make-bundle.sh(인터넷 PC) · install.sh(서버 설치·업그레이드) — docs/AIRGAP.md
```

## 실행과 검증

```bash
docker compose up -d --build               # 개발 모드 (server/app, web 이 마운트되어 즉시 반영)
python3 tools/simulate.py --once           # 테스트 데이터 (과거 24시간)
docker compose exec api python -m pytest   # 단위 + 통합 테스트 (통합은 <DB>_test 를 만들어 쓰고, Oracle 은 시험 컨테이너가 있을 때만)
docker compose exec api ruff check --no-cache app tests
curl -s localhost:8080/healthz
```

**완료 기준:**
- 테스트와 린트가 통과합니다.
- 관련 화면을 브라우저(http://localhost:8080)에서 직접 열어 확인했습니다.
- 브라우저 콘솔에 오류가 없습니다.
- 문서(이 파일, PROJECT.md, DECISIONS.md, ISMS.md 중 해당하는 것)를 갱신했습니다.

## 자주 하는 작업

| 작업 | 방법 |
|---|---|
| 새 로그 소스 | `normalizers/새소스.py` 작성 → `normalizers/__init__.py` 의 `BY_SOURCE` 등록 → 에이전트에서 `log_source: 새소스` 부착 → 테스트 추가 |
| 새 위젯 | `web/js/widgets/이름.js` (`render(body, cfg, ctx)`, 실시간이면 `live(body, cfg, ctx, events)` 도) → `widgets/index.js` 등록 → `server/app/routers/dashboards.py` 의 `WIDGET_TYPES` 추가 → `views/dashboard.js` 의 REFERENCE 설명 추가 |
| 알림 규칙 추가 | `config/alerts.yaml` 의 `rules` (형식: docs/PROJECT.md §6.1). `tests/test_alerts.py::test_shipped_config_is_valid` 가 검증 |
| 새 알림 대상 종류 | `app/alerts/notifiers.py` (Notifier 상속, `send()` 실패 시 예외) → `channels.type` CHECK 마이그레이션 → `targets.py` 의 `build_channel`/`_clean_channel_config` → `views/settings.js` → 테스트 |
| 새 API | 라우터를 `main.py` 에 등록할 때 `dependencies=[Depends(require_user)]` 로 로그인 필수, 변경 작업은 엔드포인트에 `Depends(require_admin)` + `db.audit(...)` |
| 관리자 화면 | `main.js` 의 `ADMIN_VIEWS` + 메뉴 링크에 `data-admin` (서버도 `require_admin` 으로 막을 것) |
| 새 화면 | `web/js/views/이름.js` (`mount(root, params, sub)` → cleanup 함수 반환) → `main.js` 의 `VIEWS` → `index.html` 메뉴 |
| 새 API | `routers/` 에 엔드포인트, SQL 은 `repository.py` 에 함수로 |
| DB 변경 | `server/migrations/00N_설명.sql` 추가 |
| 이벤트 ID 설명 | `web/js/catalog.js` 의 `EVENT_DOCS` (IIS 는 `HTTP_STATUS`) |
| 분류 추가·변경 | `normalizers/categories.py` 의 `classify()` + `web/js/levels.js` 의 `CATEGORY_LABELS` + 기존 데이터 UPDATE 마이그레이션 |
| 사용자·IP 추출 추가 | 정규화기에서 `Event.username`/`src_ip` 채우기 (`clean_user`/`clean_ip` 통과). Windows 는 `windows.py` 의 `USER_FIELDS`·`IP_FIELDS`·`STRING_INSERT_POSITIONS` |
| 알림 규칙 태그 | 규칙의 `tags: [MITRE Txxxx, ISMS 2.x.x]` — ISMS.md 의 '알림 규칙과 ISMS 항목' 표도 맞춤 |

## 알려진 함정

- `events` 의 파티션 키는 **`received_at`(서버 수신 시각)** 입니다. 시간 검색은 `ts`(발생 시각)로 합니다(ADR-003).
- PK는 `(id, received_at)` 입니다. 단건 조회는 `id` 로만 해도 됩니다.
- 실시간 스트림은 프로세스 메모리 기반이라 **uvicorn 워커가 1개**여야 합니다(ADR-006).
- jsonb는 `\u0000` 을, TEXT는 NUL 문자를 저장하지 못합니다. 정규화와 저장 단계에서 제거합니다.
- 보안 로그 `Level` 은 대부분 0이라 정보(4)로 들어옵니다. Keywords의 감사 실패 비트가 있으면 경고(3)로 올립니다(ADR-008).
- 개발 포트는 UI 8080, **수집 6976**, DB 15432(127.0.0.1), Mailpit 8025(127.0.0.1)입니다. 5432와 8000은 다른 로컬 프로젝트가 쓰고 있습니다.
- 개발 중 알림 메일은 밖으로 나가지 않습니다. Mailpit(http://localhost:8025)에서 확인합니다.
- 필터 규칙을 바꾸면 `server/app/filters.py`(서버·알림)와 `web/js/livefilter.js`(대시보드 실시간)를 **둘 다** 고쳐야 합니다.
  - 검색 파라미터 `user`·`ip` 는 컬럼 `username`·`src_ip` 로 매핑됩니다(`repository.COLUMN_EXPR`, `livefilter.FIELD_OF`).
  - 상위 값 목록에서 `user`·`ip` 의 빈 값 제외도 두 곳입니다(`repository.TOP_SKIP_EMPTY`, `widgets/top.js` 의 `SKIP_EMPTY`).
- **새 API 의 권한:** 관리자만이면 `require_admin`, 그룹으로 위임할 수 있는 기능이면 `require_permission("권한")`(auth/groups.py PERMISSIONS 에 추가). 화면은 `auth.can("권한")` 으로 버튼을 숨긴다.
- **이벤트를 돌려주는 새 API 는 반드시 `routers/query._filter(request)` 로 필터를 만든다.** 그래야 사용자 그룹의 조회 범위(`scopes`)가 붙는다. 단건 조회는 `filters.scopes_allow` 로 확인.
- 수집 포트(8001/6976)로는 `/api/ingest`·`/healthz` 만 열린다(`main.INGEST_PORT_PATHS`). 에이전트용 새 경로가 필요하면 거기에 추가.
- 알림 규칙을 화면에서 저장하면 그 규칙 블록만 다시 쓴다(`ruleedit.py`). 블록 안의 주석은 그 규칙을 화면에서 저장하면 사라진다(켜기/끄기만은 보존).
- UI 디자인 값은 `web/css/app.css` 의 토큰(`:root`)만 쓴다. 좁은 화면 기준: 1000px(상단 바), 700px(표→카드), 600px(휴대폰).
- 정규화기는 `None` 을 돌려 레코드를 저장하지 않을 수 있습니다(IIS `#Fields:` 머리줄). 그 외에는 버리지 않습니다.
- IIS 열 순서와 MSSQL `Error:` 머리줄은 프로세스 메모리에 기억합니다(워커 1개 전제). 테스트에서 순서에 의존하는 경우 같은 `host`·파일을 씁니다.
- MSSQL ERRORLOG 의 `Error:` 머리줄은 번호 없이 '상세'(5)로 저장됩니다. 오류 번호로 세는 규칙·위젯은 본문 줄 기준입니다(이중 집계 방지).
- 알림 규칙의 `name` 이 쿨다운 키입니다. 이름을 바꾸면 이전 발생 기록과 연결이 끊깁니다.
- 알림 엔진은 앱 안의 백그라운드 작업입니다. `uvicorn --reload` 로 재시작되면 다음 주기에 이어서 평가합니다.
- 상태를 바꾸는 API 를 테스트할 때는 `X-WLM-CSRF: 1` 헤더가 있어야 합니다. 로그인 세션은 쿠키(`wlm_session`)로 유지합니다.
- `audit_log` 는 DB 트리거로 UPDATE·DELETE·TRUNCATE 를 막습니다. 테스트나 마이그레이션에서 지우려 하면 실패합니다.
- 개발 DB 의 관리자 비밀번호는 저장소에 없습니다. `python -m app.cli reset-password admin` 으로 임시 비밀번호를 받습니다.
- `.env`·`.env.example` 에 `KEY=    # 설명` 처럼 빈 값 뒤 주석을 쓰지 않습니다. compose 가 설명문을 값으로 읽습니다(첫 관리자 비밀번호 사고 사례, docs/AIRGAP.md §13).
- 컨테이너 이미지·의존성·포트·볼륨을 바꾸면 `deploy/airgap/` 스크립트와 docs/AIRGAP.md 도 확인합니다. 폐쇄망은 인터넷 없이 `--pull never` 로 기동합니다.
  - 실행 중에 인터넷에서 무언가를 내려받는 코드(CDN, 외부 글꼴, pip install 등)를 넣지 않습니다.
- 성능을 바꾸는 변경(인덱스, 쿼리 형태)은 `tools/bench/bench.py --skip-seed` 로 전후를 재고 docs/PERFORMANCE.md 에 기록합니다.
  - 예: 수신 시각 조건을 추가한 파티션 가지치기는 오히려 10배 느려져 기각했습니다(ADR-017).
