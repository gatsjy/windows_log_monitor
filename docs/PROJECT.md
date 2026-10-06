# Log Monitor 프로젝트 명세

> 최종 갱신: 2026-10-04 · 버전 0.5.0 (… + 알림 규칙 관리 화면, 사용자 그룹·권한·조회 범위, 수집 전용 포트 6976, 폐쇄망 에이전트 설치 묶음, 반응형 화면)
> 앞으로 개발할 내용은 [BACKLOG.md](BACKLOG.md), 다른 오픈소스 제품과의 비교는 [COMPARISON.md](COMPARISON.md) 에 있습니다.
> 이 문서는 사람과 AI 에이전트가 함께 보는 **단일 기준 문서**입니다. 구현이 바뀌면 같은 변경에서 이 문서도 고칩니다.

## 1. 목표와 범위

### 목표
1. 여러 대의 Windows PC/서버(그리고 Linux 서버, 네트워크 장비)의 로그를 **한곳에 모은다**.
2. 전체를 **한눈에** 볼 수 있는 깔끔한 웹 UI를 제공한다. 어떤 데이터가 들어오는지 **직관적으로** 확인할 수 있어야 한다.
3. **오픈소스만으로** 구성하고, 사람이 **고치기 쉬운** 구조로 유지한다.
4. **ISMS 심사**에 대응할 수 있게 만든다. 로그 보관, 감사 기록, 접근통제가 대상이다.
5. 오류를 **메일, 웹훅, 사내 Oracle DB**로 전달한다 (Phase 2 알림, §6).

### 범위 밖 (현재)
- 성능 메트릭(CPU/메모리) 수집 — 로드맵 Phase 4
- 분산 저장(클러스터) — 볼륨이 커지면 ADR-004 에 따라 검토

## 2. 아키텍처

```
 Windows PC ──(Fluent Bit: winevtlog + heartbeat)──┐
   └ (선택) IIS W3C 로그, SQL Server ERRORLOG (tail)┤
 Linux 서버 ──(Fluent Bit: systemd/tail + heartbeat)┤  HTTP POST /api/ingest
 네트워크 장비 ──syslog──▶ collector (Fluent Bit) ───┘  gzip JSON, X-API-Key
                                                     ▼
                                   api (FastAPI, uvicorn 1 worker)
                                   ├─ normalizers: 소스별 → 공통 컬럼
                                   ├─ repository: PostgreSQL 읽기/쓰기 (SQL 은 여기만)
                                   ├─ live: SSE 브로드캐스트 (실시간 화면·대시보드)
                                   ├─ alerts: 규칙 평가(30초) → 메일 / 웹훅 / Oracle
                                   └─ 정적 UI(web/) 제공
                                                     ▼
                                   PostgreSQL 17 (events: 월별 파티션, alerts, audit_log)
```

### 컨테이너 (docker-compose.yml)

| 서비스 | 이미지 | 포트 | 비고 |
|---|---|---|---|
| `db` | postgres:17-alpine | (개발) 127.0.0.1:15432 | 볼륨 `pgdata` |
| `api` | server/Dockerfile | 8080 → 8000, **6976 → 8001** | 8000: UI + API, 8001: **에이전트 수집 전용**(`/api/ingest`·`/healthz` 만). 한 프로세스(`app/serve.py`). 비 root(uid 10001) |
| `collector` | fluent/fluent-bit:4.0 | 514/udp·tcp, 1514/tcp | `--profile syslog` 일 때만 |
| `mailpit` | axllent/mailpit | (개발) 127.0.0.1:8025 | **개발 전용.** 알림 메일을 실제로 보내지 않고 받아서 웹으로 보여줌 |

- `docker-compose.override.yml` 은 개발용입니다. 코드 마운트, 코드 변경 시 재시작(`watchfiles`), DB 포트 노출을 담당합니다.
- 운영에서는 `-f docker-compose.yml` 만 씁니다.

## 3. 데이터 흐름과 형식

### 3.1 수집 API

```
POST http://<서버>:6976/api/ingest      ← 에이전트는 수집 전용 포트(WLM_INGEST_PORT)로 보낸다 (8080 도 받음)
Headers: X-API-Key: <WLM_INGEST_API_KEYS 중 하나>
         Content-Encoding: gzip (선택)
Body:    JSON 배열 | JSON 객체 | NDJSON
응답:    {"accepted": <이벤트 수>, "heartbeats": <하트비트 수>}
```

에이전트가 붙이는 공통 필드는 다음과 같습니다.

| 필드 | 의미 |
|---|---|
| `agent_host` | PC 이름. **호스트 기준값** (Windows: `%COMPUTERNAME%`, Linux: `hostname -s`) |
| `log_source` | 정규화기 선택: `winevtlog` / `iis` / `mssql` / `syslog` / `journald` / `file` / (새 소스) |
| `log_channel` | (파일 로그) 화면에 보일 채널 이름 |
| `date` | Fluent Bit 레코드 시각 (UTC, `json_date_key`) |
| `type: "heartbeat"` | 하트비트. 이벤트로 저장하지 않고 `agents` 만 갱신 |

### 3.2 정규화 규칙 (`server/app/normalizers/`)

공통 컬럼은 `ts`, `host`, `source`, `channel`, `provider`, `event_id`, `level`, `message`, `category`, `username`, `src_ip` 입니다. 원본은 `raw` 에 그대로 저장합니다.
- 서버가 텍스트 줄을 해석한 값(IIS, MSSQL)은 원본 키를 건드리지 않고 `raw.iis.*`, `raw.mssql.*` 에 **덧붙입니다**.

| 소스 | ts | host | channel | provider | event_id | level |
|---|---|---|---|---|---|---|
| winevtlog | `TimeCreated` | agent_host → `Computer` | `Channel` | `ProviderName` | `EventID` | `Level` (0→4), 감사 실패 → 3 |
| syslog | `time`(시간대 있으면) → `date` | agent_host → `host` → `source_ip` | facility 이름 | `ident` | – | severity 매핑 |
| journald | `date` | agent_host → `_HOSTNAME` | `_SYSTEMD_UNIT` → facility | `SYSLOG_IDENTIFIER` | – | `PRIORITY` 매핑 |
| file/기타 | `time`/`timestamp` → `date` | agent_host → `host` | `log_channel` → 파일명 | 파일 경로 | – | level 필드 → 본문 키워드 추정 |
| iis | W3C `date`+`time` (UTC) | agent_host | `IIS/W3SVC<n>` (파일 경로) | `IIS` | HTTP 상태 (`sc-status`) | 5xx → 2, 401·403·429 → 3, 그 외 4 |
| mssql | ERRORLOG 시각 (`WLM_DISPLAY_TZ` 로 해석) | agent_host | `MSSQL/ERRORLOG` | 프로세스 (`Logon`, `spid51` …) | 오류 번호 (로그인 실패 18456) | Severity ≥20 → 1, ≥17 → 2, ≥11 → 3 |

- **level:** 1 심각(Critical), 2 오류(Error), 3 경고(Warning), 4 정보(Information), 5 상세(Verbose)
- **syslog severity 매핑:** 0~2 → 1, 3 → 2, 4 → 3, 5~6 → 4, 7 → 5
- **소스 선택:** `log_source` 가 있으면 그 값으로 고릅니다. 없으면 레코드 형태로 추정합니다.
  - `EventID`+`Channel` → winevtlog
  - `MESSAGE`+`_HOSTNAME` → journald
  - `pri` → syslog
  - 그 외 → generic
- 형식이 이상해도 **버리지 않습니다**. host가 없으면 `unknown` 으로 저장합니다.
  - 예외: IIS 의 `#Fields:` 같은 머리줄은 저장하지 않고 열 순서만 기억합니다(파일마다).
- **IIS (`normalizers/iis.py`):** 기본 열 순서(IIS 10 기본 W3C)로 읽고, `#Fields:` 머리줄을 보면 그 파일의 열 순서로 바꿉니다.
  - 메시지는 `GET /경로 → 500 (1234ms) · User-Agent` 형태로 만듭니다.
  - 열 이름 매핑: `c-ip`→`client_ip`, `sc-status`→`status`, `time-taken`→`time_taken`, `cs(User-Agent)`→`user_agent` …
- **MSSQL ERRORLOG (`normalizers/mssql.py`):** 오류는 `Error: 번호, Severity, State` 머리줄 + 본문 줄 두 줄입니다.
  - 머리줄은 '상세'(5)·번호 없음으로 저장하고, 번호·심각도는 같은 시각·프로세스의 다음 본문 줄에 붙입니다(이중 집계 방지).
  - SQL Server 는 중요한 오류·로그인 실패를 Windows 응용 프로그램 로그(공급자 `MSSQLSERVER`)에도 남깁니다. 에이전트만 설치해도 `mssql` 분류로 들어옵니다.

#### 분류 (`category`, `normalizers/categories.py`)

소스와 채널·공급자로 정합니다. 화면의 '분류' 필터, 대시보드, 알림 규칙에서 씁니다.

| 값 | 화면 이름 | 조건 |
|---|---|---|
| `iis` | 웹 서버 (IIS) | `log_source: iis` 또는 공급자 W3SVC·WAS·Microsoft-Windows-IIS* |
| `mssql` | DB (MSSQL) | `log_source: mssql` 또는 공급자 MSSQL*·SQLSERVERAGENT·SQLAgent* |
| `powershell` / `defender` / `rdp` / `sysmon` | PowerShell / 백신 / 원격 데스크톱 / Sysmon | Windows 채널 이름 |
| `security` / `system` / `application` / `windows` | 보안 / 시스템 / 응용 프로그램 / 기타 Windows | Windows 채널 |
| `linux` / `syslog` / `file` | Linux / syslog 장비 / 파일 로그 | journald / syslog / 그 외 |

- 분류를 추가하면 `classify()`, `web/js/levels.js` 의 `CATEGORY_LABELS`, 기존 데이터용 마이그레이션 UPDATE 를 함께 고칩니다.

#### 공통 필드 (`username`, `src_ip`)

소스가 달라도 같은 이름으로 찾기 위한 필드입니다(Elastic ECS 의 `user.name`, `source.ip` 에 해당).

| 소스 | username | src_ip |
|---|---|---|
| Windows | EventData `TargetUserName` → `SubjectUserName` → … (없으면 StringInserts 위치표) | EventData `IpAddress` → `SourceAddress` → … |
| IIS | `cs-username` | `c-ip` |
| MSSQL | `Login failed for user '...'` | `[CLIENT: ...]` |
| SSH (syslog/journald) | `Failed password for (invalid user) X` | `from X` |

- 의미 없는 값은 버립니다: `-`, `N/A`, `S-1-0-0`, `$` 로 끝나는 컴퓨터 계정, `::1`·`127.0.0.1`. `::ffff:` 접두사는 뗍니다.
- Windows 에이전트는 `event_data_as_map: true` 로 EventData 를 이름 있는 맵으로 보냅니다(`f.EventData.LogonType` 처럼 검색).

### 3.3 데이터 모델 (`server/migrations/`)

| 테이블 | 용도 | 핵심 |
|---|---|---|
| `events` | 로그 이벤트 | `received_at` 월별 RANGE 파티션 (`events_YYYY_MM`), PK `(id, received_at)` |
| `agents` | 로그 보낸 PC 목록 | `last_seen` 으로 상태 판정, `meta` = 하트비트 내용 |
| `field_stats` | 원본 필드 카탈로그 | `(source, path)` 별 타입·횟수·예시. 중첩은 점 경로(3단계까지) |
| `audit_log` | 시스템 감사 기록 | 대시보드·알림 설정 저장, 알림 테스트 발송, 보관기간 만료 삭제 |
| `alerts` | 발생한 알림 (002) | 규칙, 심각도, 대상(group_key), 건수, `payload` = 보낸 메시지 전체 |
| `alert_deliveries` | 알림 대상별 전송 상태 (002) | `pending/sent/failed/gave_up`, 시도 횟수, 마지막 오류 |
| `schema_migrations` | 적용된 마이그레이션 | 자동 관리 |

**events 인덱스:**
- `(ts DESC, id DESC)`
- `(category, ts DESC)`, `(username, ts DESC)`·`(src_ip, ts DESC)` (값 있는 행만, 007)
- `(host, ts)`, `(level, ts)`, `(channel, ts)`, `(event_id, ts)`, `(source, ts)`
- `message` 에 pg_trgm GIN 인덱스(부분일치 검색용)
- `(received_at)` — 알림 규칙의 '최근 N분 동안 수신' 집계용 (002)

**PC 상태:**

| 상태 | 조건 |
|---|---|
| 온라인 | 마지막 수신 ≤ `WLM_HEARTBEAT_ONLINE_SEC`(90초) |
| 지연 | 마지막 수신 ≤ `WLM_HEARTBEAT_STALE_SEC`(15분) |
| 오프라인 | 그 이후 |

## 4. 조회 API

모든 조회 API는 공통 필터 파라미터를 받습니다(`server/app/filters.py`).

| 파라미터 | 예 | 설명 |
|---|---|---|
| `since`, `until` | `24h`, `7d`, ISO8601 | 기본 `24h`. **ts(발생 시각)** 기준 |
| `host`, `channel`, `provider`, `source` | `WEB-01,WEB-02` | 콤마 = OR |
| `category`, `user`, `ip` | `iis,mssql` / `sa` / `203.0.113.5` | 분류·공통 필드 (콤마 = OR) |
| `level`, `event_id` | `1,2` | 정수 목록 |
| `q` | `timeout`, `timeout\|refused` | message 부분일치. `\|` 로 나누면 OR |
| `f.<경로>` | `f.StringInserts.5=admin` | 원본 JSON 경로 일치 (배열은 숫자 인덱스) |

| 엔드포인트 | 설명 |
|---|---|
| `GET /api/events?limit=&cursor=` | 최신순 목록. `next_cursor` 로 다음 페이지 (keyset) |
| `GET /api/events/{id}` | 단건 + raw |
| `GET /api/stats/count?compare=true` | 건수 + 직전 같은 길이 기간 건수 |
| `GET /api/stats/timeseries?group=&buckets=&interval=&tz_offset=` | 시간 구간별 건수. group 상위 6개 + `__other__` (level 은 전부) |
| `GET /api/stats/top?field=&limit=` | 상위 값. field = 컬럼명 또는 `f.<경로>` |
| `GET /api/stats/summary` | PC 상태 수, 분당 수집량, 최근 24시간 알림 수 |
| `GET /api/agents?since=` | PC 목록 + 기간 내 이벤트/오류/경고 수 + 상태 |
| `DELETE /api/agents/{host}` | 수집 PC 목록에서 삭제 (관리자, audit_log 기록, 이벤트는 보존) |
| `GET /api/fields` | 필드 카탈로그 |
| `GET /api/live?<필터>` | SSE. `event: events` 로 배열 전송 (시간 필터 무시) |
| `GET/PUT /api/dashboards/{name}` | 대시보드 JSON 읽기/저장 (저장은 audit_log 기록) |
| `GET /api/alerts?since=&rule=&severity=&host=` | 알림 이력 (전송 상태 포함) |
| `GET /api/alerts/{id}` | 알림 상세 (payload: 본문, 최근 이벤트 샘플) |
| `GET /api/alerts/config` | 엔진 상태, 규칙(최근 발생 포함), 알림 대상(비밀값 제외), 원본 YAML |
| `PUT /api/alerts/config` | 본문 = YAML. 검증 실패 시 422 + 오류 내용, 파일은 그대로 (저장은 audit_log 기록) |
| `POST /api/alerts/test/{notifier}` | 알림 대상 연결 테스트 (audit_log 기록) |
| `PUT /api/alerts/rules` | 규칙 한 개 추가·수정 (`{original?, rule}`), 그 규칙 블록만 바꿈 — `alerts.manage` |
| `DELETE /api/alerts/rules/{이름}` · `POST /api/alerts/rules/enabled` | 삭제 · 켜기/끄기 (`{names, enabled}`, 묶음 단위 가능) — `alerts.manage` |
| `POST /api/alerts/rules/preview` | 최근 N시간 데이터로 규칙 미리보기 (맞는 로그·예상 알림·대상별) — `alerts.manage` |
| `GET /api/agents/package?os=&server=&port=&iis=&mssql=` | 에이전트 설치 묶음 zip (설정·API 키·Fluent Bit 포함) — `agents.deploy`, 감사로그 |
| `GET /api/agents/package/info` | 내려받기 창 정보 (기본 서버 주소·포트, 들어갈 설치 파일) |
| `GET/POST /api/user-groups`, `PUT/DELETE /api/user-groups/{id}` | 사용자 그룹 (관리자) |
| `GET /api/meta`, `GET /healthz` | 메타 정보(소스·분류 목록 등), 상태 확인 |

OpenAPI 문서는 `http://<서버>:8080/docs` 에 있습니다.

## 5. UI

- **기술:** 순수 HTML/CSS/ES 모듈. 빌드, npm, 외부 CDN 없이 동작합니다(폐쇄망에서도 동작).
- **라우팅:** `#/dashboard/<이름>`, `#/live`, `#/events?<필터>`, `#/alerts`, `#/agents`, `#/fields?source=&path=`
  - 필터는 URL에 남기 때문에 주소를 공유하면 같은 화면이 열립니다.
- **디자인 토큰:** `web/css/app.css` 의 `:root` 에 있습니다. 라이트/다크 모두 정의되어 있고 사이드바에서 전환합니다.
- **차트 규칙 (`web/js/charts.js`):**
  - 막대는 최대 24px, 위쪽만 4px 둥글게, 막대 사이 2px 여백을 둡니다.
  - 격자선은 1px 실선이고, 마우스를 올리면 툴팁이 나옵니다.
  - 계열이 2개 이상이면 범례를 표시합니다.
  - 색은 값(엔터티)에 고정합니다. 순위로 칠하지 않습니다.
- **로그 수준과 PC 상태**는 항상 **아이콘 + 글자 + 색**으로 표시합니다. 색만으로 구분하지 않습니다.

### 5.1 대시보드 위젯 (`config/dashboards/<이름>.json`)

```json
{
  "title": "전체 현황",
  "description": "부제",
  "time_range": "24h",
  "refresh_sec": 60,
  "widgets": [
    { "type": "stat", "title": "오류", "w": 3, "metric": "count",
      "query": { "level": "1,2" }, "up_is_good": false, "color": "var(--critical)" }
  ]
}
```

| type | 옵션 | 설명 |
|---|---|---|
| `stat` | `metric`: count / agents / rate, `up_is_good`, `color`, `icon_level` | 숫자 + 직전 기간 대비 + 스파크라인 |
| `timeseries` | `group`, `buckets`, `height` | 시간대별 누적 막대. 막대 클릭 시 그 구간 검색 |
| `top` | `field`(host·channel·provider·source·event_id·level·category·user·ip·`f.<경로>`), `limit`, `color` | 상위 값 가로 막대. 클릭 시 그 값으로 검색. `user`·`ip` 는 값 없는 이벤트를 세지 않음 |
| `events` | `limit` | 최근 이벤트 표 |
| `hosts` | – | PC 카드 격자 (오류 많은 순) |
| `text` | `text` | 안내문 |
| `alerts` | `limit` | 최근 알림 목록 (누르면 알림 상세) |

모든 위젯이 받는 공통 옵션은 `title`, `w`(1~12칸), `query`(필터 객체), `since`(위젯별 기간)입니다.

**기본 대시보드:** `overview`(전체 현황), `iis`(웹 서버), `mssql`(DB), `security`(보안 감사 — 로그온 실패 계정·출발지 IP, RDP).

### 5.2 대시보드 실시간 갱신 (ADR-010)

몇 초마다 전체를 다시 조회하지 않습니다. 두 가지를 섞어서 씁니다.

1. **실시간 반영:** 대시보드가 `/api/live` (SSE)를 구독합니다. 새 이벤트를 1초 단위로 모아 각 위젯의 `live()` 로 넘깁니다.
   - 위젯 조건 판단은 `web/js/livefilter.js` 가 합니다. 서버 `filters.py` 와 같은 규칙입니다.
   - stat: 숫자와 스파크라인이 바로 올라갑니다.
   - timeseries: 해당 구간의 막대가 자랍니다.
   - top: 막대가 늘고 순위가 바뀝니다.
   - events: 새 행이 위에 끼어듭니다.
   - hosts: 로그가 들어온 PC 카드가 깜빡이고 숫자가 바뀝니다.
2. **전체 동기화:** `refresh_sec`(기본 60초)마다, 그리고 실시간으로 맞출 수 없는 변화가 생기면 API로 다시 조회합니다.
   - 실시간으로 맞출 수 없는 변화: 새 시간 구간 시작, 처음 보는 PC나 계열, 기간 밖으로 빠지는 오래된 건수.

- 헤더의 `실시간 · N건/분` 배지를 누르면 실시간 갱신을 켜고 끕니다(브라우저에 저장).
- 탭이 안 보이는 동안에는 반영을 건너뜁니다.
- **한계:** 대시보드는 필터 없이 모든 이벤트를 받습니다.
  - 초당 수천 건 규모가 되면 서버에서 위젯별로 집계해서 보내는 방식으로 바꿉니다(ADR-010).

## 6. 알림 (Phase 2)

```
config/alerts.yaml ──(변경 감지, 자동 반영)──▶ 엔진 (interval_sec 마다, advisory lock 으로 1곳에서만)
  규칙 평가: events(received_at ≥ now - window, match) GROUP BY group_by HAVING count ≥ threshold
    → cooldown 확인 → alerts + alert_deliveries(pending) 기록 → 알림 대상들로 동시에 전송
  실패 → failed (1분 → 5분 → 15분 → 1시간 간격 재시도, 5회 후 gave_up)
```

### 6.1 규칙 (`config/alerts.yaml` 의 `rules`)

| 키 | 기본 | 설명 |
|---|---|---|
| `name` | (필수) | 규칙 이름. 고유해야 하고, 쿨다운 기준이 됩니다. 이름을 바꾸면 새 규칙으로 취급합니다 |
| `kind` | `count` | `count`: 이벤트 수 기준 / `agent_silent`: PC 수신 끊김 |
| `match` | `{}` | 검색 조건과 같은 키: `host, channel, provider, source, category, user, ip, level, event_id, q, f.<경로>` |
| `window` | `5m` | 최근 이 시간 동안 **수신된** 이벤트를 셉니다 (늦게 도착한 오류도 알림) |
| `threshold` | `1` | 이 건수 이상이면 알림 |
| `group_by` | `host` | 이 값마다 따로 세고 따로 알림. `ip`(공격 출발지별), `user`(계정별)도 가능. `none` 이면 전체 합산 |
| `cooldown` | `30m` | 같은 규칙과 같은 대상은 이 시간 안에 다시 알리지 않습니다. `window` 보다 짧으면 `window` 로 맞춥니다 |
| `severity` | `warning` | `critical / error / warning / info` |
| `notify` | (필수) | 알림 대상 이름 목록 |
| `sid` | 자동 | 규칙 번호 (Snort 의 sid 처럼 고유, 100만 번대). 화면에서 만들면 다음 번호를 붙입니다 |
| `group` | `기타` | 규칙 묶음 (규칙 관리 화면 왼쪽 목록, 묶음 단위 켜기/끄기) |
| `tags` | `[]` | 분류 태그. 기본 규칙은 `MITRE T1110`, `ISMS 2.11.3` 처럼 공격 기법·ISMS 항목을 적습니다. 메시지와 화면에 표시 |
| `silent_for`, `hosts` | `10m`, 전체 | (`agent_silent`) 끊김 판정 시간, 대상 PC 목록 |

**기본 규칙 팩 (20개):** 시스템 심각 오류, 서비스 비정상 종료, 응용 프로그램 오류 다발, 서버 응답 없음,
로그온 실패 급증, 무차별 대입(출발지 IP 기준), 원격 데스크톱 무차별 대입(LogonType 10), 계정 잠금, 관리자 그룹 구성원 추가,
새 사용자 계정, 새 서비스 설치, 예약 작업 생성, 보안 감사 로그 삭제, 감사 정책 변경, 의심스러운 PowerShell, 백신 악성 코드 탐지,
웹 서버 오류 급증, SQL Server 로그인 실패 급증, SQL Server 심각 오류, Linux SSH 무차별 대입.
- 일부 규칙은 Windows 감사 정책(로그온·계정 관리·프로세스·PowerShell 스크립트 블록 로깅)이 켜져 있어야 동작합니다(ISMS.md).

- `agent_silent` 는 한 번 끊긴 동안 한 번만 알립니다. 다시 수신됐다가 또 끊기면 다시 알립니다.
- `hosts` 를 비우면 퇴근 시 꺼지는 PC까지 알림이 가므로, 서버 목록을 지정합니다.

### 6.2 알림 대상 — 환경설정 화면에서 관리 (§8)

- 규칙의 `notify` 에는 **수신 그룹 이름** 또는 **외부 연동 이름**을 씁니다. 이 이름들은 DB 에서 관리합니다.
  - 수신 그룹 → 그룹 안에서 '알림 받음'이고 이메일이 있는 수신자 전원에게 메일 한 통
  - 외부 연동(웹훅) → HTTP POST
  - 외부 연동(Oracle) → 설정한 SQL 한 문장 실행
- 규칙을 저장할 때 없는 이름이 있으면 거부합니다(422). 규칙에서 쓰는 그룹·연동은 삭제하거나 이름을 바꿀 수 없습니다.
- 대상은 엔진이 매 주기 DB 에서 다시 만듭니다. 화면에서 바꾸면 다음 평가부터 바로 반영됩니다.
- **받을 최소 수준(min_severity):** 그룹·연동마다 정합니다.
  - 정보(전부) / 경고 이상 / 오류 이상 / 심각만
  - 기준보다 낮은 알림은 보내지 않고, 전송 이력에 `skipped`(건너뜀)로 남깁니다.
  - 예: 운영팀은 경고 이상, 임원 보고용 메신저는 심각만, 사내 DB 는 전부.
- `config/alerts.yaml` 에 예전 형식의 `notifiers:` 가 있으면 설정 오류로 알려 줍니다(화면으로 옮기라는 안내).

### 6.3 메시지

모든 대상이 같은 내용을 씁니다(`app/alerts/message.py`).

- **제목:** `[경고] 로그온 실패 급증 · DC-01`
- **본문:** 요약, 설명, 발생 시각(`WLM_DISPLAY_TZ`, 기본 Asia/Seoul), 최근 이벤트 5건, `WLM_PUBLIC_URL` 기준 검색 링크
- **웹훅 json:** `{"source", "title", "text", "alert": {...}}`

### 6.4 화면 (`#/alerts`)

- 엔진 상태(마지막 평가, 설정 오류), 심각도별 수
- 알림 이력: 행을 누르면 전송 상태·오류·포함 이벤트를 봅니다.
- 탭 3개: **알림 이력**(`#/alerts`) / **규칙 관리**(`#/alerts/rules`) / **알림 대상**(`#/alerts/targets`)
- **규칙 관리 (Snort 방식):**
  - 왼쪽 **규칙 묶음**(`group`) 목록 — 묶음 단위로 켜기/끄기(일부만 켜져 있으면 반쯤 켜진 스위치)
  - 오른쪽 규칙 표 — 사용 스위치(바로 저장), **SID**, 심각도·이름·설명·태그, 조건·기준, 받는 곳, 발생 수. 검색(이름·SID·태그·조건), 사용/꺼짐 필터
  - 행을 누르면 **편집 패널**(`web/js/ruleform.js`):
    - 위쪽에 Snort 식 한 줄 규칙 문장과 우리말 요약이 입력에 따라 바로 바뀝니다 (보기 전용)
      - 예: `alert error (msg:"원격 데스크톱 무차별 대입"; event_id:4625; field:EventData.LogonType="10"; threshold:type both, track by_src, count 10, seconds 600; cooldown:3600; notify:"운영팀"; reference:MITRE T1110.001; classtype:"계정·인증 공격"; sid:1000007;)`
    - 입력: 이름·묶음·SID·설명·심각도·사용 / 감지 방식(로그 건수·PC 수신 끊김) / 어떤 로그를(분류·수준 칩, 이벤트 ID, PC, 사용자, 출발지 IP, 메시지, 원본 필드 조건) / 얼마나 자주면(기간·건수·묶음 기준·재알림 간격) / 누구에게(알림 대상 체크, 태그)
    - **미리보기:** 최근 24시간 로그에 적용했다면 맞는 로그 수, 예상 알림 횟수(재알림 간격 반영, 겹치지 않는 구간으로 근사), 대상별 횟수
  - 저장하면 서버가 `config/alerts.yaml` 에서 **그 규칙 블록만** 바꾸고(다른 규칙·주석 유지, `app/alerts/ruleedit.py`) 전체를 검증한 뒤 저장 — 감사로그 `alerts.rule.save/delete/toggle`
  - 'YAML 편집'(고급)으로 파일 전체를 직접 고칠 수도 있습니다.
- 알림 대상: 환경설정의 그룹·연동 목록, 규칙 사용 여부, **테스트 발송**
- 사이드바 '알림' 옆 숫자는 최근 24시간 알림 수입니다.

### 6.5 검증 기록 (2026-10-03, 개발 환경)

- **메일:** 15건이 발생했고, 첫 전송 실패 뒤 재시도로 전부 Mailpit에 도착했습니다.
- **웹훅:** 로컬 수신기로 json 수신을 확인했습니다.
- **Oracle:** `gvenzl/oracle-free:23-slim-faststart` 시험 컨테이너의 `LOGMON_ALERTS` 에 INSERT 했습니다.
  - CLOB 4000자 초과, 한글, 재전송 시 중복 무시를 확인했습니다.
  - 이 컨테이너는 시험에만 썼고 구성에는 넣지 않았습니다.
  - **사내 Oracle 버전과 계정 권한으로 다시 시험해야 합니다.**

## 7. 인증과 권한 (Phase 2)

| 항목 | 동작 | 설정 (.env) |
|---|---|---|
| 계정 | 개인 계정(아이디 소문자). 역할: **관리자**(모든 작업) / **조회자**(보기 + 속한 사용자 그룹의 권한) | – |
| 사용자 그룹 | DB팀·보안팀처럼 묶어 **기능 권한**과 **볼 수 있는 범위**를 준다 (§7.1) | – |
| 비밀번호 저장 | scrypt(N=2^17, r=8, p=1, 솔트 16바이트) — 표준 라이브러리 | `WLM_PASSWORD_HASH_N` |
| 비밀번호 정책 | 3종 이상 8자 / 2종 이상 10자, 아이디 포함·같은 문자 4연속 금지 | – |
| 임시 비밀번호 | 계정 생성·초기화 시 발급, 첫 로그인 때 변경 강제. 화면에 한 번만 표시 | – |
| 변경 주기 | 지나면 로그인 후 변경 강제 | `WLM_PASSWORD_MAX_AGE_DAYS`(90, 0=끔) |
| 계정 잠금 | 연속 실패 시 잠금, 관리자 '잠금 해제' 또는 시간 경과 | `WLM_LOGIN_MAX_FAILURES`(5), `WLM_LOGIN_LOCKOUT_MIN`(10) |
| 세션 | 서버 세션(DB 에는 토큰의 SHA-256만), HttpOnly·SameSite=Strict 쿠키 | `WLM_COOKIE_SECURE`(HTTPS 면 true) |
| 자동 로그아웃 | 사용자 조작이 없으면 만료. 자동 새로고침·실시간 스트림은 연장하지 않음 | `WLM_SESSION_IDLE_MIN`(30) |
| 최대 세션 | 로그인 후 최대 유지 시간 | `WLM_SESSION_MAX_HOURS`(12) |
| CSRF | 상태를 바꾸는 요청에 `X-WLM-CSRF: 1` 헤더 필수 | – |
| 로그인 경고문 | 로그인 화면 하단 문구 | `WLM_LOGIN_NOTICE` |
| 초기 관리자 | 사용자가 없으면 `admin` 생성. 비밀번호는 지정값 또는 무작위(서버 로그 1회 출력) | `WLM_ADMIN_INITIAL_PASSWORD` |

- **유휴 판정 방식:**
  - 브라우저가 모든 요청에 `X-WLM-Idle-Sec`(마지막 키보드·마우스 조작 후 경과 초)을 붙입니다.
  - 서버는 이 값이 작을 때만 세션 활동 시각을 갱신합니다. 그래서 대시보드를 켜 두기만 하면 30분 뒤 로그아웃됩니다(ISMS 세션 타임아웃).
  - 상황판처럼 계속 켜 둘 화면이 필요하면 `WLM_SESSION_IDLE_MIN` 을 정책에 맞게 늘립니다.
- **실시간 스트림(SSE):** 열려 있는 동안에도 30초마다 세션을 확인하고, 로그아웃·만료되면 끊습니다.
- **로그인 실패 문구:** 아이디가 없을 때와 비밀번호가 틀릴 때 같은 문구를 씁니다(계정 존재 여부 노출 방지). 잠금 안내만 따로 표시합니다.
- **IP 단위 제한:** 10분 동안 30회 실패하면 그 IP의 로그인 시도를 막습니다(메모리 기반, 재시작 시 초기화).
- **권한:**
  - 공개: `/api/ingest`(API 키), `/api/auth/login`, `/api/auth/info`, `/healthz`
  - 그 외 `/api/*` 는 로그인 필수
  - 관리자 또는 해당 권한 그룹: 알림 규칙 관리(`alerts.manage`), 대시보드 편집(`dashboards.edit`), 환경설정(`settings.manage`), 감사로그(`audit.view`), 에이전트 설치 묶음(`agents.deploy`)
  - 관리자만: 사용자·사용자 그룹 관리 (권한 상승 방지)
- **감사로그(audit_log):**
  - 기록 대상: 로그인 성공·실패·잠금·로그아웃·세션 만료, 비밀번호 변경, 사용자 관리, 이벤트 검색 조건·상세 조회, 모든 설정 변경, Oracle 쿼리 실행, 보관·삭제
  - DB 트리거로 **수정·삭제·TRUNCATE 를 막습니다**(보관기간 만료 삭제만 예외).
  - 화면 '감사 로그'에서 조회하고 CSV(엑셀 호환)로 내려받습니다. 내려받은 사실도 기록합니다.
- **복구 명령 (컨테이너 안):**

```bash
docker compose exec api python -m app.cli list-users
docker compose exec api python -m app.cli reset-password admin      # 임시 비밀번호 + 잠금 해제
docker compose exec api python -m app.cli create-user kim --role admin --name 김민수
docker compose exec api python -m app.cli delete-user kim --reason 퇴사   # 비활성 계정만, 감사 로그에 기록
```

### 7.1 사용자 그룹 (`#/users/groups`, 관리자)

| 항목 | 내용 |
|---|---|
| 기능 권한 | `alerts.manage` 알림 규칙 관리 · `dashboards.edit` 대시보드 편집 · `settings.manage` 환경설정 · `audit.view` 감사 로그 · `agents.deploy` 에이전트 설치 묶음 (`app/auth/groups.py` PERMISSIONS) |
| 조회 범위 | 분류(예: DB(MSSQL)) 와 PC 이름(쉼표, `MED-*` 처럼 `*` 사용, 대소문자 무시). 둘 다 정하면 '그 분류이면서 그 PC' |
| 여러 그룹 | 권한은 합치고, 범위는 합집합. 범위가 비어 있는 그룹에 속하거나 그룹이 없으면 전체 |
| 관리자 | 그룹과 상관없이 모든 권한·모든 로그 |

- **서버에서 적용:** 검색·통계(대시보드)·실시간 스트림·이벤트 상세·수집 PC 목록에 범위 조건을 붙입니다(`filters.Scope`, `repository.scope_clause`, `routers/query._filter`).
  - 알림 이력: 규칙의 분류 조건이 범위와 겹치거나, 대상(PC)이 범위의 PC 패턴에 맞는 알림만 보입니다.
  - 필드 탐색: 범위가 있는 사용자에게는 실제 값 예시를 숨깁니다.
- 화면: 메뉴·버튼은 `auth.can(권한)` 으로 보이거나 숨기고, 사이드바에 '볼 수 있는 범위'를 표시합니다. 서버도 같은 권한으로 막습니다(`deps.require_permission`).
- 감사로그: `user_group.save`(권한·범위·구성원 포함), `user_group.delete`.

## 8. 환경설정 화면 (관리자, `#/settings`)

| 탭 | 내용 |
|---|---|
| 수신자 | 이름·이메일·전화·부서·메모, 알림 받음 여부, 소속 그룹. 로그인 계정과 별개 |
| 수신 그룹 | 이름(규칙의 notify), 설명, 구성원, **받을 최소 수준**, 사용 중인 규칙 |
| 외부 연동 | 웹훅(주소·형식·헤더), Oracle DB(아래). 받을 최소 수준, 사용 여부, 테스트 |
| 메일 서버 | SMTP 호스트·포트·보안(STARTTLS/SSL/없음)·계정·비밀번호·보내는 사람, 테스트 메일. 비워 두면 `.env` 의 `WLM_SMTP_*` |
| 로그 보관 | 로테이션 정책, DB 월 파티션·보관 파일 현황, 지금 실행, 무결성 확인, 다시 불러오기 (§9) |

### 8.1 Oracle 연동

- **드라이버:** python-oracledb thin 모드 — Oracle Instant Client 설치가 필요 없습니다.
- **접속 방식 4가지 (`app/oracle.py`):**
  1. **TNS 이름:** `config/oracle/tnsnames.ora` 의 별칭. 파일 내용은 같은 화면에서 붙여 넣고 저장합니다.
  2. **호스트 + 포트 + SID**
  3. **호스트 + 포트 + 서비스 이름**
  4. **접속 문자열:** Easy Connect(`host:1521/service`) 또는 `(DESCRIPTION=...)`
- **연결 시험:** 저장 전에 입력값으로 접속해 DB 이름·서비스·스키마·버전을 보여 줍니다.
- **알림 SQL:** 알림이 생기면 실행할 한 문장입니다(기본: `LOGMON_ALERTS` INSERT, DDL 은 `docs/oracle_alerts.sql`).
  - 바인드: `:alert_id :rule_name :severity :host :event_count :window_sec :first_event_at :last_event_at :fired_at :title :message :link :detail_json`
  - 프로시저 호출은 `BEGIN 프로시저(:rule_name, :host); END;` 형태로 씁니다.
  - SQL 에 쓴 바인드만 넘기고, 알 수 없는 바인드는 저장 전에 거부합니다. 문자열 안의 `:` 는 무시합니다.
  - 시각은 UTC 기준 TIMESTAMP 입니다.
  - PK 중복(ORA-00001)은 재전송으로 보고 성공 처리합니다.
- **SQL 시험 실행:** 테스트 값으로 실행한 뒤 **되돌립니다(롤백)**. '테스트 알림 실제 저장'은 커밋합니다.
- **조회 쿼리 실행기:**
  - `SELECT` / `WITH` 만, 한 문장만 실행합니다.
  - `SET TRANSACTION READ ONLY` 후 실행하므로 `FOR UPDATE` 같은 잠금도 실패합니다.
  - 최대 500행이고 LOB 은 4000자까지 읽습니다.
  - 실행한 SQL 과 결과 행 수, 소요 시간이 감사로그에 남습니다.
- **검증:** 실제 Oracle(gvenzl/oracle-free 23ai 시험 컨테이너)에 대해 통합 테스트로 확인했습니다(`tests/test_api_settings.py`).
  - 확인 항목: TNS 이름 / SID / 서비스 이름 접속, INSERT 롤백·커밋, CLOB 읽기, 읽기 전용 차단, 잘못된 비밀번호 오류
  - 시험 컨테이너가 없으면 Oracle 테스트는 건너뜁니다.

### 8.2 비밀값 보관 (ADR-012 개정)

- 화면에서 입력한 비밀번호(SMTP·Oracle)와 웹훅 주소·헤더는 DB 에 **암호화**해서 저장합니다(`app/secrets.py`).
  - 암호화: Fernet(AES-128-CBC + HMAC-SHA256)
  - 키: `WLM_SECRET_KEY` 의 SHA-256
- API·화면은 비밀값을 절대 돌려주지 않습니다(`has_secret` 만).
  - 입력란을 비우고 저장하면 기존 값을 유지합니다.
  - 웹훅 대상은 `https://호스트/…` 까지만 표시합니다(경로의 토큰 보호).
- **`WLM_SECRET_KEY` 를 잃어버리면** 저장된 비밀값을 복호화할 수 없습니다. 화면에서 다시 입력해야 합니다.
  - `.env` 를 백업 대상에 포함하고, 키는 DB 백업과 따로 보관합니다(ISMS 2.7.2 암호키 관리).
  - 생성: `openssl rand -hex 32`

## 9. 로그 로테이션

```
수집 ─▶ DB (월 파티션, 화면에서 바로 검색)          WLM_DB_RETENTION_DAYS (기본 90일)
          │ 기간 지난 달
          ▼
        보관 파일 archive/events_YYYY_MM.jsonl.gz   WLM_RETENTION_DAYS (기본 365일)까지
        + events_YYYY_MM.meta.json (행 수, SHA-256) + audit_log 에 같은 해시
          │ 기간 지난 파일
          ▼
        삭제 (audit_log: retention.delete_archive)
```

- **실행:** 매시간 자동(`app/partitions.py: drop_expired`). 화면 '로그 보관'의 **지금 실행**이나 CLI `rotate-now` 로 즉시 실행할 수 있습니다.
- **보관 파일 형식:** 한 줄에 이벤트 하나인 JSON(모든 컬럼 + 원본 raw)을 gzip 으로 압축합니다.
  - 서버 쪽 커서로 5천 건씩 읽고, 압축은 스레드에서 해서 수집을 막지 않습니다.
  - 기록한 행 수가 파티션 행 수와 다르면 파일을 버리고 파티션을 지우지 않습니다.
- **안전장치:**
  - 파일 만들기에 실패하면 DROP 하지 않고 다음 주기에 다시 시도합니다(`retention.archive_failed` 기록).
  - 전체 보관기간까지 지난 파티션은 파일 없이 바로 지웁니다.
- **무결성 확인:**
  - 화면의 '보관 파일 무결성 확인' 또는 CLI `verify-archives` 로 확인합니다.
  - 메타데이터의 SHA-256 과 다시 계산한 값을 비교하고, 감사로그의 해시와도 대조할 수 있습니다.
- **다시 불러오기(조사용):**
  - 해시를 확인한 뒤 같은 월 파티션을 만들어 복원합니다. 이후 이벤트 검색에서 그대로 조회할 수 있습니다.
  - `hold_days` 동안은 자동 정리에서 빠지고, 기간이 지나면 다시 지워집니다(파일은 그대로).
  - 해시가 맞지 않으면 복원을 거부합니다.
- **파일 보관 끄기:** `WLM_DB_RETENTION_DAYS >= WLM_RETENTION_DAYS` 로 두면 파일 보관 없이 DB 에서 바로 삭제합니다.
- **알림 이력·감사로그**는 `WLM_RETENTION_DAYS` 동안 DB 에 둡니다.
- **그 밖의 로테이션:**
  - **Docker 컨테이너 로그:** 서비스마다 `json-file` 50MB × 5개로 제한합니다(`docker-compose.yml` 의 `x-logging`).
  - **에이전트 버퍼:** 서버 장애 때 디스크에 쌓는 버퍼의 상한은 1GB 입니다(`storage.total_limit_size`). 넘치면 오래된 것부터 버립니다.
  - **Windows 이벤트 로그 자체:** 로그가 넘쳐 덮어써지기 전에 에이전트가 읽어야 합니다. 보안 로그 크기를 GPO 로 충분히 키웁니다(`agent/windows/README.md`).
  - **파일 로그(tail):** Fluent Bit 이 이름 변경·잘라내기(rotate)를 따라갑니다. 읽은 위치는 DB 파일에 기록합니다.

## 10. 성능

- 500만 건 기준 측정 결과와 용량 가이드는 [PERFORMANCE.md](PERFORMANCE.md) 에 있습니다.
- **요약 (튜닝 후, 반복 조회):**
  - 일반 검색은 0.1초 이내입니다. 7일 원본 필드 검색 0.3초, 30일 시계열 1.5초입니다.
  - 수집 처리량은 초당 약 9,800건입니다.
  - 30일 집계 화면은 하루 수백만 건 규모부터 느려집니다 → 시간별 집계 테이블(로드맵)로 대응합니다.
- 측정 도구: `tools/bench/bench.py` (별도 DB 사용)

## 11. 설정 (환경변수)

전체 목록은 `.env.example` 에 있습니다. 서버 설정은 모두 `WLM_` 접두사를 씁니다(`server/app/config.py`).

## 12. 확장 가이드

| 하고 싶은 것 | 위치 |
|---|---|
| Windows 채널 추가 | 에이전트 `-Channels` 인자 (기본에 PowerShell/Operational, Defender, RDP 포함. Sysmon 등 추가) |
| IIS / SQL Server 로그 | 에이전트 설치 시 `-Iis` (W3SVC 폴더 자동 탐색, `-IisLogPath`), `-MssqlErrorlog` (`-MssqlErrorlogPath`) |
| 분류 추가 | `normalizers/categories.py` + `web/js/levels.js` + 기존 데이터 UPDATE 마이그레이션 |
| 새 로그 소스 | `server/app/normalizers/` + `BY_SOURCE` 등록 + 테스트 |
| 텍스트 로그 파일 | 에이전트 yaml 의 `tail` 예시 주석 해제 + `log_source: file`, `log_channel` |
| 위젯 / 화면 | `web/js/widgets/`, `web/js/views/` (AGENTS.md 참고) |
| 검색 백엔드 교체 | `server/app/repository.py` 만 재구현 (ADR-004) |
| 새 알림 대상 종류 (예: 문자, 메신저 전용 API) | `app/alerts/notifiers.py` 에 Notifier 클래스 → `channels.type` CHECK 제약(마이그레이션) → `targets.py` 의 `build_channel`·`_clean_channel_config` → 환경설정 화면 → 테스트 |
| 새 규칙 종류 | `app/alerts/rules.py` 의 `RULE_KINDS`·검증 + `engine.py` 의 `evaluate` 분기 |

## 13. 운영

- **포트:** 8080 화면(사용자·관리자), **6976 수집 전용**(에이전트·syslog 수신기). 방화벽에서 6976 은 모든 PC, 8080 은 관리 대역만 여는 것을 권장합니다.
- **에이전트 배포:** 화면 '수집 PC > 에이전트 설치' 에서 서버 주소·포트·API 키·Fluent Bit 이 들어간 설치 묶음(zip)을 받아 배포합니다(`routers/agentpkg.py`). PC 가 폐쇄망이어도 됩니다.
- **폐쇄망 배포·업그레이드·되돌리기:** [AIRGAP.md](AIRGAP.md) (`deploy/airgap/make-bundle.sh` → 반입 → `deploy/airgap/install.sh`)
  - 이미지 태그는 `WLM_API_IMAGE`(.env, 기본 `log-monitor-api:latest`)로 고정합니다. 개발은 `log-monitor-api:dev`.

- **백업:** 매일 `docker compose exec db pg_dump -U wlm -Fc wlm > backup_$(date +%F).dump` 를 실행합니다.
  - 복구 절차를 분기마다 실제로 시험합니다(ISMS 2.9.3).
- **보관기간·로테이션:** §9 참고.
  - `archive/` 폴더(보관 파일)와 `.env`(암호화 키 포함)도 백업 대상입니다.
- **알림 운영:**
  - 환경설정 > 메일 서버(또는 `.env` 의 SMTP)를 설정하고, **테스트 메일**로 확인합니다.
  - `WLM_PUBLIC_URL` 을 사용자가 접속하는 주소로 바꿔야 알림의 링크가 맞게 열립니다.
- **용량:** 이벤트 1건은 대략 1~3KB입니다(원본 JSON 포함).
  - 계산 예: PC 100대 × 하루 1만 건 × 365일이면 약 0.4~1TB입니다.
  - Security 로그는 감사 정책에 따라 크게 늘어납니다.
- **시각 동기화:** 모든 PC와 서버는 NTP(사내 DC)에 맞춥니다. 저장은 UTC, 화면은 브라우저 시간대입니다.
- **업그레이드:** `git pull` 후 `docker compose -f docker-compose.yml up -d --build` 를 실행합니다. 마이그레이션은 시작 시 자동 적용됩니다.
  - 폐쇄망은 `install.sh --upgrade` (DB 자동 백업, 화면에서 고친 `config/` 보존).
- **`.env` 작성 주의:** 값이 빈 줄 뒤에 `# 설명` 을 붙이면(`KEY=    # 설명`) docker compose 가 설명문을 값으로 읽습니다. 설명은 항상 윗줄에 씁니다.
- **Linux 운영 서버에서 대시보드 저장:**
  - 컨테이너 사용자(uid 10001)가 `config/dashboards` 에 쓸 수 있어야 합니다.
  - `sudo chown -R 10001 config/dashboards` 로 권한을 줍니다.
  - 알림 규칙(`config/alerts.yaml`)도 화면에서 저장하려면 `config` 폴더 전체에 권한을 줍니다.

## 14. 로드맵

| 단계 | 내용 | 상태 |
|---|---|---|
| Phase 1 | 수집(Windows/syslog/journald/파일), PostgreSQL, 대시보드·실시간·검색·필드 탐색, 시뮬레이터 | **완료** |
| Phase 2 | **알림**: 규칙(YAML) → 메일 / 웹훅 / Oracle, 재시도, 알림 화면·위젯, 대시보드 실시간 갱신 | **완료** (§6, §5.2) |
| 운영 | HTTPS 리버스 프록시(Caddy/Nginx) 예시 구성, 사내 SSO(LDAP/OIDC) 연동 | 필요 시 |
| Phase 2 | **인증·권한·감사로그**, **환경설정**(수신자·그룹·최소 수준, 웹훅, Oracle TNS/SID/서비스·쿼리, 메일 서버), **로그 로테이션**(보관 파일·무결성·복원), 성능 측정 | **완료** (§7~§10) |
| Phase 3 | 대용량: 시간별 집계 테이블(긴 기간 대시보드·1년 추세), 자주 쓰는 원본 필드 인덱스, 필요 시 ClickHouse 또는 OpenSearch (ADR-004) | 규모에 따라 (PERFORMANCE.md §5) |
| 0.4 | IIS·MSSQL 수집, 분류·공통 필드(사용자·IP), EventData 이름 필드, 보안 규칙 팩(MITRE·ISMS 태그), 검색 OR | **완료** (§3.2, §6.1) |
| 0.5 | 알림 규칙 관리 화면(Snort 방식·미리보기), 사용자 그룹(권한·조회 범위), 수집 전용 포트 6976, 에이전트 설치 묶음(폐쇄망 PC), 반응형·디자인 개편 | **완료** |
| Phase 4 | Windows 성능 메트릭, 에이전트 설정 원격 배포 | 검토 |

세부 항목·우선순위·완료 기준은 [BACKLOG.md](BACKLOG.md) 에서 관리합니다.

## 15. 알려진 한계

- 실시간 스트림은 단일 프로세스 메모리 방식입니다. 워커를 늘리려면 LISTEN/NOTIFY로 바꿔야 합니다(ADR-006).
- RFC3164 syslog는 장비 시각에 연도·시간대가 없어서 **수신 시각**을 씁니다.
  - PRI 가 없는 등 형식이 틀린 syslog 줄은 수신기가 버립니다(collector 로그로 확인).
- 필드 경로는 점으로 구분합니다. 키 이름 자체에 점이 들어간 필드는 `f.` 필터로 지정할 수 없습니다.
- **전송 구간이 평문 HTTP 입니다.** 운영에서는 리버스 프록시로 HTTPS 를 적용하고 `WLM_COOKIE_SECURE=true` 로 둡니다.
  - 에이전트도 `tls: on` 으로 바꿉니다.
- IP 단위 로그인 시도 제한은 프로세스 메모리 기반입니다. 재시작하면 초기화되고, 여러 인스턴스 사이에 공유되지 않습니다.
- 긴 기간(30일 이상) 집계는 행 수에 비례해 느려집니다(PERFORMANCE.md). 시간별 집계 테이블은 로드맵에 있습니다.
- 알림 규칙은 `received_at`(수신 시각) 기준입니다.
  - 에이전트가 장애 후 몰아서 보낸 과거 오류도 '새로 들어온 오류'로 알립니다(의도한 동작).
- IIS 열 순서(`#Fields:`)와 MSSQL 오류 머리줄은 프로세스 메모리에 기억합니다.
  - 서버 재시작 직후, 사용자 지정 열 순서의 IIS 파일은 다음 머리줄(새 파일·IIS 재시작)이 올 때까지 기본 순서로 읽힙니다. 원본은 `raw` 에 남습니다.
- MSSQL ERRORLOG 의 여러 줄 메시지(스택 등)는 줄마다 따로 저장됩니다(BACKLOG 참고).
- 사용자 그룹 범위는 이벤트 데이터 API 에 적용됩니다. 사이드바의 PC 온라인 수·분당 수집량·알림 수(요약)는 전체 기준입니다.
- 알림 이력의 범위 판단은 규칙의 분류 조건과 대상(PC) 이름으로 합니다. 분류 조건이 없는 규칙(예: 수준만 보는 규칙)은 PC 범위가 맞을 때만 보입니다.
- 대시보드 실시간 반영값은 다음 동기화 전까지 근사치일 수 있습니다.
  - 동기화 조회와 스트림이 겹치는 순간 1~2건 중복이 생길 수 있습니다.
