# Log Monitor 프로젝트 명세

> 최종 갱신: 2026-10-16 · 버전 0.5.0 + 미출시(HTTPS·에이전트 TLS, 검색 문장 등 — CHANGELOG) (… + 알림 규칙 관리 화면, 사용자 그룹·권한·조회 범위, 수집 전용 포트 6976, 폐쇄망 에이전트 설치 묶음, 반응형 화면)
> 앞으로 개발할 내용은 [BACKLOG.md](BACKLOG.md), 다른 모니터링 시스템과의 비교·벤치마킹은 [COMPARISON.md](COMPARISON.md) 에 있습니다.
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
| `api` | server/Dockerfile | 8080 → 8000, **6976 → 8001**, **6977 → 8002** | 8000: UI + API(`WLM_TLS=on` 이면 https 만), 8001: **에이전트 수집 전용** 평문, 8002: 수집 전용 TLS, 8003: 수집기 전용 내부(게시 안 함) — 수집 리스너는 `/api/ingest`·`/healthz` 만. 한 프로세스(`app/serve.py`). 비 root(uid 10001). TLS 는 api 가 직접(ADR-036) |
| `collector` | fluent/fluent-bit:4.0 | 514/udp·tcp, 1514/tcp | `--profile syslog` 일 때만 |
| `mailpit` | axllent/mailpit | (개발) 127.0.0.1:8025 | **개발 전용.** 알림 메일을 실제로 보내지 않고 받아서 웹으로 보여줌 |

- `docker-compose.override.yml` 은 개발용입니다. 코드 마운트, 코드 변경 시 재시작(`watchfiles`), DB 포트 노출을 담당합니다.
- 운영에서는 `-f docker-compose.yml` 만 씁니다.

## 3. 데이터 흐름과 형식

### 3.1 수집 API

```
POST https://<서버>:6977/api/ingest     ← 에이전트는 수집 전용 포트로 보낸다: TLS 6977(WLM_TLS=on), 평문 6976(전환용). 화면 포트도 받음
Headers: X-API-Key: <WLM_INGEST_API_KEYS 중 하나>
         Content-Encoding: gzip (선택)
Body:    JSON 배열 | JSON 객체 | NDJSON
응답:    {"accepted": <이벤트 수>, "heartbeats": <하트비트 수>}   (+ "quarantined": <격리 수> — 있을 때만)
```

**늘 오던 로그가 끊긴 채널 (B-37, ADR-046).** 수집할 때 (PC, 소스, 채널)마다 날짜별 건수를 `agent_streams` 에 함께 쌓습니다(같은 트랜잭션, 문장 하나).
지난 7일(오늘 제외) 중 5일 이상 오던 채널이, PC 는 다른 로그·하트비트를 보내는데 평소보다 오래 조용하면 '끊김'입니다 —
조용한 기준은 max(6시간, 평소 간격 × 10, 3일 한도). 하루 몇 건인 채널이 밤새 조용한 것은 끊김이 아닙니다. PC 자체가 끊긴 것은 '연락 끊김'이 따로 알립니다.
수집 PC 화면 위쪽 상자와 점검 보고서 '점검 필요'에 나옵니다. GPO 변경으로 DC 의 Security 수집만 멈춰도 하트비트는 계속 와서 예전에는 조용했습니다. 집계는 35일 뒤 지웁니다.

**레코드 하나가 요청 전체를 막지 않게 (B-40, ADR-044).** 에이전트는 거절된 청크를 끝없이 다시 보내므로(`retry_limit: no_limits`),
레코드 하나 때문에 요청이 실패하면 그 PC 의 로그가 멈춘다.
- 정규화기에서 예외가 나면 그 레코드만 일반 로그로 저장하고 `raw._ingest.error` 에 오류를 남긴다(원본 키는 그대로, `_ingest` 는 서버 예약 키).
- 칸 범위를 넘는 EventID·수준은 비우고(원본은 raw), JSON 의 NaN·Infinity 는 글자로, 범위를 벗어나는 시각은 다음 키·수신 시각으로 — 알려진 값 오류는 미리 막는다.
- 그래도 저장이 값 때문에 실패하면 한 트랜잭션 안에서 반씩 나눠(저장점) 저장하며 문제 레코드만 `ingest_quarantine` 에 원본 그대로 격리하고 나머지는 저장한 뒤 200.
  실패한 시도가 요청당 256번을 넘으면 400(값 오류 레코드만 잔뜩 보내 DB 를 두드릴 수 없게). 중간에 다른 오류로 500 이면 모두 되돌린다(재전송 때 중복 없음).
  격리 레코드는 로그 보관기간 동안 두고, 수집 PC 화면(관리자)의 '수집 거절·격리'에서 원본을 본다(접속기록 `events.quarantine.view`).
- 짝 없는 서로게이트(`\ud800`)는 U+FFFD, NUL 은 지운다 — 둘 다 PostgreSQL 에 저장할 수 없는 글자. 값에 글자 그대로 든 `\u0000` 은 그대로 둔다.
- **수집 거절 장부:** 서버가 거절한 요청(400 형식·401 API 키·413 크기·500·503, 보내는 도중 끊김은 499)을 보낸 IP·상태·사유·정시마다 횟수·처음·마지막
  시각으로 남긴다 (`ingest_rejections`, 메모리에 모았다가 30초마다). 키를 바꾼 뒤 옛 설치 묶음으로 보내는 PC 를 찾는 유일한 길이다(그 PC 의 에이전트 로그도
  같은 출력이라 서버로 오지 못한다). TLS 핸드셰이크 실패는 앱까지 오지 않아 남지 않는다. 점검 보고서 '점검 필요'에도 나온다.

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
  - 예외: IIS 의 `#Fields:` 같은 머리줄은 이벤트로 저장하지 않고 열 순서만 `iis_layouts` 에 저장합니다(파일마다).
- **IIS (`normalizers/iis.py`, ADR-037):** 줄마다 열 순서 후보를 차례로 대 봅니다 — 같은 요청의 `#Fields:` 머리줄 → 그 파일의 저장된 열 순서 → 같은 폴더(`W3SVC<n>`)의 최신 열 순서 → 기본 순서(IIS 10 기본 W3C).
  - 칸 수와 **값 모양**(날짜·시각·상태 코드 100–999·정수 필드·IP)이 맞는 첫 후보로 읽습니다. 그 파일의 순서면 요청자가 정하는 값(method·URI·UA·사용자)은 모양을 보지 않습니다.
  - 추정한 순서(같은 폴더·기본)는 더 엄격합니다: IIS 가 늘 쓰는 필드가 비어 있지 않고, method·URI 가 요청 모양이며, 요청자 값 칸(사용자·UA·Referer·query)에 숫자나 IP 만 있지 않아야 합니다(칸이 밀린 것을 잡기 위해).
  - 맞는 후보가 없으면 원문 그대로 저장합니다(사용자·IP 를 틀린 자리 값으로 채우지 않음). 같은 폴더·기본 순서로 읽었으면 `raw.iis._layout` 이 `site`·`default` 입니다.
  - 열 순서는 DB 에 있어 서버·에이전트를 다시 시작해도 이어집니다. 프로세스 안 캐시는 커밋한 뒤에만 채웁니다.
  - 메시지는 `GET /경로 → 500 (1234ms) · User-Agent` 형태로 만듭니다.
  - 열 이름 매핑: `c-ip`→`client_ip`, `sc-status`→`status`, `time-taken`→`time_taken`, `cs(User-Agent)`→`user_agent` …
- **MSSQL ERRORLOG (`normalizers/mssql.py`):** 오류는 `Error: 번호, Severity, State` 머리줄 + 본문 줄 두 줄입니다.
  - 머리줄은 '상세'(5)·번호 없음으로 저장하고, 번호·심각도는 같은 파일·시각·프로세스의 다음 본문 줄에 붙입니다(이중 집계 방지).
  - 여러 줄 레코드(시작 배너·시작 인자·여러 줄 메시지, 에이전트 multiline)는 첫 줄로 시각·프로세스·번호를 읽고 나머지 줄은 메시지에 붙입니다(`raw.mssql.lines` = 줄 수). 줄마다 온 레코드와 같은 방식으로 셉니다(ADR-037).
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
| Windows | EventData(에이전트가 보낸 것, 없으면 서버가 붙인 이름) `TargetUserName` → `SubjectUserName` → … (그룹 구성원 변경은 `SubjectUserName`, 이름도 없으면 StringInserts 위치표) | EventData `IpAddress` → `SourceAddress` → … |
| IIS | `cs-username` | `c-ip` |
| MSSQL | `Login failed for user '...'` | `[CLIENT: ...]` |
| SSH (syslog/journald) | `Failed password for (invalid user) X` | `from X` |

- 의미 없는 값은 버립니다: `-`, `N/A`, `S-1-0-0`, `$` 로 끝나는 컴퓨터 계정, `::1`·`127.0.0.1`. `::ffff:` 접두사는 뗍니다.
- Windows 에이전트(Fluent Bit 4.0)는 EventData 를 이름 없이 `StringInserts` 배열로만 보냅니다. 서버가 알려진 이벤트(`normalizers/win_templates.py` — 로그온·계정·그룹·서비스·예약 작업·Kerberos·PowerShell 4104 등)에 이름을 붙여 `raw.winevtlog.EventData` 에 덧붙입니다(ADR-038).
  - 검색·규칙은 `f.EventData.LogonType` 처럼 이름으로 씁니다 — 에이전트가 이름을 보내면 그 값, 아니면 서버가 붙인 값. 템플릿이 없는 이벤트는 `f.StringInserts.N`(0부터).

### 3.3 데이터 모델 (`server/migrations/`)

| 테이블 | 용도 | 핵심 |
|---|---|---|
| `events` | 로그 이벤트 | `received_at` 월별 RANGE 파티션 (`events_YYYY_MM`), PK `(id, received_at)` |
| `agents` | 로그 보낸 PC 목록 | `last_seen` 으로 상태 판정, `meta` = 하트비트 내용 |
| `field_stats` | 원본 필드 카탈로그 | `(source, path)` 별 타입·횟수·예시. 중첩은 점 경로(3단계까지) |
| `iis_layouts` | IIS 열 순서 (014) | `(host, file)` 별 `#Fields:` 이름들, 폴더(`dir`)·마지막 머리줄 시각. 이벤트와 같은 트랜잭션에 저장, 35일 지난 것은 정리(폴더마다 최신 1개는 남김) |
| `audit_log` | 시스템 감사 기록 | 대시보드·알림 설정 저장, 알림 테스트 발송, 보관기간 만료 삭제 |
| `alerts` | 발생한 알림 (002) | 규칙, 심각도, 대상(group_key), 건수, `payload` = 보낸 메시지 전체. 처리 상태 `status`(open/acked/resolved)·처리자·처리 시각, 무음 중 발생이면 `silence_id` (009) |
| `alert_deliveries` | 알림 대상별 전송 상태 (002) | `pending/sent/failed/gave_up/skipped`, 시도 횟수, 마지막 오류(건너뛴 사유: 받을 최소 수준·무음) |
| `alert_notes` | 알림 처리 기록 (009) | 확인·해결·다시 열기·메모 타임라인. **수정·삭제 불가 트리거**(알림이 보관기간 만료로 지워질 때만 함께 삭제) |
| `alert_silences` | 알림 무음 (009) | 규칙·대상(NULL = 전체)·시작·끝·사유·만든 사람. 해제는 행을 지우지 않고 끝 시각만 앞당김 |
| `reports` | 점검 보고서 (011) | 일간·주간·기간·`payload`(내용 전체)·점검 필요 수·전송 결과·점검 확인. **내용·기간 수정, 삭제·TRUNCATE 불가 트리거**(확인은 한 번만, 보관기간 만료 정리만 삭제) |
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
| `query` | `event_id:4625 -user:svc_backup "잘못된 암호"` | **검색 문장** (§4.1). 위 파라미터와 AND. 잘못되면 400 + `query_error{code, start, end, message}` |

| 엔드포인트 | 설명 |
|---|---|
| `GET /api/events?limit=&cursor=` | 최신순 목록. `next_cursor` 로 다음 페이지 (keyset) |
| `GET /api/events/{id}` | 단건 + raw |
| `GET /api/stats/count?compare=true` | 건수 + 직전 같은 길이 기간 건수 |
| `GET /api/stats/timeseries?group=&buckets=&interval=&tz_offset=` | 시간 구간별 건수. group 상위 6개 + `__other__` (level 은 전부) |
| `GET /api/stats/top?field=&limit=` | 상위 값. field = 컬럼명 또는 `f.<경로>` |
| `GET /api/stats/summary` | PC 상태 수, 분당 수집량, 최근 24시간 알림 수(`alerts_24h`), 확인하지 않은 알림 수(`alerts_open`, 조회 범위 반영) |
| `GET /api/agents?since=` | PC 목록 + 기간 내 이벤트/오류/경고 수 + 상태 + `last_transport`(마지막 하트비트의 전송 방식: `tls`·`plain`·`web`=화면 포트로 보낸 옛 묶음). `transport{tls, ingest_plain}`. `silent_streams` = 늘 오던 로그가 끊긴 (PC, 소스, 채널) (B-37, 조회 범위 반영) |
| `GET /api/agents/problems?since=` | 수집 거절 장부·격리 레코드 목록 (관리자, B-40) |
| `GET /api/agents/quarantine/{id}` | 격리 레코드 원본 (관리자, 접속기록 `events.quarantine.view`) |
| `DELETE /api/agents/{host}` | 수집 PC 목록에서 삭제 (관리자, audit_log 기록, 이벤트는 보존) |
| `POST /api/agents/delete` | 여러 PC 를 목록에서 한 번에 삭제 `{hosts:[...]}` (최대 500, 관리자). 응답 `deleted`·`missing`·`still_online` |
| `GET /api/fields` | 필드 카탈로그 |
| `GET /api/live?<필터>` | SSE. `event: events` 로 배열 전송 (시간 필터 무시). 조건이 틀리면 스트림 전에 400 |
| `GET /api/search/parse?query=` | 검색 문장 해석만 (`terms`·정규형 `canonical`·모순 `never`). 데이터 조회 없음 — 실시간 화면이 오류 위치를 받는 데 쓴다 |
| `GET/PUT /api/dashboards/{name}` | 대시보드 JSON 읽기/저장 (저장은 audit_log 기록) |
| `GET /api/alerts?since=&rule=&severity=&host=&status=` | 알림 이력 (전송·처리 상태 포함) + `counts`(기간 안 처리 상태별 수). `status` = `open`·`acked`·`resolved`·`unresolved` |
| `GET /api/alerts?format=csv` | 알림 이력 CSV (처리 상태·처리자·처리 시각·무음·전송·처리 기록, 최대 1만 건 — 넘으면 마지막 줄·`X-WLM-Truncated`·감사로그에 표시). 수식 주입 방지 — 감사로그 `alerts.export` |
| `GET /api/alerts/{id}` | 알림 상세 (payload: 본문, 최근 이벤트 샘플, 처리 기록 `notes`, 무음 `silence`, 같은 규칙·대상의 해결 안 된 다른 알림 수 `related_unresolved`) |
| `POST /api/alerts/handle` | `{ids, action, note, with_related?}` 확인(`ack`, 볼 수 있으면 누구나)·해결(`resolve`)·다시 열기(`reopen`: 확인함·해결됨 → 처리 안 됨, `alerts.handle`). 최대 1000건(`with_related` 면 같은 규칙·대상 전부), 결과 `changed/unchanged/missing` |
| `POST /api/alerts/{id}/notes` | `{text}` 메모 (볼 수 있으면 누구나, 고칠 수 없음) |
| `GET /api/alerts/silences?since=` | 무음 목록 (적용 중·예정 + 기간 안에 끝난 것, 보내지 않은 알림 수) |
| `POST /api/alerts/silences` · `DELETE /api/alerts/silences/{id}` | 무음 걸기(`{rule?, group_key?, starts_at?, ends_at? 또는 duration_sec, reason}`, 끝 시각은 지금부터 30일 안) · 일찍 해제 — `alerts.handle` |
| `GET /api/alerts/config` | 엔진 상태, 규칙(최근 발생 포함), 알림 대상(비밀값 제외), 원본 YAML |
| `PUT /api/alerts/config` | 본문 = YAML. 검증 실패 시 422 + 오류 내용, 파일은 그대로 (저장은 audit_log 기록) |
| `POST /api/alerts/test/{notifier}` | 알림 대상 연결 테스트 (audit_log 기록) |
| `POST /api/settings/webhook-preview` | `{format, severity?}` 웹훅 형식별 예시 본문·헤더 (보내지 않음) — `settings.manage` |
| `GET /api/reports` · `GET /api/reports/{id}` | 점검 보고서 목록(확인 안 한 수, 일정) · 상세(내용·요약·내용 해시) — `reports.view`, 조회 범위 없는 사용자만 |
| `GET /api/reports/{id}/html` | 메일과 같은 보고서 문서 (화면 iframe·인쇄용, CSP 로 스크립트 차단) — `reports.view` |
| `POST /api/reports` · `POST /api/reports/{id}/review` | 지금 만들기 `{kind: daily|weekly}`(보내지 않음) · 점검 확인 `{note}`(한 번만) — `reports.view` |
| `POST /api/reports/{id}/send` | 설정된 받는 곳 중 아직 못 받은 곳으로 보내기, `{all: true}` 면 모두 (이미 모두 받았으면 409) — `settings.manage` |
| `GET/PUT /api/settings/report` | 점검 보고서 일정·받는 곳 — `settings.manage` |
| `PUT /api/alerts/rules` | 규칙 한 개 추가·수정 (`{original?, rule}`), 그 규칙 블록만 바꿈 — `alerts.manage` |
| `DELETE /api/alerts/rules/{이름}` · `POST /api/alerts/rules/enabled` | 삭제 · 켜기/끄기 (`{names, enabled}`, 묶음 단위 가능) — `alerts.manage` |
| `POST /api/alerts/rules/preview` | 최근 N시간 데이터로 규칙 미리보기 (맞는 로그·예상 알림·대상별) — `alerts.manage` |
| `GET /api/agents/package?os=&server=&port=&iis=&mssql=&name=` | 에이전트 설치 묶음 zip (설정·API 키·Fluent Bit 포함, TLS 면 `ca.crt`·인증서 이름 `name`·CA 지문, 포트 6977 — 확인할 수 없는 CA·만료·없는 이름은 409/422) — `agents.deploy`, 감사로그 |
| `GET /api/agents/package/info` | 내려받기 창 정보 (기본 서버 주소·포트, 들어갈 설치 파일, `tls`: 인증서 이름·만료 D-n·CA 지문·문제) |
| `GET/POST /api/user-groups`, `PUT/DELETE /api/user-groups/{id}` | 사용자 그룹 (관리자) |
| `GET /api/meta`, `GET /healthz` | 메타 정보(소스·분류 목록 등), 상태 확인 |

- **시간 상한:** 위 조회(GET `/api/events`·`/api/stats/*`·`/api/agents`·`/api/fields` 등)와 규칙 미리보기는 쿼리 하나가 `WLM_SEARCH_TIMEOUT_SEC`(기본 30초)를 넘으면 멈추고 **503** + 그 화면에서 할 수 있는 방법을 돌려줍니다. 한꺼번에 6개 연결까지만 쓰고(나머지는 수집·알림 몫), 자리를 못 얻어도 같은 시간 뒤 503 입니다. 쓰기(PC 삭제)·알림 엔진·점검 보고서·수집에는 상한이 없습니다(ADR-035). 끝나지 않은 검색도 접속기록에 `timeout_sec` 과 함께 남습니다.

OpenAPI 문서는 `http://<서버>:8080/docs` 에 있습니다.

### 4.1 검색 문장 (`query`, BACKLOG B-01, ADR-033)

한 줄로 조건을 씁니다. 이벤트 검색·실시간 화면, API, 알림 규칙 `match.query`, 대시보드 위젯 `"query": {"query": "…"}` 가 모두 같은 문법입니다.

```
event_id:4625 ip:10.0.0.5 -user:svc_backup level:오류,심각 "잘못된 암호"
```

| 쓰기 | 뜻 |
|---|---|
| 띄어쓰기 | 그리고(AND) — 순서 상관없음 |
| `키:a,b` | 그 키가 a 또는 b |
| `-키:a` · `-단어` · `-"구절"` | 제외. **값이 없는 이벤트는 남습니다** (`-user:svc_backup` 은 사용자가 없는 로그를 지우지 않음) |
| `단어` · `"구절"` | 메시지 부분일치 (대소문자 무시). 단어 여러 개는 모두 포함 |
| `msg:a,b` | 메시지에 a 또는 b (예전 `q=a\|b`) |
| `"…"` 안의 `"` | `""` 로 두 번. 스마트 따옴표 `“ ”` 도 따옴표 |

| 키 | 대상 | 값 |
|---|---|---|
| `host` `channel` `provider` `source` | 같은 컬럼 | 정확히 일치 (대소문자 구분) |
| `user` / `ip` | `username` / `src_ip` | 정확히 일치. IP 대역(`/`)은 아직 없음 |
| `category` | 분류 | 코드 13개 (`security`… 대소문자 무시). 한글 이름은 오류 + 힌트 |
| `level` | 수준 | `심각 오류 경고 정보 상세`, `critical error warning info verbose`, `1`~`5` |
| `event_id` | 이벤트 ID | 0 이상 정수 |
| `msg` | 메시지 | 부분일치 (위) |
| `f.<경로>` | 원본 JSON `raw #>> 경로` | 글자로 비교 (숫자 4625 와 문자열 "4625" 모두 맞음). 배열 위치는 `0, 1, 2`. `f.EventData.X` 는 에이전트가 보낸 값, 없으면 서버가 붙인 `winevtlog.EventData.X` (ADR-038) |

- 같은 키를 포함으로 여러 번 쓰면 교집합입니다(`host:A,B host:B` = `host:B`). 겹치지 않으면(`host:A host:B`) 결과 0건이고 화면이 알려 줍니다.
- `키처럼 생긴 이름:` 은 키여야 합니다 — 오타(`hots:A`)는 위치와 함께 오류로 알려 주고 '`host` 로 고치기'를 제안합니다. `C:\Windows`, `http://…`, `12:30`, `fe80::1` 처럼 키가 아닌 것은 그대로 메시지 단어입니다. `Error:` 같은 말은 따옴표로.
- 와일드카드(`*`)·괄호·`|`·`AND/OR/NOT`(대문자)은 아직 없어 오류로 알려 줍니다(나중에 넣어도 기존 문장의 뜻이 바뀌지 않게).
- 한도: 500자, 조건 30개, 조건당 값 50개, 값 200자, 원본 필드 조건 10개(URL 의 `f.` 와 합계), 메시지 단어 20개.
- 오류는 처음 하나를 `검색 문장 N번째 글자 '…': 이유` 로 알립니다(위치는 글자 단위).
- **같은 뜻이면 같은 SQL** 입니다(`host=A` ≡ `host:A`). 제외(`-`)·`-단어` 는 색인을 쓰지 못해, 제외만 있는 긴 기간 건수·시계열은 느릴 수 있습니다(PERFORMANCE.md §2.1).
- 링크 공유: 같은 문장 + 같은 구간이면 같은 결과입니다. 화면의 **링크 복사**는 지금 보고 있는 구간(절대 시각)으로 고정합니다. 받는 사람의 사용자 그룹 조회 범위가 더 좁으면 그 안의 결과만 보입니다.
- 접속기록(`events.search`)에 문장 원문이 그대로 남습니다.

## 5. UI

- **기술:** 순수 HTML/CSS/ES 모듈. 빌드, npm, 외부 CDN 없이 동작합니다(폐쇄망에서도 동작).
- **라우팅:** `#/dashboard/<이름>`, `#/live`, `#/events?<필터>`, `#/alerts`, `#/agents`, `#/fields?source=&path=`, `#/reports/<번호>`
  - 필터는 URL에 남기 때문에 주소를 공유하면 같은 화면이 열립니다.
- **필터 막대 (이벤트 검색·실시간):** 1행 = 검색 문장 칸(§4.1), 2행 = 기간·PC·분류·채널·수준 칩·링크 복사·초기화.
  - 문장이 조건의 정본입니다. 드롭다운·수준 칩은 문장을 보여 주고 고치는 창입니다(그 키의 조건이 값 하나면 그 값, 아니면 '문장 조건').
  - 입력 중에 바로 해석해 `해석: …` 또는 틀린 곳(강조·빠른 고침)을 보여 주고, Enter·포커스 이동 때 확정합니다. 틀린 문장은 검색하지 않습니다.
  - [?] 도움말(키 표·예문), 자동완성(키·수준·분류·PC·채널·소스, 이미 받아 둔 목록만), `/` 로 문장 칸으로 이동.
  - 옛 링크(`host=…&q=a|b&f.X=1`)는 들어올 때 문장으로 접습니다. 뜻이 똑같이 옮겨지지 않는 값(`level=7` 등)은 칩으로 남고 서버가 그대로 적용합니다.
  - 상세 패널: 검색 화면에서 열면 값마다 [이 값만]·[＋ 좁히기]·[－ 제외]로 지금 문장을 고칩니다.
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
`query` 안에 `"query": "event_id:4625 -user:svc_backup"` 로 검색 문장(§4.1)을 쓸 수 있고 다른 조건과 AND 입니다. 저장할 때 문장을 확인합니다(틀리면 422 + 위치).

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
config/alerts.yaml ──(변경 감지, 자동 반영)──▶ 엔진 (interval_sec 마다, advisory lock 727_003 으로 1곳에서만)
  규칙 평가: events(received_at ≥ now - window, match) GROUP BY group_by HAVING count ≥ threshold
    (규칙마다 쿼리 시간 상한 WLM_ALERT_RULE_TIMEOUT_SEC, 넘기면 그 규칙만 '시간 초과' — ADR-045)
    → cooldown 확인 → alerts + alert_deliveries(pending) 기록 → 전송기를 깨움 (엔진은 보내지 않는다)
    (무음 중이면 alerts 는 기록하고 alert_deliveries 는 skipped — 보내지 않음)
전송기 (alerts/dispatcher.py, advisory lock 727_004): 보낼 차례인 행을 하나씩 잡아(claimed_at) 보냄
  받는 곳마다 한 줄씩·동시에 4곳까지·심각한 것부터. 실패 → failed (1분 → 5분 → 15분 → 1시간, 5회째 gave_up)
  받는 곳 자체가 안 되면(연결 실패·시간 초과·5xx·429) 그 곳의 다른 대기 알림도 이번엔 실패로 넘김
  보내는 중 서버가 멈추면 다음 시작 때 다시 보냄(두 번 갈 수 있음), 하루가 지난 대기 알림은 보내지 않음
처리: open(처리 안 됨) → acked(확인함) → resolved(해결됨) ⇄ 다시 열기. 기록은 alert_notes (ADR-029)
  해결됨 뒤 새 이벤트(해결 시각 뒤 수신)면 재알림 간격과 상관없이 다시 알림(재발). 확인함은 간격 유지 (B-35)
  다시 알릴 때 '지난 알림 이후 이 대상에서 n건', 발생 시각이 창보다 한참 이른 이벤트가 섞이면 '지연 수신분 포함'
설정 판본: 바뀐 설정을 적용할 때마다 alert_config_versions + 감사로그 alerts.config.apply (ADR-043)
  탐지를 약하게 하는 변경·넓은 무음 → 내장 규칙 '알림 설정 변경' 으로 바뀌기 전 받는 곳에 (무음으로 막을 수 없음)
```

### 6.0 설정 판본과 탐지 약화 알림 (ADR-043)

- **판본:** 화면 저장(`ui`), 서버에서 파일 직접 수정(`file`, 다음 평가 주기에 알아챔), 서버가 꺼져 있는 동안의 수정(`startup`)을 모두
  `alert_config_versions` 에 남깁니다(내용·해시·직전 판본과의 차이). 고치거나 지울 수 없고, 감사로그 보관기간이 지나면 정리하되 마지막 판본은 남깁니다.
  감사로그 화면 '알림 설정 변경(판본)'에서 봅니다.
- **약해지는 변경:** 규칙 삭제·끔, 건수 기준↑, 집계 기간↓, 심각도↓, 받는 곳 뺌, 조건·묶음 기준 바꿈, 서로 다른 값 조건 추가·기준↑, 재알림 간격↑,
  끊김 판정 시간↑·대상 PC 바꿈, 평가 주기↑. 확신할 수 없는 변경은 약해진 것으로 봅니다. 꺼져 있던 규칙의 변경은 아닙니다.
- **알림:** 내장 규칙 '알림 설정 변경'(대상 = 방법·누가). 받는 곳은 바뀌기 전 설정에서 그 규칙들의 받는 곳, 심각도는 그 규칙들 중 가장 높은 것.
  넓은 무음(모든 규칙·모든 대상, 또는 24시간 초과)과 깨진 설정 파일도 같은 알림입니다. 이 알림은 무음이 걸려 있어도 보냅니다.
- **다시 켠 규칙:** 다시 켜거나 다시 추가한 규칙은 마지막으로 켜져 있던 판본과 비교합니다(끄고 → 고치고 → 켜는 우회). 무음이 걸린 이름으로 바꾸는 것도 약화입니다.
- **넓은 무음의 길이:** 같거나 더 넓은 범위의 무음과 이어 붙인 구간으로 잽니다(24시간씩 이어 붙여도 넓은 무음).
- **관리 작업 알림 (B-36 2단계):** 규칙·대체 경로가 쓰는 받는 곳을 약하게 하는 저장(받는 사람 빠짐·연동 끔·최소 수준 올림·보내는 곳 바뀜), 관리자 계정 생성·관리자로 바꿈,
  사용자 그룹에 관리 권한 부여, 보관 파일 복원은 내장 규칙 '관리 작업 알림'(무음 불가)으로 대체 경로와 다른 받는 곳에 알립니다(약해진 그 곳은 빼고).
  점검 보고서에 '관리 작업 요약'.
- **깨진 파일:** 실행 중이면 이전 설정을 유지합니다. 깨졌거나 없는 채로 서버가 시작되면 마지막 판본으로 감시를 계속하고 화면에 판본 번호를 보입니다.
  그동안 규칙 하나만 고치는 저장은 409 — '고급 편집'에서 설정 전체를 저장해 고칩니다. UTF-8 이 아닌 파일도 깨진 파일입니다.

### 6.1 규칙 (`config/alerts.yaml` 의 `rules`)

| 키 | 기본 | 설명 |
|---|---|---|
| `name` | (필수) | 규칙 이름. 고유해야 하고, 쿨다운 기준이 됩니다. 이름을 바꾸면 새 규칙으로 취급합니다 |
| `kind` | `count` | `count`: 이벤트 수 기준 / `agent_silent`: PC 수신 끊김 |
| `match` | `{}` | 검색 조건과 같은 키: `host, channel, provider, source, category, user, ip, level, event_id, q, f.<경로>`, `query`(검색 문장 §4.1, 문자열만 — YAML 에서는 작은따옴표로 감싸기) |
| `window` | `5m` | 최근 이 시간 동안 **수신된** 이벤트를 셉니다 (늦게 도착한 오류도 알림) |
| `threshold` | `1` | 이 건수 이상이면 알림 |
| `group_by` | `host` | 이 값마다 따로 세고 따로 알림. `ip`(공격 출발지별), `user`(계정별)도 가능. `none` 이면 전체 합산 |
| `distinct` | 없음 | `{ field: user, min: 10 }` — 묶음마다 그 필드의 **서로 다른 값**이 `min` 개 이상일 때만(건수 기준과 함께). 패스워드 스프레이(IP 마다 서로 다른 계정), 한 계정의 여러 PC 접속. `field` 는 `group_by` 와 같은 키·`f.<경로>`, `min` ≥ 2, `window` ≤ 1d. 값이 없는(NULL) 이벤트는 세지 않음. 알림 본문에 앞의 값 10개 (ADR-041) |
| `cooldown` | `30m` | 같은 규칙과 같은 대상은 이 시간 안에 다시 알리지 않습니다. `window` 보다 짧으면 `window` 로 맞춥니다 |
| `severity` | `warning` | `critical / error / warning / info` |
| `notify` | (필수) | 알림 대상 이름 목록 |
| `sid` | 자동 | 규칙 번호 (Snort 의 sid 처럼 고유, 100만 번대). 화면에서 만들면 다음 번호를 붙입니다 |
| `group` | `기타` | 규칙 묶음 (규칙 관리 화면 왼쪽 목록, 묶음 단위 켜기/끄기) |
| `tags` | `[]` | 분류 태그. 기본 규칙은 `MITRE T1110`, `ISMS 2.11.3` 처럼 공격 기법·ISMS 항목을 적습니다. 메시지와 화면에 표시 |
| `silent_for`, `hosts` | `10m`, 전체 | (`agent_silent`) 끊김 판정 시간, 대상 PC 목록 |
| `resolve` | `count` 는 `manual`, `agent_silent` 는 `auto` | `auto` 면 조건이 풀릴 때(집계 기간의 건수가 기준 아래 / PC 가 다시 들어옴) '해결됨(자동)'으로 바꾸고 그 알림을 받은 곳에 해소 통지. 건수 규칙은 마지막 알림 뒤 max(집계 기간, 5분)이 지나야 보고, PC 마다 세는 규칙은 그 PC 가 살아 있어야 함(꺼진 PC 는 회복이 아님). 사람이 다시 연 알림은 자동으로 해결하지 않음. `distinct` 규칙은 불가. 한 번 나는 이벤트·보안 규칙은 `manual` (B-35 2단계, ADR-029 보완) |

**기본 규칙 팩 (23개):** 시스템 심각 오류, 서비스 비정상 종료, 응용 프로그램 오류 다발, 서버 응답 없음,
로그온 실패 급증, 무차별 대입(출발지 IP 기준), 원격 데스크톱 무차별 대입(LogonType 10), **패스워드 스프레이·없는 계정으로 로그온 시도·한 계정이 여러 서버에 원격 데스크톱(서로 다른 값 수)**, 계정 잠금, 관리자 그룹 구성원 추가,
새 사용자 계정, 새 서비스 설치, 예약 작업 생성, 보안 감사 로그 삭제, 감사 정책 변경, 의심스러운 PowerShell, 백신 악성 코드 탐지,
웹 서버 오류 급증, SQL Server 로그인 실패 급증, SQL Server 심각 오류, Linux SSH 무차별 대입.
- 일부 규칙은 Windows 감사 정책(로그온·계정 관리·프로세스·PowerShell 스크립트 블록 로깅)이 켜져 있어야 동작합니다(ISMS.md).

- `agent_silent` 는 한 번 끊긴 동안 한 번만 알립니다. 다시 수신됐다가 또 끊기면 다시 알립니다. 다시 들어오면 자동으로 해결합니다(`resolve: manual` 로 끔).
- 기본 팩에서 자동 해결은 응용 프로그램 오류 다발·웹 서버 오류 급증과 서버 응답 없음뿐입니다. 서비스 비정상 종료는 한 번 나는 이벤트라 조용해져도 고쳐진 것이 아니어서 사람이 해결합니다.
- 해소 통지는 받은 곳에만 보내고, 보낼 때 다시 봅니다: 그 사이 다시 열렸거나·같은 대상에 새 알림이 났거나·그 곳에 알림이 전해지지 않았으면 건너뜁니다. 무음 중이거나 알림이 7일보다 오래면 해결만 합니다.
- `hosts` 를 비우면 퇴근 시 꺼지는 PC까지 알림이 가므로, 서버 목록을 지정합니다.

### 6.2 알림 대상 — 환경설정 화면에서 관리 (§8)

- 규칙의 `notify` 에는 **수신 그룹 이름** 또는 **외부 연동 이름**을 씁니다. 이 이름들은 DB 에서 관리합니다.
  - 수신 그룹 → 그룹 안에서 '알림 받음'이고 이메일이 있는 수신자 전원에게 메일 한 통
  - 외부 연동(웹훅) → HTTP POST. 보내는 형식(아래 표)으로 Slack·Teams·두레이·잔디가 바로 보여 줄 수 있게 바꿉니다
  - 외부 연동(Oracle) → 설정한 SQL 한 문장 실행
- 규칙을 저장할 때 없는 이름이 있으면 거부합니다(422). 규칙에서 쓰는 그룹·연동은 삭제하거나 이름을 바꿀 수 없습니다.
- 대상은 엔진이 매 주기 DB 에서 다시 만듭니다. 화면에서 바꾸면 다음 평가부터 바로 반영됩니다.
- **받을 최소 수준(min_severity):** 그룹·연동마다 정합니다.
  - 정보(전부) / 경고 이상 / 오류 이상 / 심각만
  - 기준보다 낮은 알림은 보내지 않고, 전송 이력에 `skipped`(건너뜀)로 남깁니다.
  - 예: 운영팀은 경고 이상, 임원 보고용 메신저는 심각만, 사내 DB 는 전부.
- `config/alerts.yaml` 에 예전 형식의 `notifiers:` 가 있으면 설정 오류로 알려 줍니다(화면으로 옮기라는 안내).

**웹훅 보내는 형식 (메신저 프리셋, `app/alerts/messenger.py`, ADR-030):**

| 형식 | 받는 곳 | 본문 | 주소 | 같은 주소 간격 |
|---|---|---|---|---|
| `json` | 사내 시스템 | `{"source", "title", "text", "dedup_key", "event_action", "alert": {...}}` | http·https | – |
| `text` | Mattermost·Rocket.Chat 등 | `{"text": "..."}` | http·https | – |
| `slack` | Slack 'Incoming Webhooks' 앱 | 머리글 블록 + 심각도 색 막대 첨부 안의 Block Kit(요약·설명·항목·최근 이벤트·글자 링크) | https (`hooks.slack.com/services/…`) | 1초 |
| `teams` | Teams 워크플로 웹훅 | Adaptive Card 1.4 (머리 영역 색 = 심각도 스타일, 항목표, 최근 이벤트, '자세히 보기' 버튼) | https (`*.environment.api.powerplatform.com`) | 0.3초 |
| `dooray` | 두레이 메신저 Incoming | `{"botName", "text", "attachments"}` — 서식 없는 평문, 링크는 첨부 제목 | https (`hook.dooray.com` 등) | 1.1초 |
| `jandi` | 잔디 Incoming | `{"body", "connectColor", "connectInfo"}` + `Accept: application/vnd.tosslab.jandi-v2+json` | https (`wh.jandi.com`) | 1초 |

- 주소를 붙여 넣으면 화면이 형식을 골라 줍니다. 종료된 주소(Office 365 커넥터 `webhook.office.com`, 옛 `logic.azure.com`, Slack 워크플로 빌더 `hooks.slack.com/triggers/`)는 경고합니다.
- **예시 미리보기:** 형식마다 실제로 보낼 본문과 함께 보내는 헤더를 보여 줍니다(보내지 않음).
- 클라우드 메신저 4종은 **https 주소만** 받습니다(http 로도 받아 버려 주소의 토큰이 평문으로 나가므로). 같은 서버 안 중계(127.0.0.1)만 예외.
- **같은 주소로는 간격을 두고 차례로** 보냅니다. 두레이는 1초에 1건을 넘으면 성공(200)을 주고도 버립니다. 기다리다 전송 시간 제한(30초)에 걸리면 다음 재시도에서 보냅니다.
- 받는 쪽 오류 본문에 주소의 토큰이 섞여 오면(두레이) 가린 뒤 전송 이력·화면에 남깁니다. 그 밖의 전송 오류 문구(주소 형식 오류 등)도 같이 가립니다.
- **넘김(30x)을 따라가지 않습니다.** 따라가면 POST 가 본문 없는 GET 으로 바뀌어 '전송됨'이 되고 인증 헤더가 다른 호스트로 갑니다. 넘기면 '웹훅 응답 302 — 다른 주소로 넘기려 합니다' 로 실패 처리합니다.
- 메신저 호스트(`hooks.slack.com`·`hook.dooray.com` 등)는 형식을 json·text 로 골라도 https 만 받습니다. 주소에 공백·줄바꿈이 섞이면 저장하지 않습니다.
- 대상(group_key)은 로그에서 온 값이라 길이 제한이 없어서, 제목 200자·요약·설명 1,000자·항목 값 300자로 자르고 2,000자가 넘는 검색 링크는 알림 화면 링크로 바꿉니다(Teams 28KB 초과 시 '접수됨'인데 게시 실패).
- 로그에서 온 값(대상 이름, 설명, 이벤트 메시지)은 서비스별 서식 문자를 무력화합니다 — Slack `& < >` 엔티티, Teams·잔디·두레이 마크다운 링크.
- **해소 통지 (B-35 2단계):** 자동 해결된 알림을 받았던 곳에 `[해소] [오류] 규칙 · 대상` 제목, 초록 막대(Teams 는 good 스타일), 발생→해결 시각으로 보냅니다(최근 이벤트 없음).
  `dedup_key` 는 같은 규칙·대상이면 같은 값(SHA-256 앞 32자), `event_action` 은 `trigger`·`resolve` — 사내 사고관리·SMS 가 알림으로 연 것을 해소로 닫게.
  Oracle 은 바인드 `:dedup_key`·`:event_action` 을 쓸 수 있고, **SQL 에 `:event_action` 이 있을 때만** 해소를 보냅니다(기본 INSERT 는 받지 않음, `docs/oracle_alerts.sql`).
- 심각도 색은 메일과 같은 표(`message.SEVERITY_COLORS`)를 씁니다. Teams 는 임의 색을 받지 않아 스타일(심각·오류 = attention, 경고 = warning, 정보 = accent)로 나타냅니다.

### 6.3 메시지

모든 대상이 같은 내용을 씁니다(`app/alerts/message.py`).

- **제목:** `[경고] 로그온 실패 급증 · DC-01`
- **본문:** 요약, 설명, 발생 시각(`WLM_DISPLAY_TZ`, 기본 Asia/Seoul), 최근 이벤트 5건, `WLM_PUBLIC_URL` 기준 검색 링크
- **웹훅:** 형식별 본문은 §6.2 표. 형식별 실제 본문은 `server/tests/snapshots/webhook_<형식>.json` 에 있습니다.

### 6.0b 알림 기능 상태 (ADR-045)

- **상태 판단(`alerts/health.py`) 한 곳**을 알림 화면 상태 띠·규칙 '평가' 칸·알림 대상 줄, `GET /healthz/alerts`, 점검 보고서 '점검 필요'가 같이 씁니다.
  - 나쁨(알림 멈춤): 평가가 max(3×주기, 2×규칙 상한+30초, 120초) 넘게 나아가지 않음, 전송기 멈춤·꺼짐, 규칙이 쓰는 모든 받는 곳이 15분 넘게 실패.
  - 확인 필요: 평가 한 바퀴가 주기보다 김, 보낼 알림이 5분 넘게 밀림, 받는 곳 실패 중, 24시간 안 재시도 중단, 규칙 오류·시간 초과·일부만(기준을 넘은 묶음 100개 초과)·느림·평가 공백.
- **`GET /healthz/alerts`**: 로그인 없음(사내 감시 도구용), 수와 코드만(이름·오류 문구 없음), 10초 캐시. `down` 이면 503, `?strict=1` 이면 `warn` 도 503. 수집 포트에서는 404. `/healthz` 는 그대로 DB 만 봅니다(Docker HEALTHCHECK 가 메일 서버 문제로 흔들리지 않게).
- 규칙 상태는 메모리라 서버를 다시 시작하면 한 주기 동안 '평가 전'입니다. 아침 점검 보고서가 오지 않는 것도 신호입니다(보고서는 자기 경로로 보냅니다).
- **감시와 내장 알림 (2단계):** 30초마다 평가가 멈췄으면 평가 작업을 다시 시작하고 '알림 엔진 멈춤'(심각), 받는 곳이 15분 넘게 실패하면 '알림 전송 실패'(그 곳을 뺀
  받는 곳으로), 규칙이 세 번 잇달아 실패하면 '알림 규칙 동작 안 함'. 전송기가 멈추면 다시 시작만 합니다. 받는 곳은 `settings.fallback_notify`(alerts.yaml),
  비우면 점검 보고서 받는 곳. 같은 문제는 한 시간에 한 번. 무음으로 막을 수 있습니다(예정된 메일 서버 점검). 감사로그 `alerts.health.*`.
- **정기 시험 전송 (B-34):** 매주 `WLM_ALERT_TEST_WEEKDAY`(기본 1=월, 0=안 함)·`WLM_ALERT_TEST_TIME`(기본 09:00, 표시 시간대) 뒤 첫 감시 때, 켜진 규칙과
  대체 경로가 쓰는 받는 곳마다 '정기 시험 알림'을 한 건 보냅니다(그 주에 화면의 테스트 발송·연동 시험·Oracle SQL 시험 실행을 했으면 건너뜀 — Oracle '연결 시험'은
  알림 SQL 을 실행하지 않아 세지 않음, 서버가 꺼져 있었으면 다음 감시 때). Oracle 은 실행만 해 보고 되돌립니다(알림 표에 시험 행이 쌓이지 않게, 키 중복은 성공).
  실패하면 1분 뒤 한 번 더 보내고, 그래도 실패하면 그 곳을 '보내지 못하는 중'으로 두어 15분 뒤 '알림 전송 실패'가 다른 곳으로 나갑니다. 마지막 시험이
  실패한 곳은 상태 띠·보고서에 '시험 전송 실패'(`test_failed`)로 남습니다(다시 시작해도, 그 뒤 실제 알림이 나가면 사라짐). 감사로그 `alerts.test.scheduled`.
- **Oracle 생존 신호 (B-34, 선택):** Oracle 연동에 '생존 신호 SQL'(바인드 `:at :status :version :problems`)을 넣으면 1분마다 실행합니다 — 서버 전체가 멈추면
  행이 갱신되지 않아 병원 DB 감시가 알아챕니다(표·MERGE 예시: `docs/oracle_alerts.sql`). 5분 넘게 쓰지 못하면 `heartbeat_failing`, 실패·회복은 감사로그
  `alerts.health.heartbeat_fail`·`heartbeat_ok`(바뀔 때만). 앞의 생존 신호가 끝나지 않았으면(응답 없는 Oracle) 새로 내지 않습니다.
- Oracle 호출(알림·시험·생존 신호)은 전용 스레드 넷에서 돕니다 — 응답 없는 Oracle 의 멈춘 호출이 쌓여도 로그인·메일·웹훅을 막지 않게.

### 6.4 화면 (`#/alerts`)

- 상태 띠: 알림 엔진 동작 중 / 확인 필요 / 알림 멈춤 (ADR-045 — 문제마다 한 줄), 마지막 평가·한 바퀴 시간·전송 대기·적용 중인 무음 수, 심각도별 수
- 규칙 관리의 '평가' 칸: 정상·느림·일부만·시간 초과·오류·멈춤·평가 전·꺼짐(마우스를 올리면 마지막 평가·걸린 시간·후보·알림 수), 오류면 규칙 이름 아래 빨간 줄. 규칙 탭은 15초마다 표를 다시 그리지 않고 이 칸만 바꿉니다.
- 알림 대상: 받는 곳마다 최근 전송 상태(정상·실패 중 몇 분째·대기 건수·마지막 오류). '테스트 발송'이 성공하면 그 곳의 실패분을 바로 다시 보냅니다.
- 탭 4개: **알림 이력**(`#/alerts?status=`) / **규칙 관리**(`#/alerts/rules`) / **알림 대상**(`#/alerts/targets`) / **무음**(`#/alerts/silences`)
- **알림 이력 (처리, ADR-029):**
  - 처리 상태 필터: 처리 안 됨 / 확인함 / 해결됨 / 전체 (각각 기간 안 건수). 기간은 24시간·7일·30일·1년·전체(보관기간 안 전부), 처리 안 됨·확인함은 기본이 '전체'입니다(사이드바 숫자와 같은 범위).
  - 행마다 처리 상태 칩(누가·언제는 칩에 마우스), 무음 중 발생이면 '무음' 칩, 메모 수.
  - 체크해서 **여러 건을 한 번에 확인·해결**(조치 내용 한 줄 함께 기록). 좁은 화면에서는 동작 막대가 화면 아래에 뜹니다.
  - **CSV 내려받기**: 처리 상태·처리자·처리 시각·처리 기록 포함 (사고 대응 증적).
- **알림 상세:** 앞 알림과의 관계(재발·지난 알림 이후 n건)·이 알림 뒤 같은 조건으로 더 들어온 건수와 마지막 시각(같은 대상의 가장 최근 알림일 때)·지연 수신 표시(B-35), 처리 상자(확인 / 해결… / 다시 열기… / 무음…), 처리 기록 타임라인(발생 → 확인 → 해결 → 메모), 메모 입력, 전송 상태, 포함 이벤트.
  - 다시 열기는 해결됨뿐 아니라 확인함에서도 됩니다(누구나 하는 '확인'으로 대기열에서 치운 알림을 담당자가 되돌림).
  - 해결할 때 같은 규칙·대상의 해결 안 된 다른 알림을 함께 해결할 수 있습니다(재발은 합치지 않고 발생마다 따로 기록).
  - 무음…: '이 규칙·이 대상' 또는 '이 규칙 전체', 1시간·4시간·하루·사흘, 사유(필수).
- **무음 탭:** 적용 중·예정·끝난 무음(범위, 기간, 사유, 보내지 않은 알림 수, 만든 사람·일찍 해제한 사람), '무음 추가'(규칙·대상·시작·끝을 정하는 점검 시간대 예약), 해제.
  - 무음 중에도 알림은 이력에 남고 전송만 건너뜁니다. 무음이 끝난 뒤 새 로그가 들어오면(문제가 계속되면) 재알림 간격을 기다리지 않고 다음 평가에서 다시 알립니다.
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
- 사이드바 '알림' 옆 숫자는 **확인하지 않은 알림 수**(조회 범위 반영)이고, 누르면 '처리 안 됨' 목록이 열립니다.

### 6.5 검증 기록 (2026-10-03, 개발 환경)

- **메일:** 15건이 발생했고, 첫 전송 실패 뒤 재시도로 전부 Mailpit에 도착했습니다.
- **웹훅:** 로컬 수신기로 json 수신을 확인했습니다.
- **메신저 형식 (2026-10-15):** Slack·Teams(워크플로)·두레이·잔디 공식 문서와 실제 응답(가짜 토큰으로 오류 응답만)으로 본문·헤더·제한을 확인하고, 형식별 본문 스냅샷과 로컬 수신기 시험(헤더·간격·토큰 가림)으로 고정했습니다.
  - **각 서비스의 실제 채널로 보내 보는 시험은 아직입니다(BACKLOG B-04).** 받는 쪽 화면(색 막대·카드·줄바꿈)은 실채널에서 한 번씩 확인해야 합니다.
- **점검 보고서 (2026-10-16):** 개발 서버에서 주간(기동 직후, 지난주분)·일간(09:00, 어제분) 보고서가 자동으로 만들어졌고, 수신 그룹 '운영팀'으로 보낸 메일이 Mailpit 에 도착(HTML·평문·보고서 링크), 화면 열람·점검 확인·휴대폰 폭을 확인했습니다.
- **Oracle:** `gvenzl/oracle-free:23-slim-faststart` 시험 컨테이너의 `LOGMON_ALERTS` 에 INSERT 했습니다.
  - CLOB 4000자 초과, 한글, 재전송 시 중복 무시를 확인했습니다.
  - 이 컨테이너는 시험에만 썼고 구성에는 넣지 않았습니다.
  - **사내 Oracle 버전과 계정 권한으로 다시 시험해야 합니다.**

### 6.6 정기 점검 보고서 (ISMS 2.9.5, ADR-032)

```
1분마다 (app/reports/scheduler.py, advisory lock 으로 1곳에서만)
  일간: 매일 09:00 이 지나면 어제(0~24시) / 주간: 월요일 09:00 이 지나면 지난주(월~일)   — 시간대 WLM_DISPLAY_TZ
  → 같은 기간 보고서가 없으면 만들기 (reports 고유 색인: 재시작·여러 대여도 한 번만)
  → 저장(내용 고칠 수 없음, 받는 곳은 '보내는 중'으로) + 감사로그 report.create(내용 해시)
  → 받는 곳으로 보내기(결과는 보고서 행에 덧붙임 + 감사로그 report.deliver)
  → 보내다가 서버가 멈췄으면 다음 주기에 '보내는 중'인 곳만 이어서 (하루가 지나면 실패로)
```

- **내용(`app/reports/builder.py`):** 맨 위 **점검 필요**(없으면 '특이 사항 없음') →
  - 로그 현황: 수준별 건수, **지난주 같은 요일(일간)·지난주(주간)** 대비, 시간·일별 추이(서머타임 날도 실제 시각·달력 날짜로 나눔), 오류가 많은 PC, 분류별
  - 보안 이벤트: 로그온 실패(계정·출발지 IP 상위), 계정 잠금, 계정 생성·삭제·변경, 보안 그룹 구성원 추가, 감사·시스템 로그 삭제, 감사 정책 변경, 서비스 설치, 예약 작업, SQL Server 로그인 실패
  - 알림 처리: 발생(심각도별), 처리 상태, 지금 해결 안 된 알림(심각한 것·오래된 것부터), 해결까지 걸린 시간(중앙값), 알림 설정 변경(판본)·넓은 무음(ADR-043)
  - 수집 PC(온라인·지연·연락 끊김 목록, 늘 오던 로그가 끊긴 채널, 수집 거절·격리), 로그 보관(파티션·보관 파일·마지막 무결성 확인), DB 백업·복구 시험
- **점검 필요가 되는 것:** 로그 0건(수집 멈춤), 지난주 같은 요일(주간은 지난주)보다 절반 이하 — 바로 전날과 비교하면 주말·휴일 다음마다 거짓 경고가 난다, 백업 문제, 로그 삭제(bad)·감사 정책 변경·보안 그룹 추가(warn), 해결 안 된 심각·오류 알림, 연락 끊긴 PC, 없는 보관 파일·무결성 문제, 탐지를 약하게 하는 알림 설정 변경·화면을 거치지 않은 설정 변경·넓은 무음(warn)·알림 설정 파일 오류(bad).
- **보내기:** 수신 그룹은 메일(HTML 전체 + 평문), 웹훅은 형식별 요약 몇 줄 + 보고서 링크(`#/reports/<번호>`). Oracle 연동은 보고서를 받지 않습니다. 받는 곳이 없어도 보고서는 만들어 저장합니다.
  - 보내기 준비(받는 곳·비밀값 불러오기, 렌더링)가 실패해도 받는 곳마다 '실패'와 사유를 남깁니다 — '보내지 않음'(받는 곳 없음)과 구별.
  - 다시 보내기는 기본으로 **아직 못 받은 곳만**(`{all: true}` 면 모두). 전송 기록은 덮어쓰지 않고 덧붙입니다(화면은 받는 곳마다 마지막 결과).
  - 보고서가 받는 곳으로 쓰는 수신 그룹·웹훅은 이름을 바꾸거나 지울 수 없습니다(알림 규칙이 쓰는 것과 같게). 없어진 받는 곳은 환경설정 '점검 보고서'에 경고로 보입니다.
- **화면 '점검 보고서'(`#/reports`, `reports.view`):** 이력(점검 필요 수·전송 결과·점검 확인), 열람(서버가 만든 메일과 같은 문서를 sandbox iframe 으로), **점검 확인**(무엇을 보았고 어떻게 조치했는지, 한 번만·고칠 수 없음), 인쇄용으로 열기(PDF 저장), 지금 만들기(어제·지난주, 보내지 않음), 설정된 받는 곳으로 보내기(`settings.manage`).
- **환경설정 '점검 보고서':** 일간 사용·시각, 주간 사용·요일·시각, 받는 곳(수신 그룹·웹훅).
- 보고서는 모든 PC·분류를 담으므로 조회 범위가 정해진 사용자는 `reports.view` 가 있어도 볼 수 없습니다.
- 보관기간(`WLM_REPORT_RETENTION_DAYS`, 기본 1095일)이 지나면 지우고 감사로그 `retention.purge_reports` 를 남깁니다.
- `WLM_REPORT_SCHEDULER=off` 면 정기 실행을 하지 않습니다(지금 만들기만). 여러 대 중 한 대만 돌리거나 테스트에서 씁니다.
- `WLM_DISPLAY_TZ` 이름이 틀리면(오타) 멈추지 않고 UTC 로 계산하며 기동 때 경고합니다(`config.display_zone()`, 알림·수집과 같은 규칙).
- 메일 링크(`#/reports/<번호>`)를 `reports.view` 가 없는 사용자가 열면 대시보드로 가고 '권한이 없습니다'를 알립니다.

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
| 세션 | 서버 세션(DB 에는 토큰의 SHA-256만), HttpOnly·SameSite=Strict 쿠키. https 요청이면 자동으로 Secure | `WLM_COOKIE_SECURE`(true = http 에서도 Secure 강제, http 로그인은 안내와 함께 거부) |
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
  - 로그인한 사용자 누구나: 볼 수 있는 알림의 확인·메모
  - 관리자 또는 해당 권한 그룹: 알림 규칙 관리(`alerts.manage`), 알림 처리(`alerts.handle`: 해결·다시 열기·무음), 대시보드 편집(`dashboards.edit`), 환경설정(`settings.manage`), 감사로그(`audit.view`), 점검 보고서(`reports.view`, 조회 범위 없는 사용자만), 에이전트 설치 묶음(`agents.deploy`)
  - 관리자만: 사용자·사용자 그룹 관리 (권한 상승 방지)
- **감사로그(audit_log):**
  - 기록 대상: 로그인 성공·실패·잠금·로그아웃·세션 만료, 비밀번호 변경, 사용자 관리, 이벤트 검색 조건·상세 조회, 모든 설정 변경, Oracle 쿼리 실행, 보관·삭제
  - DB 트리거로 **수정·삭제·TRUNCATE 를 막습니다**(보관기간 만료 삭제만 예외).
  - 화면 '감사 로그'에서 조회하고 CSV(엑셀 호환)로 내려받습니다. 내려받은 사실도 기록합니다.
  - **개인정보가 보이는 조회의 접속기록 (ADR-042):** 이벤트 상세(`events.view`)에는 누구의 기록을 봤는지(이벤트의 사용자·IP·분류), 사용자·IP·원본 필드의 상위 값 조회는 `events.stats`(같은 사람·같은 조건은 10분에 한 번)로 남깁니다.
  - 검색·상세·개인정보 상위 값·CSV 내려받기는 **접속기록을 남기지 못하면 결과를 내주지 않습니다**(503). CSV(감사로그·알림 이력)는 내려받는 사유를 받아 기록에 함께 남깁니다(없으면 400).
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
| 기능 권한 | `alerts.manage` 알림 규칙 관리 · `alerts.handle` 알림 처리(해결·다시 열기·무음) · `dashboards.edit` 대시보드 편집 · `settings.manage` 환경설정 · `audit.view` 감사 로그 · `reports.view` 점검 보고서 · `agents.deploy` 에이전트 설치 묶음 (`app/auth/groups.py` PERMISSIONS) |
| 조회 범위 | 분류(예: DB(MSSQL)) 와 PC 이름(쉼표, `MED-*` 처럼 `*` 사용, 대소문자 무시). 둘 다 정하면 '그 분류이면서 그 PC' |
| 여러 그룹 | 권한은 합치고, 범위는 합집합. 범위가 비어 있는 그룹에 속하거나 그룹이 없으면 전체 |
| 관리자 | 그룹과 상관없이 모든 권한·모든 로그 |

- **서버에서 적용:** 검색·통계(대시보드)·실시간 스트림·이벤트 상세·수집 PC 목록에 범위 조건을 붙입니다(`filters.Scope`, `repository.scope_clause`, `routers/query._filter`).
  - 알림 이력: 규칙의 분류 조건이 범위와 겹치거나, 대상(PC)이 범위의 PC 패턴에 맞는 알림만 보입니다(`app/alerts/visibility.py`). 처리·메모·상태별 수·사이드바 숫자도 같은 기준입니다.
  - 무음: 범위가 있는 사용자는 볼 수 있는 규칙·대상 한 개에만 무음을 걸고 풀 수 있습니다. 목록에는 자기 알림에 걸릴 수 있는 무음만 보입니다 — 모든 규칙·모든 대상, 내 PC 를 대상으로 한 무음, 내 분류의 규칙 무음. 넓은 무음의 '보내지 않은 알림 수'는 범위 밖 알림까지 센 숫자라 감춥니다.
  - 필드 탐색: 범위가 있는 사용자에게는 실제 값 예시를 숨깁니다.
- 화면: 메뉴·버튼은 `auth.can(권한)` 으로 보이거나 숨기고, 사이드바에 '볼 수 있는 범위'를 표시합니다. 서버도 같은 권한으로 막습니다(`deps.require_permission`).
- 감사로그: `user_group.save`(권한·범위·구성원 포함), `user_group.delete`.

## 8. 환경설정 화면 (관리자, `#/settings`)

| 탭 | 내용 |
|---|---|
| 수신자 | 이름·이메일·전화·부서·메모, 알림 받음 여부, 소속 그룹. 로그인 계정과 별개 |
| 수신 그룹 | 이름(규칙의 notify), 설명, 구성원, **받을 최소 수준**, 사용 중인 규칙 |
| 외부 연동 | 웹훅(주소·보내는 형식 json/text/Slack/Teams/두레이/잔디·헤더, 주소로 형식 자동 선택, 예시 미리보기), Oracle DB(아래). 받을 최소 수준, 사용 여부, 테스트 |
| 메일 서버 | SMTP 호스트·포트·보안(STARTTLS/SSL/없음)·계정·비밀번호·보내는 사람, 테스트 메일. 비워 두면 `.env` 의 `WLM_SMTP_*` |
| 로그 보관 | **DB 백업·복구 시험 상태**(마지막 백업·복구 시험, 경고), 로테이션 정책, DB 월 파티션·보관 파일 현황, 지금 실행, 무결성 확인, 다시 불러오기 (§9, §13) |

### 8.1 Oracle 연동

- **드라이버:** python-oracledb thin 모드 — Oracle Instant Client 설치가 필요 없습니다.
- **접속 방식 4가지 (`app/oracle.py`):**
  1. **TNS 이름:** `config/oracle/tnsnames.ora` 의 별칭. 파일 내용은 같은 화면에서 붙여 넣고 저장합니다.
  2. **호스트 + 포트 + SID**
  3. **호스트 + 포트 + 서비스 이름**
  4. **접속 문자열:** Easy Connect(`host:1521/service`) 또는 `(DESCRIPTION=...)`
- **연결 시험:** 저장 전에 입력값으로 접속해 DB 이름·서비스·스키마·버전을 보여 줍니다.
- **알림 SQL:** 알림이 생기면 실행할 한 문장입니다(기본: `LOGMON_ALERTS` INSERT, DDL 은 `docs/oracle_alerts.sql`).
  - 바인드: `:alert_id :rule_name :severity :host :event_count :window_sec :first_event_at :last_event_at :fired_at :title :message :link :detail_json :dedup_key :event_action`
  - `:event_action` 을 쓴 SQL 에만 해소 통지(`resolve`)를 보냅니다(B-35 2단계) — 기본 INSERT 에 그대로 보내면 같은 ALERT_ID 가 아래 중복 처리로 '성공'이 되어 해소가 남지 않습니다.
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
- **보관 파일 형식:** 한 줄에 이벤트 하나인 JSON(모든 컬럼 + 원본 raw)을 gzip 으로 압축합니다(형식 `wlm-events-jsonl-v2`).
  - v2 부터 공통 필드(`category`·`username`·`src_ip`)도 넣습니다. 옛 v1 파일을 복원하면 원본에서 다시 구해 채웁니다(`normalizers.derive_common`, 감사로그 detail 의 `common_fields_derived`).
  - `events` 의 열과 보관 파일의 열이 같은지 시험이 봅니다 — 열을 더하면 `archive.COLUMNS` 에도.
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
- **기록 종류별 보관기간 (ADR-040):** 알림 이력·처리 기록은 `WLM_ALERT_RETENTION_DAYS`(비우면 로그와 같음), 감사로그는 `WLM_AUDIT_RETENTION_DAYS`(기본 1095일 — 권한 부여·변경·말소 기록 3년), 점검 보고서는 `WLM_REPORT_RETENTION_DAYS`(기본 1095일) 동안 DB 에 둡니다.
  - 법정 최소(접속기록 1년, 권한 기록 3년)보다 짧게 정하면 기동 로그 경고, 로그 보관 화면의 빨간 줄, 점검 보고서 '점검 필요'로 알립니다. 진료정보(민감정보) 처리 시스템의 접속기록이면 `WLM_SENSITIVE_ACCESS_LOG=on` 으로 두면 경고 기준이 2년(730일)이 됩니다 — 보관기간 자체는 `WLM_RETENTION_DAYS` 로 정합니다.
  - 예전 형식(v1) 보관 파일을 복원하면 공통 필드와 함께 Windows 이벤트의 EventData 이름(ADR-038)도 다시 붙여, 복원한 달에서도 `f.EventData.*` 조건이 맞습니다.
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
  - 검색 문장은 같은 뜻이면 기존 검색과 SQL 이 같아 속도도 같습니다(PERFORMANCE.md §2.1). 2글자 이하 단어만으로 찾는 검색은 색인을 못 써 느리므로 화면이 따옴표를 권하고, 쿼리마다 시간 상한(§4)을 둡니다.
- 측정 도구: `tools/bench/bench.py` (별도 DB 사용)

## 11. 설정 (환경변수)

전체 목록은 `.env.example` 에 있습니다. 서버 설정은 모두 `WLM_` 접두사를 씁니다(`server/app/config.py`).

HTTPS·에이전트 TLS (ADR-036, AIRGAP.md §7.5):

| 변수 | 기본값 | 뜻 |
|---|---|---|
| `WLM_TLS` | `off` | `on`: 화면(8000→`WLM_PORT`)·TLS 수집(8002→`WLM_INGEST_TLS_PORT`)을 TLS 로. 그 밖의 값이면 기동 거부 |
| `WLM_TLS_CERT_FILE` / `_KEY_FILE` / `_CA_FILE` | `/app/tls/server.crt` · `server.key` · `ca.crt` | 서버 인증서(리프 먼저, 중간 포함) · 암호 없는 키(소유자 uid 10001, 0600) · 설치 묶음에 넣을 루트 CA |
| `WLM_INGEST_TLS_PORT` | `6977` | 호스트 쪽 TLS 수집 포트 (compose 게시, 설치 묶음 기본) |
| `WLM_INGEST_PLAIN` | `on` | `off` 면 평문 수집 리스너를 띄우지 않음 (TLS 가 꺼져 있으면 무시하고 오류 로그) |
| `WLM_INGEST_KEEPALIVE_SEC` | `75` | 수집 리스너 keep-alive. Fluent Bit 유휴 연결(30초)보다 길게 |
| `WLM_TRUSTED_PROXIES` | (빈 값) | X-Forwarded-For/Proto 를 믿을 프록시 IP·CIDR. 비우면 프록시 헤더를 보지 않음. `*`·/0·호스트 비트가 있는 대역(`10.0.0.5/24`)·IPv4 매핑 주소는 기동 거부 (환경변수 `FORWARDED_ALLOW_IPS` 는 영향 없음) |
| `WLM_HSTS_MAX_AGE` | (빈 값) | https 응답의 HSTS 초. 비우면 보내지 않음, `0` 이면 `max-age=0`(되돌릴 때 브라우저의 기억을 지움). includeSubDomains 없음 |
| `WLM_COOKIE_SECURE` | `false` | https 요청은 자동으로 Secure. true 면 http 에서도 강제하고 http 로그인은 400 |
| `WLM_SEARCH_TIMEOUT_SEC` | `30` | 화면 조회 쿼리 시간 상한 (ADR-035) |
| `WLM_ALERT_RULE_TIMEOUT_SEC` | `20` | 알림 규칙 쿼리 하나의 시간 상한. 넘기면 그 규칙만 '시간 초과', 다음 규칙은 평가 (ADR-045, 0 = 없음) |

보관기간 (§9, ADR-040):

| 변수 | 기본값 | 뜻 |
|---|---|---|
| `WLM_DB_RETENTION_DAYS` | `90` | DB 에서 바로 검색되는 기간. 지나면 압축 보관 파일로 |
| `WLM_RETENTION_DAYS` | `365` | 로그 전체 보관기간(보관 파일 포함). 접속기록 법정 최소 1년, 진료정보 처리 시스템이면 730 |
| `WLM_ALERT_RETENTION_DAYS` | (로그와 같음) | 알림 이력·처리 기록·끝난 무음 |
| `WLM_AUDIT_RETENTION_DAYS` | `1095` | 감사로그(이 시스템의 접속·권한 부여·변경·말소 기록). 법정 최소 3년 |
| `WLM_REPORT_RETENTION_DAYS` | `1095` | 점검 보고서(점검 증적) |
| `WLM_REPLICA` | `off` | `on`: 매일 백업 뒤 백업·보관 파일을 `WLM_REPLICA_DIR`(NAS 마운트)에 복제 (B-17) |
| `WLM_REPLICA_DIR` | `./replica` | 복제 대상 호스트 경로 (backup 서비스의 `/replica`) |
| `WLM_REPLICA_BACKUP_DAYS` | `35` | 복제한 DB 백업을 남길 날 수 |
| `WLM_SENSITIVE_ACCESS_LOG` | `off` | `on`: 진료정보(민감정보) 처리 시스템의 접속기록을 받는 설치 — 로그 보관 경고 기준이 2년(730일) |

## 12. 확장 가이드

| 하고 싶은 것 | 위치 |
|---|---|
| Windows 채널 추가 | 에이전트 `-Channels` 인자 (기본에 PowerShell/Operational, Defender, RDP 포함. Sysmon 등 추가) |
| IIS / SQL Server 로그 | 에이전트 설치 시 `-Iis` (W3SVC 폴더 자동 탐색, `-IisLogPath`), `-MssqlErrorlog` (`-MssqlErrorlogPath`). ERRORLOG 는 설정 0.4.0 부터 여러 줄을 묶어 보냄(`multiline_parsers` 의 `mssql_errorlog`, tail 은 `storage.type: filesystem` 필수 — `render_agent_configs` 가 검사) |
| 분류 추가 | `normalizers/categories.py` + `web/js/levels.js` + 기존 데이터 UPDATE 마이그레이션 |
| 새 로그 소스 | `server/app/normalizers/` + `BY_SOURCE` 등록 + 테스트 |
| 텍스트 로그 파일 | 에이전트 yaml 의 `tail` 예시 주석 해제 + `log_source: file`, `log_channel` |
| 위젯 / 화면 | `web/js/widgets/`, `web/js/views/` (AGENTS.md 참고) |
| 검색 백엔드 교체 | `server/app/repository.py` 만 재구현 (ADR-004) |
| 새 알림 대상 종류 (예: 문자, 메신저 전용 API) | `app/alerts/notifiers.py` 에 Notifier 클래스 → `channels.type` CHECK 제약(마이그레이션) → `targets.py` 의 `build_channel`·`_clean_channel_config` → 환경설정 화면 → 테스트 |
| 새 규칙 종류 | `app/alerts/rules.py` 의 `RULE_KINDS`·검증 + `engine.py` 의 `evaluate` 분기 |

## 13. 운영

- **포트:** 8080 화면(사용자·관리자), **6977 수집 전용 TLS**·6976 수집 전용 평문(에이전트), 8003 수집기 내부(게시 안 함). 방화벽에서 6977(전환 중엔 6976 도)은 모든 PC, 8080 은 관리 대역만 여는 것을 권장합니다.
- **HTTPS·에이전트 TLS (ADR-036):** `WLM_TLS=on` 이면 api 가 직접 TLS(1.2 이상, ECDHE+AEAD). 인증서는 `tls/`(server.crt·server.key·ca.crt), 만들기·갱신·확인은 `python -m app.cli tls-init|tls-renew|tls-status`, CA 개인키는 api 에 마운트하지 않는 `tls-ca/`.
  - 에이전트는 설치 묶음의 `ca.crt` 와 인증서 이름(DNS)으로 서버를 확인합니다(`tls.verify`·`tls.verify_hostname` — 끌 수 없음).
  - 수집 PC 화면의 '연결' 칸(하트비트 기준 TLS·평문·평문(화면 포트))으로 남은 평문 PC 를 보고, 0 이 되면 `WLM_INGEST_PLAIN=off` 로 평문 리스너를 띄우지 않습니다. '평문(화면 포트)' 는 TLS 를 켜면 끊기는 옛 묶음입니다.
  - 인증서 확인(`tls-status`, 설치 묶음)은 에이전트와 같은 OpenSSL 로 실제 핸드셰이크를 해 봅니다 — 에이전트가 믿지 않을 인증서로는 묶음을 만들지 않습니다.
  - 인증서 만료 30일 전부터 서버 로그에 매일 경고. 인증서 파일 교체는 `restart api`, `.env` 변경은 `up -d api`.
  - 리버스 프록시를 앞에 두면 `WLM_TRUSTED_PROXIES` 에 그 IP 만 — X-Forwarded-For/Proto 를 믿는 범위 (`*`·/0 은 기동 거부). 절차: [AIRGAP.md](AIRGAP.md) §7.5
- **에이전트 배포:** 화면 '수집 PC > 에이전트 설치' 에서 서버 주소·포트·API 키·Fluent Bit 이 들어간 설치 묶음(zip)을 받아 배포합니다(`routers/agentpkg.py`). PC 가 폐쇄망이어도 됩니다.
- **폐쇄망 배포·업그레이드·되돌리기:** [AIRGAP.md](AIRGAP.md) (`deploy/airgap/make-bundle.sh` → 반입 → `deploy/airgap/install.sh`)
  - 이미지 태그는 `WLM_API_IMAGE`(.env, 기본 `log-monitor-api:latest`)로 고정합니다. 개발은 `log-monitor-api:dev`.

- **백업 (ADR-031):** `backup` 서비스가 매일 `WLM_BACKUP_TIME`(02:30)이 지나면 그날 한 번 `backups/wlm-<시각>.dump`(+ `.sha256`, `config/` 묶음)를 만들고 최근 `WLM_BACKUP_KEEP`(14, 1 이상)개를 남깁니다. 놓친 날은 켜진 뒤 바로 합니다(`backups/.last-run`).
  - **외부 저장소 복제 (B-17, ADR-047):** `WLM_REPLICA=on` 이면 매일 백업 뒤 `backups/`·`archive/` 를 `WLM_REPLICA_DIR`(NAS 마운트)에 새 파일만 복사·해시 확인합니다.
    덮어쓰지 않고(원본이 암호화돼도 복제본 보존), 만료된 것만 지웁니다. 결과는 감사로그 `backup.replicate`, 로그 보관 화면, 점검 보고서(밀림·실패·만료 전에 사라진 원본).
  - 매주 `WLM_BACKUP_VERIFY_WEEKDAY`(일요일) 백업 뒤 **임시 DB 에 실제로 복원**해 해시·마이그레이션 버전·주요 테이블 행 수를 확인합니다. 행 수는 pg_dump 와 같은 스냅숏에서 세어 두었으므로 정확히 같아야 합니다. DB 디스크 여유(DB 크기 + 1GB)가 없으면 시험하지 않고 실패로 남깁니다.
  - 결과는 감사로그 `backup.create`·`backup.failed`·`backup.verify`·`backup.restore` 와 환경설정 > 로그 보관 화면. 백업이 36시간 넘게 없거나(복원했으면 복원 시각부터), 마지막 백업이 실패했거나, 복구 시험 실패가 같은·더 새 백업의 성공으로 풀리지 않았거나, 8일 넘게 성공한 복구 시험이 없으면 경고합니다.
  - 명령: `docker compose exec backup backup.sh backup | verify [파일] | list`, 장애 복구 `docker compose stop api && docker compose run --rm backup restore <파일> --yes`(연결된 세션이 있으면 거부, 지금 DB 를 `before-restore-*.dump` 로 남기고 임시 DB 에 복원한 뒤 바꿔 끼움), 자체 시험 `docker compose run --rm backup selftest` (docs/AIRGAP.md §11).
- **보관기간·로테이션:** §9 참고.
  - `backups/`·`archive/` 는 다른 매체로 복사합니다. `.env`(암호화 키)는 DB 백업과 **따로** 보관합니다(ISMS 2.7.2).
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
| 운영 | HTTPS·에이전트 TLS(api 가 직접, ADR-036) **완료** · 사내 SSO(LDAP/OIDC) 연동·관리 화면 접근 IP 제한(BACKLOG B-12·B-30) | 필요 시 |
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
- **TLS 를 켜지 않은 설치는 전송 구간이 평문입니다** (`WLM_TLS=off` 가 기본 — 개발·업그레이드 호환). 운영은 AIRGAP.md §7.5 로 켭니다.
  - 장비 → 수신기(514) syslog 와 수집기 → api 내부(8003)는 평문입니다(후자는 compose 망 안).
  - 인증서 교체에는 api 재시작이 필요합니다(기동 때 한 번 읽음). TLS 를 켜면 화면의 http 북마크는 빈 응답이 됩니다.
  - TLS 핸드셰이크도 한 프로세스(ADR-006)가 처리합니다. 초당 200회 새 연결에서 문제없었고(PERFORMANCE.md §2.3), 더 큰 규모는 실서버에서 잽니다(B-25).
  - 에이전트는 IP SAN 으로 서버를 확인하지 못해(Fluent Bit 4.0) 서버 인증서에 DNS 이름이 꼭 있어야 합니다(DNS 등록은 필요 없음).
  - L4 로드밸런서(SNAT)를 앞에 두면 접속 IP 가 가려집니다(로그인 시도 제한·감사 IP).
- IP 단위 로그인 시도 제한은 프로세스 메모리 기반입니다. 재시작하면 초기화되고, 여러 인스턴스 사이에 공유되지 않습니다.
- 긴 기간(30일 이상) 집계는 행 수에 비례해 느려집니다(PERFORMANCE.md). 시간별 집계 테이블은 로드맵에 있습니다.
- 알림 규칙은 `received_at`(수신 시각) 기준입니다.
  - 에이전트가 장애 후 몰아서 보낸 과거 오류도 '새로 들어온 오류'로 알립니다(의도한 동작).
- IIS 열 순서는 DB 에 저장하지만, 에이전트는 머리줄을 파일 처음에만 받습니다(ADR-037).
  - 첫 설치 당일, 그리고 에이전트가 멈춘 사이 새로 생긴 파일은 머리줄이 오지 않습니다(tail 이 끝부터 읽음). 같은 폴더의 열 순서가 있으면 그것으로 읽고, 없으면 사용자 지정 열 순서 사이트는 다음 파일(00:00 UTC)까지 원문으로 남습니다(BACKLOG B-32).
  - 정수 열끼리만 순서가 바뀐 경우(`sc-bytes`↔`time-taken`)는 값 모양으로 가리지 못합니다.
- MSSQL 오류 머리줄 짝(`_pending`)은 프로세스 메모리입니다. 서버 재시작이 머리줄과 본문 사이에 끼면 본문에 번호가 붙지 않습니다(B-20).
  - 에이전트 0.4.0 은 머리줄과 본문을 다른 요청으로 보내는 일이 잦아, 장애 뒤 재전송 순서가 바뀌면 번호가 빠지거나(드물게) 같은 시각·프로세스의 다음 줄에 붙을 수 있습니다. 로그인 실패(18456)는 영향이 없고, 중요한 오류는 응용 프로그램 이벤트 로그에도 남습니다(ADR-037).
- IIS 열 순서를 추정하는 동안(그 파일의 머리줄을 아직 못 받음) UA·Referer·사용자 이름 등이 숫자나 IP '뿐'인 줄은 원문으로 저장됩니다(칸이 밀렸을 때 틀린 IP 로 읽지 않기 위해). 몇몇 드문 열 구성에서는 그 기간에 요청자가 자기 줄의 상태 코드를 정할 수 있습니다(ADR-037 대가).
- **이 버전으로 업그레이드한 직후**에는 저장된 IIS 열 순서가 없습니다. 사용자 지정 열 순서 사이트는 다음 로그 파일(하루 단위면 09:00 KST)까지 원문으로 남아 IIS 대시보드·규칙에 잡히지 않습니다. 09:00 KST 직전에 올리면 공백이 짧습니다.
- MSSQL ERRORLOG 의 여러 줄 메시지는 에이전트 설정 0.4.0 부터 한 레코드로 묶입니다. 그 전 에이전트는 줄마다 따로 저장합니다. 스택 덤프·교착 그래프는 줄마다 시각이 붙는 형식이라 묶이지 않습니다(실제 샘플로 확인 예정).
- 사용자 그룹 범위는 이벤트 데이터 API 에 적용됩니다. 사이드바의 PC 온라인 수·분당 수집량은 전체 기준입니다(확인하지 않은 알림 수는 범위 반영).
- 알림 화면의 심각도별 수와 규칙별 발생 수는 전체 기준입니다(처리 상태별 수는 범위 반영).
- 알림 이력의 범위 판단은 규칙의 분류 조건과 대상(PC) 이름으로 합니다. 분류 조건이 없는 규칙(예: 수준만 보는 규칙)은 PC 범위가 맞을 때만 보입니다.
- 검색 문장: 와일드카드·괄호·키 사이 OR·IP 대역·빈 값 검색은 아직 없습니다. PC·사용자·IP 는 대소문자를 구분합니다(색인).
  - 2글자 이하 단어(`다시`, `PC`)는 trigram 색인을 쓰지 못해 기간 전체를 읽습니다. 결과가 드물면 7일에도 수십 초가 걸려 시간 상한(기본 30초)에 걸릴 수 있습니다 — 붙어 있는 말은 따옴표로 묶거나 PC·이벤트 ID 조건을 더합니다(PERFORMANCE.md §2.1).
  - 검색(SQL)과 실시간 매칭(서버 SSE·화면)의 일치 예외 — 실수는 둘 다 지수 표기 없이(`0.00001`) 비교하지만, 화면(대시보드 실시간)은 `1000.0` 과 `1000` 을 구별하지 못합니다. 그 밖에 2^53 넘는 정수(화면), 객체 값의 `f.` 비교(jsonb 가 키 순서를 바꿈), 실시간 원본의 NUL 문자. 서버 검색 결과가 정확합니다(ADR-033).
  - 정규형(수준을 한글 이름으로 씀)은 원문보다 길 수 있어, 500자 가까운 문장을 드롭다운·칩으로 고치면 '500자까지' 오류가 날 수 있습니다.
- 대시보드 실시간 반영값은 다음 동기화 전까지 근사치일 수 있습니다.
  - 동기화 조회와 스트림이 겹치는 순간 1~2건 중복이 생길 수 있습니다.
