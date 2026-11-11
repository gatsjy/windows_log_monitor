# 기본 규칙 표본 (B-45, ADR-066)

`config/alerts.yaml` 의 기본 규칙마다 **맞아야 하는 로그**(match)와 **맞으면 안 되는 로그**(no_match)를 둡니다.
표본이 없는 규칙은 CI 가 실패합니다(`tests/test_rule_samples.py`). 로그가 아니라 하트비트·알림을 보는 규칙
(agent_silent·stream_silent·correlation)만 이유와 함께 빠집니다.

- `test_rule_samples.py` — DB 없이: 수집과 같은 정규화 → 규칙 시험기와 같은 판단(`app/alerts/ruletest.py`, 조건마다 + 묶음 값·볼 값이 비지 않았는지).
- `test_api_rule_samples.py` — 실제 수집(`/api/ingest`) → 엔진의 SQL 집계(`repository.alert_candidates`, 기준 건수·서로 다른 값 수까지)와 규칙 시험기 API.

규칙을 고치거나 새 기본 규칙을 더하면 여기 표본부터 고칩니다. 표본이 실제 PC 의 로그 모양이 아니면 시험이 통과해도
실제로는 울리지 않습니다 — ADR-038 이 그렇게 몇 주 동안 숨어 있었습니다.

## 형식 — `<규칙 번호>.yaml`

```yaml
rule: 1000007            # 파일 이름과 같은 규칙 번호
match:                   # 규칙이 세야 하는 로그
  - why: 원격 데스크톱(유형 10) 로그온 실패 — 출발지 IP 로 묶인다
    windows: {event: 4625, where: {LogonType: 3}}   # 실측 레코드(fixtures/winevtlog)에서 고르고
    inserts: {LogonType: 10, IpAddress: 198.51.100.23}   # 템플릿 이름으로 값만 바꾼다
no_match:                # 세면 안 되는 로그 (왜 안 되는지가 규칙의 경계)
  - why: 네트워크 로그온(유형 3) 실패는 원격 데스크톱이 아니다
    fails_on: [f.EventData.LogonType]               # 이 조건 하나로만 떨어져야 한다
    windows: {event: 4625, where: {LogonType: 3}}
    inserts: {IpAddress: 198.51.100.23}
```

표본마다 `why` 와 아래 중 하나:

| 키 | 만드는 레코드 |
|---|---|
| `windows: {event: N}` | `fixtures/winevtlog/agent-fb4.0.14.jsonl` 의 실측 레코드(같은 ID 가 여럿이면 `where: {템플릿 이름: 값}`, 공급자가 여럿이면 `provider:` 로 고름). `inserts` 는 템플릿 이름으로 값만 바꾸고, `fields` 는 레코드 키(Message·Level 등)를 바꾼다 — 공급자·ID·버전·채널·StringInserts 는 바꿀 수 없다(다른 이벤트면 아래 줄) |
| `windows: {event: N, envelope: M}` | **실측이 없는 이벤트.** 봉투(공급자 GUID·시각·ProcessID 등)는 실측 M 에서, 판단에 쓰이는 `fields`(ProviderName·Channel·Level·Keywords·Version·Message)는 모두 적는다. 템플릿이 있으면 `inserts` 에 모든 이름을, 없으면 `strings` 에 StringInserts 를 그대로. `ref` 필수, `where`·`provider` 는 쓰지 않음 |
| `iis: 줄 \| [줄…]` | IIS W3C 로그 줄(Fluent Bit tail: `log`·`file`) — 기본 필드 순서는 `#Fields:` 줄 없이 |
| `mssql: 줄 \| [줄…]` | SQL Server ERRORLOG 줄(에이전트 0.4.0: 시각으로 시작하는 줄마다 한 레코드). 여러 줄이면 차례로 보내고 **마지막 레코드**로 판단 — `Error:` 머리줄 + 본문 |
| `journald: {…}` | 리눅스 에이전트 systemd 입력 레코드 (`strip_underscores: off`) |
| `syslog: {…}` | syslog 수신기(collector) 레코드 |
| `record: {…}` | 그 밖의 원본 그대로 |

- **`fails_on`** (no_match 에 필수): 떨어져야 하는 조건 — 규칙 시험기의 조건 키(`event_id`·`provider`·`channel`·`category`·`level`·`source`·`q`·
  `f.EventData.LogonType` …), 묶음 값이 비어서면 `group_key:ip`, 처음 보는 값의 볼 값이 비어서면 `term_field:ip`, 제외 조건이면 `-user` 처럼 앞에 `-`.
  시험은 떨어진 조건이 **정확히 그 집합**인지 본다 — 다른 조건(IP 없음 등)으로도 떨어지는 표본은 그 경계를 지키지 못한다. 되도록 경계 하나에 표본 하나.
- **조건마다 표본:** 규칙의 조건 하나하나에 그 조건으로 떨어지는 no_match 가 있어야 한다(`test_every_rule_condition_is_guarded_by_a_no_match_sample`).
  현실 표본을 만들 수 없는 조건만 `test_rule_samples.UNGUARDED` 에 이유와 함께. PC 이름(`group_key:host`)은 늘 있어 보지 않는다.
- 기준 건수·서로 다른 값 수의 경계(같은 계정 반복, min−1개)는 표본이 아니라 `test_api_windows_real.py` 가 기본 규칙으로 본다. 새 distinct 기본 규칙을 더하면 거기에도 경계 줄을.
- 실측 레코드에서 만들지 않은 표본은 `ref` 에 형식의 근거(문서 주소)를 적습니다. 윈도 CI 캡처(`tools/ci/capture_winlog.ps1`)로
  실측이 생기면 빌더가 '실측으로 바꾸라'며 실패합니다 — `envelope` 표본을 실측 표본으로 바꾸고 `test_rule_samples.DOCS_BASED` 에서 지웁니다.
- 모르는 키(`insert:` 같은 오타)는 거부합니다. `file:` 은 `iis`·`mssql` 표본에만 — 레코드의 파일 경로를 바꿉니다(기본: W3SVC1 로그·기본 인스턴스 ERRORLOG).
- PC 이름(`agent_host`, syslog 는 `host`)은 시험이 표본마다 다르게 붙입니다. 서로 다른 값 수 규칙(distinct)은 시험이 그 값(Windows `TargetUserName`·
  `IpAddress`, 또는 PC 이름)만 바꾼 사본을 기준 수만큼 보냅니다.
- 값은 시험용 주소(198.51.100.0/24·203.0.113.0/24·10.x)와 가짜 SID 만 씁니다. 실제 사내 이름·IP 를 넣지 않습니다.
- 이 폴더의 파일은 역슬래시(경로·`\r\n`)가 많아 셸 heredoc 으로 쓰지 않습니다(윈도 Git Bash 가 `\\` 를 `\` 로 바꿈 — 편집 도구로).
