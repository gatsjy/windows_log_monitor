# 실제 에이전트 레코드 (Windows)

`agent-fb4.0.14.jsonl` — GitHub 윈도 러너에서 실제 이벤트를 일으켜(`tools/ci/capture_winlog.ps1`) 에이전트 틀과 같은
winevtlog 설정(Fluent Bit 4.0.14, `string_inserts: true`)으로 받은 레코드. CI 실행 42723626534(2026-11-09, Windows Server 2025 러너), 레코드 33개.

- 러너 이름은 `WIN-CI` 로 바꿨고, `Message` 는 200자로 잘랐다(그 밖에는 Fluent Bit 이 낸 그대로 — 값의 형도: LogonType 은 숫자).
- `EventData` 키가 없다 — 이름은 서버가 `raw.winevtlog.EventData` 로 붙인다(`normalizers/win_templates.py`, ADR-038).
- 윈도 CI 가 매번 새로 받아 같은 모양인지 본다. Fluent Bit·Windows 를 올려 모양이 바뀌면 이 파일을 다시 만든다.
- 러너에서 생기지 않은 것(`WLMOPTIONAL`): 4767(잠금 풀기)·서비스 7034 — 이 실행 뒤에 캡처에 더했다(4648·4672·4702·4723·4724·4725 와 함께, 단계마다
  `WLMSTEP` 줄). 4647(대화형 로그오프 — 캡처의 로그오프는 4634 만 남김, 일으키지 않음)·WER 1001(충돌은 일으켰으나 안 생김). 도메인 컨트롤러의
  Kerberos 4768·4769·4771, 이벤트 로그 종료 1100, 비정상 재부팅 41, Defender, SQL Server — 현장(B-28)에서 받는다.

## 다시 만들기

윈도 CI 는 `capture_winlog.ps1 -ThrowawayRunner` 로 러너를 바꿔 가며 이벤트를 일으킨다(임시 관리자·감사·잠금 정책·스풀러 복구 동작·로그 지움 — GitHub 호스트 러너
(`RUNNER_ENVIRONMENT=github-hosted`)에서만 돌고 self-hosted 러너·도메인 가입 PC·DC 에서는 거부). 현장 PC·DC 에서는 스위치 없이 돌려 **듣기만** 한다 —
그동안 필요한 동작을 손으로 일으킨다(B-28, 실행마다 `-Work` 아래 새 `run-<시각>` 폴더).
캡처 스크립트가 PC 이름을 `WIN-CI` 로 바꾸고 `Message` 를 자른 줄(`WLMCAPTURE {…}`)을 찍으므로 윈도 CI 의 줄은 그대로 옮긴다(현장 캡처는 그 PC 이름만 바뀌고 계정·SID·IP·도메인·다른 PC 이름은 실제 값이다 — 시험용 값으로 바꾼 뒤 옮긴다):

```bash
gh run view <실행 번호> --log | grep -o 'WLMCAPTURE {.*' | cut -c12- > server/tests/fixtures/winevtlog/agent-fb4.0.14.jsonl
```

그다음 `test_win_templates.py`(템플릿 길이)·`test_ingest_quality.py`(`VERIFIED` 버전)·`test_rule_samples.py`(문서 기반 표본 → 실측)·
`test_wincatalog.py`(실측 값으로 쓴 요약 기대값 — 러너의 SID·경로) 순서로 고친다.

# 공급자 매니페스트 템플릿

`manifest-templates.json` — 서버가 이름을 붙이는 이벤트(`win_templates.TEMPLATES`)마다 윈도 공급자 매니페스트의 템플릿(버전마다 필드 이름·순서).
`Get-WinEvent -ListProvider` 로 읽은 것이라 러너에서 일으킬 수 없는 이벤트(도메인 컨트롤러의 4768·4769·4771 등)와 새 버전도 들어 있다.
`test_win_templates.py` 가 버전마다 붙는 이름·순서와 '템플릿 불일치' 판단을 대조하고, 윈도 CI 는 러너의 매니페스트와 비교해 다르면 **경고**한다
(새 러너 이미지에 새 버전이 오면 — 실패로 막지 않는다).

- 이름·순서만 확인한다. 에이전트가 그 순서로 보내는지는 위 실측 레코드가 본다. 매니페스트로 순서를 정할 수 없는 템플릿 — `<struct>`, `count=` 배열
  (Fluent Bit 은 배열 값을 StringInserts 에서 뺀다), `length=` 칸(서비스 7031·7036 은 Binary 만 오고 `__binLength` 는 안 옴 — 템플릿을 두지 않음) —
  은 스크립트가 거부한다(손으로 실측과 맞춘다).
- 실측한 버전(`VERIFIED`)보다 새 버전이 뒤에 필드를 더 붙이면 `TEMPLATES` 를 늘리지 말고 `VERSIONED` 에 둔다 — 늘리면 실측한 옛 버전이
  '템플릿 불일치'가 된다. 실측한 버전이 가장 새 것이면 기본 이름이 그 버전이다(4719·1102 v1).
- 클래식 원본(`UNVERSIONED`, 응용 프로그램 충돌 1000)은 필드를 더해도 버전이 0 그대로라 매니페스트에 버전이 하나뿐이다 — 옛 Windows 의 짧은 모양은
  매니페스트로 알 수 없어 더 길 때만 '템플릿 불일치'로 센다.

윈도 PC 에서(읽기만 한다 — 아무것도 바꾸지 않음) 다시 만들거나 템플릿을 더한다(`-Add` 는 쉼표로 여럿):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\dump_templates.ps1 -Fixture server\tests\fixtures\winevtlog\manifest-templates.json -Update
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\dump_templates.ps1 -Fixture server\tests\fixtures\winevtlog\manifest-templates.json -Update -Add "Microsoft-Windows-Security-Auditing:4625,Microsoft-Windows-Security-Auditing:4634"
```

`-Update` 는 그 PC 에 없는 버전(더 새 Windows 에서 받아 둔 것)을 남기고, 같은 버전인데 이름이 다르면 거부한다(발표된 이벤트 버전은 바뀌지 않는다).
템플릿을 빼면 그 이벤트의 줄을 손으로 지운다(`test_manifest_fixture_covers_every_template` 가 맞춰 본다). `-Update` 없이 돌리면 그 PC 와 고정 자료를
비교만 한다(`WLMTEMPLATE` 줄 — 윈도 CI 는 이것을 경고로 띄운다).
