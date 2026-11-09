# 실제 에이전트 레코드 (Windows)

`agent-fb4.0.14.jsonl` — GitHub 윈도 러너에서 실제 이벤트를 일으켜(`tools/ci/capture_winlog.ps1`) 에이전트 틀과 같은
winevtlog 설정(Fluent Bit 4.0.14, `string_inserts: true`)으로 받은 레코드. CI 실행 39178315171(2026-10-19).

- 러너 이름은 `WIN-CI` 로 바꿨고, `Message` 는 200자로 잘랐다(그 밖에는 Fluent Bit 이 낸 그대로 — 값의 형도: LogonType 은 숫자).
- `EventData` 키가 없다 — 이름은 서버가 `raw.winevtlog.EventData` 로 붙인다(`normalizers/win_templates.py`, ADR-038).
- 윈도 CI 가 매번 새로 받아 같은 모양인지 본다. Fluent Bit·Windows 를 올려 모양이 바뀌면 이 파일을 다시 만든다.

## 다시 만들기

윈도 CI 는 `capture_winlog.ps1 -ThrowawayRunner` 로 러너를 바꿔 가며 이벤트를 일으킨다(임시 관리자·감사·잠금 정책·로그 지움 — GitHub 호스트 러너
(`RUNNER_ENVIRONMENT=github-hosted`)에서만 돌고 self-hosted 러너·도메인 가입 PC·DC 에서는 거부). 현장 PC·DC 에서는 스위치 없이 돌려 **듣기만** 한다 —
그동안 필요한 동작을 손으로 일으킨다(B-28, 실행마다 `-Work` 아래 새 `run-<시각>` 폴더).
캡처 스크립트가 PC 이름을 `WIN-CI` 로 바꾸고 `Message` 를 자른 줄(`WLMCAPTURE {…}`)을 찍으므로 그대로 옮긴다:

```bash
gh run view <실행 번호> --log | grep -o 'WLMCAPTURE {.*' | cut -c12- > server/tests/fixtures/winevtlog/agent-fb4.0.14.jsonl
```

그다음 `test_win_templates.py`(템플릿 길이)·`test_ingest_quality.py`(`VERIFIED` 버전)·`test_rule_samples.py`(문서 기반 표본 → 실측) 순서로 고친다.
`WLMOPTIONAL` 줄은 러너에서 생기지 않은 이벤트다 — 현장(B-28)에서 받는다.
