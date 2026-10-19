# 실제 에이전트 레코드 (Windows)

`agent-fb4.0.14.jsonl` — GitHub 윈도 러너에서 실제 이벤트를 일으켜(`tools/ci/capture_winlog.ps1`) 에이전트 틀과 같은
winevtlog 설정(Fluent Bit 4.0.14, `string_inserts: true`)으로 받은 레코드. CI 실행 39178315171(2026-10-19).

- 러너 이름은 `WIN-CI` 로 바꿨고, `Message` 는 200자로 잘랐다(그 밖에는 Fluent Bit 이 낸 그대로 — 값의 형도: LogonType 은 숫자).
- `EventData` 키가 없다 — 이름은 서버가 `raw.winevtlog.EventData` 로 붙인다(`normalizers/win_templates.py`, ADR-038).
- 윈도 CI 가 매번 새로 받아 같은 모양인지 본다. Fluent Bit·Windows 를 올려 모양이 바뀌면 이 파일을 다시 만든다.
