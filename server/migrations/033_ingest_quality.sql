-- 수집 품질 지표 (BACKLOG B-56 1단계, ISMS 2.9.4): 들어오는데 해석이 깨진 것·늦게 오는 것을 (PC, 소스, 채널, 날)마다 센다.
--   채널별 수신 집계(agent_streams, B-37)와 같은 줄·같은 문장에 칸만 더한다 — 수집 트랜잭션에 쓰기를 늘리지 않게(PERFORMANCE.md §2.8).
--   parse_errors      정규화기 예외로 일반 로그로 저장한 것 (raw._ingest.error, B-40)
--   unparsed          해석하지 못해 원문 그대로 둔 줄 (IIS 열 순서를 모름 — 사용자·IP·상태 코드가 비어 규칙이 못 본다)
--   template_mismatch Windows 이벤트 필드 수가 서버 템플릿과 다름 (이벤트 버전이 바뀜 — f.EventData 이름이 어긋날 수 있다, ADR-038)
--   late_n            받은 때보다 1시간 넘게 앞선 발생 시각 (밀린 로그·PC 시계)
--   future_n          받은 때보다 5분 넘게 뒤인 발생 시각 (PC 시계)
--   max_lag_sec       가장 늦게 온 로그의 (받은 시각 − 발생 시각) 초
ALTER TABLE agent_streams
    ADD COLUMN IF NOT EXISTS parse_errors      INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS unparsed          INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS template_mismatch INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS late_n            INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS future_n          INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_lag_sec       INTEGER NOT NULL DEFAULT 0;
