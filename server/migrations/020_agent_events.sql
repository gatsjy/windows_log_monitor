-- B-37 2단계 (ADR-046 보완): PC 마다 어떤 Windows 이벤트 ID 를 보내는지 — 규칙별 데이터 유무.
-- 규칙 팩은 감사 정책(4625 로그온 실패, 4720 계정 생성, 4688 프로세스 등)이 켜져 있다고 가정한다. GPO 부분 적용·예외 PC 가 흔해
-- '규칙은 켜져 있는데 그 PC 에서는 데이터가 오지 않는' 것이 가장 흔하고 조용한 실패다. 채널 단위(agent_streams)로는
-- Security 는 오는데 4625 만 안 오는 것을 볼 수 없다.
-- 날짜별이 아니라 (PC, 소스, 채널, 이벤트 ID)마다 한 줄 — 처음·마지막 수신만. 마지막 수신은 한 시간에 한 번만 고친다(수집 부담).
CREATE TABLE IF NOT EXISTS agent_events (
    host      TEXT        NOT NULL,
    source    TEXT        NOT NULL,
    channel   TEXT        NOT NULL DEFAULT '',
    event_id  INTEGER     NOT NULL,
    first_at  TIMESTAMPTZ NOT NULL,
    last_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host, source, channel, event_id)
);
CREATE INDEX IF NOT EXISTS agent_events_last_idx ON agent_events (last_at);

-- PC 가 다시 켜진 시각 (B-37 2단계): 채널이 조용한 시간은 PC 가 켜져 있던 동안만 센다. 주말에 꺼졌다 월요일에 켜진 PC 의
-- 채널을 'PC 는 살아 있는데 끊김'으로 알리던 것(검토에서 재현). 수신이 heartbeat_stale_sec 넘게 끊겼다 다시 오면 그때로.
-- 비어 있으면(올리기 전부터 있던 PC) 마지막 수신만 본다.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS up_since TIMESTAMPTZ;
