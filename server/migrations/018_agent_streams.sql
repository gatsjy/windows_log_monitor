-- B-37 (ADR-046): 수집 완전성 1단계 — PC·소스·채널마다 날짜별 수신 건수.
-- GPO 변경 등으로 한 PC 의 Security 수집만 끊겨도 하트비트·System 로그는 계속 와서 '연락 끊김'(agent_silent)은 조용했다.
-- 늘 오던 (PC, 채널)이 사라졌는지 보려면 채널 단위의 '평소'가 있어야 한다.
CREATE TABLE IF NOT EXISTS agent_streams (
    host      TEXT        NOT NULL,
    source    TEXT        NOT NULL,
    channel   TEXT        NOT NULL DEFAULT '',   -- 채널이 없는 소스는 ''
    day       DATE        NOT NULL,              -- 수신 날짜 (UTC)
    n         BIGINT      NOT NULL,
    first_at  TIMESTAMPTZ NOT NULL,              -- 그날 처음·마지막 수신 시각
    last_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host, source, channel, day)
);
CREATE INDEX IF NOT EXISTS agent_streams_day_idx ON agent_streams (day);
