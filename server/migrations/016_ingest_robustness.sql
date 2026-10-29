-- B-40 (ADR-044): 수집 견고성.
-- 레코드 하나의 값 때문에 저장이 실패하면 그 요청의 다른 레코드까지 거절되고, 에이전트는 같은 청크를 끝없이 다시 보냈다.
-- 이제 문제 레코드만 여기에 격리하고 나머지는 저장한다. 원본은 JSON 글자 그대로(어떤 글자든 저장되게 ASCII 로 이스케이프).
CREATE TABLE IF NOT EXISTS ingest_quarantine (
    id          BIGSERIAL   PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_ip   TEXT,
    host        TEXT,                    -- 정규화가 고른 PC 이름 (찾을 때 쓰기 위해)
    source      TEXT,
    category    TEXT,                    -- 정규화가 뽑은 정보주체 — 원본 열람 접속기록에 남긴다(ADR-042)
    username    TEXT,
    src_ip      TEXT,
    error       TEXT        NOT NULL,    -- 저장이 실패한 이유 (DB 오류 문구)
    record      TEXT        NOT NULL     -- 원본 레코드 JSON (64KB 까지, 넘으면 잘림 표시)
);
CREATE INDEX IF NOT EXISTS ingest_quarantine_at_idx ON ingest_quarantine (received_at DESC);

-- 수집 거절 장부: 보낸 IP·상태·사유·시간(정시)마다 한 줄. 시간으로 나눠야 보고서가 '그 기간의 거절'을 센다 —
-- 누적 한 줄이면 계속 거절되는 PC 는 마지막 시각이 보고서 기간 뒤라 빠지고, 멈춘 PC 는 몇 달치가 한 기간에 잡혔다(검토에서 재현).
-- 401 은 키를 바꾼 뒤 옛 키로 보내는 PC 를 찾는 유일한 길이다.
CREATE TABLE IF NOT EXISTS ingest_rejections (
    client_ip   TEXT        NOT NULL,
    status      INT         NOT NULL,
    reason      TEXT        NOT NULL,
    hour        TIMESTAMPTZ NOT NULL,    -- date_trunc('hour', 거절 시각)
    first_at    TIMESTAMPTZ NOT NULL,
    last_at     TIMESTAMPTZ NOT NULL,
    count       BIGINT      NOT NULL,
    PRIMARY KEY (client_ip, status, reason, hour)
);
CREATE INDEX IF NOT EXISTS ingest_rejections_hour_idx ON ingest_rejections (hour DESC);
