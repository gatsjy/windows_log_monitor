-- 002_alerts: 알림 (Phase 2)

-- 알림 규칙은 '최근 N분 동안 수신된' 이벤트를 센다 → 수신 시각 인덱스
CREATE INDEX events_received_idx ON events (received_at);

-- 발생한 알림. payload = 알림 대상에 보낸 메시지 전체 (재전송·화면 표시에 사용)
CREATE TABLE alerts (
    id              BIGSERIAL PRIMARY KEY,
    fired_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    rule            TEXT        NOT NULL,              -- 규칙 이름 (config/alerts.yaml)
    severity        TEXT        NOT NULL,              -- critical | error | warning | info
    group_key       TEXT        NOT NULL DEFAULT '',   -- 묶음 기준 값 (보통 PC 이름)
    event_count     BIGINT      NOT NULL DEFAULT 0,
    first_event_at  TIMESTAMPTZ,
    last_event_at   TIMESTAMPTZ,
    payload         JSONB       NOT NULL
);
CREATE INDEX alerts_fired_idx    ON alerts (fired_at DESC);
CREATE INDEX alerts_rule_key_idx ON alerts (rule, group_key, fired_at DESC);

-- 알림 대상별 전송 상태. 실패하면 엔진이 간격을 늘려 가며 재시도한다.
CREATE TABLE alert_deliveries (
    alert_id    BIGINT      NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    notifier    TEXT        NOT NULL,                  -- 알림 대상 이름
    status      TEXT        NOT NULL DEFAULT 'pending', -- pending | sent | failed | gave_up
    attempts    INTEGER     NOT NULL DEFAULT 0,
    last_error  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at     TIMESTAMPTZ,
    PRIMARY KEY (alert_id, notifier)
);
CREATE INDEX alert_deliveries_failed_idx ON alert_deliveries (updated_at) WHERE status = 'failed';
