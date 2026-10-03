-- 001_init: 초기 스키마
-- 마이그레이션 규칙: 이미 적용된 파일은 절대 수정하지 않는다. 변경은 002_xxx.sql 처럼 새 파일로 추가.

-- 수집된 로그 이벤트. received_at(서버 수신 시각) 기준 월별 파티션.
-- 파티션 생성/삭제는 app/partitions.py 가 담당한다 (보관기간 = WLM_RETENTION_DAYS).
CREATE TABLE events (
    id           BIGSERIAL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),  -- 서버가 받은 시각 (파티션 키)
    ts           TIMESTAMPTZ NOT NULL,                -- 이벤트 발생 시각 (TimeCreated)
    host         TEXT        NOT NULL,                -- PC 이름 (agent_host)
    source       TEXT        NOT NULL,                -- 수집 입력 종류: winevtlog | file | ...
    channel      TEXT,                                -- System / Application / Security ...
    provider     TEXT,                                -- ProviderName
    event_id     INTEGER,                             -- EventID
    level        SMALLINT    NOT NULL,                -- 1 심각, 2 오류, 3 경고, 4 정보, 5 상세
    message      TEXT,
    raw          JSONB       NOT NULL,                -- 에이전트가 보낸 원본 레코드 (가공 없음)
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

CREATE INDEX events_ts_idx       ON events (ts DESC, id DESC);
CREATE INDEX events_host_ts_idx  ON events (host, ts DESC);
CREATE INDEX events_level_ts_idx ON events (level, ts DESC);
CREATE INDEX events_chan_ts_idx  ON events (channel, ts DESC);
CREATE INDEX events_eid_ts_idx   ON events (event_id, ts DESC);
CREATE INDEX events_src_ts_idx   ON events (source, ts DESC);

-- 메시지 부분일치 검색(ILIKE '%...%')용 trigram 인덱스. 대용량 전문검색은 docs/DECISIONS.md ADR-004 참고
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX events_message_trgm_idx ON events USING gin (message gin_trgm_ops);

-- 로그를 보내는 PC 목록. 이벤트/하트비트를 받을 때마다 갱신된다.
CREATE TABLE agents (
    host               TEXT PRIMARY KEY,
    first_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_event_at      TIMESTAMPTZ,
    last_heartbeat_at  TIMESTAMPTZ,
    last_ip            TEXT,
    events_total       BIGINT      NOT NULL DEFAULT 0,
    meta               JSONB       NOT NULL DEFAULT '{}'::jsonb  -- 하트비트에 담긴 에이전트 정보
);

-- 필드 카탈로그: 원본 JSON 에 어떤 필드가 들어오는지 (필드 탐색 화면)
CREATE TABLE field_stats (
    source      TEXT        NOT NULL,
    path        TEXT        NOT NULL,   -- 점 표기 경로. 예) EventData.TargetUserName
    json_type   TEXT        NOT NULL,   -- string | number | boolean | array | object | null
    seen        BIGINT      NOT NULL DEFAULT 0,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    sample      TEXT,
    PRIMARY KEY (source, path)
);

-- 감사 로그: 설정 변경, 보관기간 만료 삭제 등 시스템 자체의 중요 행위 기록 (ISMS 2.9.4)
CREATE TABLE audit_log (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     TEXT        NOT NULL,     -- 사용자명 또는 'system'
    actor_ip  TEXT,
    action    TEXT        NOT NULL,     -- 예) dashboard.save, retention.drop_partition
    target    TEXT,
    detail    JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
