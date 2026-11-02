-- 처음 보는 값 탐지 (BACKLOG B-47, ADR-063): 규칙마다 본 값 조합(seen_terms)과 진행 상태(new_terms_state).
-- 엔진이 주기마다 받은 시각(received_at) 구간을 훑어 처음 보는 조합만 알린다. 수집 경로는 그대로(ADR-046).
-- 값은 사용자·IP 같은 개인정보다 — ISMS.md '처음 보는 값' 보관 줄, 화면 열람은 접속기록.

-- 값 조합의 열쇠 — 표시용 글은 잘라 두지만 열쇠는 전체 값으로(ImagePath 처럼 긴 값이 btree 한도를 넘지 않게 해시).
-- 이 함수는 고치지 않는다(바꾸면 모든 조합이 '처음 보는 값'이 된다). 쓰는 곳은 이 함수 하나.
CREATE FUNCTION wlm_terms_hash(t text[]) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
RETURN sha256(convert_to(array_to_json(t)::text, 'UTF8'));

CREATE TABLE IF NOT EXISTS new_terms_state (
    id           BIGSERIAL   PRIMARY KEY,
    rule_key     TEXT        NOT NULL,                 -- configdiff.rule_key (sid 또는 이름) — 이름을 바꿔도 sid 면 같은 상태
    fields       TEXT[]      NOT NULL,                 -- 필드를 바꾸면 새 상태(처음부터 다시 배움)
    filter_sig   TEXT        NOT NULL,                 -- 조건(저장한 검색 문장 + match)의 해시 — 바뀌면 다시 배움
    cursor_at    TIMESTAMPTZ NOT NULL,                 -- 여기까지 받은 로그를 봤다
    learn_until  TIMESTAMPTZ NOT NULL,                 -- 이 뒤에 처음 본 값만 알린다
    backfill_from TIMESTAMPTZ,                         -- 거슬러 배울 구간 [from, to) — 끝나면 NULL
    backfill_to   TIMESTAMPTZ,
    chunk_sec    INT         NOT NULL DEFAULT 900,     -- 한 번에 볼 받은 시각 구간 (시간 초과면 반, 빠르면 두 배)
    terms_n      INT         NOT NULL DEFAULT 0,       -- 지금 둔 조합 수
    overflow_n   BIGINT      NOT NULL DEFAULT 0,       -- 상한(max_terms)을 넘어 두지 못한 새 조합 수 — 0 보다 크면 규칙 오류
    relearn_reason TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_key, fields)
);

CREATE TABLE IF NOT EXISTS seen_terms (
    ns             BIGINT      NOT NULL REFERENCES new_terms_state ON DELETE CASCADE,
    term_hash      BYTEA       NOT NULL,
    term           TEXT[]      NOT NULL,               -- 표시용 (값마다 256자까지)
    first_seen     TIMESTAMPTZ NOT NULL,               -- 받은 시각 기준 — 시계가 틀린 PC·밀린 로그에 흔들리지 않게
    last_seen      TIMESTAMPTZ NOT NULL,
    first_ts       TIMESTAMPTZ,                        -- 그때 로그의 발생 시각 (표시)
    first_event_id BIGINT,
    first_host     TEXT,
    prev_last_seen TIMESTAMPTZ,                        -- history 가 지나 다시 새로 봤을 때 그 전 마지막 (‘n일 만에 다시’)
    state          TEXT        NOT NULL CHECK (state IN ('learned', 'pending', 'alerted', 'aggregated')),
    alert_id       BIGINT,
    PRIMARY KEY (ns, term_hash)
);
CREATE INDEX IF NOT EXISTS seen_terms_pending_idx ON seen_terms (ns, first_seen) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS seen_terms_last_idx ON seen_terms (ns, last_seen);
