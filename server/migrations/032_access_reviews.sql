-- 분기 권한 검토 (BACKLOG B-72 2단계, ISMS 2.5.6, ADR-058): 시작할 때의 계정·권한을 스냅샷으로 두고, 계정마다 유지·회수·조정 결정과
-- 점검자 서명 → (다른) 책임자 승인·반려를 한 줄씩 남긴다. 결재 증적이라 감사로그처럼 고치거나 지울 수 없다(추가만).
-- 사용자를 지워도 기록은 남는다(사용자 표를 참조하지 않고 스냅샷의 아이디로).
CREATE TABLE IF NOT EXISTS access_reviews (
    id          BIGSERIAL   PRIMARY KEY,
    title       TEXT        NOT NULL,
    started_by  TEXT        NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    users       JSONB       NOT NULL     -- [{id, username, display_name, role, is_active, groups, permissions, scoped, last_used, mfa}]
);

CREATE TABLE IF NOT EXISTS access_review_entries (
    id          BIGSERIAL   PRIMARY KEY,
    review_id   BIGINT      NOT NULL REFERENCES access_reviews (id),
    kind        TEXT        NOT NULL CHECK (kind IN ('decision', 'sign', 'approve', 'reject')),
    user_id     BIGINT,                   -- decision 만: 스냅샷의 사용자 id
    username    TEXT,
    decision    TEXT        CHECK (decision IN ('keep', 'revoke', 'change')),
    note        TEXT        NOT NULL DEFAULT '',
    author      TEXT        NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((kind = 'decision') = (user_id IS NOT NULL AND decision IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS access_review_entries_review_idx ON access_review_entries (review_id, id);

CREATE FUNCTION access_reviews_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% 는 수정하거나 삭제할 수 없습니다 (권한 검토 결재 증적)', TG_TABLE_NAME;
END
$$;

CREATE TRIGGER access_reviews_append_only BEFORE UPDATE OR DELETE ON access_reviews
    FOR EACH ROW EXECUTE FUNCTION access_reviews_guard();
CREATE TRIGGER access_reviews_no_truncate BEFORE TRUNCATE ON access_reviews
    FOR EACH STATEMENT EXECUTE FUNCTION access_reviews_guard();
CREATE TRIGGER access_review_entries_append_only BEFORE UPDATE OR DELETE ON access_review_entries
    FOR EACH ROW EXECUTE FUNCTION access_reviews_guard();
CREATE TRIGGER access_review_entries_no_truncate BEFORE TRUNCATE ON access_review_entries
    FOR EACH STATEMENT EXECUTE FUNCTION access_reviews_guard();
