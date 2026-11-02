-- 접속기록 점검 결과서 (BACKLOG B-72 3단계, ISMS 2.9.5, ADR-060): 내부 관리계획의 주기마다 점검 항목(보관기간·위·변조·내려받기 사유·
-- 업무시간 외 접속·인증 실패·권한 변경·대량 조회·외부 업체·서비스 계정)을 적정·부적정·해당 없음과 조치로 남기고 점검자 서명 → (다른)
-- 책임자 승인·반려. 시작할 때 항목별 근거(그 기간의 숫자)를 스냅샷으로 둔다. 결재 증적이라 고치거나 지울 수 없다(권한 검토와 같은 방식).
CREATE TABLE IF NOT EXISTS inspections (
    id           BIGSERIAL   PRIMARY KEY,
    kind         TEXT        NOT NULL CHECK (kind IN ('access_log')),
    title        TEXT        NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end   TIMESTAMPTZ NOT NULL,
    started_by   TEXT        NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    items        JSONB       NOT NULL,     -- 시작 때의 점검 항목 [{key, label, basis, evidence: {...}, summary}]
    CHECK (period_start < period_end)
);

CREATE TABLE IF NOT EXISTS inspection_entries (
    id            BIGSERIAL   PRIMARY KEY,
    inspection_id BIGINT      NOT NULL REFERENCES inspections (id),
    kind          TEXT        NOT NULL CHECK (kind IN ('result', 'sign', 'approve', 'reject')),
    item          TEXT,                     -- result 만: 점검 항목 key
    result        TEXT        CHECK (result IN ('ok', 'issue', 'na')),
    note          TEXT        NOT NULL DEFAULT '',
    author        TEXT        NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((kind = 'result') = (item IS NOT NULL AND result IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS inspection_entries_idx ON inspection_entries (inspection_id, id);

CREATE FUNCTION inspections_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% 는 수정하거나 삭제할 수 없습니다 (접속기록 점검 결재 증적)', TG_TABLE_NAME;
END
$$;

CREATE TRIGGER inspections_append_only BEFORE UPDATE OR DELETE ON inspections
    FOR EACH ROW EXECUTE FUNCTION inspections_guard();
CREATE TRIGGER inspections_no_truncate BEFORE TRUNCATE ON inspections
    FOR EACH STATEMENT EXECUTE FUNCTION inspections_guard();
CREATE TRIGGER inspection_entries_append_only BEFORE UPDATE OR DELETE ON inspection_entries
    FOR EACH ROW EXECUTE FUNCTION inspections_guard();
CREATE TRIGGER inspection_entries_no_truncate BEFORE TRUNCATE ON inspection_entries
    FOR EACH STATEMENT EXECUTE FUNCTION inspections_guard();
