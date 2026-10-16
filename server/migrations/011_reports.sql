-- 011_reports: 정기 점검 보고서 (BACKLOG B-05, ADR-032) — ISMS 2.9.5 '로그를 정기적으로 점검하고 결과를 남길 것'
--   일간·주간 보고서를 정한 시각에 만들어 저장하고(받는 곳이 없어도), 수신 그룹·메신저로 보낸다.
--   담당자가 화면에서 '확인'(점검 의견)을 남긴다 — 자동 메일만으로는 사람이 점검했다는 증적이 약하다.

CREATE TABLE reports (
    id            BIGSERIAL   PRIMARY KEY,
    kind          TEXT        NOT NULL CHECK (kind IN ('daily', 'weekly')),
    scheduled     BOOLEAN     NOT NULL DEFAULT true,     -- false = 화면에서 '지금 만들기'
    period_start  TIMESTAMPTZ NOT NULL,
    period_end    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT        NOT NULL DEFAULT 'system',
    payload       JSONB       NOT NULL,                  -- 보고서 내용 전체 (만든 뒤 바뀌지 않는다)
    attention     INTEGER     NOT NULL DEFAULT 0,        -- '점검 필요' 항목 수 (목록 표시용)
    deliveries    JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- [{target, status, error, at}]
    reviewed_by   TEXT,
    reviewed_at   TIMESTAMPTZ,
    review_note   TEXT        NOT NULL DEFAULT '',
    CHECK (period_end > period_start)
);
-- 같은 기간의 정기 보고서는 하나만 — 서버가 재시작되거나 여러 대여도 두 번 만들지 않는다
CREATE UNIQUE INDEX reports_period_uidx ON reports (kind, period_start) WHERE scheduled;
CREATE INDEX reports_created_idx ON reports (created_at DESC);

-- 내용(payload)·기간·만든 정보는 고칠 수 없다. 확인(reviewed_*)은 한 번만. 전송 결과(deliveries)만 나중에 채운다.
-- 삭제는 보관기간 만료 정리(SET LOCAL wlm.report_purge = 'on', app/partitions.py)만 허용한다.
CREATE FUNCTION reports_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('wlm.report_purge', true) = 'on' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'reports 는 삭제할 수 없습니다 (점검 증적, 보관기간 만료 때만 정리)';
    END IF;
    IF NEW.payload IS DISTINCT FROM OLD.payload OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.scheduled IS DISTINCT FROM OLD.scheduled OR NEW.period_start IS DISTINCT FROM OLD.period_start
       OR NEW.period_end IS DISTINCT FROM OLD.period_end OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.attention IS DISTINCT FROM OLD.attention THEN
        RAISE EXCEPTION 'reports 의 내용은 고칠 수 없습니다 (점검 증적)';
    END IF;
    IF OLD.reviewed_at IS NOT NULL AND (NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by
       OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at OR NEW.review_note IS DISTINCT FROM OLD.review_note) THEN
        RAISE EXCEPTION '이미 확인한 보고서입니다';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER reports_guarded
    BEFORE UPDATE OR DELETE ON reports
    FOR EACH ROW EXECUTE FUNCTION reports_guard();

CREATE FUNCTION reports_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'reports 는 삭제할 수 없습니다 (점검 증적)';
END
$$;

CREATE TRIGGER reports_no_truncate
    BEFORE TRUNCATE ON reports
    FOR EACH STATEMENT EXECUTE FUNCTION reports_no_truncate();
