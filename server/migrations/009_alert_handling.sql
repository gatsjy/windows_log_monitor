-- 009_alert_handling: 알림 처리 기록(확인·해결·메모)과 무음(silence) — BACKLOG B-02, B-03, ADR-029
--   ISMS 2.11.5 사고 대응은 '인지 → 조치 → 종료' 를 누가·언제 했는지 남기라고 요구한다.
--   이미 있던 알림은 'open'(처리 안 됨)으로 둔다. 아무도 처리하지 않은 알림을 처리한 것처럼 꾸미지 않기 위해서다.

-- 무음: 점검·배포 중 예상된 알림을 보내지 않는다. 알림 발생은 그대로 기록하고 전송만 건너뛴다.
--   rule / group_key 가 NULL 이면 '모든 규칙' / '모든 대상'.
--   해제는 행을 지우지 않고 ends_at 을 앞당긴다 → 언제 무음이 걸려 있었는지가 그대로 남는다.
CREATE TABLE alert_silences (
    id          BIGSERIAL PRIMARY KEY,
    rule        TEXT,
    group_key   TEXT,
    starts_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ends_at     TIMESTAMPTZ NOT NULL,
    reason      TEXT        NOT NULL,
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_by    TEXT,                       -- 일찍 해제한 사람 (기간이 끝나 저절로 풀리면 NULL)
    CHECK (ends_at >= starts_at)            -- 시작 전에 해제하면 길이 0 (한 번도 적용 안 됨)
);
CREATE INDEX alert_silences_ends_idx ON alert_silences (ends_at);

ALTER TABLE alerts
    ADD COLUMN status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acked', 'resolved')),
    ADD COLUMN acked_by     TEXT,
    ADD COLUMN acked_at     TIMESTAMPTZ,
    ADD COLUMN resolved_by  TEXT,
    ADD COLUMN resolved_at  TIMESTAMPTZ,
    ADD COLUMN silence_id   BIGINT REFERENCES alert_silences (id) ON DELETE SET NULL;
-- 사이드바 숫자(확인 안 된 알림)와 '처리 안 됨' 필터용
CREATE INDEX alerts_unresolved_idx ON alerts (fired_at DESC) WHERE status <> 'resolved';

-- 처리 기록 타임라인: 확인·해결·다시 열기와 메모. 감사 성격이라 수정·삭제할 수 없다.
CREATE TABLE alert_notes (
    id        BIGSERIAL PRIMARY KEY,
    alert_id  BIGINT      NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    author    TEXT        NOT NULL,
    action    TEXT        NOT NULL CHECK (action IN ('note', 'ack', 'resolve', 'reopen')),
    text      TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX alert_notes_alert_idx ON alert_notes (alert_id, at);

-- 수정 금지. 삭제는 알림 자체가 보관기간 만료로 지워질 때(ON DELETE CASCADE)만 통과한다
-- (연쇄 삭제 시점에는 부모 알림이 이미 보이지 않는다).
CREATE FUNCTION alert_notes_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM alerts WHERE id = OLD.alert_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'alert_notes 는 수정하거나 삭제할 수 없습니다 (알림 처리 기록)';
END
$$;

CREATE TRIGGER alert_notes_append_only
    BEFORE UPDATE OR DELETE ON alert_notes
    FOR EACH ROW EXECUTE FUNCTION alert_notes_guard();
