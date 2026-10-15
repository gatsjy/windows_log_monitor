-- 010_alert_notes_no_truncate: 알림 처리 기록(alert_notes)도 audit_log 처럼 TRUNCATE 를 막는다.
--   009 의 행 트리거는 UPDATE·DELETE 만 막아서 'TRUNCATE alert_notes'(또는 'TRUNCATE alerts CASCADE') 한 문장으로
--   처리 기록 전체를 지울 수 있었다. 보관기간 만료 삭제는 DELETE(연쇄 삭제)라 영향이 없다.
--   009 를 고치지 않고 새 파일로 둔다 (마이그레이션은 추가만, AGENTS.md 절대 규칙 3).
CREATE FUNCTION alert_notes_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'alert_notes 는 수정하거나 삭제할 수 없습니다 (알림 처리 기록)';
END
$$;

CREATE TRIGGER alert_notes_no_truncate
    BEFORE TRUNCATE ON alert_notes
    FOR EACH STATEMENT EXECUTE FUNCTION alert_notes_no_truncate();
