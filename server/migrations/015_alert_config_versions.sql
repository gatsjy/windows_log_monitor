-- NEW-M2 (ADR-043): 적용한 알림 설정의 판본. 화면 저장·서버 파일 직접 수정·서버가 꺼져 있는 동안의 수정을
-- 모두 한 줄씩 남긴다. 예전에는 파일을 직접 고치면 로그 한 줄만 남고 바로 적용돼, 탐지를 끈 사실이 아무 데도 없었다.
-- 마지막 판본은 파일이 깨진 채로 서버가 다시 시작될 때 쓰는 설정이기도 하다(규칙 0개로 도는 것을 막음).
CREATE TABLE IF NOT EXISTS alert_config_versions (
    id          BIGSERIAL   PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    source      TEXT        NOT NULL CHECK (source IN ('ui', 'file', 'startup')),  -- 화면 · 실행 중 파일 수정 · 시작 때 발견
    actor       TEXT        NOT NULL,              -- 화면이면 사용자, 파일이면 system (누가 고쳤는지 알 수 없음)
    sha256      TEXT        NOT NULL,
    yaml        TEXT        NOT NULL,              -- 그때 적용한 파일 내용 그대로
    changes     JSONB       NOT NULL DEFAULT '[]', -- 직전 판본과의 차이 [{rule, sid, change, text, weakens}]
    weakened    BOOLEAN     NOT NULL DEFAULT false -- 탐지를 약하게 하는 변경이 있었는가
);
CREATE INDEX IF NOT EXISTS alert_config_versions_at_idx ON alert_config_versions (applied_at DESC);

-- 변경 관리 증적이라 감사로그처럼 추가만 한다. 보관기간 만료 삭제만 감사로그와 같은 스위치(wlm.audit_purge)로 허용.
CREATE FUNCTION alert_config_versions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('wlm.audit_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'alert_config_versions 는 수정하거나 삭제할 수 없습니다 (append-only)';
END
$$;

CREATE TRIGGER alert_config_versions_append_only
    BEFORE UPDATE OR DELETE ON alert_config_versions
    FOR EACH ROW EXECUTE FUNCTION alert_config_versions_guard();

CREATE TRIGGER alert_config_versions_no_truncate
    BEFORE TRUNCATE ON alert_config_versions
    FOR EACH STATEMENT EXECUTE FUNCTION alert_config_versions_guard();
