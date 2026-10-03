-- 003_auth: 로그인 사용자, 세션, 감사로그 위·변조 방지 (Phase 2 인증)

CREATE TABLE users (
    id                    BIGSERIAL PRIMARY KEY,
    username              TEXT        NOT NULL UNIQUE,          -- 소문자로 저장
    display_name          TEXT        NOT NULL DEFAULT '',
    role                  TEXT        NOT NULL CHECK (role IN ('admin', 'viewer')),
    password_hash         TEXT        NOT NULL,                 -- scrypt$N$r$p$salt$hash
    is_active             BOOLEAN     NOT NULL DEFAULT true,
    must_change_password  BOOLEAN     NOT NULL DEFAULT true,    -- 임시 비밀번호 → 첫 로그인 때 변경
    failed_count          INTEGER     NOT NULL DEFAULT 0,       -- 연속 로그인 실패 횟수
    locked_until          TIMESTAMPTZ,
    password_changed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at         TIMESTAMPTZ,
    last_login_ip         TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by            TEXT
);

-- 서버 세션. 쿠키에는 무작위 토큰, DB 에는 그 SHA-256 만 저장한다 (DB 가 유출돼도 세션 탈취 불가)
CREATE TABLE sessions (
    token_hash        TEXT        PRIMARY KEY,
    user_id           BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at  TIMESTAMPTZ NOT NULL DEFAULT now(),       -- 사용자가 마지막으로 조작한 시각 (유휴 만료 기준)
    expires_at        TIMESTAMPTZ NOT NULL,                     -- 절대 만료 시각
    ip                TEXT,
    user_agent        TEXT
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE INDEX audit_log_actor_idx  ON audit_log (actor, at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, at DESC);

-- 감사로그는 추가만 가능 (수정·삭제·TRUNCATE 금지).
-- 보관기간 만료 삭제만 예외: 같은 트랜잭션에서 SET LOCAL wlm.audit_purge = 'on' 을 한 경우 (app/partitions.py)
CREATE FUNCTION audit_log_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('wlm.audit_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_log 는 수정하거나 삭제할 수 없습니다 (append-only)';
END
$$;

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_guard();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_guard();
