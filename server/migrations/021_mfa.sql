-- B-74: 관리자 2단계 인증 (TOTP, RFC 6238). 이 서버는 병원 전체의 보안 로그·감사 증적을 쥔 자산인데 비밀번호 하나로 열렸다.
-- 비밀값은 app/secrets.py 로 암호화(WLM_SECRET_KEY), 복구 코드는 서버 키로 HMAC 한 값만. 마지막으로 받은 시간 칸(30초)을 기억해
-- 같은 코드를 두 번 쓰지 못하게 한다(재사용 방지).
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_secret_enc TEXT,            -- 등록 중이거나 등록한 비밀값 (암호화)
    ADD COLUMN IF NOT EXISTS mfa_enabled_at TIMESTAMPTZ,     -- 등록을 마친 시각 (NULL = 아직 안 씀)
    ADD COLUMN IF NOT EXISTS mfa_last_step  BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS mfa_recovery_codes_user_idx ON mfa_recovery_codes (user_id);

-- 비밀번호까지만 맞은 세션 (2단계 코드를 기다림) — 인증 API 일부만 쓸 수 있고 5분 뒤 끝난다. 이미 있던 세션은 그대로 유효
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_ok BOOLEAN NOT NULL DEFAULT true;
