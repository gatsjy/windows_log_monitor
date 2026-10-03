-- 004_settings: 화면에서 관리하는 환경설정 — 알림 수신자·그룹, 외부 연동(웹훅·Oracle), 메일 서버

-- 키-값 설정 (예: smtp). 비밀값은 secret_enc 에 암호화해서 (app/secrets.py, 키 = WLM_SECRET_KEY)
CREATE TABLE app_settings (
    key         TEXT        PRIMARY KEY,
    value       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    secret_enc  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT
);

-- 알림 받는 사람 (로그인 계정과 별개 — 로그인하지 않는 사람도 알림을 받을 수 있다)
CREATE TABLE contacts (
    id          BIGSERIAL   PRIMARY KEY,
    name        TEXT        NOT NULL,
    email       TEXT,
    phone       TEXT,
    department  TEXT        NOT NULL DEFAULT '',
    memo        TEXT        NOT NULL DEFAULT '',
    is_active   BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 수신 그룹. 알림 규칙(config/alerts.yaml)의 notify 에 그룹 이름을 쓴다
CREATE TABLE contact_groups (
    id           BIGSERIAL   PRIMARY KEY,
    name         TEXT        NOT NULL UNIQUE,
    description  TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE contact_group_members (
    group_id    BIGINT NOT NULL REFERENCES contact_groups (id) ON DELETE CASCADE,
    contact_id  BIGINT NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, contact_id)
);

-- 외부 연동 (웹훅, Oracle DB). notify 에 이름을 쓴다. 이름은 그룹과도 겹치면 안 된다 (앱에서 확인)
CREATE TABLE channels (
    id          BIGSERIAL   PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    type        TEXT        NOT NULL CHECK (type IN ('webhook', 'oracle')),
    description TEXT        NOT NULL DEFAULT '',
    is_active   BOOLEAN     NOT NULL DEFAULT true,
    config      JSONB       NOT NULL DEFAULT '{}'::jsonb,   -- 비밀이 아닌 설정
    secret_enc  TEXT,                                       -- 암호화된 비밀값 (비밀번호, URL 토큰, 인증 헤더)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT
);

-- 기본 수신 그룹 (config/alerts.yaml 기본 규칙이 사용). 구성원은 화면에서 추가
INSERT INTO contact_groups (name, description) VALUES ('운영팀', '기본 알림 수신 그룹');
