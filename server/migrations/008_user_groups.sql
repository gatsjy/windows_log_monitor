-- 008_user_groups: 사용자 그룹 (예: DB팀, 보안팀, 의료정보과) — 그룹 단위로 기능 권한과 조회 범위를 준다.
--   permissions       기능 권한 (app/auth/groups.py 의 PERMISSIONS). 관리자는 그룹과 상관없이 전부 가능
--   scope_categories  볼 수 있는 로그 분류 (비어 있으면 전체)
--   scope_hosts       볼 수 있는 PC (비어 있으면 전체, 'MED-*' 처럼 * 사용 가능)
-- 사용자가 여러 그룹에 속하면 권한·범위를 합친다. 그룹이 없는 조회자는 예전처럼 전체를 본다.

CREATE TABLE user_groups (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT        NOT NULL UNIQUE,
    description       TEXT        NOT NULL DEFAULT '',
    permissions       TEXT[]      NOT NULL DEFAULT '{}',
    scope_categories  TEXT[]      NOT NULL DEFAULT '{}',
    scope_hosts       TEXT[]      NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_group_members (
    group_id  BIGINT NOT NULL REFERENCES user_groups (id) ON DELETE CASCADE,
    user_id   BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX user_group_members_user_idx ON user_group_members (user_id);
