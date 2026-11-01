-- B-64: 저장한 검색 — 정기 점검(ISMS 2.9.5)의 반복 검색(관리자 로그온, 업무시간 외 접속)을 이름 붙여 저장·공유.
-- 담당자가 바뀌어도 점검 기준이 같게. 알림 규칙이 match.saved 로 쓰면 그 검색은 지우거나 이름을 바꿀 수 없다(쓰는 곳 — 라우터가 확인).
-- protected = 관리자만 고치거나 지울 수 있다(점검 기준으로 정한 검색).
CREATE TABLE IF NOT EXISTS saved_searches (
    id          BIGSERIAL   PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
    query       TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    owner       TEXT        NOT NULL,
    shared      BOOLEAN     NOT NULL DEFAULT false,
    protected   BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saved_searches_owner_idx ON saved_searches (owner);
