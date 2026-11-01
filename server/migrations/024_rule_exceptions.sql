-- B-46: 알림 규칙 예외 — 백업·의료장비 연동 서비스 계정, 유지보수 업체 IP 같은 영구적·필드 단위 제외.
-- 예전에는 규칙 문장에 -user: 를 직접 써야 해서 누가·왜·언제까지 뺐는지 남지 않았고, 업그레이드의 alerts.yaml.new 와 손으로 합쳐야 했다.
-- 예외 하나 = 검색 조건 하나(term, 정본 표기) — 엔진이 규칙 문장에 제외 항(-term)으로 합친다(값이 없는 이벤트는 남기는 검색 문장의 제외 의미).
-- 지우지 않는다: 끝내기 = ended_at 을 채움(한 번만). 처리 기록처럼 트리거로 내용 수정·삭제·TRUNCATE 를 막는다.
CREATE TABLE IF NOT EXISTS rule_exceptions (
    id          BIGSERIAL   PRIMARY KEY,
    rule        TEXT        NOT NULL,
    term        TEXT        NOT NULL,
    reason      TEXT        NOT NULL CHECK (char_length(btrim(reason)) >= 2),
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    review_at   TIMESTAMPTZ,
    ended_at    TIMESTAMPTZ,
    ended_by    TEXT,
    end_reason  TEXT
);
CREATE INDEX IF NOT EXISTS rule_exceptions_open_idx ON rule_exceptions (rule) WHERE ended_at IS NULL;

CREATE OR REPLACE FUNCTION rule_exceptions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL
       AND (NEW.id, NEW.rule, NEW.term, NEW.reason, NEW.created_by, NEW.created_at, NEW.expires_at, NEW.review_at)
           IS NOT DISTINCT FROM (OLD.id, OLD.rule, OLD.term, OLD.reason, OLD.created_by, OLD.created_at, OLD.expires_at, OLD.review_at) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'rule_exceptions 는 끝내기(ended_at)만 한 번 할 수 있습니다 (B-46)';
END
$$;

DROP TRIGGER IF EXISTS rule_exceptions_guard ON rule_exceptions;
CREATE TRIGGER rule_exceptions_guard BEFORE UPDATE OR DELETE ON rule_exceptions FOR EACH ROW EXECUTE FUNCTION rule_exceptions_guard();
DROP TRIGGER IF EXISTS rule_exceptions_no_truncate ON rule_exceptions;
CREATE TRIGGER rule_exceptions_no_truncate BEFORE TRUNCATE ON rule_exceptions FOR EACH STATEMENT EXECUTE FUNCTION rule_exceptions_guard();
