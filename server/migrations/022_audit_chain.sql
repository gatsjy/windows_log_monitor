-- B-71: 감사로그 위·변조 증명 — 해시 체인.
-- 트리거로 수정·삭제를 막아도 DB 슈퍼유저(이 배포의 wlm)는 트리거를 끄고 고칠 수 있고 그 흔적도 같은 DB 에만 남는다.
-- 행마다 앞 행의 해시를 넣은 SHA-256 을 남기면 가운데 행을 고치거나 지우면 그 뒤가 모두 어긋난다. 끝을 지우거나 체인을 통째로 다시 쓰는 것은
-- DB 밖에 매일 남기는 앵커(보관 폴더의 integrity-*.json → 외부 저장소 복제, 점검 보고서 메일)로 드러난다. 검증은 app/integrity.py(파이썬으로 따로 계산).

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS row_hash  TEXT;

-- 행위별 '마지막에 넣은' 기록(번호 순서) — 마지막 검증·앵커를 시각이 아니라 번호로 고른다(repository.latest_audit_by_id)
CREATE INDEX IF NOT EXISTS audit_log_action_id_idx ON audit_log (action, id DESC);

-- 한 줄짜리 머리: 마지막 행의 번호·해시. 이 행을 잠그는 것으로 감사로그 INSERT 가 줄을 선다(체인 순서 = 번호 순서).
-- start_hash = 체인 첫 행의 앞 해시(빈 글의 해시 — 상수), backfill_max_id = 이 마이그레이션이 해시를 채운 기존 행의 마지막 번호(정보용)
CREATE TABLE IF NOT EXISTS audit_chain (
    id              INTEGER     PRIMARY KEY CHECK (id = 1),
    start_hash      TEXT        NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    backfill_rows   BIGINT      NOT NULL,
    backfill_max_id BIGINT      NOT NULL,
    last_id         BIGINT      NOT NULL,
    last_hash       TEXT        NOT NULL
);

-- 행 하나를 글자로: 칸마다 NULL 이면 'N', 아니면 '글자 수:값' 을 | 로 — 칸 사이로 글자를 옮기거나 NULL 과 빈 글을 바꿔도 같은 글이
-- 되지 않게(검토에서 재현: 'NULL → 빈 글' 바꾸기가 통과). 시각은 UTC 마이크로초(세션 시간대와 무관), detail 은 jsonb 의 글 모양
-- (키 순서가 정해져 있다). 파이썬 검증기(app/integrity.canonical)와 한 글자도 다르면 안 된다.
-- 칸마다 CASE 를 풀어 쓴다 — 도우미 함수로 묶으면 인자(detail::text)를 여러 번 쓰는 함수라 인라인되지 않아 행마다 7배 느렸다
-- (100만 행 업그레이드가 십수 분, PERFORMANCE.md §2.7)
CREATE OR REPLACE FUNCTION audit_log_canonical(p_prev TEXT, p_id BIGINT, p_at TIMESTAMPTZ, p_actor TEXT, p_ip TEXT,
                                               p_action TEXT, p_target TEXT, p_detail JSONB) RETURNS TEXT
LANGUAGE sql IMMUTABLE AS $$
    SELECT concat_ws('|',
        CASE WHEN p_prev IS NULL THEN 'N' ELSE char_length(p_prev) || ':' || p_prev END,
        p_id::text,
        ((extract(epoch FROM p_at) * 1000000)::bigint)::text,
        CASE WHEN p_actor IS NULL THEN 'N' ELSE char_length(p_actor) || ':' || p_actor END,
        CASE WHEN p_ip IS NULL THEN 'N' ELSE char_length(p_ip) || ':' || p_ip END,
        CASE WHEN p_action IS NULL THEN 'N' ELSE char_length(p_action) || ':' || p_action END,
        CASE WHEN p_target IS NULL THEN 'N' ELSE char_length(p_target) || ':' || p_target END,
        CASE WHEN p_detail IS NULL THEN 'N' ELSE char_length(p_detail::text) || ':' || p_detail::text END)
$$;

CREATE OR REPLACE FUNCTION audit_log_hash(p_canonical TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE AS $$ SELECT encode(sha256(convert_to(p_canonical, 'UTF8')), 'hex') $$;

-- 이미 있는 행에도 해시를 채운다 — 따로 묶어 두면(genesis) 업그레이드 직후 앵커가 해시 없는 행을 가리키고, 그 행들의 만료 삭제를
-- 설명할 수 없어 거짓 경보가 났다(검토에서 재현). 내용(at·actor·…)은 건드리지 않고 해시 칸만 채운다. 수정 금지 트리거는 이 트랜잭션에서만 끈다
DO $$
DECLARE
    h TEXT := audit_log_hash('');
    start TEXT := h;
    prev TEXT;
    r RECORD;
    n BIGINT := 0;
    top BIGINT := 0;
BEGIN
    IF EXISTS (SELECT 1 FROM audit_chain) THEN
        RETURN;
    END IF;
    CREATE TEMP TABLE audit_backfill (id BIGINT PRIMARY KEY, prev_hash TEXT, row_hash TEXT) ON COMMIT DROP;
    FOR r IN SELECT id, at, actor, actor_ip, action, target, detail FROM audit_log ORDER BY id LOOP
        prev := h;
        h := audit_log_hash(audit_log_canonical(prev, r.id, r.at, r.actor, r.actor_ip, r.action, r.target, r.detail));
        INSERT INTO audit_backfill VALUES (r.id, prev, h);
        n := n + 1;
        top := r.id;
    END LOOP;
    IF n > 0 THEN
        ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;
        UPDATE audit_log a SET prev_hash = b.prev_hash, row_hash = b.row_hash FROM audit_backfill b WHERE a.id = b.id;
        ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;
    END IF;
    INSERT INTO audit_chain (id, start_hash, backfill_rows, backfill_max_id, last_id, last_hash)
    VALUES (1, start, n, top, top, h);
END
$$;

-- 새 행: 머리를 잠그고, 잠근 뒤 번호를 새로 받는다 — 기본값으로 먼저 받은 번호는 잠금을 기다리는 순서와 달라 체인이 번호 순서와 어긋난다.
-- 시각도 여기서 정한다(잠금 순서 = 시각 순서). 넣는 쪽이 at 을 주면 체인을 지키면서 과거·미래의 기록을 만들 수 있었다(검토에서 재현).
-- 머리가 없으면 넣지 않는다 — 체인 없이 조용히 쌓이면 증명이 꺼진 것을 아무도 모른다
CREATE OR REPLACE FUNCTION audit_log_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    head RECORD;
BEGIN
    SELECT last_hash INTO head FROM audit_chain WHERE id = 1 FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_chain 머리가 없어 감사로그를 남길 수 없습니다 (위·변조 증명, B-71)';
    END IF;
    NEW.id := nextval(pg_get_serial_sequence('audit_log', 'id'));
    NEW.at := clock_timestamp();
    NEW.prev_hash := head.last_hash;
    NEW.row_hash := audit_log_hash(audit_log_canonical(NEW.prev_hash, NEW.id, NEW.at, NEW.actor, NEW.actor_ip,
                                                       NEW.action, NEW.target, NEW.detail));
    UPDATE audit_chain SET last_id = NEW.id, last_hash = NEW.row_hash WHERE id = 1;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS audit_log_chain ON audit_log;
CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_chain();

-- 머리 지키기: 시작 값은 바꿀 수 없고, 마지막 번호는 앞으로만 간다, 지우거나 비울 수 없다 — 트리거를 끄지 않고 머리를 되돌려
-- 끝을 감추거나 시작 해시를 바꿔 앞부분 삭제를 감추는 것을 막는다(검토에서 재현). 슈퍼유저는 끌 수 있다 — 그때는 DB 밖 앵커가 잡는다
CREATE OR REPLACE FUNCTION audit_chain_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.id = OLD.id AND NEW.start_hash = OLD.start_hash AND NEW.started_at = OLD.started_at
       AND NEW.backfill_rows = OLD.backfill_rows AND NEW.backfill_max_id = OLD.backfill_max_id AND NEW.last_id > OLD.last_id THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit_chain 은 감사로그 INSERT 만 앞으로 옮길 수 있습니다 (위·변조 증명, B-71)';
END
$$;

DROP TRIGGER IF EXISTS audit_chain_guard ON audit_chain;
CREATE TRIGGER audit_chain_guard BEFORE UPDATE OR DELETE ON audit_chain FOR EACH ROW EXECUTE FUNCTION audit_chain_guard();
DROP TRIGGER IF EXISTS audit_chain_no_truncate ON audit_chain;
CREATE TRIGGER audit_chain_no_truncate BEFORE TRUNCATE ON audit_chain FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_guard();
