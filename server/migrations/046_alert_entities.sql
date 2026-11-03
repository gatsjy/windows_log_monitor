-- 알림의 개체 (BACKLOG B-67, ADR-064): 이 알림이 어느 PC·계정·IP 에 관한 것인가.
-- 관련 알림(같은 개체, 앞뒤 1시간)과 개체 페이지(#/entity/host|user|ip/<값>)가 이 열로 찾는다.
-- 계정은 표기 통일 열쇠(wlm_user_key, 마이그레이션 038)로 — kim·HOSP\kim·kim@hosp.local 이 한 사람.
ALTER TABLE alerts
    ADD COLUMN entity_hosts    text[] NOT NULL DEFAULT '{}',
    ADD COLUMN entity_accounts text[] NOT NULL DEFAULT '{}',
    ADD COLUMN entity_ips      text[] NOT NULL DEFAULT '{}';

-- 채우는 규칙은 이 함수 하나 — 새 알림(repository.insert_alert)과 옛 알림(아래 UPDATE)이 같이 쓴다.
--   대상: 묶음 기준이 host·ip·user·account 인 대상 이름, PC 끊김의 PC, 채널 끊김·처음 보는 값의 PC, 처음 보는 값 한 조합의 값
--         — 알림이 '그 개체에 관한 것'이라 늘 넣는다.
--   여러 값: 처음 보는 값이 몰려온 묶음의 값들, 본 것(observed — 평가 때 조건에 맞은 로그에서 센 PC·계정·IP, 상한 + 1개까지).
--         observed 가 NULL 이면(옛 알림·세기가 시간 초과) 표본 로그의 PC 로. 종류마다 서로 다른 값이 10개를 넘으면 넣지 않는다 —
--         PC 수십 대에 걸친 알림이 모든 PC 의 관련 알림이 되면 관련 알림이 아무 뜻이 없다(repository.ENTITY_MAX 와 같게).
-- 256자를 넘는 값은 넣지 않는다 — 로그에서 온 긴 값이 GIN 색인 한 줄 상한을 넘으면 알림 INSERT 가 실패한다.
-- payload 는 오래된·깨진 모양일 수 있어 배열·객체인지 보고 꺼낸다(마이그레이션이 옛 행 하나 때문에 멈추지 않게).
-- 이 함수는 고치지 않는다(CREATE OR REPLACE 금지) — 뜻을 바꾸면 새 이름(_v2)·새 ADR. 시험(test_alert_entities)이 표로 고정한다.
CREATE FUNCTION wlm_alert_entities(p jsonb, kind text, observed text[]) RETURNS text[]
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
WITH t AS (
    SELECT CASE WHEN jsonb_typeof(p->'terms') = 'object' THEN p->'terms' END AS terms
), f AS (   -- 처음 보는 값의 필드 → 개체 종류 (위치는 0부터)
    SELECT (e.i - 1)::int AS i,
           CASE e.name WHEN 'host' THEN 'host' WHEN 'ip' THEN 'ip' WHEN 'user' THEN 'account' WHEN 'account' THEN 'account' END AS k
      FROM t, jsonb_array_elements_text(CASE WHEN jsonb_typeof(t.terms->'fields') = 'array' THEN t.terms->'fields' ELSE '[]' END)
           WITH ORDINALITY e(name, i)
), subject(v, k) AS (
    SELECT p->>'group_key',
           CASE WHEN p->>'kind' = 'agent_silent' THEN 'host'
                WHEN p->>'kind' = 'count' AND p->>'group_by' IN ('host', 'ip') THEN p->>'group_by'
                WHEN p->>'kind' = 'count' AND p->>'group_by' IN ('user', 'account') THEN 'account' END
    UNION ALL SELECT p->'stream'->>'host', 'host' WHERE jsonb_typeof(p->'stream') = 'object'
    UNION ALL SELECT t.terms->>'host', 'host' FROM t
    UNION ALL SELECT t.terms->'values'->>f.i, f.k FROM t, f WHERE jsonb_typeof(t.terms->'values') = 'array'
), many(v, k) AS (
    SELECT it->'values'->>f.i, f.k
      FROM t, f, jsonb_array_elements(CASE WHEN jsonb_typeof(t.terms->'items') = 'array' THEN t.terms->'items' ELSE '[]' END) it
     WHERE jsonb_typeof(it->'values') = 'array'
), seen(v, k) AS (
    SELECT unnest(observed), kind WHERE observed IS NOT NULL
    UNION ALL
    SELECT s->>'host', 'host'
      FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p->'samples') = 'array' THEN p->'samples' ELSE '[]' END) s
     WHERE observed IS NULL AND jsonb_typeof(s) = 'object'
), tagged(v, o) AS (
    SELECT CASE WHEN k = 'account' THEN wlm_user_key(v) ELSE v END, 0 FROM subject WHERE k = kind
    UNION ALL SELECT CASE WHEN k = 'account' THEN wlm_user_key(v) ELSE v END, 1 FROM many WHERE k = kind
    UNION ALL SELECT CASE WHEN k = 'account' THEN wlm_user_key(v) ELSE v END, 2 FROM seen WHERE k = kind
), clean(v, o) AS (
    SELECT v, o FROM tagged WHERE v <> '' AND length(v) <= 256
), kept(v, o) AS (
    SELECT v, o FROM clean c
     WHERE c.o = 0 OR (SELECT count(DISTINCT x.v) FROM clean x WHERE x.o = c.o) <= 10
)
SELECT COALESCE(array_agg(v ORDER BY o, v), '{}') FROM (SELECT v, min(o) AS o FROM kept GROUP BY v) d
$$;

UPDATE alerts SET entity_hosts    = wlm_alert_entities(payload, 'host', NULL),
                  entity_accounts = wlm_alert_entities(payload, 'account', NULL),
                  entity_ips      = wlm_alert_entities(payload, 'ip', NULL);

-- 개체 페이지(한 개체의 기간 안 알림)용. 관련 알림(앞뒤 1시간)은 발생 시각 색인으로 좁힌 뒤 거른다
CREATE INDEX alerts_entity_hosts_idx    ON alerts USING gin (entity_hosts);
CREATE INDEX alerts_entity_accounts_idx ON alerts USING gin (entity_accounts);
CREATE INDEX alerts_entity_ips_idx      ON alerts USING gin (entity_ips);
