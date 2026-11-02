-- 계정 표기 통일 열쇠 (BACKLOG B-54, ADR-062): 'HOSP\kim'·'kim@hosp.local'·'KIM' → 'kim'. 검색 account:·group_by·distinct 가 쓴다.
-- 행을 고치지 않고(수집 로그 다이제스트, ADR-050) 읽을 때 만든다 — 옛 행·복원한 달도 같은 열쇠.
-- querylang.account_key(Python)·accountKey(JS)와 한 글자도 같아야 한다(케이스 표 account_key, test_account_key 가 DB 로 비교):
--   1) 끝의 역슬래시를 빼고 본 마지막 '\' 뒤 (없으면 그대로)  2) 첫 '@' 가 둘째 글자 이후이고 그 뒤에 '.' 가 있으면 그 앞
--   3) A-Z 만 소문자 — lower() 는 로캘(glibc)에 따라 달라 이미지를 올리면 색인이 조용히 깨진다
-- 표현식 하나(FROM·STRICT·SET 없음)라 플래너가 펼쳐(inline) 줄마다 함수 호출 비용이 없다. 인자가 열 하나라 여러 번 써도 펼친다.
-- 같은 조각을 여러 번 계산하므로(PostgreSQL 은 공통 식을 묶지 않는다) '\'·'@' 가 없는 이름은 맨 앞에서 끝낸다.
-- 이 함수는 고치지 않는다(CREATE OR REPLACE 금지) — 뜻을 바꾸면 새 이름(_v2)·새 색인·새 ADR. 정의는 시험이 고정한다.
CREATE FUNCTION wlm_user_key(u text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
RETURN translate(
    CASE
        -- 대부분(Windows TargetUserName·syslog)은 '\'·'@' 가 없다 — 바로 소문자만 (수집 COPY 비용, PERFORMANCE.md §2.10)
        WHEN strpos(u, '\') = 0 AND strpos(u, '@') = 0 THEN u
        WHEN strpos(CASE WHEN strpos(rtrim(u, '\'), '\') > 0
                         THEN substr(u, length(rtrim(u, '\')) - strpos(reverse(rtrim(u, '\')), '\') + 2) ELSE u END, '@') >= 2
         AND strpos(substr(CASE WHEN strpos(rtrim(u, '\'), '\') > 0
                                THEN substr(u, length(rtrim(u, '\')) - strpos(reverse(rtrim(u, '\')), '\') + 2) ELSE u END,
                           strpos(CASE WHEN strpos(rtrim(u, '\'), '\') > 0
                                       THEN substr(u, length(rtrim(u, '\')) - strpos(reverse(rtrim(u, '\')), '\') + 2) ELSE u END, '@') + 1),
                    '.') > 0
        THEN left(CASE WHEN strpos(rtrim(u, '\'), '\') > 0
                       THEN substr(u, length(rtrim(u, '\')) - strpos(reverse(rtrim(u, '\')), '\') + 2) ELSE u END,
                  strpos(CASE WHEN strpos(rtrim(u, '\'), '\') > 0
                              THEN substr(u, length(rtrim(u, '\')) - strpos(reverse(rtrim(u, '\')), '\') + 2) ELSE u END, '@') - 1)
        ELSE CASE WHEN strpos(rtrim(u, '\'), '\') > 0
                  THEN substr(u, length(rtrim(u, '\')) - strpos(reverse(rtrim(u, '\')), '\') + 2) ELSE u END
    END,
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');

-- 부모 색인만 만든다(ON ONLY — 카탈로그만, 즉시). 있던 월 파티션의 색인은 서버가 뒤에서 하나씩 CONCURRENTLY 로 만들어 붙인다
-- (partitions.build_account_indexes) — 행 1억 개를 이 트랜잭션에서 훑으면 기동이 몇십 분 멈춰 설치 스크립트의 기동 대기(2분)를 넘는다.
-- 새로 만드는 파티션(다음 달·복원)은 PostgreSQL 이 이 색인을 바로 함께 만든다. 모든 파티션이 붙으면 부모 색인이 유효해진다.
CREATE INDEX IF NOT EXISTS events_account_ts_idx ON ONLY events (wlm_user_key(username), ts DESC) WHERE username IS NOT NULL;
