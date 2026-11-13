-- 다 찬 월 파티션의 색인을 한 번 다시 만든 기록 (ADR-067).
-- (값, ts DESC) 색인은 받는 순서(시각이 느는 순서)로 넣으면 잎 페이지가 반씩 쪼개져 채움이 50% 에 머문다(실측).
-- 수집이 끝난 지난달 파티션을 REINDEX 하면 색인이 약 40% 준다 — 같은 파티션을 두 번 하지 않게 남긴다.
CREATE TABLE partition_compactions (
    relid              oid PRIMARY KEY,   -- 파티션 테이블 oid: 지웠다가 같은 이름으로 다시 만든(복원한) 달은 새 oid 라 다시 한다
    name               text        NOT NULL,
    compacted_at       timestamptz NOT NULL DEFAULT now(),
    index_bytes_before bigint      NOT NULL,
    index_bytes_after  bigint      NOT NULL,
    seconds            real        NOT NULL
);
