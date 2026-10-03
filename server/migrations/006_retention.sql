-- 006_retention: 보관 파일에서 다시 불러온 파티션은 일정 기간 자동 정리에서 제외 (조사용)
CREATE TABLE partition_holds (
    name        TEXT        PRIMARY KEY,       -- 파티션 이름 (events_YYYY_MM)
    hold_until  TIMESTAMPTZ NOT NULL,
    reason      TEXT        NOT NULL DEFAULT '',
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
