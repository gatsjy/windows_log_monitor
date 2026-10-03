-- 005_min_severity: 수신 그룹·외부 연동마다 '받을 최소 알림 수준'
-- info(전부) < warning < error < critical. 기준보다 낮은 알림은 보내지 않고 전송 이력에 skipped 로 남긴다.
ALTER TABLE contact_groups ADD COLUMN min_severity TEXT NOT NULL DEFAULT 'info'
    CHECK (min_severity IN ('info', 'warning', 'error', 'critical'));
ALTER TABLE channels ADD COLUMN min_severity TEXT NOT NULL DEFAULT 'info'
    CHECK (min_severity IN ('info', 'warning', 'error', 'critical'));
