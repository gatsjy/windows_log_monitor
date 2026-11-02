-- 알림 묶음 전송 (BACKLOG B-41, ADR-057): 같은 받는 곳·규칙·종류의 알림을 한 통으로 보낸다. 증적은 알림마다 그대로(ADR-029).
--   batch_size = 그 통에 함께 간 알림 수 (1 = 혼자, NULL = 이 기능 전·보내지 않음) — 상세 패널 '묶어 보냄(n건)'.
--   묶음 간격(group_interval)은 같은 받는 곳·규칙·종류로 마지막에 보낸 시각부터 센다 → 받는 곳별 보낸 시각 색인.
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS batch_size INTEGER;
CREATE INDEX IF NOT EXISTS alert_deliveries_sent_idx ON alert_deliveries (notifier, sent_at) WHERE status = 'sent';
