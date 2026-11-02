-- 확인 안 된 알림 에스컬레이션 (BACKLOG B-43, ADR-055, ISMS 2.11.5): 기한이 지나도 확인(또는 해결)되지 않은 알림을 다른 받는 곳에
-- 다시 알린다. 전송은 기존 대기열(alert_deliveries)을 쓰고, 단계마다 action = 'escalate:<초>:<acked|resolved>' 한 줄씩
-- (기본 키 (alert_id, notifier, action) 이라 같은 단계는 한 번만). 보낼 차례에 확인·해결됐으면 건너뛴다(dispatcher._stale).
ALTER TABLE alert_deliveries DROP CONSTRAINT IF EXISTS alert_deliveries_action_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_action_check
    CHECK (action IN ('trigger', 'resolve') OR action ~ '^escalate:[0-9]+:(acked|resolved)$');
-- 처리 기록 타임라인에 '에스컬레이션' (누구에게 언제 다시 알렸는지 — 고칠 수 없는 증적)
ALTER TABLE alert_notes DROP CONSTRAINT alert_notes_action_check;
ALTER TABLE alert_notes ADD CONSTRAINT alert_notes_action_check
    CHECK (action IN ('note', 'ack', 'resolve', 'reopen', 'auto_resolve', 'escalate'));
