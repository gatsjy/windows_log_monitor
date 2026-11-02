-- 확인 시간 초과 (BACKLOG B-43 2단계, ADR-055 보완): 확인만 하고 해결하지 않은 채 ack_timeout 이 지나면 알림을 다시 열고
-- 정책의 첫 단계 받는 곳에 다시 알린다. 대기열 한 줄의 action = 'acktimeout:<초>:<회차>' — 다시 확인했다가 또 넘기면 회차가 는다
-- (기본 키 (alert_id, notifier, action) 이라 회차마다 한 번). 처리 기록에는 'ack_timeout'(시스템이 다시 엶 — 사람이 다시 연 reopen 과
-- 다르다: 사람이 다시 연 알림은 자동 해결하지 않지만, 시간 초과로 다시 연 알림은 조건이 풀리면 자동 해결된다).
ALTER TABLE alert_deliveries DROP CONSTRAINT IF EXISTS alert_deliveries_action_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_action_check
    CHECK (action IN ('trigger', 'resolve') OR action ~ '^escalate:[0-9]+:(acked|resolved)$'
           OR action ~ '^acktimeout:[0-9]+:[0-9]+$');
ALTER TABLE alert_notes DROP CONSTRAINT alert_notes_action_check;
ALTER TABLE alert_notes ADD CONSTRAINT alert_notes_action_check
    CHECK (action IN ('note', 'ack', 'resolve', 'reopen', 'auto_resolve', 'escalate', 'ack_timeout'));
