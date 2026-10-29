-- B-35 2단계 (ADR-029 보완): 자동 해결과 해소 통지, 사고관리 연동용 묶음 키.
--   운영 규칙(PC 수신 끊김, resolve: auto 를 단 규칙)은 조건이 풀리면 엔진이 '해결됨(자동)'으로 바꾸고,
--   그 알림을 받은 곳에 해소 통지를 보낸다. 해소 통지도 전송 대기열(alert_deliveries)을 같이 쓴다 — 받는 곳마다 줄 하나가
--   알림(trigger)과 해소(resolve) 두 줄이 될 수 있어 기본 키에 action 을 더한다.

ALTER TABLE alert_deliveries
    ADD COLUMN IF NOT EXISTS action    TEXT        NOT NULL DEFAULT 'trigger' CHECK (action IN ('trigger', 'resolve')),
    -- 대기열에 들어온 시각. 하루가 지난 대기 행을 버릴 때 해소 통지는 알림 발생이 아니라 이 시각으로 센다
    -- (이틀 끊겼던 PC 가 돌아온 해소 통지가 넣자마자 '하루 지남'으로 버려지지 않게)
    ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_pkey;
ALTER TABLE alert_deliveries ADD PRIMARY KEY (alert_id, notifier, action);

-- 자동으로 해결한 알림 (사람이 해결하면 false). 보고서는 따로 세고, 해결까지 걸린 시간(중앙값)은 사람이 해결한 것만
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS auto_resolved BOOLEAN NOT NULL DEFAULT false;

-- 처리 기록에 '자동 해결'. 제약을 바꾸는 것은 행을 고치지 않으므로 수정 금지 트리거와 부딪히지 않는다
ALTER TABLE alert_notes DROP CONSTRAINT alert_notes_action_check;
ALTER TABLE alert_notes ADD CONSTRAINT alert_notes_action_check
    CHECK (action IN ('note', 'ack', 'resolve', 'reopen', 'auto_resolve'));
