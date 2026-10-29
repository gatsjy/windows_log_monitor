-- B-34 (ADR-045): 알림 전송을 평가와 나눈다. alert_deliveries 가 전송 대기열이 된다.
--   전송기가 next_attempt_at 이 지난 pending·failed 행을 하나씩 잡아(claimed_at) 보낸다.
--   DEFAULT now(): 이전 판으로 되돌린 동안 예전 코드가 넣은 행도 다시 올리면 바로 보낼 차례가 되게.
ALTER TABLE alert_deliveries
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS claimed_at      TIMESTAMPTZ;        -- 보내는 중 (서버가 멈추면 다음 시작 때 풀어 다시 보낸다)

-- 예전 재시도 간격(1·5·15·60분)을 이어 간다 — 올린 직후 실패분이 한꺼번에 나가지 않게
UPDATE alert_deliveries
   SET next_attempt_at = updated_at + (ARRAY[1, 5, 15, 60])[LEAST(GREATEST(attempts, 1), 4)] * interval '1 minute'
 WHERE status = 'failed' AND attempts < 5;
-- 다섯 번 실패하고 다음 주기를 기다리던 행 (예전 엔진은 다음 주기에 gave_up 으로 바꿨다)
UPDATE alert_deliveries SET status = 'gave_up', updated_at = now() WHERE status = 'failed' AND attempts >= 5;

CREATE INDEX IF NOT EXISTS alert_deliveries_due_idx ON alert_deliveries (notifier, next_attempt_at)
    WHERE status IN ('pending', 'failed');
