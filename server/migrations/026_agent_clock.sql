-- 에이전트 시계 차이 (BACKLOG B-57 1단계, ISMS 2.9.6): 하트비트의 발생 시각(PC 시계, Fluent Bit 의 date)과 받은 시각의 차이.
-- 차이 = (서버 시계 − PC 시계) + 전송 지연. 지연은 0 이상이라 일정 시간 동안의 가장 작은 값이 시계 차이에 가깝다(NTP 의 최소 지연 거르기).
-- 창 두 개(지금·앞 15분)의 최솟값을 두어 오래된 값이 남지 않으면서도 창이 막 바뀐 직후에 지연 큰 값 하나로 튀지 않게 한다.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS hb_lag_ms BIGINT;            -- 마지막 하트비트의 (받은 시각 − PC 시각)
ALTER TABLE agents ADD COLUMN IF NOT EXISTS clock_cur_ms BIGINT;         -- 지금 창의 최솟값
ALTER TABLE agents ADD COLUMN IF NOT EXISTS clock_prev_ms BIGINT;        -- 앞 창의 최솟값
ALTER TABLE agents ADD COLUMN IF NOT EXISTS clock_window_at TIMESTAMPTZ; -- 지금 창을 시작한 시각
