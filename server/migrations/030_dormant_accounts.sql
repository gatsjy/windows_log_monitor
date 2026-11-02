-- 장기 미사용 계정 자동 잠금 (BACKLOG B-72 1단계, ISMS 2.5.6): WLM_DORMANT_DAYS(기본 90) 동안 로그인하지 않은 계정을 매일 정리 때 끈다.
--   disabled_reason = 'dormant' 이면 화면에 '장기 미사용으로 잠김'. 관리자가 다시 켜면 reenabled_at 부터 다시 센다
--   (그러지 않으면 옛 마지막 로그인 때문에 다음 정리에서 바로 다시 잠긴다).
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_reason TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reenabled_at TIMESTAMPTZ;
