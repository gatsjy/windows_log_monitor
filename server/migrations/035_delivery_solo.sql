-- 묶음을 받는 쪽이 거절했을 때 (BACKLOG B-41 검토 보완, ADR-057): 알림 하나의 내용 때문에 거절될 수 있으므로 그 묶음의 행을
-- 하나씩 다시 보낸다 — solo = 이 행은 다시 묶지 않는다. 예전에는 묶음을 반씩 나눠 그 자리에서 다시 보냈는데, 한 줄이 전송 자리를
-- 오래 쥐고(다른 받는 곳의 심각 알림이 기다림) 오래된 잡힘 정리가 보내는 중인 행을 풀어 두 번 보냈다(검토에서 재현).
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS solo BOOLEAN NOT NULL DEFAULT false;
