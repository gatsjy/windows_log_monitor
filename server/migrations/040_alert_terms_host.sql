-- 처음 보는 값(B-47) 알림의 PC 를 칸으로 (ADR-063): 알림의 '같은 대상'은 (규칙, 대상 이름, 이 PC) 셋이다.
-- payload->'terms'->>'host' 로 읽으면 목록·숫자·'함께 해결'마다 모든 알림의 payload(표본 5개)를 풀어 5배 넘게 느렸다(검토에서 측정).
-- 다른 종류의 알림은 NULL. 넣을 때 repository.insert_alert 가 채운다.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS terms_host TEXT;
UPDATE alerts SET terms_host = payload->'terms'->>'host' WHERE payload->>'kind' = 'new_terms' AND terms_host IS NULL;
