-- 처음 보는 값(B-47, ADR-063): 배우는 기간이 어디서 시작했고(learn_from) 얼마였는지(learn_sec) — 규칙의 learn 을 바꾸면 배우는 중인
-- 기간에 맞춰 줄이거나 늘린다. 저장하지 않으면 learn 을 고쳐도 처음 정한 끝(learn_until)이 그대로라 '배우는 중'이 이어졌다(검토에서 재현).
-- 예전 상태는 NULL — 처음 볼 때 지금 learn 으로 채운다(바꾸지 않음).
ALTER TABLE new_terms_state ADD COLUMN IF NOT EXISTS learn_from TIMESTAMPTZ;
ALTER TABLE new_terms_state ADD COLUMN IF NOT EXISTS learn_sec INT;
