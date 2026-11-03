-- 처음 보는 값(B-47, ADR-063): 배우다 상한으로 두지 못한 값이 있던 받은 시각 구간 — 자리가 생기면 그 구간을 그대로 다시 배운다.
-- learn_until(앞으로 배우는 끝)으로 구간을 짐작하면 조건을 바꾼 뒤의 다시 배우기에서 넘친 값을 엉뚱한 구간에서 찾아 거짓 알림이 됐다(검토에서 재현).
ALTER TABLE new_terms_state ADD COLUMN IF NOT EXISTS dropped_from TIMESTAMPTZ;
ALTER TABLE new_terms_state ADD COLUMN IF NOT EXISTS dropped_to TIMESTAMPTZ;
