-- 처음 보는 값(B-47, ADR-063): 배우는 동안 상한(max_terms) 때문에 두지 못한 조합이 있었나 — 자리가 다시 생기면 그 기간을 다시 거슬러
-- 배운다. 그렇지 않으면 배우는 기간에 늘 보이던 값이 상한을 올린 뒤 '처음 보는 값'으로 거짓 알림이 됐다(검토에서 재현).
ALTER TABLE new_terms_state ADD COLUMN IF NOT EXISTS learn_dropped BOOLEAN NOT NULL DEFAULT false;
