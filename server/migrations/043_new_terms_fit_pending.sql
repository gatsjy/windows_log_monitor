-- 처음 보는 값(B-47, ADR-063): 배우는 기간을 규칙이 보는 소스(source·channel·PC)를 처음 받은 때에 아직 맞추지 않았나.
-- 처음 켤 때·조건을 바꿀 때 켜고, 거슬러 배우기가 끝난 뒤 맞추면(또는 맞출 필요가 없으면) 끈다. 그 소스가 아직 들어오지 않았으면 켠 채로
-- 두었다가 들어오는 때 맞춘다(규칙을 먼저 만들고 에이전트를 나중에 설치하면 정상 값이 모두 알림이 됐다 — 검토에서 재현).
ALTER TABLE new_terms_state ADD COLUMN IF NOT EXISTS fit_pending BOOLEAN NOT NULL DEFAULT false;
