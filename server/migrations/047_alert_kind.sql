-- 알림 종류 (BACKLOG B-67 2단계 검토, ADR-065): payload.kind 를 열로 — 상관 알림은 조회 범위가 없는 사용자만 보는데, 지금 설정의 규칙 종류로
-- 판단하면 상관 규칙을 지우거나 이름을 바꾼 뒤 옛 상관 알림('PC DC-01')이 PC 패턴 'PC*' 범위의 사용자에게 보였다(검토에서 재현).
-- 목록·숫자는 payload 를 읽으면 느려서(terms_host 와 같은 이유, 마이그레이션 040) 열로 둔다. 새 알림은 insert_alert 가 모두 채우고,
-- 옛 알림은 판단에 쓰는 상관 알림만 채운다(전체를 다시 쓰지 않게 — 그 밖의 옛 알림은 NULL = 종류 모름).
ALTER TABLE alerts ADD COLUMN kind text;
UPDATE alerts SET kind = 'correlation' WHERE payload->>'kind' = 'correlation';
