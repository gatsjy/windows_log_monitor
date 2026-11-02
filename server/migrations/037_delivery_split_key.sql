-- 거절된 묶음을 반씩 다시 (BACKLOG B-41 3차 검토 보완, ADR-057): split_key = 같은 반쪽의 행끼리만 다시 묶는다(그 반쪽 첫 알림의 번호).
-- 035 의 solo(하나씩)는 거절된 묶음 300개를 300통으로 다시 보내 묶음 전송의 뜻을 되돌렸다 — 반씩 나누면 나쁜 알림 하나에 약 2·log2(n)통.
-- solo 칸은 남기지만 더는 쓰지 않는다(마이그레이션은 추가만).
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS split_key BIGINT;
