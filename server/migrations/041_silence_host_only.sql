-- PC 로만 맞추는 무음 (B-47 검토, ADR-063): 조회 범위가 정해진 사용자가 건 무음은 그 PC 의 알림에만 걸린다.
-- 대상 이름으로도 맞추면 처음 보는 값의 값 조합(계정 'ws-ops', IP '10.91.0.7' 처럼 PC 범위 모양인 값)이 같은 글자일 때
-- 범위 밖 PC 의 알림까지 막았다(검토에서 재현). 관리자가 건 무음은 예전처럼(false).
ALTER TABLE alert_silences ADD COLUMN IF NOT EXISTS host_only BOOLEAN NOT NULL DEFAULT false;
