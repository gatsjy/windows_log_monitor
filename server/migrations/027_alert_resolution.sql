-- 알림 종료 분류 (BACKLOG B-44, ADR-029 보완, ISMS 2.11.4): 해결할 때 정탐·오탐을 남겨 어떤 규칙을 고치거나 끌지 데이터로 정한다.
--   tp_malicious 정탐-의심 행위 / tp_expected 정탐-예상된 관리 작업 / fp_rule 오탐-규칙 문제 / fp_data 오탐-데이터 문제 /
--   undetermined 판단 불가 / auto 자동 해소(엔진, B-35 2단계). 다시 열면 비운다.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution TEXT
    CHECK (resolution IN ('tp_malicious', 'tp_expected', 'fp_rule', 'fp_data', 'undetermined', 'auto'));
-- 처리 기록에도 그때 고른 분류 — 다시 열었다가 다르게 닫아도 처음 판단이 남는다(alert_notes 는 고칠 수 없음)
ALTER TABLE alert_notes ADD COLUMN IF NOT EXISTS resolution TEXT;
-- 이미 엔진이 자동으로 해결한 알림은 '자동 해소'가 확실하다. 사람이 해결한 옛 알림은 비워 둔다(판단을 지어내지 않음)
UPDATE alerts SET resolution = 'auto' WHERE status = 'resolved' AND auto_resolved AND resolution IS NULL;
-- 규칙별 90일 품질(발생·오탐률·해결 시간)
CREATE INDEX IF NOT EXISTS alerts_rule_fired_idx ON alerts (rule, fired_at);
