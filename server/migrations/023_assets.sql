-- B-55: 수집 대상 대조 — 로그를 보내야 할 시스템 목록(자산 목록)과 실제로 보내는 PC(agents)를 맞춰 본다.
-- 수집 PC 화면은 한 번이라도 보낸 PC 만 보여 아예 설치되지 않은 중요 서버는 어디에도 나타나지 않았다.
-- host = 비교용 짧은 이름(FQDN 의 첫 마디, 소문자) — 에이전트는 PC 이름을 짧게도 FQDN 으로도 보낸다. name = 목록에 적힌 그대로.
-- 목록은 화면에서 CSV(Get-ADComputer 내보내기 등)나 이름 목록을 붙여 넣어 통째로 바꾼다(audit: agent.assets.save).
CREATE TABLE IF NOT EXISTS assets (
    host       TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL,
    grade      TEXT        NOT NULL DEFAULT 'normal' CHECK (grade IN ('critical', 'normal')),
    note       TEXT        NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
