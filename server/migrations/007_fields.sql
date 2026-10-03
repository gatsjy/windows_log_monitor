-- 007_fields: 분류(category)와 공통 필드(사용자·IP)
--   category  로그 분류: security, system, application, powershell, defender, rdp, sysmon, windows,
--             iis, mssql, linux, syslog, file (규칙: server/app/normalizers/categories.py)
--   username  관련 사용자 (Windows TargetUserName, SSH 로그인 계정, IIS cs-username, MSSQL 로그인 …)
--   src_ip    접속해 온 쪽 IP (Windows IpAddress, SSH from, IIS c-ip, MSSQL CLIENT …)
-- 소스가 달라도 같은 이름으로 검색할 수 있게 하는 공통 스키마 (Elastic ECS 의 user.name / source.ip 에 해당)

ALTER TABLE events ADD COLUMN category TEXT;
ALTER TABLE events ADD COLUMN username TEXT;
ALTER TABLE events ADD COLUMN src_ip   TEXT;

CREATE INDEX events_cat_ts_idx  ON events (category, ts DESC);
CREATE INDEX events_user_ts_idx ON events (username, ts DESC) WHERE username IS NOT NULL;
CREATE INDEX events_ip_ts_idx   ON events (src_ip, ts DESC) WHERE src_ip IS NOT NULL;

-- 기존 행의 분류 채우기 (한 번만. 행 수에 비례해 시간이 걸린다 — 500만 건에 수 분)
UPDATE events SET category = CASE
    WHEN source = 'iis' OR provider ILIKE 'W3SVC%' OR provider ILIKE 'WAS' OR provider ILIKE 'Microsoft-Windows-WAS%' OR provider ILIKE 'Microsoft-Windows-IIS%' THEN 'iis'
    WHEN source = 'mssql' OR provider ILIKE 'MSSQL%' OR provider ILIKE 'SQLSERVERAGENT%' OR provider ILIKE 'SQLAgent%' THEN 'mssql'
    WHEN source = 'winevtlog' AND channel ILIKE '%PowerShell%' THEN 'powershell'
    WHEN source = 'winevtlog' AND channel ILIKE '%Windows Defender%' THEN 'defender'
    WHEN source = 'winevtlog' AND (channel ILIKE '%TerminalServices%' OR channel ILIKE '%RemoteDesktop%') THEN 'rdp'
    WHEN source = 'winevtlog' AND channel ILIKE '%Sysmon%' THEN 'sysmon'
    WHEN source = 'winevtlog' AND channel = 'Security' THEN 'security'
    WHEN source = 'winevtlog' AND channel = 'System' THEN 'system'
    WHEN source = 'winevtlog' AND channel = 'Application' THEN 'application'
    WHEN source = 'winevtlog' THEN 'windows'
    WHEN source = 'journald' THEN 'linux'
    WHEN source = 'syslog' THEN 'syslog'
    ELSE 'file'
END
WHERE category IS NULL;
