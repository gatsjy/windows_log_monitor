-- B-06 (ADR-036): PC 마다 마지막 하트비트가 들어온 전송 방식 — 평문 수집을 닫아도 되는지 판단하는 근거, ISMS 2.7.1 증적.
-- 하트비트에서만 채운다: syslog 장비(하트비트 없음)는 수집기 내부 리스너로 오므로 '평문 PC' 로 섞이지 않게 NULL 로 둔다.
ALTER TABLE agents ADD COLUMN last_transport TEXT CHECK (last_transport IN ('tls', 'plain'));
