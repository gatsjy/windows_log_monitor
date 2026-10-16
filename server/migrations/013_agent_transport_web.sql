-- B-06 (ADR-036): 화면 포트(8080)로 평문을 보내는 PC 를 'web' 으로 따로 기록한다.
-- 0.4 이전 설치 묶음은 수집 포트를 8080 으로 적었고 설정 버전으로는 0.5 묶음과 구별되지 않는다(둘 다 0.2.0/0.1.0).
-- TLS 를 켜면 8080 은 https 만 받으므로 이 PC 들은 끊긴다 — 켜기 전에 골라 다시 설치하게 한다.
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_last_transport_check;
ALTER TABLE agents ADD CONSTRAINT agents_last_transport_check CHECK (last_transport IN ('tls', 'plain', 'web'));
