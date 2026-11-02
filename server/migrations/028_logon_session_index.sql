-- 로그온 세션 보기 (BACKLOG B-63) 의 짝짓기 색인: 같은 PC·같은 TargetLogonId 의 로그오프·새 로그온을 바로 찾는다.
-- 없으면 로그오프가 없는 로그온마다 그 PC 의 max_hours 안 4634/4647 을 모두 읽어 원본 경로를 꺼냈다 — 네트워크 로그온이 많은
-- 파일 서버·DC 에서 30초 상한(503)에 걸렸다(검토에서 재현). 식은 repository.LOGON_ID_SQL 과 글자까지 같아야 쓰인다
-- (EventData 별칭: 에이전트가 보낸 이름 → 서버가 붙인 이름, ADR-038). 세 이벤트만 담는 부분 색인이라 작다.
-- 업그레이드 때 events 를 한 번 훑으므로 첫 기동이 그만큼 늦다(행 1억 개에 몇 분).
CREATE INDEX IF NOT EXISTS events_logon_id_idx ON events
    (host, (COALESCE(raw #>> '{EventData,TargetLogonId}', raw #>> '{winevtlog,EventData,TargetLogonId}')), ts)
    WHERE event_id IN (4624, 4634, 4647);
