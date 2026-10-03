"""알림 (Phase 2): 규칙(config/alerts.yaml) → 엔진 평가 → 메일/웹훅/Oracle 전송.

  rules.py      설정 파일 읽기/검증
  message.py    알림 문구 (모든 알림 대상이 같은 내용을 쓴다)
  notifiers.py  알림 대상 구현 (email / webhook / oracle)
  engine.py     주기 평가, 쿨다운, 재시도
"""
