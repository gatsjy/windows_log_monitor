"""내장 알림 이름 — 설정 파일에 없는 규칙 (다른 모듈을 import 하지 않아 어디서나 쓴다).

사용자 규칙이 같은 이름을 쓰면 재알림 간격(이름이 열쇠)·조회 범위·이력이 섞인다 → rules.parse 가 거부한다.
"""

from __future__ import annotations

# 탐지를 약하게 하는 설정 변경·넓은 무음·깨진 설정 파일 (ADR-043). 무음으로 막을 수 없다
CONFIG_RULE = "알림 설정 변경"

# 알림 기능 자체의 문제 (ADR-045 2단계, alerts/watchdog.py). 무음으로 막을 수 있다 — 메일 서버 점검처럼 예정된 일
ENGINE_STALL_RULE = "알림 엔진 멈춤"
TARGET_DOWN_RULE = "알림 전송 실패"
RULE_BROKEN_RULE = "알림 규칙 동작 안 함"
SYSTEM_RULES = frozenset({ENGINE_STALL_RULE, TARGET_DOWN_RULE, RULE_BROKEN_RULE})

BUILTIN_RULES = SYSTEM_RULES | {CONFIG_RULE}
