"""내장 알림 이름 — 설정 파일에 없는 규칙 (다른 모듈을 import 하지 않아 어디서나 쓴다).

사용자 규칙이 같은 이름을 쓰면 재알림 간격(이름이 열쇠)·조회 범위·이력이 섞인다 → rules.parse 가 거부한다.
"""

from __future__ import annotations

# 탐지를 약하게 하는 설정 변경·넓은 무음·깨진 설정 파일 (ADR-043). 무음으로 막을 수 없다
CONFIG_RULE = "알림 설정 변경"

BUILTIN_RULES = frozenset({CONFIG_RULE})
