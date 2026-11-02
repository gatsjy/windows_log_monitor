"""수집 품질 판단 (BACKLOG B-56 1단계, ISMS 2.9.4) — 점검 보고서·운영 준비도 공용.

규칙이 조용히 데이터를 못 받는 두 번째 경로는 '들어오는데 해석이 깨진 것'이다. 수집 트랜잭션이 agent_streams 의 칸으로 센 것
(repository.ingest_quality)을 사람이 읽는 줄로 바꾼다. 늦게 온 로그는 장애 뒤 밀린 로그로 흔하므로 많을 때만 알린다.
"""

from __future__ import annotations

from typing import Any

LATE_SHARE = 0.2          # 늦게 온 로그가 이 비율을 넘고
LATE_MIN = 100            # 이만큼 이상이면 알린다

# 칸 → (점검 필요 문구, 무엇을 고치나)
PROBLEMS = {
    "parse_errors": ("해석하지 못해 일반 로그로 저장한 로그", "서버 로그의 정규화 오류를 확인하세요 (raw._ingest.error)"),
    "unparsed": ("열 순서를 몰라 원문 그대로 둔 IIS 줄", "사용자·IP·상태 코드 규칙이 이 줄을 보지 못합니다 — 그 사이트의 #Fields 머리줄을 확인하세요"),
    "template_mismatch": ("필드 수가 템플릿과 다른 Windows 이벤트", "이벤트 버전이 바뀌어 f.EventData 조건이 어긋날 수 있습니다 (ADR-038)"),
    "future_n": ("발생 시각이 5분 넘게 미래인 로그", "PC 시계를 확인하세요"),
}
LABELS = {"parse_errors": "해석 오류", "unparsed": "원문 그대로", "template_mismatch": "템플릿 불일치", "late_n": "1시간+ 늦음",
          "future_n": "미래 시각"}


def _where(rows: list[dict[str, Any]], column: str) -> str:
    hit = [r for r in rows if r.get(column)]
    names = [f"{r['host']}({r['source']}{' · ' + r['channel'] if r['channel'] else ''})" for r in hit[:3]]
    return ", ".join(names) + (f" 외 {len(hit) - 3}곳" if len(hit) > 3 else "")


def attention(q: dict[str, Any] | None) -> list[dict[str, str]]:
    """점검 필요 줄 (warn). q = repository.ingest_quality 의 결과. 없으면(옛 보고서) 빈 목록."""
    if not q:
        return []
    total, rows, out = q["total"], q["rows"], []
    for column, (what, fix) in PROBLEMS.items():
        if total.get(column):
            out.append({"level": "warn", "text": f"{what} {total[column]:,}건 — {_where(rows, column)}. {fix}"})
    late, n = total.get("late_n", 0), total.get("n", 0)
    if late >= LATE_MIN and n and late / n > LATE_SHARE:
        out.append({"level": "warn", "text": f"1시간 넘게 늦게 들어온 로그 {late:,}건({round(late / n * 100)}%) — {_where(rows, 'late_n')}. "
                                             "에이전트가 밀린 로그를 보냈거나 PC 시계가 틀렸습니다 (알림 판단은 받은 시각 기준)"})
    return out
