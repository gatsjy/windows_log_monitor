"""CSV 내려받기 공용 (감사로그·알림 이력). 심사 증적으로 엑셀에서 여는 파일이라 두 가지를 지킨다.

- UTF-8 BOM: 엑셀에서 한글이 깨지지 않게.
- 수식 주입 방지: 로그에서 온 값(인증 없는 syslog 의 호스트 이름, 사용자 이름 등)이 = + - @ 로 시작하면
  엑셀이 수식으로 실행한다(예: =HYPERLINK 로 옆 칸 값을 밖으로 보냄). 그런 글자 앞에 ' 를 붙여 글자로만 보이게 한다.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from typing import Any

from fastapi.responses import Response

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> Any:
    """문자열만 바꾼다. 숫자(건수·번호)는 그대로 둬야 엑셀에서 숫자로 정렬된다."""
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


def export_reason(reason: str | None) -> str:
    """내려받는 사유 (ADR-042) — 개인정보가 든 파일은 왜 꺼내는지 접속기록에 함께 남긴다. 없으면 400."""
    from fastapi import HTTPException

    text = (reason or "").strip()
    if len(text) < 2:
        raise HTTPException(400, "내려받는 사유를 입력하세요 (예: 월간 점검, 사고 조사)")
    return text[:200]


def weak_reason(text: str | None) -> bool:
    """뜻이 없을 만큼 짧은 사유 — 점검 보고서가 따로 보인다(B-38). '월간 점검'·'사고 조사' 같은 짧은 문구는 통과,
    '확인'·'업무'·'ㅁㅁㅁㅁ'·'....' 은 걸린다."""
    compact = "".join((text or "").split())
    return len(compact) < 4 or len(set(compact)) == 1 or not any(ch.isalpha() for ch in compact)


def csv_text(header: list[str], rows: Iterable[list[Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow([safe_cell(v) for v in row])
    return "﻿" + buffer.getvalue()


def csv_bytes(header: list[str], rows: Iterable[list[Any]]) -> bytes:
    """묶음(zip) 안에 넣는 CSV (심사 증적 B-73) — 내려받기와 같은 BOM·수식 주입 방지."""
    return csv_text(header, rows).encode("utf-8")


def csv_response(header: list[str], rows: Iterable[list[Any]], filename: str,
                 headers: dict[str, str] | None = None) -> Response:
    return Response(csv_text(header, rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', **(headers or {})})
