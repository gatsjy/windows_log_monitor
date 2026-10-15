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


def csv_response(header: list[str], rows: Iterable[list[Any]], filename: str,
                 headers: dict[str, str] | None = None) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow([safe_cell(v) for v in row])
    return Response("﻿" + buffer.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', **(headers or {})})
