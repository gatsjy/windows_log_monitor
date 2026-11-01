"""수집 대상 목록 읽기 (BACKLOG B-55) — DB 없이."""

from __future__ import annotations

import pytest

from app.assets import parse, short_name


@pytest.mark.parametrize(("name", "short"), [
    ("DB-01", "db-01"), ("db-01.corp.local", "db-01"), ("PC0012$", "pc0012"), (" Web-01 ", "web-01"),
])
def test_short_name(name, short):
    """에이전트는 PC 이름을 짧게도 FQDN 으로도 보내고, AD 의 컴퓨터 계정은 끝에 $ — 첫 마디 소문자로 맞춘다."""
    assert short_name(name) == short


def test_plain_list_with_grades_and_comments():
    items, problems = parse("# 의료정보과 서버\nDC-01,중요\nDB-01, critical\nWEB-01\n\nPC-0012\n")
    assert problems == []
    assert {i["host"]: i["grade"] for i in items} == {"dc-01": "critical", "db-01": "critical", "web-01": "normal", "pc-0012": "normal"}


def test_get_adcomputer_csv_export():
    """Get-ADComputer … | Export-Csv — 머리줄의 Name·DNSHostName·Description 을 알아본다(따옴표·$ 계정 포함)."""
    text = ('"Name","DNSHostName","Description","OperatingSystem"\n'
            '"DC01$","dc01.corp.local","도메인 컨트롤러","Windows Server 2022"\n'
            '"EMR-DB","emr-db.corp.local","EMR DB, 주","Windows Server 2019"\n')
    items, problems = parse(text)
    assert problems == []
    assert [(i["host"], i["name"], i["note"]) for i in items] == [("dc01", "DC01", "도메인 컨트롤러"), ("emr-db", "EMR-DB", "EMR DB, 주")]


def test_korean_header_tab_separated_and_duplicates():
    items, problems = parse("호스트\t등급\t비고\nDB-01\t일반\t\ndb-01.corp.local\t중요\t본 서버\nWEB-01\t\t\n")
    assert problems == []
    assert {i["host"]: i["grade"] for i in items} == {"db-01": "critical", "web-01": "normal"}   # 같은 이름은 하나로, 중요가 이긴다


def test_bad_names_are_reported_not_stored():
    items, problems = parse("DB-01\n<script>\n../etc\n")
    assert [i["host"] for i in items] == ["db-01"]
    assert len(problems) == 2 and "2번째 줄" in problems[0]


def test_empty_list():
    assert parse("\n# 비어 있음\n") == ([], ["목록이 비어 있습니다"])
