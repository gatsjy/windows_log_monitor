"""접속기록 점검 결과서 (BACKLOG B-72 3단계) — DB 없는 단위 시험: 결재 흐름 상태, 지난달 기간, 점검 필요 문구."""

from __future__ import annotations

from datetime import UTC, datetime

from app import inspection

AT = datetime(2026, 11, 2, tzinfo=UTC)
INSP = {"items": [{"key": "retention"}, {"key": "downloads"}, {"key": "accounts"}]}


def _e(kind, item=None, result=None, author="kim", note=""):
    return {"kind": kind, "item": item, "result": result, "author": author, "note": note, "at": AT}


def test_state_follows_entries_in_order():
    st = inspection.state(INSP, [])
    assert (st["status"], st["missing"], st["issues"]) == ("open", ["retention", "downloads", "accounts"], [])
    entries = [_e("result", "retention", "ok"), _e("result", "downloads", "issue", note="사유 '확인' 2건 — 본인 확인함"),
               _e("result", "accounts", "na"), _e("result", "accounts", "ok")]
    st = inspection.state(INSP, entries)
    assert st["missing"] == [] and st["issues"] == ["downloads"] and st["results"]["accounts"]["result"] == "ok"
    entries += [_e("sign"), _e("reject", author="lee", note="외부 업체 계정 확인")]
    assert inspection.state(INSP, entries)["status"] == "open"
    entries += [_e("sign"), _e("approve", author="lee")]
    st = inspection.state(INSP, entries)
    assert st["status"] == "approved" and st["approved"]["author"] == "lee"


def test_last_month_in_display_zone():
    start, end = inspection.last_month(datetime(2026, 11, 2, 3, 0, tzinfo=UTC))   # 한국 시간 11월 2일 12시
    assert (start.isoformat(), end.isoformat()) == ("2026-09-30T15:00:00+00:00", "2026-10-31T15:00:00+00:00")
    start, _ = inspection.last_month(datetime(2026, 1, 5, tzinfo=UTC))
    assert start.isoformat() == "2025-11-30T15:00:00+00:00"   # 1월이면 지난해 12월


def test_attention_when_overdue():
    base = {"days": 31, "age_days": 10, "last_title": "10월", "overdue": False, "in_progress": []}
    assert inspection.attention(base) == [] and inspection.attention(None) == []
    [line] = inspection.attention({**base, "overdue": True, "age_days": 40})
    assert line["level"] == "warn" and "40일 전('10월')" in line["text"]
    assert "승인한 접속기록 점검이 없습니다" in inspection.attention({**base, "overdue": True, "age_days": None})[0]["text"]
    assert [k for k, _, _ in inspection.CHECKLIST] == list(inspection.ITEM_KEYS) and len(inspection.ITEM_KEYS) == 8
