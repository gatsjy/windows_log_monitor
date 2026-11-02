"""분기 권한 검토 (BACKLOG B-72 2단계, ISMS 2.5.6) — DB 없는 단위 시험: 결재 흐름 상태, 점검 필요 문구."""

from __future__ import annotations

from datetime import UTC, datetime

from app.auth import review

AT = datetime(2026, 11, 2, tzinfo=UTC)
REVIEW = {"users": [{"id": 1, "username": "admin", "is_active": True}, {"id": 2, "username": "kim", "is_active": True},
                    {"id": 3, "username": "old", "is_active": False}]}


def _e(kind, user_id=None, decision=None, author="admin", note=""):
    return {"kind": kind, "user_id": user_id, "decision": decision, "author": author, "note": note, "at": AT}


def test_state_follows_entries_in_order():
    st = review.state(REVIEW, [])
    assert (st["status"], st["active"], st["decided"], st["missing"]) == ("open", 2, 0, ["admin", "kim"])
    entries = [_e("decision", 1, "keep"), _e("decision", 2, "keep"), _e("decision", 2, "revoke", note="퇴직")]
    st = review.state(REVIEW, entries)
    assert st["decisions"][2]["decision"] == "revoke" and st["missing"] == []      # 마지막 결정이 지금 결정
    entries.append(_e("sign"))
    assert review.state(REVIEW, entries)["status"] == "signed"
    entries.append(_e("reject", author="boss", note="kim 은 휴직"))
    st = review.state(REVIEW, entries)
    assert st["status"] == "open" and st["signed"] is None and st["rejected"]["author"] == "boss"   # 반려하면 다시 고친다
    entries += [_e("decision", 2, "keep", note="휴직 — 복직 예정"), _e("sign"), _e("approve", author="boss")]
    st = review.state(REVIEW, entries)
    assert st["status"] == "approved" and st["approved"]["author"] == "boss" and st["decisions"][2]["decision"] == "keep"


def test_attention_lines():
    base = {"days": 92, "age_days": 10, "last_title": "3분기", "overdue": False, "follow_up": [], "in_progress": []}
    assert review.attention(base) == [] and review.attention(None) == []
    lines = review.attention({**base, "follow_up": ["kim"], "overdue": True, "age_days": 120})
    assert [x["level"] for x in lines] == ["bad", "warn"]
    assert "kim" in lines[0]["text"] and "120일 전('3분기')" in lines[1]["text"]
    assert "승인한 권한 검토가 없습니다" in review.attention({**base, "overdue": True, "age_days": None})[0]["text"]
