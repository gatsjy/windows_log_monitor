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


def _item(title, status, end, start=None):
    return {"title": title, "status": status, "period_end": end, "period_start": start or end}


def test_due_counts_a_full_cycle_plus_grace():
    """기한 = 마지막 승인 기간 끝 + 한 주기 + 여유. 기간 끝에서 31일만 재면 11월 점검을 12월 1~2일 안에 승인까지 마쳐야 했다(검토에서 재현)."""
    october = _item("10월", "approved", datetime(2026, 10, 31, 15, tzinfo=UTC))      # 한국 시간 11월 1일 0시
    assert (inspection.grace_days(31), inspection.grace_days(7), inspection.grace_days(1)) == (14, 3, 1)
    for day in (3, 10, 15):
        assert not inspection.judge([october], datetime(2026, 12, day, 3, tzinfo=UTC), 31)["overdue"], day
    late = inspection.judge([october], datetime(2026, 12, 16, 15, tzinfo=UTC), 31)
    assert late["overdue"] and late["due"] == "2026-12-15T15:00:00+00:00" and late["grace_days"] == 14
    assert "주기(31일 + 여유 14일)" in inspection.attention(late)[0]["text"]
    assert inspection.judge([], AT, 31)["overdue"] and not inspection.judge([], AT, 0)["overdue"]


def test_in_progress_hides_runs_already_covered_by_an_approved_one():
    """점검 행은 지울 수 없다 — 겹쳐 시작했거나 버려진 진행 중 점검이 준비도에 영영 남지 않게."""
    october = _item("10월", "approved", datetime(2026, 10, 31, 15, tzinfo=UTC))
    dup = _item("10월 (두 번 누름)", "open", datetime(2026, 10, 31, 15, tzinfo=UTC))
    november = _item("11월", "signed", datetime(2026, 11, 30, 15, tzinfo=UTC))
    assert inspection.judge([november, october, dup], AT, 31)["in_progress"] == ["11월"]


def test_month_title_uses_display_zone():
    assert inspection.month_title(datetime(2026, 9, 30, 15, tzinfo=UTC)) == "2026년 10월 접속기록 점검"


def _rec(action, at, detail=None, target=""):
    return {"action": action, "at": at, "detail": detail or {}, "target": target}


def test_integrity_evidence_looks_at_the_whole_period():
    """지금 상태만 보면 기간 안에 있었다가 풀린 검증 실패·보관 때 다이제스트 불일치가 가려져 '정상'으로 남았다(검토에서 재현)."""
    from datetime import timedelta

    start, end = datetime(2026, 10, 1, tzinfo=UTC), datetime(2026, 10, 4, tzinfo=UTC)
    daily = [_rec(a, start + timedelta(days=d, hours=1), {"ok": True} if a == "integrity.verify" else None)
             for d in range(3) for a in ("integrity.verify", "integrity.anchor", "backup.create")]
    clean = inspection._integrity_period(daily, start, end)
    assert clean["problems"] == [] and clean["runs"] == {"integrity.verify": 3, "integrity.anchor": 3, "backup.create": 3}
    rows = [*daily, _rec("integrity.verify", start + timedelta(days=1, hours=2), {"ok": False, "problems": ["#12 해시 다름"]}),
            _rec("integrity.events_mismatch", start + timedelta(days=2), {"problems": ["2026-10-01 03시"]}, "events_2026_10"),
            _rec("backup.verify", start + timedelta(days=2), {"ok": False, "reason": "복원 실패"}, "wlm-20261002.dump"),
            _rec("backup.verify", start + timedelta(days=2), {"ok": True}, "wlm-20261003.dump")]
    texts = [p["text"] for p in inspection._integrity_period(rows, start, end)["problems"]]
    assert texts == ["감사로그·수집 로그 위·변조 검증 실패: #12 해시 다름",
                     "보관 파일로 옮긴 로그가 다이제스트와 다름 (events_2026_10): 2026-10-01 03시",
                     "복구 시험 실패 (wlm-20261002.dump): 복원 실패"]
    # 빈 구간·기록 없음: 검증이 첫날 뒤로 끊김, 백업은 아예 없음
    gap = [r for r in daily if r["action"] != "backup.create" and (r["action"] != "integrity.verify" or r["at"] < start + timedelta(days=1))]
    texts = [p["text"] for p in inspection._integrity_period(gap, start, end)["problems"]]
    assert texts[0].startswith("위·변조 검증 기록이 71시간 비었습니다 (10-01 10:00 뒤)") and texts[1] == "기간에 백업 기록이 없습니다"
