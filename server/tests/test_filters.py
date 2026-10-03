from datetime import UTC, datetime, timedelta

import pytest

from app.filters import EventFilter, FilterError
from app.repository import where_clause

NOW = datetime(2026, 10, 3, 5, 0, 0, tzinfo=UTC)


class Params(dict):
    """starlette QueryParams 대용 (getlist / multi_items)."""

    def getlist(self, key):
        value = self.get(key)
        return [] if value is None else [value]

    def multi_items(self):
        return list(self.items())


def test_relative_since_and_lists():
    f = EventFilter.from_params(Params(since="1h", host="A,B", level="1,2"), now=NOW)
    assert f.since == NOW - timedelta(hours=1)
    assert f.hosts == ["A", "B"]
    assert f.levels == [1, 2]


def test_default_since_can_be_disabled():
    assert EventFilter.from_params(Params(), default_since=None, now=NOW).since is None


def test_invalid_values_raise():
    with pytest.raises(FilterError):
        EventFilter.from_params(Params(level="x"), now=NOW)
    with pytest.raises(FilterError):
        EventFilter.from_params(Params(since="yesterday"), now=NOW)


def test_field_filters_and_matches():
    f = EventFilter.from_params(Params(**{"f.EventData.User": "admin", "level": "3"}), now=NOW)
    assert f.fields == [(["EventData", "User"], "admin")]
    assert f.matches({"level": 3, "raw": {"EventData": {"User": "admin"}}})
    assert not f.matches({"level": 3, "raw": {"EventData": {"User": "guest"}}})
    assert not f.matches({"level": 4, "raw": {"EventData": {"User": "admin"}}})


def test_matches_number_as_text():
    f = EventFilter.from_params(Params(**{"f.EventID": "4625"}), now=NOW)
    assert f.matches({"raw": {"EventID": 4625}})


def test_where_clause_params_order():
    f = EventFilter.from_params(Params(since="1h", host="A", q="50%_off"), now=NOW)
    _, params = where_clause(f)
    assert params == [NOW - timedelta(hours=1), ["A"], "%50\\%\\_off%"]


def test_q_with_pipe_is_or():
    f = EventFilter.from_params(Params(q="timeout|refused"), default_since=None, now=NOW)
    where, params = where_clause(f)
    assert "SQL(' OR ')" in repr(where)
    assert params == ["%timeout%", "%refused%"]
    assert f.matches({"message": "connect() failed: Connection REFUSED"})
    assert not f.matches({"message": "all good"})


def test_category_user_ip_filters():
    f = EventFilter.from_params(Params(category="iis", user="kim", ip="10.0.0.5"), default_since=None, now=NOW)
    assert f.matches({"category": "iis", "username": "kim", "src_ip": "10.0.0.5"})
    assert not f.matches({"category": "iis", "username": "lee", "src_ip": "10.0.0.5"})
    _, params = where_clause(f)
    assert params == [["iis"], ["kim"], ["10.0.0.5"]]
