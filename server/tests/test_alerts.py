from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.alerts.engine import _link_params, _with_group
from app.alerts.message import AlertMessage
from app.alerts.notifiers import EmailNotifier, NotifierError, SmtpConfig, WebhookNotifier, oracle_binds
from app.alerts.rules import ConfigError, parse, parse_text
from app.filters import EventFilter
from app.oracle import OracleConn, OracleError, tns_aliases

NOW = datetime(2026, 10, 3, 5, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent.parent

BASE = {"rules": [{"name": "오류", "match": {"level": "1,2"}, "window": "5m", "notify": ["운영팀"]}]}


def message(**overrides) -> AlertMessage:
    values = {
        "rule": "로그온 실패 급증", "severity": "warning", "kind": "count", "group_by": "host",
        "group_key": "DC-01", "event_count": 27, "threshold": 20, "window_sec": 600, "fired_at": NOW,
        "first_event_at": NOW - timedelta(minutes=9), "last_event_at": NOW,
        "link": "http://x/#/events", "alert_id": 7,
        "samples": [{"id": 1, "ts": NOW.isoformat(), "host": "DC-01", "level": 3, "channel": "Security",
                     "event_id": 4625, "message": "계정을 로그온하지 못했습니다.\r\n상세"}],
    }
    values.update(overrides)
    return AlertMessage(**values)


# ------------------------------------------------------------------ rules

def test_shipped_config_is_valid():
    # 저장소: server/tests → ../../config, 컨테이너: /app/tests → /app/config
    path = next(p for p in (ROOT / "config" / "alerts.yaml", ROOT.parent / "config" / "alerts.yaml") if p.exists())
    config = parse_text(path.read_text(encoding="utf-8"))
    assert config.rules and config.used_targets()


def test_defaults_and_cooldown_at_least_window():
    doc = {**BASE, "rules": [{**BASE["rules"][0], "window": "1h", "cooldown": "5m"}]}
    rule = parse(doc).rules[0]
    assert rule.kind == "count" and rule.group_by == "host" and rule.severity == "warning"
    assert rule.cooldown == timedelta(hours=1)


@pytest.mark.parametrize("change, message_part", [
    ({"notify": []}, "알림 대상"),
    ({"window": "five"}, "기간 형식"),
    ({"match": {"level": "abc"}}, "정수"),
    ({"match": {"colour": "red"}}, "알 수 없는 조건"),
    ({"severity": "panic"}, "severity"),
    ({"group_by": "nickname"}, "group_by"),
    ({"threshold": 0}, "threshold"),
])
def test_rule_validation_errors(change, message_part):
    with pytest.raises(ConfigError, match=message_part):
        parse({**BASE, "rules": [{**BASE["rules"][0], **change}]})


def test_duplicate_rule_names():
    with pytest.raises(ConfigError, match="중복"):
        parse({**BASE, "rules": [BASE["rules"][0], BASE["rules"][0]]})


def test_notifiers_in_file_are_rejected():
    with pytest.raises(ConfigError, match="환경설정"):
        parse({**BASE, "notifiers": {"mail": {"type": "email", "to": ["a@b.c"]}}})


def test_used_targets():
    doc = {"rules": [{"name": "a", "notify": ["운영팀", "erp"]}, {"name": "b", "notify": ["운영팀"]}]}
    assert parse(doc).used_targets() == {"운영팀": ["a", "b"], "erp": ["a"]}


def test_yaml_syntax_error():
    with pytest.raises(ConfigError, match="YAML"):
        parse_text("rules: [")


def test_agent_silent_rule():
    doc = {"rules": [{"name": "응답 없음", "kind": "agent_silent", "silent_for": "10m",
                      "hosts": ["WEB-01"], "notify": ["운영팀"]}]}
    rule = parse(doc).rules[0]
    assert rule.silent_for == timedelta(minutes=10) and rule.hosts == ("WEB-01",)


# ---------------------------------------------------------------- engine

def test_with_group_adds_filter():
    f = EventFilter()
    assert _with_group(f, "host", "WEB-01").hosts == ["WEB-01"]
    assert _with_group(f, "event_id", "4625").event_ids == [4625]
    assert _with_group(f, "f.StringInserts.5", "admin").fields == [(["StringInserts", "5"], "admin")]
    assert _with_group(f, "none", "") is f


def test_link_params_include_group():
    rule = parse(BASE).rules[0]
    params = _link_params(rule, "WEB-01", NOW)
    assert params == {"since": NOW.isoformat(), "level": "1,2", "host": "WEB-01"}


# --------------------------------------------------------------- message

def test_message_round_trip_and_text():
    m = message()
    again = AlertMessage.from_dict(m.to_dict())
    assert again == m
    assert m.title() == "[경고] 로그온 실패 급증 · DC-01"
    text = m.text()
    assert "최근 10분 동안 조건에 맞는 이벤트 27건 (기준 20건 이상)" in text
    assert "2026-10-03 14:00:00" in text  # Asia/Seoul 표시
    assert "\r" not in text.split("최근 이벤트:")[1].split("자세히")[0].splitlines()[1]


def test_silent_message_summary():
    m = message(kind="agent_silent", event_count=0, threshold=0, last_event_at=NOW - timedelta(minutes=12))
    assert "로그/하트비트가 들어오지 않았습니다" in m.summary()


# ------------------------------------------------------------- notifiers

SMTP = SmtpConfig(host="smtp.example.com", sender="logmon@example.com")


def test_email_build_has_korean_subject_and_html():
    mail = EmailNotifier("운영팀", ["a@x.com", "b@x.com"], SMTP).build(message())
    assert mail["To"] == "a@x.com, b@x.com"
    assert mail["From"] == "logmon@example.com"
    assert "로그온 실패 급증" in str(mail["Subject"])
    assert {p.get_content_type() for p in mail.iter_parts()} == {"text/plain", "text/html"}


def test_email_without_recipients_fails_clearly():
    notifier = EmailNotifier("빈그룹", [], SMTP)
    with pytest.raises(NotifierError, match="수신자가 없습니다"):
        notifier._send(notifier.build(message()))


def test_min_severity_filter():
    hook = WebhookNotifier("w", "https://h/x")
    assert hook.accepts("info")
    hook.min_severity = "error"
    assert not hook.accepts("warning") and hook.accepts("error") and hook.accepts("critical")


def test_webhook_payload_formats():
    as_json = WebhookNotifier("w", "https://h/x").payload(message())
    assert as_json["alert"]["event_count"] == 27 and as_json["title"].startswith("[경고]")
    as_text = WebhookNotifier("w", "https://h/x", "text").payload(message())
    assert set(as_text) == {"text"} and "http://x/#/events" in as_text["text"]


def test_webhook_target_hides_path_and_credentials():
    hook = WebhookNotifier("w", "https://user:pw@hooks.example.com/services/T000/SECRET?token=zzz")
    assert hook.target() == "https://hooks.example.com/…"


def test_webhook_rejects_non_http_url():
    with pytest.raises(NotifierError):
        WebhookNotifier("w", "file:///etc/passwd")


def test_oracle_binds_follow_sql_and_use_naive_utc():
    sql = "INSERT INTO T (A, B, C) VALUES (:alert_id, :host, :fired_at)"
    binds = oracle_binds(sql, message())
    assert binds == {"alert_id": 7, "host": "DC-01", "fired_at": NOW.replace(tzinfo=None)}


def test_oracle_binds_ignore_string_literals_and_reject_unknown():
    assert set(oracle_binds("INSERT INTO T (A, B) VALUES (:title, 'a:b:c')", message())) == {"title"}
    with pytest.raises(NotifierError, match="알 수 없는 바인드"):
        oracle_binds("INSERT INTO T (A) VALUES (:nope)", message())


# ----------------------------------------------------------------- oracle

TNS = """
# 주석
ERP_PROD =
  (DESCRIPTION =
    (ADDRESS = (PROTOCOL = TCP)(HOST = db1)(PORT = 1521))
    (CONNECT_DATA = (SID = ORCL)))

ERP_DEV, ERP_TEST = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = db2)(PORT = 1521))
  (CONNECT_DATA = (SERVICE_NAME = devpdb)))
"""


def test_tns_alias_parsing():
    assert tns_aliases(TNS) == ["ERP_PROD", "ERP_DEV", "ERP_TEST"]


@pytest.mark.parametrize("config, described", [
    ({"mode": "tns", "user": "u", "tns_alias": "ERP_PROD"}, "u@TNS ERP_PROD"),
    ({"mode": "sid", "user": "u", "host": "db1", "port": 1522, "sid": "ORCL"}, "u@db1:1522 SID=ORCL"),
    ({"mode": "service", "user": "u", "host": "db1", "service_name": "pdb1"}, "u@db1:1521/pdb1"),
    ({"mode": "dsn", "user": "u", "dsn": "db1:1521/pdb1"}, "u@db1:1521/pdb1"),
])
def test_oracle_conn_modes(config, described):
    assert OracleConn.from_config(config, "pw").describe() == described


@pytest.mark.parametrize("config", [
    {"mode": "sid", "user": "u", "host": "db1"},          # SID 없음
    {"mode": "tns", "user": "u"},                          # 별칭 없음
    {"mode": "service", "host": "h", "service_name": "s"},  # 계정 없음
    {"mode": "magic", "user": "u"},
])
def test_oracle_conn_validation(config):
    with pytest.raises(OracleError):
        OracleConn.from_config(config, "pw")


def test_rule_tags_reach_the_message():
    doc = {"rules": [{"name": "r", "match": {"event_id": "4625"}, "notify": ["운영팀"],
                      "tags": ["MITRE T1110", "ISMS 2.11.3"]}]}
    rule = parse(doc).rules[0]
    assert rule.tags == ("MITRE T1110", "ISMS 2.11.3")
    m = message(tags=list(rule.tags))
    assert "태그: MITRE T1110, ISMS 2.11.3" in m.text() and "MITRE T1110" in m.html()
