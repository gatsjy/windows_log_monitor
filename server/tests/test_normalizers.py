from datetime import UTC, datetime

import pytest

from app.normalizers import Event, Heartbeat, normalize

NOW = datetime(2026, 10, 3, 5, 0, 0, tzinfo=UTC)


def winevt(**overrides):
    record = {
        "date": "2026-10-03T05:22:01.123456Z",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "EventID": 4625,
        "Level": 0,
        "Keywords": "0x8010000000000000",
        "TimeCreated": "2026-10-03 14:22:01 +0900",
        "Channel": "Security",
        "Computer": "WEB-01.corp.local",
        "Message": "계정을 로그온하지 못했습니다.",
        "StringInserts": ["S-1-0-0", "administrator"],
        "agent_host": "WEB-01",
        "log_source": "winevtlog",
    }
    record.update(overrides)
    return record


def test_windows_event_basic_fields():
    e = normalize(winevt(), NOW)
    assert isinstance(e, Event)
    assert e.source == "winevtlog"
    assert e.host == "WEB-01"  # agent_host 우선
    assert e.channel == "Security"
    assert e.event_id == 4625
    assert e.ts == datetime(2026, 10, 3, 5, 22, 1, tzinfo=UTC)


def test_windows_audit_failure_promoted_to_warning():
    assert normalize(winevt(), NOW).level == 3
    success = normalize(winevt(EventID=4624, Keywords="0x8020000000000000"), NOW)
    assert success.level == 4


def test_windows_level_zero_is_information_and_error_kept():
    assert normalize(winevt(Keywords="0x80000000000000", Level=0), NOW).level == 4
    assert normalize(winevt(Keywords="0x80000000000000", Level=2), NOW).level == 2


def test_windows_message_falls_back_to_string_inserts():
    e = normalize(winevt(Message=""), NOW)
    assert e.message == "S-1-0-0 | administrator"


def test_windows_detected_without_log_source():
    record = winevt()
    del record["log_source"]
    assert normalize(record, NOW).source == "winevtlog"


def test_nul_characters_removed():
    e = normalize(winevt(Message="a\x00b"), NOW)
    assert e.message == "ab"


def test_heartbeat():
    hb = normalize({"type": "heartbeat", "agent_host": "WEB-01", "config_version": "0.1.0"}, NOW)
    assert isinstance(hb, Heartbeat)
    assert hb.host == "WEB-01"
    assert hb.meta == {"config_version": "0.1.0"}


def test_syslog_rfc3164_uses_receive_time_and_severity():
    record = {
        "date": "2026-10-03T05:00:01Z",
        "pri": "11",  # facility 1(user), severity 3(err)
        "time": "Oct  3 14:00:01",
        "host": "switch-01",
        "ident": "sshd",
        "message": "Failed password for root",
        "source_ip": "10.0.0.5",
        "log_source": "syslog",
    }
    e = normalize(record, NOW)
    assert e.source == "syslog"
    assert e.level == 2
    assert e.channel == "user"
    assert e.provider == "sshd"
    assert e.host == "switch-01"
    assert e.ts == datetime(2026, 10, 3, 5, 0, 1, tzinfo=UTC)


def test_syslog_rfc5424_time_with_offset():
    record = {"pri": "86", "time": "2026-10-03T14:00:01.000+09:00", "host": "lnx", "message": "x",
              "log_source": "syslog"}
    e = normalize(record, NOW)
    assert e.ts == datetime(2026, 10, 3, 5, 0, 1, tzinfo=UTC)
    assert e.channel == "authpriv"
    assert e.level == 4


def test_journald():
    record = {"PRIORITY": "4", "_HOSTNAME": "lnx-01", "SYSLOG_IDENTIFIER": "kernel",
              "_SYSTEMD_UNIT": "nginx.service", "MESSAGE": "warn"}
    e = normalize(record, NOW)
    assert (e.source, e.host, e.level, e.channel, e.provider) == ("journald", "lnx-01", 3, "nginx.service", "kernel")


def test_generic_file_line_level_guess():
    record = {"log": "2026-10-03 ERROR something broke", "log_source": "file", "log_channel": "iis",
              "file": r"C:\inetpub\logs\u_ex261003.log", "agent_host": "WEB-01"}
    e = normalize(record, NOW)
    assert (e.source, e.channel, e.level) == ("file", "iis", 2)
    assert e.ts == NOW


def test_unknown_record_is_still_accepted():
    e = normalize({"foo": "bar"}, NOW)
    assert e.source == "file"
    assert e.host == "unknown"
    assert e.raw == {"foo": "bar"}


# ------------------------------------------------- 공통 필드 · 분류 (007)

def test_windows_eventdata_map_gives_user_and_ip():
    e = normalize(winevt(EventData={"TargetUserName": "kim.minsu", "IpAddress": "::ffff:10.1.2.3",
                                    "LogonType": "10"}), NOW)
    assert (e.username, e.src_ip, e.category) == ("kim.minsu", "10.1.2.3", "security")


def test_windows_string_inserts_fallback_positions():
    inserts = ["S-1-0-0", "-", "-", "0x0", "S-1-0-0", "administrator", "CORP", "0xc000006d", "%%2313",
               "0xc000006a", "3", "NtLmSsp", "NTLM", "WS01", "-", "-", "0", "0x0", "-", "203.0.113.9", "51515"]
    e = normalize(winevt(StringInserts=inserts), NOW)
    assert (e.username, e.src_ip) == ("administrator", "203.0.113.9")


def test_windows_ignores_machine_accounts_and_dashes():
    e = normalize(winevt(EventID=4624, EventData={"TargetUserName": "WEB-01$", "IpAddress": "-"}), NOW)
    assert (e.username, e.src_ip) == (None, None)


def test_mssql_event_log_is_classified_and_parsed():
    e = normalize(winevt(Channel="Application", ProviderName="MSSQLSERVER", EventID=18456, Level=0,
                         Keywords="0x90000000000000",
                         Message="Login failed for user 'sa'. Reason: Password did not match. [CLIENT: 10.9.8.7]"), NOW)
    assert (e.category, e.username, e.src_ip) == ("mssql", "sa", "10.9.8.7")


@pytest.mark.parametrize("channel, provider, category", [
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", "powershell"),
    ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "defender"),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "x", "rdp"),
    ("System", "Microsoft-Windows-WAS", "iis"),
    ("System", "Service Control Manager", "system"),
    ("Application", "Application Error", "application"),
])
def test_windows_categories(channel, provider, category):
    assert normalize(winevt(Channel=channel, ProviderName=provider), NOW).category == category


def test_ssh_failed_password_fields():
    record = {"pri": "38", "host": "lnx", "ident": "sshd", "log_source": "syslog",
              "message": "Failed password for invalid user admin from 203.0.113.45 port 40022 ssh2"}
    e = normalize(record, NOW)
    assert (e.username, e.src_ip, e.category) == ("admin", "203.0.113.45", "syslog")


# ------------------------------------------------------------------- IIS

IIS_LINE = ("2026-10-04 01:02:03 10.0.0.10 GET /api/orders id=7 443 - 203.0.113.5 "
            "Mozilla/5.0+(Windows+NT+10.0) https://example.com/ 500 0 0 1234")


def iis(log, file=r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex261004.log", host="WEB-01"):
    return {"log": log, "file": file, "agent_host": host, "log_source": "iis"}


def test_iis_default_layout():
    e = normalize(iis(IIS_LINE), NOW)
    assert e.source == "iis" and e.category == "iis" and e.channel == "IIS/W3SVC1"
    assert (e.event_id, e.level, e.src_ip, e.username) == (500, 2, "203.0.113.5", None)
    assert e.ts == datetime(2026, 10, 4, 1, 2, 3, tzinfo=UTC)
    assert e.raw["iis"]["uri_stem"] == "/api/orders" and e.raw["log"] == IIS_LINE  # 원본 유지
    assert "GET /api/orders?id=7 → 500 (1234ms)" in e.message
    assert "Mozilla/5.0 (Windows NT 10.0)" in e.message


def test_iis_header_sets_custom_layout_and_is_not_stored():
    header = "#Fields: date time c-ip cs-username cs-method cs-uri-stem sc-status time-taken"
    assert normalize(iis(header, host="WEB-09"), NOW) is None
    e = normalize(iis("2026-10-04 01:02:03 10.1.1.1 kim GET /login 401 15", host="WEB-09"), NOW)
    assert (e.event_id, e.level, e.username, e.src_ip) == (401, 3, "kim", "10.1.1.1")


def test_iis_unparseable_line_is_kept():
    e = normalize(iis("garbage line"), NOW)
    assert e.message == "garbage line" and e.category == "iis"


# ------------------------------------------------------------------ MSSQL

def mssql(log):
    return {"log": log, "agent_host": "DB-01", "log_source": "mssql", "file": "ERRORLOG"}


def test_mssql_errorlog_error_header_merges_into_next_line():
    head = normalize(mssql("2026-10-04 10:15:22.53 spid51      Error: 9002, Severity: 17, State: 2."), NOW)
    assert (head.event_id, head.level, head.provider, head.category) == (None, 5, "spid51", "mssql")
    assert head.ts == datetime(2026, 10, 4, 1, 15, 22, 530000, tzinfo=UTC)  # Asia/Seoul → UTC
    body = normalize(mssql("2026-10-04 10:15:22.53 spid51      The transaction log for database 'ERP' is full."), NOW)
    assert (body.event_id, body.level) == (9002, 2)
    assert body.raw["mssql"]["severity"] == 17
    normalize(mssql("2026-10-04 10:15:23.00 spid9s      Error: 824, Severity: 24, State: 2."), NOW)
    assert normalize(mssql("2026-10-04 10:15:23.00 spid9s      I/O error detected."), NOW).level == 1


def test_mssql_errorlog_header_not_merged_into_later_line():
    normalize(mssql("2026-10-04 10:15:22.53 spid51      Error: 9002, Severity: 17, State: 2."), NOW)
    later = normalize(mssql("2026-10-04 10:20:00.00 spid51      Starting up database 'ERP'."), NOW)
    assert (later.event_id, later.level) == (None, 4)


def test_mssql_login_failure_counted_once():
    events = [normalize(mssql(line), NOW) for line in (
        "2026-10-04 10:15:22.53 Logon       Error: 18456, Severity: 14, State: 8.",
        "2026-10-04 10:15:22.53 Logon       Login failed for user 'sa'. Reason: x [CLIENT: 10.0.0.5]")]
    assert [e.event_id for e in events] == [None, 18456]


def test_mssql_errorlog_login_failed():
    e = normalize(mssql("2026-10-04 10:15:22.53 Logon       Login failed for user 'sa'. "
                        "Reason: Password did not match that for the login provided. [CLIENT: 10.0.0.5]"), NOW)
    assert (e.event_id, e.level, e.username, e.src_ip) == (18456, 3, "sa", "10.0.0.5")
