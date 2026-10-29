from datetime import UTC, datetime

import pytest

from app.normalizers import Event, Heartbeat, IisContext, layout_keys, normalize
from app.normalizers.iis import DEFAULT_FIELDS

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
    ctx = IisContext()
    header = "#Fields: date time c-ip cs-username cs-method cs-uri-stem sc-status time-taken"
    assert normalize(iis(header, host="WEB-09"), NOW, ctx) is None
    e = normalize(iis("2026-10-04 01:02:03 10.1.1.1 kim GET /login 401 15", host="WEB-09"), NOW, ctx)
    assert (e.event_id, e.level, e.username, e.src_ip) == (401, 3, "kim", "10.1.1.1")
    assert "_layout" not in e.raw["iis"]  # 머리줄로 확인한 순서는 추정 표시가 없다
    assert ctx.learned == {("WEB-09", IIS_FILE): (IIS_DIR, tuple(header.split()[1:]))}


def test_iis_unparseable_line_is_kept():
    e = normalize(iis("garbage line"), NOW)
    assert e.message == "garbage line" and e.category == "iis"


# 사용자 지정 15열 (s-computername 을 앞에 더하고 Referer 를 뺌) — 칸 수가 기본 순서와 같다
CUSTOM_FIELDS = ("date", "time", "s-computername", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port",
                 "cs-username", "c-ip", "cs(User-Agent)", "sc-status", "sc-substatus", "sc-win32-status", "time-taken")
CUSTOM_LINE = "2026-10-04 01:02:03 WEB01 10.0.0.10 POST /login - 443 lee 198.51.100.9 Mozilla/5.0 401 1 0 15"
IIS_FILE = r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex261004.log"
IIS_DIR = "C:/inetpub/logs/LogFiles/W3SVC1"


def test_iis_custom_layout_without_header_is_kept_raw_not_misread():
    # 회귀(B-08): 예전에는 서버 재시작 뒤 이 줄을 기본 순서로 읽어 src_ip='lee', username='443' 이 되었다
    e = normalize(iis(CUSTOM_LINE), NOW, IisContext())
    assert (e.src_ip, e.username, e.event_id, e.channel) == (None, None, None, "IIS")
    assert "iis" not in e.raw and e.message == CUSTOM_LINE


def test_iis_stored_layout_after_restart():
    ctx = IisContext(stored={("WEB-01", IIS_FILE): CUSTOM_FIELDS})
    e = normalize(iis(CUSTOM_LINE), NOW, ctx)
    assert (e.event_id, e.level, e.username, e.src_ip) == (401, 3, "lee", "198.51.100.9")
    assert e.raw["iis"]["server"] == "WEB01" and "_layout" not in e.raw["iis"]


def test_iis_site_layout_for_new_file_and_shape_mismatch_falls_through():
    # 에이전트가 멈춘 사이 날짜가 바뀐 새 파일: 머리줄은 못 받았지만 같은 폴더의 최신 열 순서가 있다
    new_file = IIS_FILE.replace("261004", "261005")
    ctx = IisContext(site={("WEB-01", IIS_DIR): CUSTOM_FIELDS})
    e = normalize(iis(CUSTOM_LINE, file=new_file), NOW, ctx)
    assert (e.src_ip, e.username, e.raw["iis"]["_layout"]) == ("198.51.100.9", "lee", "site")
    # 같은 폴더 순서와 칸 수는 같지만 값 모양이 다른 줄(기본 순서 줄) → 다음 후보인 기본 순서로
    e = normalize(iis(IIS_LINE, file=new_file), NOW, ctx)
    assert (e.event_id, e.src_ip, e.raw["iis"]["_layout"]) == (500, "203.0.113.5", "default")


def test_iis_default_layout_is_marked():
    e = normalize(iis(IIS_LINE), NOW, IisContext())
    assert e.raw["iis"]["_layout"] == "default"


def test_iis_requester_values_cannot_break_parsing_with_the_files_own_layout():
    # method·URI·UA 는 요청자가 정한다 — 그 파일의 머리줄로 확인한 순서면 이상한 값이어도 해석·상태 코드(오류 수준)는 그대로
    line = "2026-10-04 01:02:03 10.0.0.10 1.2.3.4 /x - 443 - 203.0.113.5 500 - 500 0 0 7"
    for ctx in (IisContext(stored={("WEB-01", IIS_FILE): DEFAULT_FIELDS}),
                IisContext(learned={("WEB-01", IIS_FILE): (IIS_DIR, DEFAULT_FIELDS)})):
        e = normalize(iis(line), NOW, ctx)
        assert (e.event_id, e.level, e.src_ip) == (500, 2, "203.0.113.5")
        assert e.raw["iis"]["method"] == "1.2.3.4" and e.raw["iis"]["user_agent"] == "500"
    # 추정(기본 순서)일 때는 요청자 값이 서버 값 모양이면 원문으로 — 틀린 칸으로 읽는 것보다 낫다
    e = normalize(iis(line), NOW, IisContext())
    assert (e.event_id, e.src_ip, "iis" in e.raw) == (None, None, False)


@pytest.mark.parametrize(("client", "guessed", "stored"), [
    ("fe80::1%12", True, True), ("2001:db8::7", True, True), ("203.0.113.5", True, True),
    ("-", False, True),  # IIS 는 c-ip 를 늘 쓴다 — 추정할 때 비어 있으면 칸이 밀린 것
    ("cafe", False, False), ("dead", False, False), ("lee", False, False), ("443", False, False),
])
def test_iis_client_ip_shape(client, guessed, stored):
    line = IIS_LINE.replace("203.0.113.5", client)
    assert ("iis" in normalize(iis(line), NOW, IisContext()).raw) is guessed
    ctx = IisContext(stored={("WEB-01", IIS_FILE): DEFAULT_FIELDS})
    assert ("iis" in normalize(iis(line), NOW, ctx).raw) is stored


@pytest.mark.parametrize(("name", "old", "new"), [
    ("s-ip 가 IP 아님", "10.0.0.10", "WEB01"),
    ("time-taken 이 정수 아님", " 1234", " 12.5"),
    ("날짜 모양", "2026-10-04", "2026/10/04"),
    ("시각 모양", "01:02:03", "1:02:03"),
    ("상태 코드 0", " 500 0 0", " 0 0 0"),
    ("상태 코드 1000", " 500 0 0", " 1000 0 0"),
])
def test_iis_each_server_shape_alone_rejects(name, old, new):
    line = IIS_LINE.replace(old, new, 1)
    assert line != IIS_LINE, name
    for ctx in (IisContext(), IisContext(stored={("WEB-01", IIS_FILE): DEFAULT_FIELDS})):
        e = normalize(iis(line), NOW, ctx)
        assert ("iis" not in e.raw and e.event_id is None), name


def test_iis_nonstandard_status_with_the_files_own_layout():
    # 회귀(검토): 응용 프로그램이 돌려준 6xx·999 도 그 파일의 순서로는 읽는다
    ctx = IisContext(stored={("WEB-01", IIS_FILE): DEFAULT_FIELDS})
    assert normalize(iis(IIS_LINE.replace(" 500 0 0", " 999 0 0")), NOW, ctx).event_id == 999


# 실제 열 구성: 기본에서 cs-username 을 빼고 cs-host 를 더함 (IIS 순서 그대로, 15칸 — 기본과 칸 수가 같다)
HOST_FIELDS = ("date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "c-ip", "cs(User-Agent)",
               "cs(Referer)", "cs-host", "sc-status", "sc-substatus", "sc-win32-status", "time-taken")


@pytest.mark.parametrize("agent", ["198.51.100.77", "-"])
def test_iis_guess_cannot_be_steered_by_the_requester(agent):
    # 검토에서 재현한 공격: 머리줄을 모르는 동안 UA 를 IP 로 보내면 기본 순서로 읽혀 src_ip=공격자가 정한 값,
    # username=실제 IP 가 되었다. 이제 원문으로 남고, 그 파일의 순서를 알면 맞게 읽는다
    line = f"2026-10-04 01:02:03 10.0.0.10 POST /login - 443 203.0.113.5 {agent} - shop.example 401 1 0 15"
    e = normalize(iis(line), NOW, IisContext())
    assert (e.src_ip, e.username, e.event_id, "iis" in e.raw) == (None, None, None, False)
    e = normalize(iis(line), NOW, IisContext(site={("WEB-01", IIS_DIR): CUSTOM_FIELDS}))
    assert "iis" not in e.raw
    e = normalize(iis(line), NOW, IisContext(stored={("WEB-01", IIS_FILE): HOST_FIELDS}))
    assert (e.src_ip, e.username, e.event_id) == ("203.0.113.5", None, 401)


def test_iis_site_layout_cannot_misread_a_default_line_with_odd_values():
    # 같은 폴더의 순서(CUSTOM)와 칸 수가 같은 기본 순서 줄 + 요청자 값(method 1.2.3.4, UA 에 IP) → 원문
    line = "2026-10-04 01:02:03 10.0.0.10 1.2.3.4 /x - 443 - 203.0.113.5 198.51.100.77 - 401 0 0 7"
    e = normalize(iis(line), NOW, IisContext(site={("WEB-01", IIS_DIR): CUSTOM_FIELDS}))
    assert (e.src_ip, e.username, "iis" in e.raw) == (None, None, False)


@pytest.mark.parametrize("substatus", ["0", "100"])
def test_iis_guess_rejects_a_shifted_status(substatus):
    # 기본에서 Referer 를 빼고 sc-bytes 를 더한 구성(15칸): 기본으로 읽으면 하위 상태가 상태 코드 칸에 간다.
    # 500.100(ASP 오류)을 100(정보)으로 숨기지 않게 — Referer 칸에 숫자만 있으면 추정하지 않는다
    line = f"2026-10-04 01:02:03 10.0.0.10 GET /a.asp - 443 - 203.0.113.5 Mozilla/5.0 500 {substatus} 0 5120 15"
    e = normalize(iis(line), NOW, IisContext())
    assert (e.event_id, "iis" in e.raw) == (None, False)


def test_iis_learned_header_beats_stored_layout():
    # 같은 요청에서 받은 머리줄이 DB 의 옛 순서보다 우선 (파일 중간에 열 구성이 바뀐 경우).
    # 둘 다 모양 검사를 통과하고 결과만 다르게: 옛 순서에서는 그 칸이 cs(Cookie) 였다
    old = tuple("cs(Cookie)" if f == "cs-username" else f for f in DEFAULT_FIELDS)
    line = "2026-10-04 01:02:03 10.0.0.10 GET /x - 443 kim 203.0.113.5 Mozilla/5.0 - 401 0 0 7"
    ctx = IisContext(stored={("WEB-01", IIS_FILE): old})
    assert normalize(iis(line), NOW, ctx).username is None
    normalize(iis("#Fields: " + " ".join(DEFAULT_FIELDS)), NOW, ctx)
    e = normalize(iis(line), NOW, ctx)
    assert (e.username, e.src_ip, "_layout" in e.raw["iis"]) == ("kim", "203.0.113.5", False)


def test_iis_learned_layout_that_does_not_fit_falls_through():
    # 같은 요청의 머리줄과 칸 수가 다른 줄(저장된 순서 없음) → 추정으로 넘어간다 (멈추지 않는다)
    ctx = IisContext()
    normalize(iis("#Fields: " + " ".join(CUSTOM_FIELDS[:-1])), NOW, ctx)
    e = normalize(iis(IIS_LINE), NOW, ctx)
    assert (e.event_id, e.raw["iis"]["_layout"]) == (500, "default")
    ctx.stored[("WEB-01", IIS_FILE)] = DEFAULT_FIELDS  # 저장된 순서가 있으면 그것으로 (추정 표시 없음)
    assert "_layout" not in normalize(iis(IIS_LINE), NOW, ctx).raw["iis"]


def test_iis_custom_field_names_are_learned():
    # IIS 8.5+ 사용자 지정 필드: 관리자가 정한 이름(한글도) — 회귀(검토): 예전에는 ASCII 만 받아 그 사이트를 못 읽었다
    ctx = IisContext()
    fields = DEFAULT_FIELDS + ("클라이언트IP",)
    normalize(iis("#Fields: " + " ".join(fields)), NOW, ctx)
    e = normalize(iis(IIS_LINE + " 198.51.100.200"), NOW, ctx)
    assert e.event_id == 500 and e.raw["iis"]["클라이언트ip"] == "198.51.100.200"
    normalize(iis("#Fields: date time " + "x" * 300), NOW, ctx := IisContext())
    assert ctx.learned == {}  # 너무 긴 이름은 배우지 않는다


def test_iis_only_fields_header_is_learned_and_keys_are_per_file():
    ctx = IisContext()
    for line in ("#Software: Microsoft Internet Information Services 10.0", "#Version: 1.0", "#Date: 2026-10-04"):
        assert normalize(iis(line), NOW, ctx) is None
    assert ctx.learned == {}
    assert normalize(iis("#Fields: date time bad\x01name"), NOW, ctx) is None
    assert ctx.learned == {}  # 제어 문자가 든 이름은 배우지 않는다
    other = IIS_FILE.replace("W3SVC1", "W3SVC2")
    records = [iis(IIS_LINE), iis(IIS_LINE), iis("#Fields: date time"), iis(IIS_LINE, file=other),
               iis(IIS_LINE, host="WEB-02"), {"log": IIS_LINE, "log_source": "file"}, iis(IIS_LINE, file="a\x00b")]
    assert layout_keys(records) == {("WEB-01", IIS_FILE, IIS_DIR), ("WEB-01", other, IIS_DIR.replace("1", "2")),
                                    ("WEB-02", IIS_FILE, IIS_DIR)}


def test_iis_header_in_request_also_serves_other_files_in_same_folder():
    ctx = IisContext()
    normalize(iis("#Fields: " + " ".join(CUSTOM_FIELDS)), NOW, ctx)
    e = normalize(iis(CUSTOM_LINE, file=IIS_FILE.replace("261004", "261005")), NOW, ctx)
    assert (e.src_ip, e.raw["iis"]["_layout"]) == ("198.51.100.9", "site")


# ------------------------------------------------------------------ MSSQL

def mssql(log, file="ERRORLOG"):
    return {"log": log, "agent_host": "DB-01", "log_source": "mssql", "file": file}


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


# 에이전트 0.4.0 (multiline): 시각으로 시작하지 않는 줄은 앞 레코드에 붙어 온다 — UTF-16 을 UTF-8 로 바꾼 뒤라 CRLF 의 \r 이 남는다
BANNER = ("2026-10-04 09:00:01.12 Server      Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64) \r\n"
          "\tOct  8 2022 05:58:25 \r\n\tCopyright (C) 2022 Microsoft Corporation\r\n"
          "\tDeveloper Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64>\r\n")


def test_mssql_multiline_record_parsed_by_first_line():
    e = normalize(mssql(BANNER), NOW)
    assert e.ts == datetime(2026, 10, 4, 0, 0, 1, 120000, tzinfo=UTC) and e.provider == "Server"
    assert e.raw["mssql"]["lines"] == 4 and e.raw["log"] == BANNER  # 원본은 그대로
    assert e.raw["mssql"]["text"].startswith("Microsoft SQL Server 2022") and "\r" not in e.message
    assert e.message.splitlines()[1:] == ["\tOct  8 2022 05:58:25 ", "\tCopyright (C) 2022 Microsoft Corporation",
                                          "\tDeveloper Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64>"]
    assert e.level == 4


def test_mssql_multiline_error_body_gets_number_once():
    head = normalize(mssql("2026-10-04 10:15:22.53 spid51      Error: 50000, Severity: 16, State: 1.\r\n"), NOW)
    body = normalize(mssql("2026-10-04 10:15:22.53 spid51      Nightly job failed:\r\n"
                           "\tstep 3 (copy) returned 5\r\n\r\n\tcontact the DBA\r\n"), NOW)
    assert (head.event_id, head.level, "lines" in head.raw["mssql"]) == (None, 5, False)
    assert (body.event_id, body.level, body.raw["mssql"]["lines"]) == (50000, 3, 3)
    assert body.message == "Nightly job failed:\n\tstep 3 (copy) returned 5\n\tcontact the DBA"


def test_mssql_plain_and_multiline_records_count_the_same():
    plain = ["2026-10-04 10:15:22.53 Logon       Error: 18456, Severity: 14, State: 8.",
             "2026-10-04 10:15:22.53 Logon       Login failed for user 'sa'. Reason: x [CLIENT: 10.0.0.5]",
             "2026-10-04 10:16:00.00 spid9s      Starting up database 'ERP'.",
             "\tcontinued detail line"]
    one_by_one = [normalize(mssql(line, file="A\\ERRORLOG"), NOW) for line in plain]
    merged = [normalize(mssql(rec, file="B\\ERRORLOG"), NOW) for rec in (plain[0], plain[1], plain[2] + "\n" + plain[3])]
    assert [e.event_id for e in one_by_one if e.event_id] == [e.event_id for e in merged if e.event_id] == [18456]
    key = lambda e: (e.ts, e.provider, e.event_id, e.level)
    assert [key(e) for e in one_by_one[:3]] == [key(e) for e in merged]
    assert one_by_one[3].provider is None and one_by_one[3].ts == NOW  # 0.3.0 의 이어지는 줄은 지금처럼


def test_mssql_edge_lines_keep_old_behaviour():
    assert normalize(mssql("\r\n"), NOW) is None
    e = normalize(mssql("\ufeff2026-10-04 10:15:22.53 Server      Starting up\r\n"), NOW)
    assert (e.provider, e.message, "lines" in e.raw["mssql"]) == ("Server", "Starting up", False)
    e = normalize(mssql("\tat line 5 error"), NOW)  # clean_text 가 앞뒤 공백을 지우는 것도 예전과 같다
    assert (e.ts, e.provider, e.level, e.message) == (NOW, None, 2, "at line 5 error")


def test_mssql_error_header_pairs_only_within_the_same_file():
    # 한 PC 의 두 인스턴스(파일이 다름)가 같은 시각·프로세스로 섞여 와도 파일 안에서만 짝을 맞춘다
    stamp = "2026-10-04 10:15:22.53 spid51      "
    normalize(mssql(stamp + "Error: 9002, Severity: 17, State: 2.", file="I1\\ERRORLOG"), NOW)
    normalize(mssql(stamp + "Error: 824, Severity: 24, State: 2.", file="I2\\ERRORLOG"), NOW)
    b1 = normalize(mssql(stamp + "The transaction log is full.", file="I1\\ERRORLOG"), NOW)
    b2 = normalize(mssql(stamp + "I/O error detected.", file="I2\\ERRORLOG"), NOW)
    assert (b1.event_id, b2.event_id) == (9002, 824)


# ------------------------------------------------ 저장된 값만으로 공통 필드 다시 구하기 (옛 보관 파일 복원)

def _roundtrip_records():
    import json
    from pathlib import Path

    real = [json.loads(line) for line in (Path(__file__).resolve().parent / "fixtures" / "winevtlog" / "agent-fb4.0.14.jsonl")
            .read_text(encoding="utf-8").splitlines() if line.strip()]
    yield from ({**r, "agent_host": "WIN-CI", "log_source": "winevtlog"} for r in real)
    yield winevt()                                                       # EventData 맵을 보낸 레코드
    yield winevt(EventID=18456, ProviderName="MSSQLSERVER", Channel="Application", EventData=None,
                 Message="Login failed for user 'sa'. Reason: x [CLIENT: 10.9.8.7]")
    yield iis(IIS_LINE)
    yield mssql("2026-10-04 10:15:22.53 Logon       Login failed for user 'kim'. Reason: x [CLIENT: 10.0.0.5]")
    yield mssql("2026-10-04 10:15:22.53 spid51      Starting up database 'ERP'.")
    yield {"pri": 38, "host": "lnx", "ident": "sshd", "log_source": "syslog",
           "message": "Failed password for invalid user admin from 203.0.113.45 port 40022 ssh2"}
    yield {"MESSAGE": "Invalid user bob from 198.51.100.4", "_HOSTNAME": "lnx2", "SYSLOG_IDENTIFIER": "sshd",
           "log_source": "journald"}
    yield {"log": "2026-10-03 ERROR something broke", "log_source": "file", "log_channel": "app"}


def test_derive_common_matches_normalize_for_every_source():
    from app.normalizers import derive_common

    events = [e for e in (normalize(r, NOW) for r in _roundtrip_records()) if isinstance(e, Event)]
    assert len(events) > 20 and any(e.username for e in events) and any(e.src_ip for e in events)
    for e in events:
        assert derive_common(e.source, e.channel, e.provider, e.event_id, e.message, e.raw) == \
            (e.category, e.username, e.src_ip), (e.source, e.event_id, e.message[:60])


def test_nul_bytes_are_removed_from_every_text_field():
    # 회귀(벤치마킹 검토에서 재현): NUL 하나가 그 요청 전체를 500 으로 만들어 에이전트가 같은 청크를 끝없이 다시 보냈다
    e = normalize({"pri": 38, "host": "sw\x00itch", "ident": "ss\x00hd", "log_source": "syslog",
                   "message": "Failed password for ev\x00il from 203.0.113.\x0045 port 1 ssh2"}, NOW)
    assert (e.host, e.provider, "\x00" in e.message) == ("switch", "sshd", False)
    w = normalize(winevt(Channel="Sec\x00urity", EventData={"TargetUserName": "ki\x00m", "IpAddress": "10.0.0.\x005"}), NOW)
    assert (w.channel, w.username, w.src_ip) == ("Security", "kim", "10.0.0.5")
    assert normalize({"agent_host": "\x00", "log_source": "file", "log": "x"}, NOW).host == "unknown"
