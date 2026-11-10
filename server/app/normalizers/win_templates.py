"""Windows 이벤트의 EventData 필드 이름 (공급자, 이벤트 ID) → 이름 순서.

에이전트(Fluent Bit 4.0 winevtlog)는 EventData 를 이름 없이 StringInserts 배열로만 보낸다(event_data_as_map 은 5.1 부터,
857359e 에서 뺐다). 배열의 순서는 공급자 매니페스트의 템플릿 순서와 같다 — 그래서 서버가 이름을 붙여
raw.winevtlog.EventData 에 덧붙인다(원본 StringInserts 는 그대로, AGENTS.md 원본 보존).

- 출처: 윈도 공급자 매니페스트의 템플릿(`Get-WinEvent -ListProvider` — 고정 자료 tests/fixtures/winevtlog/manifest-templates.json,
  tools/ci/dump_templates.ps1)이 버전마다 이름·순서를 정하고, 윈도 CI(tools/ci/capture_winlog.ps1)가 실제 이벤트를 일으켜
  에이전트 레코드로 필드 수를 확인한다(tests/test_win_templates.py). 문서를 보고 손으로 옮긴 이름은 틀리기도 했다(4702).
- 이벤트 버전(레코드의 Version)마다 다를 수 있다. 보통은 뒤에 붙지만 4624 v3 은 RemoteCredentialGuard 를 **중간에**
  넣었다(실측) → VERSIONED 에 버전별로 두고, 없으면 기본(TEMPLATES)을 쓴다. 배열보다 긴 이름은 버린다(옛 버전 이벤트).
- 이름이 이미 오는 레코드(EventData 맵)에는 쓰지 않는다.
"""

from __future__ import annotations

SECURITY = "Microsoft-Windows-Security-Auditing"
_SUBJECT = ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId")
_TARGET_ACCOUNT = ("TargetUserName", "TargetDomainName", "TargetSid")
_GROUP_MEMBER = ("MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", *_SUBJECT, "PrivilegeList")
_TASK = (*_SUBJECT, "TaskName", "TaskContent", "ClientProcessStartKey", "ClientProcessId", "ParentProcessId",
         "RpcCallClientLocality", "FQDN")
_4768 = ("TargetUserName", "TargetDomainName", "TargetSid", "ServiceName", "ServiceSid", "TicketOptions", "Status",
         "TicketEncryptionType", "PreAuthType", "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint")
_4769 = ("TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid", "TicketOptions", "TicketEncryptionType",
         "IpAddress", "IpPort", "Status", "LogonGuid", "TransmittedServices")
# Kerberos v2 가 뒤에 붙이는 암호화 종류 — 계정·서비스·DC 가 지원하는 종류와 가진 키, 세션 키
_KERBEROS_ETYPES = ("AccountSupportedEncryptionTypes", "AccountAvailableKeys", "ServiceSupportedEncryptionTypes",
                    "ServiceAvailableKeys", "DCSupportedEncryptionTypes", "DCAvailableKeys",
                    "ClientAdvertizedEncryptionTypes", "SessionKeyEncryptionType")

TEMPLATES: dict[tuple[str, int], tuple[str, ...]] = {
    # 로그온·로그오프
    (SECURITY, 4624): (*_SUBJECT, "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType",
                       "LogonProcessName", "AuthenticationPackageName", "WorkstationName", "LogonGuid",
                       "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress",
                       "IpPort", "ImpersonationLevel", "RestrictedAdminMode", "TargetOutboundUserName",
                       "TargetOutboundDomainName", "VirtualAccount", "TargetLinkedLogonId", "ElevatedToken"),
    (SECURITY, 4625): (*_SUBJECT, "TargetUserSid", "TargetUserName", "TargetDomainName", "Status", "FailureReason",
                       "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
                       "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress",
                       "IpPort"),
    (SECURITY, 4634): ("TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType"),
    (SECURITY, 4647): ("TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId"),
    (SECURITY, 4648): (*_SUBJECT, "LogonGuid", "TargetUserName", "TargetDomainName", "TargetLogonGuid",
                       "TargetServerName", "TargetInfo", "ProcessId", "ProcessName", "IpAddress", "IpPort"),
    (SECURITY, 4672): (*_SUBJECT, "PrivilegeList"),
    # 프로세스·서비스·예약 작업
    (SECURITY, 4688): (*_SUBJECT, "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId", "CommandLine",
                       "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "ParentProcessName",
                       "MandatoryLabel"),
    (SECURITY, 4697): (*_SUBJECT, "ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType", "ServiceAccount",
                       "ClientProcessStartKey", "ClientProcessId", "ParentProcessId"),
    (SECURITY, 4698): _TASK,
    (SECURITY, 4699): _TASK,
    (SECURITY, 4702): (*_SUBJECT, "TaskName", "TaskContentNew", *_TASK[6:]),   # 바뀐 뒤의 내용 — 4698 과 이름이 다르다(매니페스트)
    # 정책·계정·그룹
    # v1(Server 2025 실측, Windows 11 24H2 매니페스트도 같다)은 바꾼 프로세스를 뒤에 붙인다 — 옛 v0 은 앞 8개만 온다(배열보다 긴 이름은 버림)
    (SECURITY, 4719): (*_SUBJECT, "CategoryId", "SubcategoryId", "SubcategoryGuid", "AuditPolicyChanges",
                       "ClientProcessId", "ClientProcessStartKey"),
    (SECURITY, 4720): (*_TARGET_ACCOUNT, *_SUBJECT, "PrivilegeList", "SamAccountName", "DisplayName",
                       "UserPrincipalName", "HomeDirectory", "HomePath", "ScriptPath", "ProfilePath", "UserWorkstations",
                       "PasswordLastSet", "AccountExpires", "PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue",
                       "NewUacValue", "UserAccountControl", "UserParameters", "SidHistory", "LogonHours"),
    (SECURITY, 4722): (*_TARGET_ACCOUNT, *_SUBJECT),
    (SECURITY, 4738): ("Dummy", *_TARGET_ACCOUNT, *_SUBJECT, "PrivilegeList", "SamAccountName", "DisplayName",
                       "UserPrincipalName", "HomeDirectory", "HomePath", "ScriptPath", "ProfilePath", "UserWorkstations",
                       "PasswordLastSet", "AccountExpires", "PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue",
                       "NewUacValue", "UserAccountControl", "UserParameters", "SidHistory", "LogonHours"),
    (SECURITY, 4723): (*_TARGET_ACCOUNT, *_SUBJECT, "PrivilegeList"),
    (SECURITY, 4724): (*_TARGET_ACCOUNT, *_SUBJECT),
    (SECURITY, 4725): (*_TARGET_ACCOUNT, *_SUBJECT),
    (SECURITY, 4726): (*_TARGET_ACCOUNT, *_SUBJECT, "PrivilegeList"),
    (SECURITY, 4728): _GROUP_MEMBER,
    (SECURITY, 4729): _GROUP_MEMBER,
    (SECURITY, 4732): _GROUP_MEMBER,
    (SECURITY, 4733): _GROUP_MEMBER,
    (SECURITY, 4756): _GROUP_MEMBER,
    (SECURITY, 4757): _GROUP_MEMBER,
    (SECURITY, 4740): (*_TARGET_ACCOUNT, *_SUBJECT),
    (SECURITY, 4767): (*_TARGET_ACCOUNT, *_SUBJECT),
    # Kerberos·NTLM (도메인 컨트롤러)
    (SECURITY, 4768): _4768,
    (SECURITY, 4769): _4769,
    (SECURITY, 4771): ("TargetUserName", "TargetSid", "ServiceName", "TicketOptions", "Status", "PreAuthType",
                       "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint"),
    (SECURITY, 4776): ("PackageName", "TargetUserName", "Workstation", "Status"),
    # 다른 공급자
    # UserData/LogFileCleared — v1 은 지운 프로세스를 뒤에 붙인다(실측). 104 는 지운 로그 이름(Channel)이 온다
    ("Microsoft-Windows-Eventlog", 1102): (*_SUBJECT, "ClientProcessId", "ClientProcessStartKey"),
    ("Microsoft-Windows-Eventlog", 104): ("SubjectUserName", "SubjectDomainName", "Channel", "BackupPath",
                                          "ClientProcessId", "ClientProcessStartKey"),
    ("Application Error", 1000): ("AppName", "AppVersion", "AppTimeStamp", "ModuleName", "ModuleVersion", "ModuleTimeStamp",
                                  "ExceptionCode", "FaultingOffset", "ProcessId", "ProcessCreationTime", "AppPath",
                                  "ModulePath", "IntegratorReportId", "PackageFullName", "PackageRelativeAppId"),
    ("Service Control Manager", 7045): ("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"),
    ("Microsoft-Windows-PowerShell", 4104): ("MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"),
}


# TEMPLATES 가 맞는 이벤트 버전 — 윈도 CI 실측 레코드(tests/fixtures/winevtlog/agent-fb4.0.14.jsonl)로 확인한 것만(test_win_templates 가 대조).
# 4624 의 기본 이름은 v2(문서), v3 은 VERSIONED
VERIFIED: dict[tuple[str, int], int] = {
    ("Microsoft-Windows-PowerShell", 4104): 1, (SECURITY, 4624): 2, (SECURITY, 4625): 0, (SECURITY, 4688): 2,
    (SECURITY, 4697): 1, (SECURITY, 4720): 0, (SECURITY, 4726): 0, (SECURITY, 4732): 0, (SECURITY, 4733): 0,
    (SECURITY, 4738): 0, ("Service Control Manager", 7045): 0,
    # 윈도 CI 캡처 확대 (B-45, 실행 42723626534)
    (SECURITY, 4634): 0, (SECURITY, 4698): 1, (SECURITY, 4699): 1, (SECURITY, 4719): 1, (SECURITY, 4722): 0,
    (SECURITY, 4740): 0, (SECURITY, 4776): 0, ("Microsoft-Windows-Eventlog", 1102): 1, ("Microsoft-Windows-Eventlog", 104): 1,
    ("Application Error", 1000): 0,
}
# 클래식 이벤트 원본 — 필드를 더해도 Version 이 늘지 않는다(늘 0). 옛 Windows(7·2008 R2)의 응용 프로그램 충돌은 앞 13개만 온다 →
# 버전으로 옛 모양을 가를 수 없으니 실측했어도 템플릿보다 길 때만 '템플릿 불일치'(검토)
UNVERSIONED = frozenset({("Application Error", 1000)})

_4624_V3 = list(TEMPLATES[(SECURITY, 4624)])
_4624_V3.insert(_4624_V3.index("RestrictedAdminMode") + 1, "RemoteCredentialGuard")
# 실측한 버전(VERIFIED)보다 새 버전이 뒤에 필드를 더 붙이면 여기에 둔다(매니페스트) — 기본을 그 버전으로 늘리면 실측한 옛 버전
# (4732 v0)이 '템플릿 불일치'가 되고, 두지 않으면 새 버전 레코드가 '처음 보는 버전'으로 '템플릿 불일치'가 된다(도메인 컨트롤러의
# 4768·4769 마다). 실측한 버전이 가장 새 것이면 기본 이름이 그 버전이다(4719·1102 v1).
VERSIONED: dict[tuple[str, int, int], tuple[str, ...]] = {
    (SECURITY, 4624, 3): tuple(_4624_V3),
    # 시간 제한 그룹 구성원(AD 권한 있는 액세스 관리)의 만료 시각
    (SECURITY, 4728, 1): (*_GROUP_MEMBER, "MembershipExpirationTime"),
    (SECURITY, 4732, 1): (*_GROUP_MEMBER, "MembershipExpirationTime"),
    (SECURITY, 4756, 1): (*_GROUP_MEMBER, "MembershipExpirationTime"),
    (SECURITY, 4768, 1): (*_4768, "ResponseTicket"),
    (SECURITY, 4768, 2): (*_4768, "ResponseTicket", *_KERBEROS_ETYPES, "PreAuthEncryptionType"),
    (SECURITY, 4769, 1): (*_4769, "RequestTicketHash", "ResponseTicketHash"),
    (SECURITY, 4769, 2): (*_4769, "RequestTicketHash", "ResponseTicketHash", *_KERBEROS_ETYPES),
}


def _version(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def mismatch(provider: str | None, event_id: int | None, inserts, version=None) -> bool:
    """이름이 어긋났을 수 있는 이벤트 (수집 품질, B-56): 실측한 버전·VERSIONED 버전인데 필드 수가 다르거나, 처음 보는 **새** 버전인데
    필드 수가 다르다(4624 v3 처럼 중간에 끼었을 수 있다). 옛 버전은 앞부분이 같아 named 가 뒤 이름만 버린다 — 표시하지 않는다
    (검토에서 재현: Server 2016·2019 의 4697 v0 가 매일 '템플릿 불일치'로 남았다). 실측하지 않은 템플릿과 버전이 늘지 않는 클래식 원본
    (UNVERSIONED)은 필드가 더 많을 때만."""
    if not isinstance(inserts, list):
        return False
    key, v = (provider or "", event_id or 0), _version(version)
    if (names := VERSIONED.get((*key, v))) is not None:
        return len(inserts) != len(names)
    if (names := TEMPLATES.get(key)) is None:
        return False
    if key in UNVERSIONED:
        return len(inserts) > len(names)
    known = [k[2] for k in VERSIONED if k[:2] == key] + ([VERIFIED[key]] if key in VERIFIED else [])
    if not known:
        return len(inserts) > len(names)
    if v == VERIFIED.get(key) or v < 0 or v > max(known):
        return len(inserts) != len(names)
    return False


def named(provider: str | None, event_id: int | None, inserts: list, version=None) -> dict | None:
    """StringInserts 에 이름을 붙인 맵. 모르는 이벤트면 None. 배열보다 긴 이름(새 버전에서 붙은 필드)은 버린다."""
    key = (provider or "", event_id or 0)
    names = VERSIONED.get((*key, _version(version))) or TEMPLATES.get(key)
    if names is None or not isinstance(inserts, list):
        return None
    return dict(zip(names, inserts, strict=False))
