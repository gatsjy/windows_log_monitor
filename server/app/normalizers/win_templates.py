"""Windows 이벤트의 EventData 필드 이름 (공급자, 이벤트 ID) → 이름 순서.

에이전트(Fluent Bit 4.0 winevtlog)는 EventData 를 이름 없이 StringInserts 배열로만 보낸다(event_data_as_map 은 5.1 부터,
857359e 에서 뺐다). 배열의 순서는 공급자 매니페스트의 템플릿 순서와 같다 — 그래서 서버가 이름을 붙여
raw.winevtlog.EventData 에 덧붙인다(원본 StringInserts 는 그대로, AGENTS.md 원본 보존).

- 출처: Microsoft Learn 의 이벤트 문서(필드 순서)와 `wevtutil gp <공급자> /ge /gm:true` 의 템플릿.
  윈도 CI(tools/ci/capture_winlog.ps1)가 실제 이벤트를 일으켜 에이전트 레코드로 순서를 확인한다(tests/test_win_templates.py).
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
    (SECURITY, 4702): _TASK,
    # 정책·계정·그룹
    (SECURITY, 4719): (*_SUBJECT, "CategoryId", "SubcategoryId", "SubcategoryGuid", "AuditPolicyChanges"),
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
    (SECURITY, 4768): ("TargetUserName", "TargetDomainName", "TargetSid", "ServiceName", "ServiceSid", "TicketOptions",
                       "Status", "TicketEncryptionType", "PreAuthType", "IpAddress", "IpPort", "CertIssuerName",
                       "CertSerialNumber", "CertThumbprint"),
    (SECURITY, 4769): ("TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid", "TicketOptions",
                       "TicketEncryptionType", "IpAddress", "IpPort", "Status", "LogonGuid", "TransmittedServices"),
    (SECURITY, 4771): ("TargetUserName", "TargetSid", "ServiceName", "TicketOptions", "Status", "PreAuthType",
                       "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint"),
    (SECURITY, 4776): ("PackageName", "TargetUserName", "Workstation", "Status"),
    # 다른 공급자
    ("Microsoft-Windows-Eventlog", 1102): _SUBJECT,  # UserData/LogFileCleared
    ("Service Control Manager", 7045): ("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"),
    ("Microsoft-Windows-PowerShell", 4104): ("MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"),
}


_4624_V3 = list(TEMPLATES[(SECURITY, 4624)])
_4624_V3.insert(_4624_V3.index("RestrictedAdminMode") + 1, "RemoteCredentialGuard")
VERSIONED: dict[tuple[str, int, int], tuple[str, ...]] = {
    (SECURITY, 4624, 3): tuple(_4624_V3),
}


def _version(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def named(provider: str | None, event_id: int | None, inserts: list, version=None) -> dict | None:
    """StringInserts 에 이름을 붙인 맵. 모르는 이벤트면 None. 배열보다 긴 이름(새 버전에서 붙은 필드)은 버린다."""
    key = (provider or "", event_id or 0)
    names = VERSIONED.get((*key, _version(version))) or TEMPLATES.get(key)
    if names is None or not isinstance(inserts, list):
        return None
    return dict(zip(names, inserts, strict=False))
