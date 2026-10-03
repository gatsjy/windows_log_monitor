"""로그 분류(category). 화면의 '분류' 필터·대시보드·알림 규칙에서 쓴다.

분류를 바꾸거나 추가하려면 classify() 에 규칙을 넣고, 화면 표시 이름은 web/js/levels.js 의 CATEGORY_LABELS,
기존 데이터는 마이그레이션의 UPDATE (007_fields.sql 참고) 로 맞춘다.
"""

from __future__ import annotations

# 값 → 화면 이름 (서버 쪽 참고용. 실제 표시 이름은 web/js/levels.js)
CATEGORIES = {
    "security": "보안 (Windows)",
    "system": "시스템 (Windows)",
    "application": "응용 프로그램 (Windows)",
    "powershell": "PowerShell",
    "defender": "백신 (Defender)",
    "rdp": "원격 데스크톱",
    "sysmon": "Sysmon",
    "windows": "기타 Windows",
    "iis": "웹 서버 (IIS)",
    "mssql": "DB (MSSQL)",
    "linux": "Linux",
    "syslog": "syslog 장비",
    "file": "파일 로그",
}

_IIS_PROVIDERS = ("w3svc", "was", "microsoft-windows-was", "microsoft-windows-iis", "iis")
_MSSQL_PROVIDERS = ("mssql", "sqlserveragent", "sqlagent", "sqlbrowser", "sqlwriter")


def classify(source: str, channel: str | None, provider: str | None) -> str:
    p = (provider or "").lower()
    c = (channel or "").lower()
    if source == "iis" or p.startswith(_IIS_PROVIDERS):
        return "iis"
    if source == "mssql" or p.startswith(_MSSQL_PROVIDERS):
        return "mssql"
    if source == "winevtlog":
        if "powershell" in c:
            return "powershell"
        if "windows defender" in c:
            return "defender"
        if "terminalservices" in c or "remotedesktop" in c:
            return "rdp"
        if "sysmon" in c:
            return "sysmon"
        return {"security": "security", "system": "system", "application": "application"}.get(c, "windows")
    if source == "journald":
        return "linux"
    if source == "syslog":
        return "syslog"
    return "file"
