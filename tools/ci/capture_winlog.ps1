# CI: raise real Windows security events on the runner and record what the agent's winevtlog input emits
# (same winevtlog settings as the agent template, output to a file). Prints one line per record:
#   WLMCAPTURE {json}
# so the record shape (StringInserts order and value types, EventData presence) can be checked against the server
# (normalizers/windows.py, rules in config/alerts.yaml). Throwaway local account and service, removed at the end.
# ASCII only (Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page).
param(
    [Parameter(Mandatory = $true)] [string] $FluentBitExe,
    [Parameter(Mandatory = $true)] [string] $Rendered,       # agent-render\windows-min.yaml
    [string] $Work = (Join-Path ([System.IO.Path]::GetTempPath()) "wlm-winlog"),
    [string] $Python = "python"
)
$ErrorActionPreference = "Stop"
if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
foreach ($d in "state", "out") { New-Item -ItemType Directory -Force -Path (Join-Path $Work $d) | Out-Null }
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$cfg = Join-Path $Work "fb.yaml"
$out = Join-Path $Work "out\records.jsonl"

# Audit policy by subcategory GUID (names are localised): Logon, User Account Mgmt, Security Group Mgmt,
# Process Creation, Security System Extension
foreach ($g in "{0CCE9215-69AE-11D9-BED3-505054503030}", "{0CCE9235-69AE-11D9-BED3-505054503030}",
               "{0CCE9237-69AE-11D9-BED3-505054503030}", "{0CCE922B-69AE-11D9-BED3-505054503030}",
               "{0CCE9211-69AE-11D9-BED3-505054503030}") {
    & auditpol /set /subcategory:$g /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $g" }
}
$sys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Force -Path $sys | Out-Null
Set-ItemProperty -Path $sys -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
$sbl = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Force -Path $sbl | Out-Null
Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord

& $Python (Join-Path $here "render_agent_configs.py") --derive-winlog $Rendered $cfg --state "$Work\state" --out $out `
    --channels "Security,System,Microsoft-Windows-PowerShell/Operational"
if ($LASTEXITCODE -ne 0) { throw "derive-winlog failed" }
$fb = Start-Process $FluentBitExe -ArgumentList "-c", $cfg -PassThru -NoNewWindow
Start-Sleep -Seconds 6   # subscriptions are set up; read_existing_events is false

Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class WlmLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
$user = "wlmci"
$pass = "Wl!" + [guid]::NewGuid().ToString("N").Substring(0, 16) + "a9"
try {
    & net user $user $pass /add | Out-Null                       # 4720 (+4722, 4738)
    & net localgroup administrators $user /add | Out-Null         # 4732 TargetSid S-1-5-32-544
    foreach ($type in 2, 3) {                                     # 4625 interactive, network
        $t = [IntPtr]::Zero
        [WlmLogon]::LogonUser($user, ".", "wrong-password", $type, 0, [ref]$t) | Out-Null
    }
    $t = [IntPtr]::Zero
    if ([WlmLogon]::LogonUser($user, ".", $pass, 3, 0, [ref]$t)) { [WlmLogon]::CloseHandle($t) | Out-Null }  # 4624 type 3
    & sc.exe create wlmcisvc binPath= "C:\Windows\System32\cmd.exe /c exit" | Out-Null   # 7045 (System), 4697
    & powershell -NoProfile -Command "Write-Output 'wlm-scriptblock-check'" | Out-Null  # 4104 (script block logging), 4688
} finally {
    & sc.exe delete wlmcisvc | Out-Null
    & net localgroup administrators $user /delete 2>$null | Out-Null   # 4733
    & net user $user /delete 2>$null | Out-Null                        # 4726
}
Start-Sleep -Seconds 8
Stop-Process -Id $fb.Id -Force

$code = @'
import json, sys
want = {4624, 4625, 4688, 4697, 4720, 4726, 4732, 4733, 4738, 7045, 4104}
seen = {}
for line in open(sys.argv[1], encoding="utf-8"):
    if not line.strip():
        continue
    r = json.loads(line)
    eid = r.get("EventID")
    if eid not in want or seen.get(eid, 0) >= 2:
        continue
    if eid == 4688 and "wlm" not in json.dumps(r) and "powershell" not in json.dumps(r).lower():
        continue
    seen[eid] = seen.get(eid, 0) + 1
    r["Message"] = (r.get("Message") or "")[:200]
    print("WLMCAPTURE " + json.dumps(r, ensure_ascii=True))
print("WLMSUMMARY " + json.dumps({str(k): v for k, v in sorted(seen.items())}))
missing = {4625, 4720, 4732} - set(seen)
sys.exit(1 if missing else 0)
'@
$py = Join-Path $Work "show.py"
Set-Content -Encoding ASCII -Path $py -Value $code
& $Python $py $out
if ($LASTEXITCODE -ne 0) { throw "expected 4625, 4720 and 4732 in the agent output" }
