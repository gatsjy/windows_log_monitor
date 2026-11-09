# Record what the agent's winevtlog input emits for real Windows events (same winevtlog settings as the agent template,
# output to a file). Prints one line per record:
#   WLMCAPTURE {json}
# so the record shape (StringInserts order and value types, EventData presence) can be checked against the server
# (normalizers/windows.py, rules in config/alerts.yaml). The machine name is replaced by WIN-CI, so the WLMCAPTURE lines
# can become the fixture as they are (BACKLOG B-45).
#
# Two modes:
#   -ThrowawayRunner  CI only. Raises the events by changing the machine: throwaway local admin account, audit and
#                     lockout policy (left at 0), a service and a scheduled task, kills the print spooler, crashes a
#                     process and clears the System and Security logs (1102, 104). Refused unless this is a
#                     GitHub-hosted runner (GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted, not act), and
#                     always refused on a domain member or a domain controller. Self-hosted runners are refused too:
#                     they are not thrown away after the job.
#   (default)         Listen only for -ListenSeconds and change nothing on this PC: raise the events you need by hand
#                     meanwhile (field captures on real PCs and DCs, BACKLOG B-28). Each run writes to a new
#                     run-<time> folder under -Work and deletes nothing.
# ASCII only (Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page).
param(
    [Parameter(Mandatory = $true)] [string] $FluentBitExe,
    [Parameter(Mandatory = $true)] [string] $Rendered,       # agent-render\windows-min.yaml
    [string] $Work = (Join-Path ([System.IO.Path]::GetTempPath()) "wlm-winlog"),
    # Committed real records (server/tests/fixtures/winevtlog): the fresh capture must have the same shape
    [string] $Fixture = "",
    [string] $Python = "python",
    [switch] $ThrowawayRunner,
    [int] $ListenSeconds = 300
)
$ErrorActionPreference = "Stop"
$marker = ".wlm-capture"   # written into folders this script made, so it only ever deletes its own folder
if ($ThrowawayRunner) {
    if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted" -or $env:ACT) {
        throw "-ThrowawayRunner changes the machine: only on a GitHub-hosted runner (GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted, not act)"
    }
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    if ($cs.PartOfDomain -or $os.ProductType -eq 2) { throw "Refusing to change a domain member or a domain controller" }
    if (Test-Path $Work) {
        $own = Test-Path (Join-Path $Work $marker)
        if (-not $own -and @(Get-ChildItem -Force $Work).Count) { throw "Refusing to delete $Work - not made by this script" }
        Remove-Item -Recurse -Force $Work
    }
} else {
    $Work = Join-Path $Work ("run-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
foreach ($d in "state", "out") { New-Item -ItemType Directory -Force -Path (Join-Path $Work $d) | Out-Null }
Set-Content -Path (Join-Path $Work $marker) -Value "capture_winlog.ps1" -Encoding ASCII
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$cfg = Join-Path $Work "fb.yaml"
$out = Join-Path $Work "out\records.jsonl"

# Native commands whose failure does not matter (cleanup, best-effort events). Windows PowerShell 5.1 turns their stderr
# into a terminating error under ErrorActionPreference Stop - that skipped the rest of the cleanup (review).
function Invoke-Native([scriptblock] $Block) {
    try { & $Block 2>&1 | Out-Null } catch { }
}

if ($ThrowawayRunner) {
    # Audit policy by subcategory GUID (names are localised): Logon, Logoff, User Account Mgmt, Security Group Mgmt,
    # Process Creation, Security System Extension, Other Object Access (scheduled tasks), Audit Policy Change,
    # Credential Validation (4776)
    $audit = "{0CCE9215-69AE-11D9-BED3-505054503030}", "{0CCE9216-69AE-11D9-BED3-505054503030}",
             "{0CCE9235-69AE-11D9-BED3-505054503030}", "{0CCE9237-69AE-11D9-BED3-505054503030}",
             "{0CCE922B-69AE-11D9-BED3-505054503030}", "{0CCE9211-69AE-11D9-BED3-505054503030}",
             "{0CCE9227-69AE-11D9-BED3-505054503030}", "{0CCE922F-69AE-11D9-BED3-505054503030}",
             "{0CCE923F-69AE-11D9-BED3-505054503030}"
    foreach ($g in $audit) {
        & auditpol /set /subcategory:$g /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $g" }
    }
    $sys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Force -Path $sys | Out-Null
    Set-ItemProperty -Path $sys -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
    $sbl = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Force -Path $sbl | Out-Null
    Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord
}

& $Python (Join-Path $here "render_agent_configs.py") --derive-winlog $Rendered $cfg --state "$Work\state" --out $out `
    --channels "Security,System,Application,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Windows Defender/Operational"
if ($LASTEXITCODE -ne 0) { throw "derive-winlog failed" }
$fb = Start-Process $FluentBitExe -ArgumentList "-c", $cfg -PassThru -NoNewWindow
Start-Sleep -Seconds 6   # subscriptions are set up; read_existing_events is false

if ($ThrowawayRunner) {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class WlmLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
    function Invoke-Logon([string] $name, [string] $password, [int] $type) {
        $t = [IntPtr]::Zero
        if ([WlmLogon]::LogonUser($name, ".", $password, $type, 0, [ref]$t)) { [WlmLogon]::CloseHandle($t) | Out-Null }  # 4634
    }
    $user = "wlmci"
    # 14 characters at most: net user asks "longer than 14 characters ... continue? (Y/N)" and fails without a console
    $pass = "Wl!" + [guid]::NewGuid().ToString("N").Substring(0, 9) + "a9"
    $task = "wlmci-task"
    $subcat = "{0CCE9227-69AE-11D9-BED3-505054503030}"
    try {
        & net user $user $pass /add | Out-Null                       # 4720 (+4722, 4738)
        if ($LASTEXITCODE -ne 0) { throw "net user /add failed ($LASTEXITCODE)" }
        & net localgroup administrators $user /add | Out-Null         # 4732 TargetSid S-1-5-32-544
        if ($LASTEXITCODE -ne 0) { throw "net localgroup /add failed ($LASTEXITCODE)" }
        foreach ($type in 2, 3) { Invoke-Logon $user "wrong-password" $type }   # 4625 interactive, network (+4776)
        Invoke-Logon $user $pass 3                                    # 4624 type 3 (+4776, 4634)
        Invoke-Logon $user $pass 2                                    # 4624 type 2 (+4634)
        & sc.exe create wlmcisvc binPath= "C:\Windows\System32\cmd.exe /c exit" | Out-Null   # 7045 (System), 4697
        & powershell -NoProfile -Command "Write-Output 'wlm-scriptblock-check'" | Out-Null  # 4104 (script block logging), 4688
        Invoke-Native { schtasks /create /tn $task /tr "C:\Windows\System32\cmd.exe /c exit" /sc once /st 23:59 /f }   # 4698
        Invoke-Native { schtasks /delete /tn $task /f }               # 4699
        Invoke-Native { auditpol /set /subcategory:$subcat /failure:disable }   # 4719 (and back below)
        Invoke-Native { auditpol /set /subcategory:$subcat /failure:enable }
        # 4740: lock the throwaway account out (the policy goes back to 0 = never lock in finally; the runner is thrown away)
        Invoke-Native { net accounts /lockoutthreshold:3 }
        foreach ($i in 1..4) { Invoke-Logon $user "wrong-password" 3 }
        # 7031 / 7036: kill the print spooler; SCM restarts it (recovery action) - skipped where it is not running
        $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
        if ($spooler -and $spooler.Status -eq "Running") { Stop-Process -Name spoolsv -Force -ErrorAction SilentlyContinue }
        # Application Error 1000 (+ Windows Error Reporting 1001): a process that fails fast
        $crash = Start-Process powershell -ArgumentList "-NoProfile", "-Command", "[Environment]::FailFast('wlmci')" -PassThru -WindowStyle Hidden
        $crash | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue
    } finally {
        Invoke-Native { net accounts /lockoutthreshold:0 }
        Invoke-Native { schtasks /delete /tn $task /f }
        Invoke-Native { sc.exe delete wlmcisvc }
        Invoke-Native { net localgroup administrators $user /delete }   # 4733
        Invoke-Native { net user $user /delete }                        # 4726
    }
    Start-Sleep -Seconds 8
    # Last, after everything above was read: clearing a log is what rule 1000013 looks for
    Invoke-Native { wevtutil cl System }                           # 104 (Microsoft-Windows-Eventlog, System)
    Invoke-Native { wevtutil cl Security }                         # 1102 (Microsoft-Windows-Eventlog, Security)
    Start-Sleep -Seconds 6
} else {
    Write-Host "Listening for $ListenSeconds s - nothing on this PC is changed. Raise the events you need meanwhile."
    Start-Sleep -Seconds $ListenSeconds
}
Stop-Process -Id $fb.Id -Force

$code = @'
import json, os, re, sys
SEC, SCM, EVENTLOG = "Microsoft-Windows-Security-Auditing", "Service Control Manager", "Microsoft-Windows-Eventlog"
DEFENDER = "Microsoft-Windows-Windows Defender"
# (provider, EventID) to keep, at most 2 records each. A low event ID means different things per provider.
want = {(SEC, i) for i in (4624, 4625, 4634, 4647, 4688, 4697, 4698, 4699, 4719, 4720, 4722, 4726, 4732, 4733, 4738,
                           4740, 4767, 4768, 4769, 4771, 4776)}
want |= {(SCM, 7031), (SCM, 7034), (SCM, 7036), (SCM, 7045), ("Microsoft-Windows-PowerShell", 4104),
         ("Application Error", 1000), ("Windows Error Reporting", 1001), (EVENTLOG, 104), (EVENTLOG, 1100), (EVENTLOG, 1102),
         ("Microsoft-Windows-Kernel-Power", 41), (DEFENDER, 1001), (DEFENDER, 1116), (DEFENDER, 1117),
         ("MSSQLSERVER", 18453), ("MSSQLSERVER", 18454), ("MSSQLSERVER", 18456), ("MSSQLSERVER", 18486),
         ("MSSQLSERVER", 9002), ("MSSQLSERVER", 3041)}
ids = {i for _p, i in want}


def kind(provider, event_id):
    # A named SQL Server instance logs as MSSQL$<instance> - keep it like MSSQLSERVER (the record keeps its own name)
    if str(provider or "").upper().startswith("MSSQL$"):
        provider = "MSSQLSERVER"
    return (provider, event_id)
# argv: mode, records[, fixture] - Windows PowerShell 5.1 drops an empty argument, so the optional one comes last
raised = sys.argv[1] == "raise"
records = sys.argv[2]
fixture = sys.argv[3] if len(sys.argv) > 3 else ""
required = {(SEC, 4625), (SEC, 4720), (SEC, 4732)} if raised else set()
names = {n for n in (os.environ.get("COMPUTERNAME"), os.environ.get("HOSTNAME")) if n}


def anonymize(text, record):
    found = set(names)
    computer = str(record.get("Computer") or "")
    if computer:
        found |= {computer, computer.split(".")[0]}
    for name in sorted(found, key=len, reverse=True):
        if len(name) >= 3:
            text = re.sub(re.escape(name), "WIN-CI", text, flags=re.IGNORECASE)
    return text


seen, other = {}, set()
for line in open(records, encoding="utf-8"):
    if not line.strip():
        continue
    r = json.loads(line)
    key = kind(r.get("ProviderName"), r.get("EventID"))
    if key not in want:
        if key[1] in ids:
            other.add(key)   # same ID from another provider: a rule that filters on the provider would miss it
        continue
    if seen.get(key, 0) >= 2:
        continue
    if key == (SEC, 4688) and "wlm" not in json.dumps(r) and "powershell" not in json.dumps(r).lower():
        continue
    if raised and key == ("Application Error", 1000) and "powershell" not in json.dumps(r).lower():
        continue
    seen[key] = seen.get(key, 0) + 1
    r["Message"] = (r.get("Message") or "")[:200]
    print("WLMCAPTURE " + anonymize(json.dumps(r, ensure_ascii=True), r))
print("WLMSUMMARY " + json.dumps(sorted([p, i, n] for (p, i), n in seen.items())))
for p, i in sorted(other, key=str)[:20]:
    print("WLMOTHER provider " + json.dumps([p, i]) + " (not kept)")
if raised:
    optional = sorted(set(want) - required - set(seen))
    print("WLMOPTIONAL not seen (B-45/B-28): " + json.dumps(optional))
missing = required - set(seen)
bad = []
if fixture:
    # Same (provider, EventID, Version) -> same StringInserts length and value types as the committed fixture
    shape = {}
    for line in open(fixture, encoding="utf-8"):
        if line.strip():
            f = json.loads(line)
            shape[(f["ProviderName"], f["EventID"], f.get("Version"))] = [type(v).__name__ for v in f["StringInserts"]]
    for line in open(records, encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        expect = shape.get((r.get("ProviderName"), r.get("EventID"), r.get("Version")))
        got = [type(v).__name__ for v in r.get("StringInserts") or []]
        if expect is not None and got != expect:
            bad.append((r.get("ProviderName"), r.get("EventID"), r.get("Version"), expect, got))
    for b in bad[:5]:
        print("WLMSHAPE differs from the fixture: " + json.dumps(b))
# Listening on a real PC only reports: its Windows version may differ from the CI runner
sys.exit(1 if raised and (missing or bad) else 0)
'@
$py = Join-Path $Work "show.py"
Set-Content -Encoding ASCII -Path $py -Value $code
$mode = "listen"
if ($ThrowawayRunner) { $mode = "raise" }
& $Python $py $mode $out $Fixture
if ($LASTEXITCODE -ne 0) { throw "expected 4625, 4720 and 4732 with the same shape as the fixture in the agent output" }
Write-Host "All records (not anonymized): $out"
