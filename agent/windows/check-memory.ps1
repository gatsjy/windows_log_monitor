# Log Monitor agent - memory check on a PC where the agent (service knuh-agent, fluent-bit.exe) uses a lot of memory.
# Samples the agent every -IntervalSec for -Minutes and writes a CSV, then prints a short verdict:
#   - Private Bytes (commit size) keeps rising        -> a leak or heartbeats piling up while the server is unreachable
#   - high but flat, buffer folder large              -> backlog waiting for the server (disk buffer, bounded)
#   - "retry" / "connection" lines in fluent-bit.log  -> the agent cannot reach the server (check port, key, TLS)
# Run as Administrator:  powershell -ExecutionPolicy Bypass -File .\check-memory.ps1 [-Minutes 30] [-IntervalSec 30]
# ASCII only (Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page).
param(
    [int] $Minutes = 30,
    [int] $IntervalSec = 30,
    [string] $DataDir = "C:\ProgramData\wlm-agent",
    [string] $Out = (Join-Path ([Environment]::GetFolderPath("Desktop")) ("wlm-agent-memory-" + $env:COMPUTERNAME + ".csv"))
)
$ErrorActionPreference = "Stop"

function Get-AgentProcess {
    $svc = Get-CimInstance Win32_Service -Filter "Name='knuh-agent'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.ProcessId) { return Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue }
    return Get-Process fluent-bit -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Get-BufferMB {
    $files = Get-ChildItem (Join-Path $DataDir "buffer") -Recurse -File -ErrorAction SilentlyContinue
    if (-not $files) { return 0 }
    return [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 1)
}

$version = ""
$cfg = Join-Path $DataDir "fluent-bit.yaml"
if (Test-Path $cfg) {
    $m = Select-String -Path $cfg -Pattern '"config_version":"([0-9.]+)"' | Select-Object -First 1
    if ($m) { $version = $m.Matches[0].Groups[1].Value }
}
Write-Host "Agent config_version: $(if ($version) { $version } else { 'unknown' })  (0.4.1 or later has the heartbeat memory fix)"
Write-Host "Sampling every $IntervalSec s for $Minutes min -> $Out"

$rows = @()
$end = (Get-Date).AddMinutes($Minutes)
do {
    $p = Get-AgentProcess
    if (-not $p) { Write-Warning "Agent process not found (service knuh-agent not running?)" }
    else {
        $row = [pscustomobject]@{
            time       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            pid        = $p.Id
            private_mb = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
            ws_mb      = [math]::Round($p.WorkingSet64 / 1MB, 1)
            handles    = $p.HandleCount
            threads    = $p.Threads.Count
            buffer_mb  = Get-BufferMB
        }
        $rows += $row
        $row | Export-Csv -Path $Out -Append -NoTypeInformation -Encoding ASCII
        Write-Host ("{0}  private {1} MB  working set {2} MB  handles {3}  buffer {4} MB" -f $row.time, $row.private_mb, $row.ws_mb, $row.handles, $row.buffer_mb)
    }
    if ((Get-Date) -lt $end) { Start-Sleep -Seconds $IntervalSec }
} while ((Get-Date) -lt $end)

if ($rows.Count -lt 2) { Write-Warning "Not enough samples"; exit 1 }
$first = $rows[0]; $last = $rows[-1]
$grow = [math]::Round($last.private_mb - $first.private_mb, 1)
$perHour = [math]::Round($grow / [math]::Max(($Minutes / 60.0), 0.01), 1)
Write-Host ""
Write-Host "Private Bytes: $($first.private_mb) -> $($last.private_mb) MB ($grow MB, about $perHour MB/hour)"
Write-Host "Disk buffer:   $($first.buffer_mb) -> $($last.buffer_mb) MB"

$log = Join-Path $DataDir "fluent-bit.log"
$errors = @()
if (Test-Path $log) {
    $errors = @(Get-Content $log -Tail 2000 | Select-String -Pattern "retry|connection|refused|timed out|tls|401|403|413" | Select-Object -Last 5)
}
if ($errors.Count) {
    Write-Host "Recent send problems in fluent-bit.log:"
    $errors | ForEach-Object { Write-Host "  $($_.Line)" }
}

if ($perHour -gt 20 -and $errors.Count) {
    Write-Host "VERDICT: memory rises while sends fail. Fix the connection (port/key/TLS) and update the agent to config 0.4.1+."
} elseif ($perHour -gt 20) {
    Write-Host "VERDICT: memory keeps rising while sends work. Send the CSV and fluent-bit.log to the Log Monitor admin (possible Fluent Bit leak)."
} elseif ($last.buffer_mb -gt 50) {
    Write-Host "VERDICT: memory is flat; a backlog is waiting on disk for the server. It drains when the server catches up."
} else {
    Write-Host "VERDICT: memory is flat. Task Manager 'Memory' shows the private working set; compare with private_mb above."
}
