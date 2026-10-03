#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs the Log Monitor agent (Fluent Bit as a Windows service).

.DESCRIPTION
  1. Install Fluent Bit for Windows first (https://fluentbit.io, Apache-2.0).
  2. Run this script as Administrator:
       powershell -ExecutionPolicy Bypass -File .\install.ps1 -ServerHost 10.0.0.10 -ServerPort 8080 -ApiKey <key>
     Web server (IIS access logs):       add  -Iis
     SQL Server (ERRORLOG, optional):    add  -MssqlErrorlog

  Re-running the script updates the config and restarts the service.
  (Messages are in English on purpose: Windows PowerShell 5.1 misreads non-ASCII in BOM-less scripts.)
#>
param(
    [Parameter(Mandatory = $true)] [string] $ServerHost,
    [int] $ServerPort = 8080,
    [Parameter(Mandatory = $true)] [string] $ApiKey,
    [string] $Channels = "System,Application,Security,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    [switch] $Iis,
    # Comma separated file patterns. Default: every site folder found under C:\inetpub\logs\LogFiles
    [string] $IisLogPath = "",
    [switch] $MssqlErrorlog,
    # Comma separated paths. Default: every ERRORLOG found under C:\Program Files\Microsoft SQL Server
    [string] $MssqlErrorlogPath = "",
    [string] $FluentBitExe = "C:\Program Files\fluent-bit\bin\fluent-bit.exe"
)

$ErrorActionPreference = "Stop"
$ServiceName = "wlm-agent"
$DataDir = "C:\ProgramData\wlm-agent"
$ConfigPath = Join-Path $DataDir "fluent-bit.yaml"

if (-not (Test-Path $FluentBitExe)) {
    throw "Fluent Bit not found at '$FluentBitExe'. Install Fluent Bit for Windows first, or pass -FluentBitExe."
}

# Uncomment the lines between "# @@NAME_BEGIN" and "# @@NAME_END" (the markers themselves stay comments)
function Enable-Block([string] $text, [string] $name) {
    $inside = $false
    $lines = foreach ($line in ($text -split "`n")) {
        if ($line -match "# @@${name}_BEGIN") { $inside = $true; $line; continue }
        if ($line -match "# @@${name}_END") { $inside = $false; $line; continue }
        if ($inside -and $line -match '^(\s*)# (- |  )') { $line -replace '^(\s*)# ', '$1' } else { $line }
    }
    return ($lines -join "`n")
}

Write-Host "[1/4] Preparing $DataDir"
New-Item -ItemType Directory -Force -Path $DataDir, (Join-Path $DataDir "buffer") | Out-Null

Write-Host "[2/4] Writing config"
$template = Get-Content -Raw -Encoding UTF8 (Join-Path $PSScriptRoot "fluent-bit.yaml")
$config = $template.Replace("@SERVER_HOST@", $ServerHost).Replace("@SERVER_PORT@", "$ServerPort").Replace("@API_KEY@", $ApiKey).Replace("@CHANNELS@", $Channels)

if ($Iis) {
    if (-not $IisLogPath) {
        $sites = Get-ChildItem "C:\inetpub\logs\LogFiles" -Directory -Filter "W3SVC*" -ErrorAction SilentlyContinue
        if (-not $sites) { throw "No IIS log folder found under C:\inetpub\logs\LogFiles. Pass -IisLogPath." }
        $IisLogPath = ($sites | ForEach-Object { Join-Path $_.FullName "*.log" }) -join ","
    }
    Write-Host "      IIS logs: $IisLogPath"
    $config = (Enable-Block $config "IIS").Replace("@IIS_PATH@", $IisLogPath)
}
if ($MssqlErrorlog) {
    if (-not $MssqlErrorlogPath) {
        $logs = Get-ChildItem "C:\Program Files\Microsoft SQL Server" -Recurse -Filter "ERRORLOG" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -like "*\MSSQL\Log" }
        if (-not $logs) { throw "No SQL Server ERRORLOG found. Pass -MssqlErrorlogPath." }
        $MssqlErrorlogPath = ($logs | ForEach-Object { $_.FullName }) -join ","
    }
    Write-Host "      SQL Server ERRORLOG: $MssqlErrorlogPath"
    $config = (Enable-Block $config "MSSQL").Replace("@MSSQL_PATH@", $MssqlErrorlogPath)
}
[System.IO.File]::WriteAllText($ConfigPath, $config, (New-Object System.Text.UTF8Encoding $false))

# The config contains the API key: only SYSTEM and Administrators may read it
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

Write-Host "[3/4] Registering service '$ServiceName'"
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") { Stop-Service -Name $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}
$binPath = "`"$FluentBitExe`" -c `"$ConfigPath`""
New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName "Log Monitor Agent (Fluent Bit)" `
    -Description "Sends Windows event logs (and optional IIS / SQL Server logs) to the Log Monitor server" -StartupType Automatic | Out-Null
# Restart automatically if the agent crashes
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null

Write-Host "[4/4] Starting service"
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
Get-Service -Name $ServiceName | Format-Table -AutoSize Name, Status, StartType

Write-Host "Done. This PC should appear on the server's agents page within 30 seconds."
Write-Host "Troubleshooting: run in foreground ->  & `"$FluentBitExe`" -c `"$ConfigPath`""
