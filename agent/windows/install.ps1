#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs the Log Monitor agent (Fluent Bit as a Windows service). Works offline (air-gapped PCs).

.DESCRIPTION
  Offline package (downloaded from the Log Monitor server: Agents page > "Download agent package"):
    right-click install.cmd > Run as administrator      (or: install.cmd /quiet  for GPO / SCCM)
    -> server address, port and API key are read from settings.json next to this script,
       Fluent Bit is installed from fluent-bit\*.zip (or *.exe) in the package if it is not installed yet.

  Manual:
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -ServerHost 10.0.0.10 -ApiKey <key>   (log port 6976 by default)
    Web server (IIS access logs):       add  -Iis
    SQL Server (ERRORLOG, optional):    add  -MssqlErrorlog

  Command line parameters override settings.json. Re-running the script updates the config and restarts the service.
  (Messages are in English on purpose: Windows PowerShell 5.1 misreads non-ASCII in BOM-less scripts.)
#>
param(
    [string] $ServerHost = "",
    # Log Monitor ingest-only port (WLM_INGEST_PORT on the server, default 6976)
    [int] $ServerPort = 0,
    [string] $ApiKey = "",
    [string] $Channels = "",
    [switch] $Iis,
    # Comma separated file patterns. Default: every site folder found under C:\inetpub\logs\LogFiles
    [string] $IisLogPath = "",
    [switch] $MssqlErrorlog,
    # Comma separated paths. Default: every ERRORLOG found under C:\Program Files\Microsoft SQL Server
    [string] $MssqlErrorlogPath = "",
    [string] $FluentBitExe = "C:\Program Files\fluent-bit\bin\fluent-bit.exe",
    # Settings file written by the server when the package is downloaded
    [string] $Settings = (Join-Path $PSScriptRoot "settings.json")
)

$ErrorActionPreference = "Stop"
$ServiceName = "wlm-agent"
$DataDir = "C:\ProgramData\wlm-agent"
$ConfigPath = Join-Path $DataDir "fluent-bit.yaml"

$DefaultChannels = "System,Application,Security,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

# ---- settings.json (from the server's package download). Command line values win.
if (Test-Path $Settings) {
    Write-Host "Reading settings: $Settings"
    $cfg = Get-Content -Raw -Encoding UTF8 $Settings | ConvertFrom-Json
    if (-not $ServerHost -and $cfg.ServerHost) { $ServerHost = [string]$cfg.ServerHost }
    if (-not $ServerPort -and $cfg.ServerPort) { $ServerPort = [int]$cfg.ServerPort }
    if (-not $ApiKey -and $cfg.ApiKey) { $ApiKey = [string]$cfg.ApiKey }
    if (-not $Channels -and $cfg.Channels) { $Channels = [string]$cfg.Channels }
    if (-not $Iis -and $cfg.Iis) { $Iis = $true }
    if (-not $MssqlErrorlog -and $cfg.MssqlErrorlog) { $MssqlErrorlog = $true }
}
if (-not $ServerPort) { $ServerPort = 6976 }
if (-not $Channels) { $Channels = $DefaultChannels }
if (-not $ServerHost -or -not $ApiKey) {
    throw "Server address and API key are required: use the package from the server (settings.json) or pass -ServerHost and -ApiKey."
}

# ---- Fluent Bit: install from the package when missing (no internet needed)
if (-not (Test-Path $FluentBitExe)) {
    $pkgDir = Join-Path $PSScriptRoot "fluent-bit"
    $zip = Get-ChildItem $pkgDir -Filter "fluent-bit-*-win64.zip" -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    $exe = Get-ChildItem $pkgDir -Filter "fluent-bit-*-win64.exe" -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    $target = Split-Path (Split-Path $FluentBitExe -Parent) -Parent
    if ($zip) {
        Write-Host "Installing Fluent Bit from $($zip.Name) to $target"
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wlm-fluent-bit-" + [guid]::NewGuid())
        Expand-Archive -Path $zip.FullName -DestinationPath $tmp -Force
        $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
        $source = if ($inner -and (Test-Path (Join-Path $inner.FullName "bin"))) { $inner.FullName } else { $tmp }
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Copy-Item -Path (Join-Path $source "*") -Destination $target -Recurse -Force
        Remove-Item $tmp -Recurse -Force
    } elseif ($exe) {
        Write-Host "Installing Fluent Bit from $($exe.Name) (silent)"
        Start-Process -FilePath $exe.FullName -ArgumentList "/S" -Wait
    }
    if (-not (Test-Path $FluentBitExe)) {
        throw "Fluent Bit not found at '$FluentBitExe'. Put fluent-bit-<version>-win64.zip in the 'fluent-bit' folder of this package, install it manually, or pass -FluentBitExe."
    }
}
& $FluentBitExe --version | Select-Object -First 1
Write-Host "Server: ${ServerHost}:$ServerPort"

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
