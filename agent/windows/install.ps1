<#
.SYNOPSIS
  Installs the Log Monitor agent (Fluent Bit as a Windows service). Works offline (air-gapped PCs).

.DESCRIPTION
  Offline package (downloaded from the Log Monitor server: Agents page > "Download agent package"):
    right-click install.cmd > Run as administrator      (or: install.cmd /quiet  for GPO / SCCM)
    -> server address, port and API key are read from settings.json next to this script,
       Fluent Bit is installed from fluent-bit\*.zip (or *.exe) in the package if it is not installed yet.
    -> when the server has HTTPS on, settings.json also names ca.crt (in the package), the certificate
       name and the CA fingerprint: the agent then sends over TLS (port 6977) and verifies the server.

  Manual:
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -ServerHost 10.0.0.10 -ApiKey <key>   (plain HTTP, port 6976)
    HTTPS (TLS, port 6977):             add  -CaFile .\ca.crt [-TlsServerName logmon.corp.local]
    Web server (IIS access logs):       add  -Iis
    SQL Server (ERRORLOG, optional):    add  -MssqlErrorlog
    Check the rendered config only:     add  -RenderOnly .\out.yaml   (installs nothing, no admin needed)

  Command line parameters override settings.json. Re-running the script updates the config and restarts the service.
  (Messages are in English on purpose: Windows PowerShell 5.1 misreads non-ASCII in BOM-less scripts.)
#>
param(
    [string] $ServerHost = "",
    # Log Monitor ingest-only port. Default 6976 (WLM_INGEST_PORT, plain) or 6977 with -CaFile (WLM_INGEST_TLS_PORT)
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
    # Settings file written by the server when the package is downloaded. Default: settings.json next to this script
    # (resolved below: Windows PowerShell 5.1 can leave $PSScriptRoot empty inside param() defaults)
    [string] $Settings = "",
    [string] $ServiceName = "knuh-agent",
    [string] $DisplayName = "",
    # HTTPS: CA certificate (PEM) of the server certificate. Turns TLS on.
    # In settings.json a relative path is relative to the settings.json folder (the package has "ca.crt").
    [string] $CaFile = "",
    # DNS name in the server certificate. Default: -ServerHost (required when -ServerHost is an IP address)
    [string] $TlsServerName = "",
    # Write the rendered config to this file and stop: no Fluent Bit check, no ProgramData, no ACL, no service (CI)
    [string] $RenderOnly = ""
)

$ErrorActionPreference = "Stop"
$Here = $PSScriptRoot
if (-not $Here) { $Here = Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $Settings) { $Settings = Join-Path $Here "settings.json" }
# Not "#Requires -RunAsAdministrator": -RenderOnly must work without admin rights (CI, preview)
if (-not $RenderOnly) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator (or use install.cmd > Run as administrator)."
    }
}
if (-not $DisplayName) {
    # Default display name is Korean ('knuh <Windows monitoring>'). Built from UTF-8 bytes because
    # PS 5.1 reads BOM-less scripts in the ANSI code page, so this file must stay ASCII only.
    $DisplayName = [System.Text.Encoding]::UTF8.GetString([byte[]]@(0x6b, 0x6e, 0x75, 0x68, 0x20, 0xec, 0x9c, 0x88, 0xeb, 0x8f, 0x84, 0xec, 0x9a, 0xb0, 0x20, 0xeb, 0xaa, 0xa8, 0xeb, 0x8b, 0x88, 0xed, 0x84, 0xb0, 0xeb, 0xa7, 0x81))
}
$DataDir = "C:\ProgramData\wlm-agent"
# Plain strings, not Join-Path: Join-Path fails where drive C: does not exist (-RenderOnly in pwsh on Linux / macOS)
$ConfigPath = "$DataDir\fluent-bit.yaml"
$CaTarget = "$DataDir\ca.crt"

$DefaultChannels = "System,Application,Security,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

# ---- settings.json (from the server's package download). Command line values win.
$CaSha256 = ""
$cfgPort = 0
$cfgTls = $false
if (Test-Path $Settings) {
    Write-Host "Reading settings: $Settings"
    $cfg = Get-Content -Raw -Encoding UTF8 $Settings | ConvertFrom-Json
    if (-not $ServerHost -and $cfg.ServerHost) { $ServerHost = [string]$cfg.ServerHost }
    if ($cfg.ServerPort) { $cfgPort = [int]$cfg.ServerPort }
    $cfgTls = [bool]$cfg.CaFile
    if (-not $ApiKey -and $cfg.ApiKey) { $ApiKey = [string]$cfg.ApiKey }
    if (-not $Channels -and $cfg.Channels) { $Channels = [string]$cfg.Channels }
    if (-not $Iis -and $cfg.Iis) { $Iis = $true }
    if (-not $MssqlErrorlog -and $cfg.MssqlErrorlog) { $MssqlErrorlog = $true }
    if (-not $CaFile -and $cfg.CaFile) {
        # The package says "ca.crt": relative to the package folder, not to the current directory (GPO / SCCM run elsewhere)
        $CaFile = [string]$cfg.CaFile
        if (-not [System.IO.Path]::IsPathRooted($CaFile)) {
            $CaFile = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $Settings).ProviderPath) $CaFile
        }
    }
    if (-not $TlsServerName -and $cfg.TlsServerName) { $TlsServerName = [string]$cfg.TlsServerName }
    if ($cfg.CaSha256) { $CaSha256 = ([string]$cfg.CaSha256).Trim().ToLower() }
}
$Tls = [bool]$CaFile
# The package port belongs to the package mode: a plain package says 6976, which does not speak TLS.
# Use it only when this run sends the same way (e.g. -CaFile given here on top of an old plain package -> 6977).
if (-not $ServerPort -and $cfgPort -and ($cfgTls -eq $Tls)) { $ServerPort = $cfgPort }
if (-not $ServerPort) {
    if ($Tls) { $ServerPort = 6977 } else { $ServerPort = 6976 }
}
if (-not $Channels) { $Channels = $DefaultChannels }
if (-not $ServerHost -or -not $ApiKey) {
    throw "Server address and API key are required: use the package from the server (settings.json) or pass -ServerHost and -ApiKey."
}

# ---- TLS: check the name and the CA before touching this PC.
# A wrong name or CA would only show up later as a service that restarts forever (Fluent Bit exits on a bad ca_file).
if ($Tls) {
    if (-not $TlsServerName) {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($ServerHost, [ref]$ip)) {
            throw "IP host needs -TlsServerName (a DNS name in the server certificate)"
        }
        $TlsServerName = $ServerHost
    }
    # DNS name only (at least one letter): the value goes into the YAML config as is
    if ($TlsServerName -notmatch '^(?=.{1,253}\z)(?=.*[A-Za-z])[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z') {
        throw "Invalid -TlsServerName '$TlsServerName': use a DNS name from the server certificate (letters, digits, '-', '.')."
    }
    if (-not (Test-Path -LiteralPath $CaFile -PathType Leaf)) { throw "CA file not found: $CaFile" }
    $CaFile = (Resolve-Path -LiteralPath $CaFile).ProviderPath
    # Read the PEM ourselves and open the DER bytes (PS 5.1 / .NET Framework has no PEM loader).
    # Get-Content also decodes UTF-16 (what PS 5.1 '>' and Out-File write); OpenSSL cannot read that,
    # so the CA is written again below as plain ASCII PEM with the certificates only (no key, no text).
    $blocks = [regex]::Matches((Get-Content -Raw -LiteralPath $CaFile), '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
    if ($blocks.Count -eq 0) { throw "CA file is not a PEM certificate: $CaFile" }
    $CaPem = ""
    foreach ($block in $blocks) {
        $b64 = $block.Groups[1].Value -replace '\s', ''
        try { [void][Convert]::FromBase64String($b64) } catch { throw "CA file has a broken certificate (base64): $CaFile" }
        $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
        $CaPem += "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----`n"
    }
    # The first certificate is the one the server names (CaSha256) and the one checked here
    $der = [Convert]::FromBase64String(($blocks[0].Groups[1].Value -replace '\s', ''))
    $ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
    $sha = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($der))).Replace('-', '').ToLower()
    Write-Host "CA certificate: $($ca.Subject)  valid until $($ca.NotAfter.ToString('yyyy-MM-dd'))  SHA-256 $sha"
    if ($ca.NotAfter -lt (Get-Date)) { throw "CA certificate expired on $($ca.NotAfter.ToString('yyyy-MM-dd')): $CaFile" }
    if ($ca.NotBefore -gt (Get-Date)) { Write-Warning "CA certificate is valid only from $($ca.NotBefore.ToString('yyyy-MM-dd')): check the clock of this PC." }
    $bc = $ca.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
    if (-not $bc -or -not $bc.CertificateAuthority) { throw "Not a CA certificate (server.crt instead of ca.crt?): $CaFile" }
    if ($CaSha256 -and $CaSha256 -ne $sha) {
        throw "CA file differs from the one packaged by the server (SHA-256 $sha, settings.json CaSha256 $CaSha256): $CaFile"
    }
} elseif ($TlsServerName) {
    Write-Warning "-TlsServerName is ignored without -CaFile: sending over plain HTTP."
}

# ---- Fluent Bit: install from the package when missing (no internet needed). -RenderOnly does not need it.
if (-not $RenderOnly -and -not (Test-Path $FluentBitExe)) {
    $pkgDir = Join-Path $Here "fluent-bit"
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
if (-not $RenderOnly) { & $FluentBitExe --version | Select-Object -First 1 }
if ($Tls) { $transport = "TLS, certificate name $TlsServerName" } else { $transport = "plain HTTP" }
Write-Host "Server: ${ServerHost}:$ServerPort ($transport)"

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

if (-not $RenderOnly) {
    Write-Host "[1/4] Preparing $DataDir"
    New-Item -ItemType Directory -Force -Path $DataDir, (Join-Path $DataDir "buffer") | Out-Null
    # A standard user can create C:\ProgramData\wlm-agent before the first install (ProgramData lets Users create folders)
    # and would stay owner with their own ACEs - then they could swap the CA or the config later.
    # So take ownership for Administrators and replace every ACE BEFORE the CA and the config (API key) are written.
    & icacls $DataDir /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed on $DataDir ($LASTEXITCODE)" }
    & icacls $DataDir /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /reset failed on $DataDir ($LASTEXITCODE)" }
    # Only SYSTEM (the service) and Administrators; files below inherit this
    & icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $DataDir ($LASTEXITCODE)" }
}

Write-Host "[2/4] Writing config"
$template = Get-Content -Raw -Encoding UTF8 (Join-Path $Here "fluent-bit.yaml")
$config = $template.Replace("@SERVER_HOST@", $ServerHost).Replace("@SERVER_PORT@", "$ServerPort").Replace("@API_KEY@", $ApiKey).Replace("@CHANNELS@", $Channels)
# Empty without TLS: the placeholder then stays only in the commented-out TLS block
if ($Tls) { $config = (Enable-Block $config "TLS").Replace("@TLS_SERVER_NAME@", $TlsServerName) } else { $config = $config.Replace("@TLS_SERVER_NAME@", "") }

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
if ($RenderOnly) {
    # Resolve against the PowerShell location (.NET would use the process directory)
    $out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RenderOnly)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $out) | Out-Null
    [System.IO.File]::WriteAllText($out, $config, (New-Object System.Text.UTF8Encoding $false))
    # The CA exactly as it would be installed (CI checks it with OpenSSL)
    if ($Tls) { [System.IO.File]::WriteAllText("$out.ca.crt", $CaPem, (New-Object System.Text.ASCIIEncoding)) }
    Write-Host "Rendered config only (nothing installed): $out"
    exit 0
}
if ($Tls) {
    # Before the config: never a config pointing at a missing CA. The folder ACL above already limits it to
    # SYSTEM and Administrators (files inherit it). Written from memory, so -CaFile may be the installed file itself.
    [System.IO.File]::WriteAllText($CaTarget, $CaPem, (New-Object System.Text.ASCIIEncoding))
}
# The config contains the API key: the folder ACL above lets only SYSTEM and Administrators read it
[System.IO.File]::WriteAllText($ConfigPath, $config, (New-Object System.Text.UTF8Encoding $false))

Write-Host "[3/4] Registering service '$ServiceName' ($DisplayName)"
# Also remove the service name used before 0.2.2 so an upgrade does not leave two agents sending twice
foreach ($svc in (@($ServiceName, "wlm-agent") | Select-Object -Unique)) {
    $existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "      Cleaning up existing service '$svc'"
        if ($existing.Status -ne "Stopped") { Stop-Service -Name $svc -Force }
        sc.exe delete $svc | Out-Null
        # sc delete only marks the service; New-Service fails until SCM really removes it
        for ($i = 0; $i -lt 30 -and (Get-Service -Name $svc -ErrorAction SilentlyContinue); $i++) {
            Start-Sleep -Milliseconds 500
        }
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            throw "Service '$svc' is still marked for deletion. Close services.msc / Event Viewer and run again."
        }
    }
}
$binPath = "`"$FluentBitExe`" -c `"$ConfigPath`""
New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $DisplayName `
    -Description "KNUH Windows Log Monitor Agent (Fluent Bit)" -StartupType Automatic | Out-Null
# Restart automatically if the agent crashes
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null

Write-Host "[4/4] Starting service"
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
Get-Service -Name $ServiceName | Format-Table -AutoSize Name, Status, StartType

Write-Host "Done. This PC should appear on the server's agents page within 30 seconds."
Write-Host "Troubleshooting: run in foreground ->  & `"$FluentBitExe`" -c `"$ConfigPath`""
