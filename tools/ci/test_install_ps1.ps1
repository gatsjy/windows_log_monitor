# CI (B-06): runs agent/windows/install.ps1 -RenderOnly the way the server package uses it and checks the result.
#   Windows PowerShell 5.1 in CI (what install.cmd uses), pwsh 7 on a developer PC:
#   powershell -File tools/ci/test_install_ps1.ps1 -RenderDir agent-render -CaSha256 <sha of the fixture, computed elsewhere>
# -RenderDir is the output of tools/ci/render_agent_configs.py: install.ps1 must render byte for byte the same.
# -CaSha256 comes from render_agent_configs.py --ca-sha256 (a separate implementation), not from this script.
# ASCII only (Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page).
param(
    [Parameter(Mandatory = $true)] [string] $RenderDir,
    [Parameter(Mandatory = $true)] [string] $CaSha256,
    [string] $Repo = "",   # default: the repository root (resolved below; 5.1 can leave $PSScriptRoot empty in param defaults)
    [string] $Work = (Join-Path ([System.IO.Path]::GetTempPath()) "wlm-ps1-test")
)
$ErrorActionPreference = "Stop"
if (-not $Repo) {
    $here = $PSScriptRoot
    if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $Repo = Join-Path $here "..\.."
}
$Repo = (Resolve-Path $Repo).ProviderPath
$RenderDir = (Resolve-Path $RenderDir).ProviderPath
$Ps = Join-Path $Repo "agent/windows/install.ps1"
$Fix = Join-Path $Repo "tools/ci/fixtures/ci-ca.crt"
$Exe = (Get-Process -Id $PID).Path
if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$None = Join-Path $Work "none.json"
"PowerShell $($PSVersionTable.PSVersion) ($Exe)"

function Fail([string] $msg) { Write-Host "FAIL: $msg"; exit 1 }
function Run([string] $script, [string[]] $arguments) {
    # Windows PowerShell 5.1 turns redirected stderr of a native command into a terminating error under "Stop":
    # judge by the exit code and the text instead
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $Exe -NoProfile -ExecutionPolicy Bypass -File $script @arguments 2>&1 | Out-String
        return @{ Code = $LASTEXITCODE; Out = $out }
    } finally {
        $ErrorActionPreference = $old
    }
}
function Same([string] $a, [string] $b) {
    return [System.IO.File]::ReadAllText($a) -eq [System.IO.File]::ReadAllText($b)
}
# Active lines only: install.ps1 leaves @IIS_PATH@ / @MSSQL_PATH@ in the commented-out blocks it does not enable
function Same-Active([string] $a, [string] $b) {
    $strip = { param($f) ([System.IO.File]::ReadAllText($f) -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }
    return (& $strip $a) -eq (& $strip $b)
}
function Cert-Body([string] $path) {
    $m = [regex]::Matches([System.IO.File]::ReadAllText($path), '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
    return (($m | ForEach-Object { $_.Groups[1].Value -replace '\s', '' }) -join "|")
}
$plainArgs = @("-ServerHost", "logmon.ci.local", "-ApiKey", "ci-test-key", "-Channels", "System,Application,Security", "-Settings", $None)
$iisArgs = @("-Iis", "-IisLogPath", "C:\inetpub\logs\LogFiles\W3SVC1\*.log",
             "-MssqlErrorlog", "-MssqlErrorlogPath", "C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG")

# 1) Plain: same as the render script (windows-min.yaml, windows.yaml)
$r = Run $Ps (@("-RenderOnly", (Join-Path $Work "plain.yaml"), "-ServerPort", "6976") + $plainArgs)
if ($r.Code -ne 0) { $r.Out; Fail "plain render" }
if (-not (Same-Active (Join-Path $Work "plain.yaml") (Join-Path $RenderDir "windows-min.yaml"))) { Fail "plain render differs from windows-min.yaml" }
$r = Run $Ps (@("-RenderOnly", (Join-Path $Work "plain-iis.yaml"), "-ServerPort", "6976") + $plainArgs + $iisArgs)
if ($r.Code -ne 0 -or -not (Same (Join-Path $Work "plain-iis.yaml") (Join-Path $RenderDir "windows.yaml"))) { $r.Out; Fail "plain IIS/MSSQL render differs from windows.yaml" }

# 2) TLS from the command line: same as windows-tls.yaml (default port 6977), CA written as ASCII PEM
$r = Run $Ps (@("-RenderOnly", (Join-Path $Work "tls.yaml"), "-CaFile", $Fix, "-TlsServerName", "logmon.ci.internal") + $plainArgs + $iisArgs)
if ($r.Code -ne 0) { $r.Out; Fail "tls render" }
if (-not (Same (Join-Path $Work "tls.yaml") (Join-Path $RenderDir "windows-tls.yaml"))) { Fail "tls render differs from windows-tls.yaml" }
if ((Cert-Body (Join-Path $Work "tls.yaml.ca.crt")) -ne (Cert-Body $Fix)) { Fail "rendered CA differs from the fixture" }

# 3) The server package: settings.json next to install.ps1 with a RELATIVE CaFile and the server's CaSha256, run from elsewhere
$pkg = Join-Path $Work "pkg"
New-Item -ItemType Directory -Force -Path $pkg | Out-Null
Copy-Item $Ps, (Join-Path $Repo "agent/windows/fluent-bit.yaml") $pkg
Copy-Item $Fix (Join-Path $pkg "ca.crt")
@{ ServerHost = "10.0.0.10"; ServerPort = 6977; ApiKey = "ci"; Iis = $false; MssqlErrorlog = $false
   CaFile = "ca.crt"; TlsServerName = "logmon.ci.internal"; CaSha256 = $CaSha256 } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $pkg "settings.json")
Push-Location $Repo
try { $r = Run (Join-Path $pkg "install.ps1") @("-RenderOnly", (Join-Path $Work "pkg.yaml")) } finally { Pop-Location }
if ($r.Code -ne 0) { $r.Out; Fail "package render (relative CaFile + server CaSha256)" }
$cfg = [System.IO.File]::ReadAllText((Join-Path $Work "pkg.yaml"))
foreach ($want in @("port: 6977", "tls.vhost: logmon.ci.internal", "tls.ca_file: C:\ProgramData\wlm-agent\ca.crt", "host: 10.0.0.10")) {
    if (-not $cfg.Contains($want)) { Fail "package render lacks '$want'" }
}

# 4) Old plain package folder (ServerPort 6976) + -CaFile on the command line: TLS must go to 6977, not 6976
$old = Join-Path $Work "oldpkg"
New-Item -ItemType Directory -Force -Path $old | Out-Null
Copy-Item $Ps, (Join-Path $Repo "agent/windows/fluent-bit.yaml") $old
@{ ServerHost = "10.0.0.10"; ServerPort = 6976; ApiKey = "old" } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $old "settings.json")
$r = Run (Join-Path $old "install.ps1") @("-RenderOnly", (Join-Path $Work "old.yaml"), "-CaFile", $Fix, "-TlsServerName", "logmon.ci.internal")
if ($r.Code -ne 0 -or -not [System.IO.File]::ReadAllText((Join-Path $Work "old.yaml")).Contains("port: 6977")) { $r.Out; Fail "-CaFile on an old plain package must use 6977" }

# 5) CA saved as UTF-16 (PS 5.1 '>' / Out-File): accepted, but installed as ASCII PEM (OpenSSL cannot read UTF-16)
$utf16 = Join-Path $Work "ca-utf16.crt"
Get-Content $Fix | Out-File -Encoding Unicode $utf16
$r = Run $Ps (@("-RenderOnly", (Join-Path $Work "u16.yaml"), "-CaFile", $utf16, "-TlsServerName", "logmon.ci.internal") + $plainArgs)
if ($r.Code -ne 0) { $r.Out; Fail "UTF-16 CA render" }
$bytes = [System.IO.File]::ReadAllBytes((Join-Path $Work "u16.yaml.ca.crt"))
if ($bytes -contains 0 -or [System.Text.Encoding]::ASCII.GetString($bytes, 0, 27) -ne "-----BEGIN CERTIFICATE-----") { Fail "CA must be written as ASCII PEM" }

# 6) Must fail, without writing a config
function Must-Fail([string] $name, [string] $want, [string[]] $arguments) {
    $out = (Join-Path $Work "neg.yaml")
    if (Test-Path $out) { Remove-Item $out }
    $r = Run $Ps (@("-RenderOnly", $out) + $arguments)
    if ($r.Code -eq 0 -or $r.Out -notmatch [regex]::Escape($want)) { $r.Out; Fail "$name must fail with '$want'" }
    if (Test-Path $out) { Fail "$name wrote a config" }
}
Must-Fail "IP host without a name" "IP host needs -TlsServerName" @("-ServerHost", "10.0.0.10", "-ApiKey", "ci", "-CaFile", $Fix, "-Settings", $None)
$bad = Join-Path $Work "bad-sha.json"
@{ ServerHost = "logmon.ci.internal"; ApiKey = "ci"; CaFile = $Fix; CaSha256 = ("0" * 64) } | ConvertTo-Json | Set-Content -Encoding UTF8 $bad
Must-Fail "CaSha256 mismatch" "differs from the one packaged" @("-Settings", $bad)
$broken = Join-Path $Work "broken.crt"
Set-Content -Encoding ASCII $broken "-----BEGIN CERTIFICATE-----`nAAA=AAA`n-----END CERTIFICATE-----"
Must-Fail "broken base64" "broken certificate" @("-ServerHost", "logmon.ci.internal", "-ApiKey", "ci", "-CaFile", $broken, "-Settings", $None)
foreach ($name in @("*.corp.local", "a b.corp", "x.corp`n  tls: off", "10.0.0.1")) {
    Must-Fail "name '$name'" "Invalid -TlsServerName" @("-ServerHost", "logmon.ci.internal", "-ApiKey", "ci", "-CaFile", $Fix, "-TlsServerName", $name, "-Settings", $None)
}
"install.ps1 tests passed"
exit 0
