#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Removes the Log Monitor agent service. Use -RemoveData to also delete C:\ProgramData\wlm-agent
  (config, read positions, offline buffer).
#>
param(
    [switch] $RemoveData,
    # Same as install.ps1 -ServiceName when a custom name was used
    [string] $ServiceName = "knuh-agent"
)

$ErrorActionPreference = "Stop"
$TargetServices = @($ServiceName, "knuh-agent", "wlm-agent") | Select-Object -Unique
$removed = 0
$DataDir = "C:\ProgramData\wlm-agent"

foreach ($svc in $TargetServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne "Stopped") { Stop-Service -Name $svc -Force }
        sc.exe delete $svc | Out-Null
        Write-Host "Service '$svc' removed."
        $removed++
    }
}
if ($removed -eq 0) { Write-Host "No agent service found." }

if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item -Recurse -Force $DataDir
    Write-Host "Removed $DataDir"
}
