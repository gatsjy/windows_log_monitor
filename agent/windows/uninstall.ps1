#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Removes the Log Monitor agent service. Use -RemoveData to also delete C:\ProgramData\wlm-agent
  (config, read positions, offline buffer).
#>
param([switch] $RemoveData)

$ErrorActionPreference = "Stop"
$ServiceName = "wlm-agent"
$DataDir = "C:\ProgramData\wlm-agent"

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") { Stop-Service -Name $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "Service '$ServiceName' removed."
} else {
    Write-Host "Service '$ServiceName' not found."
}

if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item -Recurse -Force $DataDir
    Write-Host "Removed $DataDir"
}
