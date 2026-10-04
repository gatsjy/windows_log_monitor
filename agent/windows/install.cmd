@echo off
rem Log Monitor agent installer for offline (air-gapped) PCs.
rem   Right-click > Run as administrator.  For GPO / SCCM: install.cmd /quiet
rem   Reads settings.json (server, port, API key) and installs Fluent Bit from the fluent-bit folder if needed.
setlocal
net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Run this file as Administrator.
  if /i not "%~1"=="/quiet" pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set RC=%ERRORLEVEL%
if /i not "%~1"=="/quiet" pause
exit /b %RC%
