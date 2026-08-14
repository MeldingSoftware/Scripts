@echo off
set "SCRIPT=%~dp0Maintenance.ps1"

PowerShell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process PowerShell -Verb RunAs -WorkingDirectory '%~dp0' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%SCRIPT%""'"
