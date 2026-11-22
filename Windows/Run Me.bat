@echo off
setlocal
title Threat Inspection

set "TI_SCRIPT=%~dp0ThreatInspection.ps1"
if not exist "%TI_SCRIPT%" (
    echo ThreatInspection.ps1 was not found beside Run Me.bat.
    echo Keep both files in the same folder.
    echo.
    pause
    exit /b 1
)

rem Use the built-in Windows PowerShell 5.1 and request administrator access.
rem Pass the path via an environment variable to avoid embedding it in PowerShell code.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p = $env:TI_SCRIPT; $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'; $arguments = '-NoExit -NoProfile -ExecutionPolicy Bypass -File ' + [char]34 + $p + [char]34; Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs -Wait"
if errorlevel 1 (
    echo.
    echo Threat Inspection could not be started. Check the error above.
    pause
    exit /b 1
)
endlocal
