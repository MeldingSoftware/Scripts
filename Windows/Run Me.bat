@echo off
setlocal
set "TI_SCRIPT=%~dp0ThreatInspection.ps1"

if not exist "%TI_SCRIPT%" (
    echo ThreatInspection.ps1 was not found beside Run Me.bat.
    echo Keep both files in the same folder.
    echo.
    pause
    exit /b 1
)

rem Launch one elevated, maximized Windows PowerShell 5.1 console.
rem Do not use -NoExit or -Wait: the console closes when the scan finishes,
rem and the temporary CMD launcher exits immediately after starting it.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p = $env:TI_SCRIPT; $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'; $argsText = '-NoProfile -ExecutionPolicy Bypass -File ' + [char]34 + $p + [char]34; Start-Process -FilePath $exe -ArgumentList $argsText -Verb RunAs -WindowStyle Maximized -ErrorAction Stop"
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (
    echo.
    echo Threat Inspection could not be started. Check the error above.
    pause
)
exit /b %RESULT%
