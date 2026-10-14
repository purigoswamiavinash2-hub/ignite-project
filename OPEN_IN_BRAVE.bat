@echo off
TITLE ThreatGuard AI — Launching in Brave Browser
COLOR 0B
cls

echo =====================================================================
echo       OPENING THREATGUARD AI DASHBOARD IN BRAVE BROWSER...
echo =====================================================================
echo.

set "HTML_FILE=%~dp0ThreatGuard_Dashboard.html"
set "BRAVE_PATH=C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"

if exist "%BRAVE_PATH%" (
    echo [OK] Launching Brave Browser directly...
    start "" "%BRAVE_PATH%" "%HTML_FILE%"
) else (
    echo [OK] Launching in Default Browser...
    start "" "%HTML_FILE%"
)

echo.
echo Dashboard successfully opened!
echo File: %HTML_FILE%
echo.
timeout /t 3 >nul
exit
