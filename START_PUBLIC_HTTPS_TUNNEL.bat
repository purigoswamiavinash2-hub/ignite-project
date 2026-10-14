@echo off
TITLE ThreatGuard AI — Instant Public HTTPS Tunnel
COLOR 0B
cls

echo =====================================================================
echo       SKIT025 — THREATGUARD AI: INSTANT PUBLIC HTTPS TUNNEL
echo =====================================================================
echo  This tool creates a secure, publicly accessible HTTPS URL so hackathon
echo  judges can inspect your ThreatGuard Dashboard & test Telegram bot
echo  directly from their own smartphones or laptops anywhere in the world!
echo =====================================================================
echo.

set "PATH=C:\Users\UCS\AppData\Local\Programs\nodejs;C:\Users\UCS\AppData\Local\Python\pythoncore-3.14-64;%PATH%"

echo [1/2] Verifying FastAPI backend is active on port 8000...
curl -s http://127.0.0.1:8000/health >nul
if %errorlevel% neq 0 (
    echo [!] Backend is not running. Starting ThreatGuard AI backend...
    start "ThreatGuard Backend" cmd /k "cd /d %~dp0 && python -m uvicorn backend.main:app --port 8000"
    timeout /t 3 >nul
) else (
    echo [*] Backend is running and healthy on port 8000.
)

echo.
echo [2/2] Generating Instant Public HTTPS Live Link...
echo.
echo =====================================================================
echo  SHARE THE GENERATED HTTPS URL WITH JUDGES:
echo =====================================================================
echo.
npx localtunnel --port 8000
pause
