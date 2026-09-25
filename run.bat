@echo off
title CyberShield - Wi-Fi Security Analyser
color 0b
echo =====================================================================
echo          CYBERSHIELD WI-FI SECURITY ANALYSER ^& AUDITOR
echo =====================================================================
echo.
echo [1] Launch Interactive Web Dashboard (Recommended)
echo [2] Run Terminal CLI Security Audit
echo [3] Exit
echo.
set /p choice="Select an option (1-3): "

if "%choice%"=="1" (
    echo.
    echo Starting Web Server... Open your browser at http://127.0.0.1:5050
    start http://127.0.0.1:5050
    python app.py
) else if "%choice%"=="2" (
    echo.
    echo Running Terminal Wi-Fi Security Audit...
    python cli.py
    echo.
    pause
) else (
    exit
)
