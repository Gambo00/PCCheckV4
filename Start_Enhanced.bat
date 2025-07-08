@echo off
title PCCheck Advanced Forensic Analysis Tool - Administrator Check
color 0A

echo.
echo ================================================
echo   PCCheck Advanced Forensic Analysis Tool
echo   Version 3.0 - Stealth Edition
echo ================================================
echo.

:: Check for Administrator rights
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo [WARNING] Not running as Administrator!
    echo.
    echo For full functionality, right-click this file and select:
    echo "Run as administrator"
    echo.
    echo Press any key to continue anyway...
    pause >nul
    echo.
)

:: Change to script directory
cd /d "%~dp0"

:: Check if PowerShell script exists
if not exist "PcCheck.ps1" (
    echo [ERROR] PcCheck.ps1 not found in current directory!
    echo Please ensure both files are in the same folder.
    echo.
    pause
    exit /b 1
)

echo Starting PowerShell script...
echo.

:: Execute PowerShell script with proper parameters
powershell.exe -ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -File "%~dp0PcCheck.ps1"

echo.
echo Script execution completed.
echo Press any key to exit...
pause >nul
