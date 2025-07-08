@echo off
title PCCheck Advanced Forensic Analysis Tool
cd /d "%~dp0"
echo Starting PCCheck Advanced Forensic Analysis Tool...
echo.
powershell.exe -ExecutionPolicy Bypass -WindowStyle Normal -File "%~dp0PcCheck.ps1"
echo.
echo Script execution completed.
pause
