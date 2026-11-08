@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0Revival-Offline.exe" (
    echo Revival-Offline.exe eksik. Tam launcher paketini cikarin.
    pause
    exit /b 1
)
start "" /wait "%~dp0Revival-Offline.exe"
if errorlevel 1 pause
