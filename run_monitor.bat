@echo off
TITLE Network Inspector Launcher
CLS

:: Check for Administrator privileges
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [!] This tool requires Administrator privileges to capture traffic.
    echoRequesting Admin rights...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Change Directory to script location (Fix for System32 error)
cd /d "%~dp0"

echo [INFO] Network Traffic Inspector
echo [INFO] -------------------------
echo.

:: Check if Python is installed
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not found! Please install Python 3.
    pause
    exit /b
)

:: Install Dependencies
echo [INFO] Checking dependencies...
pip install -r requirements.txt >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [WARN] Could not install dependencies automatically.
    echo        Trying manual install of key libs...
    pip install customtkinter scapy psutil
)

:: Run the Application
echo [INFO] Starting Inspector...
echo.
python net_admin.py

pause
