@echo off
setlocal
title SecureMailScope setup
cd /d "%~dp0"

echo ============================================
echo  SecureMailScope - one-time setup
echo ============================================

rem ---- Pick a Python launcher -------------------------------------------
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python 3.11+ was not found. Install it from https://www.python.org/downloads/
    echo         and tick "Add python.exe to PATH".
    pause
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js was not found. Install Node.js 22 LTS from https://nodejs.org/
    pause
    exit /b 1
)

rem ---- Backend virtual environment ----------------------------------------
rem A venv is tied to the Python install of the machine that created it.
rem A venv copied from another laptop (e.g. inside a zip) is broken, so it
rem is recreated automatically when it cannot start.
if exist "backend\.venv\Scripts\python.exe" (
    "backend\.venv\Scripts\python.exe" -c "import sys" >nul 2>nul
    if errorlevel 1 (
        echo Existing backend\.venv belongs to another machine. Recreating it...
        rmdir /s /q "backend\.venv"
    )
)

if not exist "backend\.venv\Scripts\python.exe" (
    echo Creating backend virtual environment...
    %PY% -m venv "backend\.venv"
    if errorlevel 1 (
        echo [ERROR] Could not create the virtual environment.
        pause
        exit /b 1
    )
)

echo Installing backend dependencies...
"backend\.venv\Scripts\python.exe" -m pip install --upgrade pip >nul
"backend\.venv\Scripts\python.exe" -m pip install -r "backend\requirements.txt"
if errorlevel 1 (
    echo [ERROR] Backend dependency installation failed.
    pause
    exit /b 1
)

if not exist "backend\.env" (
    copy "backend\.env.example" "backend\.env" >nul
    echo Created backend\.env from .env.example - add your Google OAuth client ID/secret.
)

rem ---- Frontend -------------------------------------------------------------
echo Installing frontend dependencies...
pushd frontend
call npm install
if errorlevel 1 (
    popd
    echo [ERROR] Frontend dependency installation failed.
    pause
    exit /b 1
)
popd

echo.
echo Setup complete. Run start.bat to launch SecureMailScope.
pause
