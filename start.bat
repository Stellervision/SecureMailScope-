@echo off
setlocal
cd /d "%~dp0"

if not exist "backend\.venv\Scripts\python.exe" (
    echo Backend is not set up yet. Running setup.bat first...
    call setup.bat
)

"backend\.venv\Scripts\python.exe" -c "import fastapi" >nul 2>nul
if errorlevel 1 (
    echo Backend environment is broken or incomplete. Running setup.bat...
    call setup.bat
)

if not exist "frontend\node_modules" (
    echo Frontend is not set up yet. Running setup.bat first...
    call setup.bat
)

rem Host/ports must stay 127.0.0.1:8000 and localhost:5173: they are
rem registered as the Google OAuth redirect URI and CORS origins.
rem /D sets the working folder, which is safe for paths with spaces.
start "SecureMailScope backend" /D "%~dp0backend" cmd /k .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
start "SecureMailScope frontend" /D "%~dp0frontend" cmd /k npm run dev -- --host localhost --port 5173 --strictPort

timeout /t 6 >nul
start "" "http://localhost:5173"

echo SecureMailScope is starting:
echo   Frontend  http://localhost:5173
echo   Backend   http://127.0.0.1:8000/docs
