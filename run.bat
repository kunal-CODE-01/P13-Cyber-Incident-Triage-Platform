@echo off
setlocal
cd /d "%~dp0"
echo ================================================
echo P13 Cyber Incident Triage Platform
echo Portable Windows Launcher
echo ================================================
if not exist .venv (
    echo Creating virtual environment...
    py -m venv .venv
    if errorlevel 1 python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if not exist .env copy /Y .env.example .env >nul
where nmap >nul 2>nul
if errorlevel 1 (
    echo.
echo WARNING: Nmap executable was not found in PATH.
echo Network Scan will not work until Nmap is installed and added to PATH.
echo The web application will still start.
) else (
    nmap --version | findstr /B /C:"Nmap version"
)
echo.
echo Starting P13 on http://127.0.0.1:5000
echo From another device on the same LAN use: http://YOUR-PC-IP:5000
echo Press CTRL+C to stop.
waitress-serve --listen=0.0.0.0:5000 app:app
pause
