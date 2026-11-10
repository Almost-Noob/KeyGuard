@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [KeyGuard] Python environment not found:
    echo   .venv\Scripts\python.exe
    echo Please rebuild .venv using the instructions in README.md.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" "main.py" %*
exit /b %ERRORLEVEL%
