@echo off
setlocal
cd /d "%~dp0"

if not exist ".conda\python.exe" (
    echo [KeyGuard] conda environment not found:
    echo   .conda\python.exe
    echo Create it with: conda create --prefix .conda python=3.12 -y
    pause
    exit /b 1
)

".conda\python.exe" "main.py" %*
exit /b %ERRORLEVEL%
