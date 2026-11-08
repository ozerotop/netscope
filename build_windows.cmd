@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Python virtual environment missing. Run: py -3 -m venv .venv
  exit /b 1
)
echo [1/2] Running unit tests...
".venv\Scripts\python.exe" -m pytest -q
if errorlevel 1 exit /b 1
echo [2/2] Building the Windows application...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onedir --windowed --name NetScope --paths src src\netscope\gui.py
if errorlevel 1 exit /b 1
echo.
echo Build complete: %CD%\dist\NetScope\NetScope.exe
echo IMPORTANT: Keep the entire dist\NetScope folder together when sharing.
endlocal
