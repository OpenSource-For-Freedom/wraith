@echo off
:: ═══════════════════════════════════════════════════════════════════════
:: WRAITH Setup Script
:: Installs Python dependencies, builds native scanner, restores NuGet
:: Run as Administrator for best results
:: ═══════════════════════════════════════════════════════════════════════
setlocal enabledelayedexpansion

echo.
echo  ▲ WRAITH - Windows Runtime Analysis ^& Intrusion Threat Hunter
echo  ═══════════════════════════════════════════════════════════════
echo  Setup Script v1.0
echo.

set SCRIPTDIR=%~dp0
set SCANNER_DIR=%SCRIPTDIR%scanner
set NATIVE_DIR=%SCRIPTDIR%native
set RULES_DIR=%SCRIPTDIR%scanner\rules

:: ── Step 1: Check Python ─────────────────────────────────────────────
echo [1/5] Checking Python...
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  ERROR: Python not found.
    echo  Please install Python 3.10+ from https://python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
python --version
echo  Python OK.

:: ── Step 2: Install Python dependencies ─────────────────────────────
echo.
echo [2/5] Installing Python dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install -r "%SCANNER_DIR%\requirements.txt"
if %ERRORLEVEL% NEQ 0 (
    echo  WARNING: Some packages may have failed to install.
    echo  YARA scanning will be unavailable if yara-python failed.
    echo  You can try: pip install yara-python --pre
    echo.
)
echo  Python dependencies installed.

:: ── Step 3: Build native C scanner (optional) ───────────────────────
echo.
echo [3/5] Building native file scanner (C, optional)...
if not exist "%NATIVE_DIR%" (
    echo  native\ directory not found — skipping native scanner build.
    echo  The app will still work without it ^(Python handles all scanning^).
    goto :skip_native
)
pushd "%NATIVE_DIR%"
call build.bat
if %ERRORLEVEL% NEQ 0 (
    echo  WARNING: Native scanner build failed.
    echo  The app will still work without it (Python handles scanning).
    echo  To fix: install Visual Studio Build Tools or MinGW gcc.
) else (
    echo  Native scanner built OK.
)
popd
:skip_native

:: ── Step 4: Download YARA rules ──────────────────────────────────────
echo.
echo [4/5] Downloading YARA rules (requires internet)...
python "%SCANNER_DIR%\yara_scanner.py" --download-only 2>nul
if not exist "%RULES_DIR%\wraith_core.yar" (
    echo  Bundled rules already in place.
) else (
    echo  YARA rules ready.
)

:: ── Step 5: Restore .NET packages and build ──────────────────────────
echo.
echo [5/5] Building WRAITH (.NET 8 WPF)...
where dotnet >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  ERROR: .NET SDK not found.
    echo  Install .NET 8 SDK from: https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

dotnet restore "%SCRIPTDIR%ThreatScanner.sln" --nologo
dotnet build   "%SCRIPTDIR%ThreatScanner.sln" --configuration Release --nologo
if %ERRORLEVEL% NEQ 0 (
    echo  Build failed. Check errors above.
    pause
    exit /b 1
)

echo.
echo  ═══════════════════════════════════════════════════════════════
echo  ✓ WRAITH setup complete!
echo.
echo  Run LAUNCH.bat (as Administrator) to start scanning.
echo  ═══════════════════════════════════════════════════════════════
echo.
pause
