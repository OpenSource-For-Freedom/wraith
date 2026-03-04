#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Local simulation of .github/workflows/deploy.yml
    Runs every step (except the GitHub Release upload) and reports pass/fail.
.EXAMPLE
    .\test-deploy.ps1
    .\test-deploy.ps1 -Version v1.2.3
#>
param(
    [string]$Version = "v1.0.0-dev.local"
)

$ErrorActionPreference = "Stop"
$Root    = Split-Path -Parent $MyInvocation.MyCommand.Path
$ZipName = "WRAITH-${Version}-win-x64.zip"
$Pass    = 0
$Fail    = 0
$Warns   = 0

Push-Location $Root

function Step($name) {
    Write-Host ""
    Write-Host "  ── STEP: $name" -ForegroundColor Cyan
    Write-Host ("  " + ("-" * ($name.Length + 8))) -ForegroundColor DarkGray
}

function Ok($msg)   { Write-Host "  [PASS] $msg" -ForegroundColor Green;  $script:Pass++ }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red;    $script:Fail++ }
function Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:Warns++ }

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — Prerequisites
# ─────────────────────────────────────────────────────────────────────────────
Step "Prerequisites"

if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $dnVer = (dotnet --version)
    Ok  ".NET SDK present: $dnVer"
} else {
    Fail ".NET SDK not found — install from https://dot.net"
}

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyVer = (python --version 2>&1)
    Ok  "Python present: $pyVer"
} else {
    Warn "Python not found — START.bat auto-installs it, but can't test venv here"
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — dotnet publish (self-contained, single-file)
# ─────────────────────────────────────────────────────────────────────────────
Step "dotnet publish"

$publishDir = Join-Path $Root "publish-test"
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }

$publishArgs = @(
    "publish", "WRAITH/WRAITH.csproj",
    "--configuration", "Release",
    "--runtime", "win-x64",
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:DebugType=None",
    "-p:DebugSymbols=false",
    "--output", $publishDir,
    "--nologo"
)

Write-Host "  Running: dotnet $($publishArgs -join ' ')" -ForegroundColor DarkGray
$publishOutput = dotnet @publishArgs 2>&1
$publishExit   = $LASTEXITCODE

$publishOutput | Where-Object { $_ -match 'error|warning|succeeded|failed' } |
    ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

if ($publishExit -eq 0) {
    Ok "dotnet publish succeeded"
} else {
    Fail "dotnet publish FAILED (exit $publishExit)"
    Write-Host "  Full output:" -ForegroundColor DarkGray
    $publishOutput | ForEach-Object { Write-Host "    $_" }
}

$wraith_exe = Join-Path $publishDir "WRAITH.exe"
if (Test-Path $wraith_exe) {
    $sizeMB = [math]::Round((Get-Item $wraith_exe).Length / 1MB, 1)
    Ok  "WRAITH.exe produced (${sizeMB} MB)"
} else {
    Fail "WRAITH.exe not found in publish output"
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — Sign WRAITH.exe (temporary self-signed cert, local test only)
# ─────────────────────────────────────────────────────────────────────────────
Step "Sign WRAITH.exe (self-signed)"

$signThumbprint = $null
try {
    # Create a short-lived self-signed code-signing cert in the user's My store
    $cert = New-SelfSignedCertificate `
        -Subject        "CN=WRAITH Local Test" `
        -Type           CodeSigning `
        -CertStoreLocation Cert:\CurrentUser\My `
        -HashAlgorithm  SHA256 `
        -NotAfter       (Get-Date).AddHours(1)   # expires quickly - test only

    $signThumbprint = $cert.Thumbprint

    $signResult = Set-AuthenticodeSignature `
        -FilePath      $wraith_exe `
        -Certificate   $cert `
        -HashAlgorithm SHA256
        # (no timestamp server - local test; CI uses http://timestamp.digicert.com)

    # Self-signed certs produce 'UnknownError' ("no trust chain") which is expected
    if ($signResult.Status -in @("Valid", "UnknownError")) {
        Ok  "WRAITH.exe Authenticode-signed (self-signed / local test)"
        Ok  "Signer subject : $($cert.Subject)"
        Ok  "Cert thumbprint: $($cert.Thumbprint)"
    } else {
        Fail "Signing failed: $($signResult.Status) - $($signResult.StatusMessage)"
    }

    # Verify the signature is embedded and thumbprint matches
    $verify = Get-AuthenticodeSignature -FilePath $wraith_exe
    if ($verify.SignerCertificate -and
        $verify.SignerCertificate.Thumbprint -eq $cert.Thumbprint) {
        Ok  "Signature read-back OK - thumbprint verified"
    } else {
        Warn "Thumbprint mismatch on read-back (unexpected for self-signed)"
    }

    # Remove the ephemeral cert from the store
    Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
    Ok  "Ephemeral signing cert removed from store"

} catch {
    Warn "Code signing skipped: $_"
    Warn "Signing requires Windows PowerShell 5+ with PKI module."
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — Stage release bundle
# ─────────────────────────────────────────────────────────────────────────────
Step "Stage release bundle"

$releaseDir = Join-Path $Root "release-test"
if (Test-Path $releaseDir) { Remove-Item $releaseDir -Recurse -Force }
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

$copies = @(
    @{ Src = $wraith_exe;                        Dst = "$releaseDir/WRAITH.exe" },
    @{ Src = (Join-Path $Root "scanner");          Dst = "$releaseDir/scanner";   IsDir = $true },
    @{ Src = (Join-Path $Root "quick-scan.ps1");   Dst = "$releaseDir/quick-scan.ps1" },
    @{ Src = (Join-Path $Root "README.md");        Dst = "$releaseDir/README.md" },
    @{ Src = (Join-Path $Root "LICENSE");          Dst = "$releaseDir/LICENSE" }
)

$scannerMissing = $false
foreach ($c in $copies) {
    if (Test-Path $c.Src) {
        if ($c.IsDir) {
            Copy-Item $c.Src $c.Dst -Recurse -Force
        } else {
            Copy-Item $c.Src $c.Dst -Force
        }
        Ok  "Staged: $(Split-Path $c.Dst -Leaf)"
    } else {
        $leaf = Split-Path $c.Dst -Leaf
        if ($leaf -eq "scanner") {
            Warn "scanner/ directory not found on disk - Python scan engine must be committed to git for CI to work"
            $script:scannerMissing = $true
        } else {
            Fail "Source not found: $($c.Src)"
        }
    }
}

# Blank env template
'{ "python": "", "scanner_dir": "" }' | Set-Content "$releaseDir/wraith.env.json" -Encoding UTF8
Ok  "Staged: wraith.env.json (blank template)"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 — Generate START.bat (same heredoc + trim logic as workflow)
# ─────────────────────────────────────────────────────────────────────────────
Step "Generate START.bat"

$bat = @'
@echo off
setlocal enabledelayedexpansion

echo.
echo  ==========================================
echo   W R A I T H  --  Expecto Patronum
echo  ==========================================
echo.

set ROOT=%~dp0
set VENV_DIR=%ROOT%.venv
set VENV_PYTHON=%VENV_DIR%\Scripts\python.exe
set VENV_PIP=%VENV_DIR%\Scripts\pip.exe
set REQ=%ROOT%scanner\requirements.txt
set EXE=%ROOT%WRAITH.exe

:: ── Step 1: Verify / auto-install Python ──────────────────────────
echo [1/3] Checking Python...
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  Python not found. Installing automatically...
    echo.
    where winget >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo  Using winget to install Python 3.11...
        winget install --id Python.Python.3.11 --source winget ^
          --silent --accept-package-agreements --accept-source-agreements
    ) else (
        echo  winget not available. Downloading Python 3.11 installer...
        powershell -NoProfile -Command ^
          "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile '%TEMP%\python-setup.exe'; Write-Host '  Download complete.'"
        echo  Running silent installer (this may take a minute)...
        "%TEMP%\python-setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1
        del /f /q "%TEMP%\python-setup.exe" >nul 2>&1
    )
    for /f "tokens=*" %%P in ('powershell -NoProfile -Command ^
      "[Environment]::GetEnvironmentVariable('PATH','User')"') do set "PATH=%%P;%PATH%"
    where python >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo  Python was installed but is not on PATH yet.
        echo  Please close this window and run START.bat again.
        pause
        exit /b 1
    )
    echo  Python installed successfully.
)
python --version
echo  Python OK.

:: ── Step 2: Python venv + dependencies ────────────────────────────
echo.
echo [2/3] Setting up Python environment...
if not exist "%VENV_PYTHON%" (
    echo  Creating virtual environment...
    python -m venv "%VENV_DIR%"
    if %ERRORLEVEL% NEQ 0 (
        echo  ERROR: Failed to create venv.
        pause
        exit /b 1
    )
) else (
    echo  Reusing existing venv.
)

echo  Installing scan dependencies (first run may take a minute)...
"%VENV_PYTHON%" -m pip install --upgrade pip --quiet --disable-pip-version-check
"%VENV_PIP%" install -r "%REQ%" --quiet --disable-pip-version-check
if %ERRORLEVEL% NEQ 0 (
    echo  WARNING: Some packages failed. YARA scanning may be unavailable.
    echo  All other modules will still run.
) else (
    echo  Dependencies OK.
)

powershell -NoProfile -Command ^
  "@{ python = '%VENV_PYTHON:\=\\%'; scanner_dir = '%ROOT:\=\\%scanner' } | ConvertTo-Json | Set-Content '%ROOT:\=\\%wraith.env.json' -Encoding UTF8"

:: ── Step 3: Launch ─────────────────────────────────────────────────
echo.
echo [3/3] Launching WRAITH...
if not exist "%EXE%" (
    echo  ERROR: WRAITH.exe not found at %EXE%
    pause
    exit /b 1
)
taskkill /F /T /IM WRAITH.exe >nul 2>&1
start "" "%EXE%"
echo  WRAITH launched.
timeout /t 2 >nul
'@

$bat | Set-Content "$releaseDir/START.bat" -Encoding ASCII

if (Test-Path "$releaseDir/START.bat") {
    $lines = (Get-Content "$releaseDir/START.bat").Count
    Ok  "START.bat written ($lines lines)"
} else {
    Fail "START.bat was not created"
}

# Validate key sections exist in START.bat
$startContent = Get-Content "$releaseDir/START.bat" -Raw
$checks = @{
    "Python auto-install block"  = "Python not found. Installing automatically"
    "winget install"             = "winget install --id Python.Python.3.11"
    "Silent installer fallback"  = "python-3.11.9-amd64.exe"
    "venv creation"              = "python -m venv"
    "pip install"                = "%VENV_PIP%.*install.*-r|pip.*install.*requirements"
    "wraith.env.json write"      = "wraith.env.json"
    "WRAITH.exe launch"          = 'start "" "%EXE%"'
}
foreach ($kv in $checks.GetEnumerator()) {
    if ($startContent -match $kv.Value) {
        Ok  "START.bat contains: $($kv.Key)"
    } else {
        Fail "START.bat MISSING: $($kv.Key)"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 — Create ZIP
# ─────────────────────────────────────────────────────────────────────────────
Step "Create ZIP"

$zipPath = Join-Path $Root $ZipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Compress-Archive -Path "$releaseDir/*" -DestinationPath $zipPath -CompressionLevel Optimal
if (Test-Path $zipPath) {
    $sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Ok  "ZIP created: $ZipName (${sizeMB} MB)"
} else {
    Fail "ZIP was not created"
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 7 — Validate ZIP contents
# ─────────────────────────────────────────────────────────────────────────────
Step "Validate ZIP contents"

$expected = @(
    "WRAITH.exe",
    "START.bat",
    "scanner/requirements.txt",
    "quick-scan.ps1",
    "README.md",
    "LICENSE",
    "wraith.env.json"
)

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
$entries = $zip.Entries | ForEach-Object { $_.FullName -replace '\\','/' }
$zip.Dispose()

foreach ($item in $expected) {
    $found = $entries | Where-Object { $_ -eq $item -or $_ -like "*/$item" -or $_ -like "$item*" }
    if ($found) {
        Ok  "ZIP contains: $item"
    } elseif ($item -like "scanner/*" -and $scannerMissing) {
        Warn "ZIP missing: $item (scanner/ not on disk - see warning above)"
    } else {
        Fail "ZIP MISSING:   $item"
    }
}

# Confirm wraith.env.json is blank (no local paths leaked)
$tmpExtract = Join-Path $env:TEMP "wraith-zip-check"
if (Test-Path $tmpExtract) { Remove-Item $tmpExtract -Recurse -Force }
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tmpExtract)
$envJson = Get-Content "$tmpExtract/wraith.env.json" -Raw | ConvertFrom-Json
if ($envJson.python -eq "" -and $envJson.scanner_dir -eq "") {
    Ok  "wraith.env.json is clean (no local paths)"
} else {
    Fail "wraith.env.json contains local paths - would break fresh clones"
}

# Verify WRAITH.exe inside the ZIP carries an Authenticode signature
$exeInZip = Join-Path $tmpExtract "WRAITH.exe"
if (Test-Path $exeInZip) {
    $sig = Get-AuthenticodeSignature -FilePath $exeInZip
    if ($sig.SignerCertificate) {
        if ($sig.Status -in @("Valid", "UnknownError")) {
            # "UnknownError" = self-signed cert not in Trusted Publishers — expected locally
            Ok  "WRAITH.exe in ZIP is Authenticode-signed  (status=$($sig.Status))"
            Ok  "Signer: $($sig.SignerCertificate.Subject)"
        } else {
            Fail "WRAITH.exe signature status: $($sig.Status) - $($sig.StatusMessage)"
        }
    } else {
        Warn "WRAITH.exe in ZIP has NO Authenticode signature"
        Warn "CI will sign using SIGNING_CERT_PFX secret; local test uses a self-signed cert."
    }
} else {
    Fail "WRAITH.exe not found in extracted ZIP (cannot check signature)"
}

Remove-Item $tmpExtract -Recurse -Force

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 8 — Cleanup temp artefacts
# ─────────────────────────────────────────────────────────────────────────────
Step "Cleanup"
Remove-Item $publishDir  -Recurse -Force
Remove-Item $releaseDir  -Recurse -Force
Ok  "Temp artefacts removed (ZIP kept at project root)"

# ─────────────────────────────────────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ==========================================" -ForegroundColor DarkGray
$total = $Pass + $Fail
if ($Fail -eq 0) {
    Write-Host "  ALL CHECKS PASSED  ($Pass/$total)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Artefact ready:  $ZipName" -ForegroundColor Cyan
    Write-Host "  Push to main or tag v* to trigger CI release." -ForegroundColor DarkCyan
} else {
    Write-Host "  $Fail FAILED  /  $Pass passed  /  $Warns warnings" -ForegroundColor Red
}
if ($Warns -gt 0) {
    Write-Host "  $Warns warning(s) - see above" -ForegroundColor Yellow
}
Write-Host "  ==========================================" -ForegroundColor DarkGray
Write-Host ""

Pop-Location
exit $Fail
