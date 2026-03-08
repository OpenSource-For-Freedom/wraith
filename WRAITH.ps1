# WRAITH - Single-command launcher
# Self-elevates to Administrator, creates Python venv, installs deps, builds app, launches UI.

param(
    [switch]$Close,
    [switch]$ElevatedClose
)

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Run in current user context (no forced elevation).
# This allows users to close/terminate WRAITH without admin credentials.

$Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir    = Join-Path $Root ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip    = Join-Path $VenvDir "Scripts\pip.exe"
$ReqFile    = Join-Path $Root "scanner\requirements.txt"
$ScannerDir = Join-Path $Root "scanner"
$SlnFile    = Join-Path $Root "ThreatScanner.sln"
$ExeRelease = Join-Path $Root "WRAITH\bin\Release\net8.0-windows\WRAITH.exe"
$ExeDebug   = Join-Path $Root "WRAITH\bin\Debug\net8.0-windows\WRAITH.exe"

function Banner($msg) {
    Write-Host ""
    Write-Host "  [$msg]" -ForegroundColor Cyan
    Write-Host ("  " + ("-" * ($msg.Length + 2))) -ForegroundColor DarkGray
}

function Stop-WraithProcess {
    Write-Host ""
    Write-Host "  WRAITH - Close Mode" -ForegroundColor Cyan
    Write-Host ""

    $targets = Get-Process -Name "WRAITH" -ErrorAction SilentlyContinue
    if (-not $targets) {
        Write-Host "  No running WRAITH process found." -ForegroundColor Green
        return 0
    }

    foreach ($proc in $targets) {
        try {
            if (-not $proc.HasExited -and $proc.MainWindowHandle -ne 0) {
                [void]$proc.CloseMainWindow()
            }
        } catch {}
    }

    Start-Sleep -Milliseconds 1200

    $remaining = Get-Process -Name "WRAITH" -ErrorAction SilentlyContinue
    if ($remaining) {
        foreach ($proc in $remaining) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Host "  Stopped WRAITH PID $($proc.Id)." -ForegroundColor Yellow
            }
            catch {
                try {
                    $tk = Start-Process -FilePath "taskkill.exe" -ArgumentList "/F /T /PID $($proc.Id)" -NoNewWindow -Wait -PassThru
                    if ($tk.ExitCode -eq 0) {
                        Write-Host "  Stopped WRAITH PID $($proc.Id) via taskkill." -ForegroundColor Yellow
                        continue
                    }
                } catch {}

                Write-Host "  Could not stop PID $($proc.Id): $($_.Exception.Message)" -ForegroundColor Red
                if (-not (Test-IsAdmin)) {
                    Write-Host "  This process likely runs elevated. Re-run with admin prompt: LAUNCH.bat -Close" -ForegroundColor DarkYellow
                }
            }
        }
    }

    $left = Get-Process -Name "WRAITH" -ErrorAction SilentlyContinue
    if ($left) {
        Write-Host "  WRAITH is still running (permission boundary)." -ForegroundColor Red
        return 1
    }

    Write-Host "  WRAITH is fully stopped." -ForegroundColor Green
    return 0
}

if ($Close) {
    if (-not (Test-IsAdmin) -and -not $ElevatedClose) {
        Write-Host "  Requesting Administrator privileges to close elevated WRAITH process(es)..." -ForegroundColor Yellow
        $argStr = "-ExecutionPolicy Bypass -NoProfile -File `"$($MyInvocation.MyCommand.Path)`" -Close -ElevatedClose"
        try {
            Start-Process powershell -ArgumentList $argStr -Verb RunAs
            exit 0
        }
        catch {
            Write-Host "  Elevation cancelled. Could not close elevated process(es)." -ForegroundColor Red
            exit 1
        }
    }

    exit (Stop-WraithProcess)
}

Clear-Host
Write-Host ""
Write-Host "  WRAITH - Windows Runtime Analysis and Intrusion Threat Hunter" -ForegroundColor Cyan
Write-Host "  Expecto Patronum - Running in current user context" -ForegroundColor DarkCyan
Write-Host ""

# Step 1: Verify Python
Banner "Step 1/5 - Checking Python"
$pythonExe = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($LASTEXITCODE -eq 0 -and "$ver" -match "Python 3") {
            $pythonExe = $candidate
            Write-Host "  Found: $ver" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $pythonExe) {
    Write-Host "  Python not found. Attempting auto-install via winget..." -ForegroundColor Yellow
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        # Detect OS build to choose the most secure compatible Python
        $buildNum = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber -as [int]
        $pyId = if ($buildNum -ge 22000) { 'Python.Python.3.14' } else { 'Python.Python.3.12' }
        $pyIdFb = if ($buildNum -ge 22000) { 'Python.Python.3.13' } else { 'Python.Python.3.11' }
        Write-Host "  Installing $pyId (Windows build $buildNum)..." -ForegroundColor Yellow
        winget install --id $pyId --silent --scope user --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  Trying fallback $pyIdFb..." -ForegroundColor Yellow
            winget install --id $pyIdFb --silent --scope user --accept-package-agreements --accept-source-agreements
        }
        # Refresh PATH so newly installed Python is visible
        $env:PATH = [Environment]::GetEnvironmentVariable('PATH','User') + ';' +
                    [Environment]::GetEnvironmentVariable('PATH','Machine')
        Start-Sleep -Seconds 2
        foreach ($candidate in @('python', 'python3')) {
            try {
                $ver = & $candidate --version 2>&1
                if ($LASTEXITCODE -eq 0 -and "$ver" -match 'Python 3') {
                    $pythonExe = $candidate
                    Write-Host "  Python installed: $ver" -ForegroundColor Green
                    break
                }
            } catch {}
        }
    }
    if (-not $pythonExe) {
        Write-Host "  ERROR: Python could not be installed automatically." -ForegroundColor Red
        Write-Host "  Install from https://python.org -- check 'Add Python to PATH'." -ForegroundColor Yellow
        Read-Host "  Press Enter to exit"
        exit 1
    }
}

# Step 2: Create / reuse venv
Banner "Step 2/5 - Python virtual environment"

if (-not (Test-Path $VenvPython)) {
    Write-Host "  Creating venv at $VenvDir ..." -ForegroundColor Yellow
    & $pythonExe -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: venv creation failed." -ForegroundColor Red
        Read-Host "  Press Enter to exit"
        exit 1
    }
    Write-Host "  Venv created." -ForegroundColor Green
} else {
    Write-Host "  Reusing existing venv: $VenvDir" -ForegroundColor Green
}

Write-Host "  Installing dependencies..." -ForegroundColor Yellow
# Upgrade pip silently
& $VenvPython -m pip install --upgrade pip --quiet --disable-pip-version-check 2>$null

# Install requirements — redirect stderr to suppress pip [notice] lines which
# PowerShell mis-reports as NativeCommandError
$pipResult = & $VenvPip install -r $ReqFile --disable-pip-version-check 2>$null
$pipExit = $LASTEXITCODE
$pipResult | Where-Object { $_ -match 'Successfully|already satisfied|ERROR|error' } |
    ForEach-Object { Write-Host "  $_" }
if ($pipExit -ne 0) {
    Write-Host "  WARNING: Some packages failed (yara-python may not support your Python version)." -ForegroundColor Yellow
    Write-Host "  YARA mode will be skipped; all other scan modules will still run." -ForegroundColor DarkYellow
} else {
    Write-Host "  Dependencies OK." -ForegroundColor Green
}

# Write venv config so the C# app uses the venv python, not system python
@{ python = $VenvPython; scanner_dir = $ScannerDir } |
    ConvertTo-Json | Set-Content (Join-Path $Root "wraith.env.json") -Encoding UTF8

# Step 3: Build .NET app
Banner "Step 3/5 - Building WRAITH"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Host "  .NET 8 SDK not found. Installing via winget..." -ForegroundColor Yellow
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        winget install --id Microsoft.DotNet.SDK.8 --silent --accept-package-agreements --accept-source-agreements
        # Refresh PATH in this session — dotnet installs to C:\Program Files\dotnet
        $env:PATH = [Environment]::GetEnvironmentVariable('PATH','Machine') + ';' +
                    [Environment]::GetEnvironmentVariable('PATH','User')
        if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
            # Winget may not have updated Machine PATH yet; probe the known default location
            $dotnetExe = 'C:\Program Files\dotnet\dotnet.exe'
            if (Test-Path $dotnetExe) { $env:PATH = "C:\Program Files\dotnet;$env:PATH" }
        }
    }
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Write-Host "  ERROR: .NET 8 SDK could not be installed automatically." -ForegroundColor Red
        Write-Host "  Install manually from https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
        Read-Host "  Press Enter to exit"
        exit 1
    }
    Write-Host "  .NET 8 SDK installed successfully." -ForegroundColor Green
}

Write-Host "  Running dotnet build (Release)..." -ForegroundColor Yellow
Push-Location $Root
$buildFailed = $false
# Stream build output line-by-line so progress is visible in real-time.
# Filter to errors/warnings/summary; suppress noisy restore lines.
dotnet build $SlnFile -c Release --nologo 2>&1 | ForEach-Object {
    $line = "$_"
    if ($line -match 'error\s|warning\s|Build succeeded|FAILED|Error') {
        $color = if ($line -match 'error\s|FAILED|Error') { 'Red' }
                 elseif ($line -match 'warning') { 'Yellow' }
                 else { 'Green' }
        Write-Host "  $line" -ForegroundColor $color
    }
    if ($line -match 'FAILED') { $buildFailed = $true }
}
$buildExit = $LASTEXITCODE
Pop-Location

if ($buildExit -ne 0 -or $buildFailed) {
    Write-Host "  Build FAILED. Check output above." -ForegroundColor Red
    Read-Host "  Press Enter to exit"
    exit 1
}
Write-Host "  Build succeeded." -ForegroundColor Green

# Step 4: Desktop shortcut
Banner "Step 4/5 - Desktop Shortcut"

$IconPath     = Join-Path $Root "WRAITH\Assets\wraith.ico"
$ShortcutPaths = @()

$CurrentDesktop = [Environment]::GetFolderPath("Desktop")
if ($CurrentDesktop) {
    $ShortcutPaths += (Join-Path $CurrentDesktop "WRAITH.lnk")
}

$PublicDesktop = Join-Path $env:PUBLIC "Desktop"
if (Test-Path $PublicDesktop) {
    $ShortcutPaths += (Join-Path $PublicDesktop "WRAITH.lnk")
}

$ShortcutPaths = $ShortcutPaths | Select-Object -Unique

try {
    $exeForShortcut = if (Test-Path $ExeRelease) { $ExeRelease } else { $ExeDebug }
    if (-not (Test-Path $exeForShortcut)) {
        throw "WRAITH.exe not found for shortcut creation."
    }

    $WshShell = New-Object -ComObject WScript.Shell
    foreach ($ShortcutPath in $ShortcutPaths) {
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath       = $exeForShortcut
        $Shortcut.Arguments        = ""
        $Shortcut.WorkingDirectory = $Root
        $Shortcut.Description      = "WRAITH - Windows Runtime Analysis and Intrusion Threat Hunter"
        if (Test-Path $IconPath) { $Shortcut.IconLocation = "$IconPath,0" }
        $Shortcut.Save()

        # Ensure shortcut does NOT force Run as Administrator (clear byte 21, bit 6)
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[21] = $bytes[21] -band (-bnot 0x20)
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)

        Write-Host "  Shortcut created: $ShortcutPath" -ForegroundColor Green
    }
    Write-Host "  Desktop launcher updated. Double-click WRAITH.lnk to launch." -ForegroundColor Cyan
} catch {
    Write-Host "  WARNING: Could not create desktop shortcut: $_" -ForegroundColor Yellow
}

# Step 5: Launch
Banner "Step 5/5 - Launching WRAITH"

$exePath = if (Test-Path $ExeRelease) { $ExeRelease } else { $ExeDebug }

if (-not (Test-Path $exePath)) {
    Write-Host "  ERROR: WRAITH.exe not found." -ForegroundColor Red
    Read-Host "  Press Enter to exit"
    exit 1
}

Write-Host "  Launching: $exePath" -ForegroundColor Cyan

# Kill stale WRAITH instances before launching a fresh one
try {
    $tk = Start-Process -FilePath "taskkill.exe" -ArgumentList "/F /T /IM WRAITH.exe" -NoNewWindow -Wait -PassThru
    if ($tk.ExitCode -eq 0) {
        Write-Host "  Cleared stale WRAITH process(es)." -ForegroundColor Yellow
    }
} catch {
    # Ignore if nothing is running or taskkill unavailable
}

Start-Process $exePath
Write-Host "  WRAITH launched." -ForegroundColor Green
Start-Sleep 2
