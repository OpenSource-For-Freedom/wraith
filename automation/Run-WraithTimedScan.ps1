[CmdletBinding()]
param(
    [string]$ScanPath = "C:\",
    [int]$Hours = 24,
    [string]$Mode = "all",
    # Explicit absolute paths injected by Register-WraithTimedScan.ps1.
    # Falls back to PATH-relative `python` and a $PSScriptRoot-derived
    # scanner dir for the manual-invocation case.
    [string]$PythonPath = "python",
    [string]$ScannerDir = ""
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($ScannerDir)) {
    $root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $ScannerDir = Join-Path $root "scanner"
}

$outDir = Join-Path $env:ProgramData "WRAITH\ScheduledScans"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $outDir "scan_${Mode}_${stamp}.json"
$logFile = Join-Path $outDir "scan_${Mode}_${stamp}.log"

Push-Location $ScannerDir
try {
    # Invoke python directly by absolute path instead of via `cmd /c python ...`
    # so we don't rely on PATH at all. Output gets captured into the same log
    # so a missing python or missing scanner.py is visible after the fact.
    $raw = & $PythonPath "scanner.py" "--mode" $Mode "--path" $ScanPath "--hours" $Hours 2>&1
    $raw | Out-File -FilePath $logFile -Encoding UTF8

    $jsonLine = $raw | Select-String -Pattern '^{"scanner":' | Select-Object -Last 1
    if ($jsonLine) {
        $jsonLine.Line | Out-File -FilePath $outFile -Encoding UTF8
    } else {
        "{\"scanner\":\"WRAITH-scheduler\",\"error\":\"No JSON emitted by scanner\"}" | Out-File -FilePath $outFile -Encoding UTF8
    }
}
finally {
    Pop-Location
}
