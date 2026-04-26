[CmdletBinding()]
param(
    [string]$ScanPath = "C:\",
    [int]$Hours = 24,
    [string]$Mode = "all"
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$scannerDir = Join-Path $root "scanner"
$outDir = Join-Path $env:ProgramData "WRAITH\ScheduledScans"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $outDir "scan_${Mode}_${stamp}.json"
$logFile = Join-Path $outDir "scan_${Mode}_${stamp}.log"

Push-Location $scannerDir
try {
    $cmd = "python scanner.py --mode $Mode --path \"$ScanPath\" --hours $Hours"
    $raw = cmd /c $cmd 2>&1
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
