[CmdletBinding()]
param(
    [string]$ScanPath = "C:\",
    [int]$PollSeconds = 120,
    [int]$Hours = 24,
    [switch]$AutoKillCritical,
    [string]$SlackWebhookUrl = ""
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$scannerDir = Join-Path $root "scanner"
$outDir = Join-Path $env:ProgramData "WRAITH\PersistenceWatch"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "WRAITH persistence listener running. Poll=$PollSeconds sec Path=$ScanPath" -ForegroundColor Cyan

function Send-SlackAlert {
    param(
        [string]$Webhook,
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Webhook)) { return }

    try {
        $payload = @{ text = $Message } | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri $Webhook -Method Post -ContentType "application/json" -Body $payload -TimeoutSec 12 | Out-Null
    } catch {
        Write-Host "Slack post failed: $_" -ForegroundColor DarkYellow
    }
}

while ($true) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jsonOut = Join-Path $outDir "persistence_${stamp}.json"

    Push-Location $scannerDir
    try {
        $raw = cmd /c "python scanner.py --mode persistence --path \"$ScanPath\" --hours $Hours" 2>&1
    }
    finally {
        Pop-Location
    }

    $jsonLine = $raw | Select-String -Pattern '^{"scanner":' | Select-Object -Last 1
    if (-not $jsonLine) {
        Write-Host "[$stamp] scanner emitted no JSON" -ForegroundColor Yellow
        Start-Sleep -Seconds $PollSeconds
        continue
    }

    $jsonLine.Line | Out-File -FilePath $jsonOut -Encoding UTF8
    $obj = $jsonLine.Line | ConvertFrom-Json
    $crit = @($obj.findings | Where-Object { $_.severity -eq 'CRITICAL' })
    $high = @($obj.findings | Where-Object { $_.severity -eq 'HIGH' })

    if ($crit.Count -gt 0 -or $high.Count -gt 0) {
        Write-Host "[$stamp] ALERT: CRITICAL=$($crit.Count) HIGH=$($high.Count)" -ForegroundColor Red
        [console]::beep(1300,250)

        $top = @($obj.findings | Where-Object { $_.severity -in @('CRITICAL','HIGH') } | Select-Object -First 5)
        $lines = @()
        foreach ($f in $top) {
            $lines += "- $($f.severity) | $($f.title) | $($f.path)"
        }
        $msg = "WRAITH persistence alert`nPath: $ScanPath`nCRITICAL=$($crit.Count) HIGH=$($high.Count)`n" + ($lines -join "`n")
        Send-SlackAlert -Webhook $SlackWebhookUrl -Message $msg

        if ($AutoKillCritical) {
            foreach ($f in $crit) {
                if ($f.pid) {
                    try {
                        Stop-Process -Id ([int]$f.pid) -Force -ErrorAction Stop
                        Write-Host "Killed PID $($f.pid) from finding '$($f.title)'" -ForegroundColor Yellow
                    } catch {
                        Write-Host "Kill failed for PID $($f.pid): $_" -ForegroundColor DarkYellow
                    }
                }
            }
        }
    } else {
        Write-Host "[$stamp] clean" -ForegroundColor DarkGreen
    }

    Start-Sleep -Seconds $PollSeconds
}
