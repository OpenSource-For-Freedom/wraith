[CmdletBinding()]
param(
    [string]$TaskName = "WRAITH Timed Scan",
    [int]$IntervalMinutes = 30,
    [string]$ScanPath = "C:\",
    [int]$Hours = 24,
    [string]$Mode = "all",
    [switch]$RunAsSystem
)

$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "Run-WraithTimedScan.ps1"
if (-not (Test-Path $scriptPath)) { throw "Timed scan runner not found: $scriptPath" }

$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ScanPath `"$ScanPath`" -Hours $Hours -Mode $Mode"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 9999)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)

if ($RunAsSystem) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -User "SYSTEM" -Force | Out-Null
} else {
    $user = "$env:USERDOMAIN\$env:USERNAME"
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -User $user -Force | Out-Null
}

Write-Host "Registered scheduled task '$TaskName' every $IntervalMinutes minute(s)." -ForegroundColor Green
