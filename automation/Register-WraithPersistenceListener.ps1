[CmdletBinding()]
param(
    [string]$TaskName = "WRAITH Persistence Listener",
    [string]$ScanPath = "C:\",
    [int]$PollSeconds = 120
)

$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "Start-WraithPersistenceListener.ps1"
if (-not (Test-Path $scriptPath)) { throw "Listener script not found: $scriptPath" }

$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ScanPath `"$ScanPath`" -PollSeconds $PollSeconds"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 12)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -User "SYSTEM" -Force | Out-Null

# Start now so user gets immediate protection
Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Write-Host "Registered and started '$TaskName'." -ForegroundColor Green
