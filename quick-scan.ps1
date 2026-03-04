#!/usr/bin/env pwsh
<#
.SYNOPSIS
    WRAITH Quick Scan - Can run immediately without building the GUI app.
    Checks persistence, processes, npm supply chain, and event logs.
    Run as Administrator for full visibility.
.EXAMPLE
    .\quick-scan.ps1
    .\quick-scan.ps1 -Hours 168 -OutPath C:\wraith-report.json
#>
[CmdletBinding()]
param(
    [int]    $Hours   = 72,
    [string] $OutPath = ".\wraith_quickscan_$(Get-Date -f yyyyMMdd_HHmmss).json"
)

$ErrorActionPreference = "Continue"
$findings = @()
$scanStart = Get-Date

Write-Host ""
Write-Host " ▲ WRAITH Quick Scan" -ForegroundColor Cyan
Write-Host " ═══════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " Scanning for persistent threats, suspicious processes," -ForegroundColor Gray
Write-Host " compromised npm packages, and security events..." -ForegroundColor Gray
Write-Host ""

# ── Helper ───────────────────────────────────────────────────────────────
function Add-Finding($severity, $category, $title, $path, $reason) {
    $c = switch($severity) {
        "CRITICAL" { "Red" }; "HIGH" { "DarkRed" }
        "MEDIUM"   { "Yellow" }; "LOW" { "Blue" }
        default    { "Gray" }
    }
    Write-Host "  [$severity] $title" -ForegroundColor $c
    Write-Host "    Path:   $path" -ForegroundColor DarkGray
    Write-Host "    Reason: $reason" -ForegroundColor DarkGray
    Write-Host ""
    $script:findings += [PSCustomObject]@{
        Severity = $severity; Category = $category; Title = $title
        Path = $path; Reason = $reason; Time = (Get-Date -f "s")
    }
}

$suspiciousKeywords = @(
    'openclaw','metaquest','oculusservice',
    'powershell.*-e[nc]','invoke-expression','iex\(',
    'downloadstring','frombase64','certutil.*-decode',
    'bitsadmin.*transfer','wscript','cscript','mshta',
    'regsvr32.*/s','\btemp\\','\btmp\\',
    'appdata\\roaming\\npm','node_modules',
    'mimikatz','cobalt','meterpreter','shellcode','xmrig'
)
$suspPattern = ($suspiciousKeywords -join '|')

# ════════════════════════════════════════════════════════════════════════
# 1. REGISTRY RUN KEYS
# ════════════════════════════════════════════════════════════════════════
Write-Host "[1/6] Scanning registry run keys..." -ForegroundColor Cyan
$runKeys = @(
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        try {
            $vals = Get-ItemProperty $key -ErrorAction Stop
            $vals.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' } | ForEach-Object {
                $val = $_.Value
                if ($val -match $suspPattern) {
                    Add-Finding "HIGH" "persistence/registry" "Suspicious Run Key: $($_.Name)" "$key\$($_.Name)" "Value contains suspicious pattern: $val"
                } elseif ($val -match '\\temp\\|\\tmp\\') {
                    Add-Finding "CRITICAL" "persistence/registry" "Run Key Points to TEMP: $($_.Name)" "$key\$($_.Name)" "Executable in TEMP: $val"
                } else {
                    Write-Host "  [INFO] Run key: $($_.Name) = $($val.Substring(0,[Math]::Min(80,$val.Length)))" -ForegroundColor DarkGray
                }
            }
        } catch {}
    }
}

# ════════════════════════════════════════════════════════════════════════
# 2. SCHEDULED TASKS
# ════════════════════════════════════════════════════════════════════════
Write-Host "[2/6] Scanning scheduled tasks..." -ForegroundColor Cyan
try {
    Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        $task = $_
        $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        $actionStr = $actions -join '; '
        if ($actionStr -match $suspPattern) {
            Add-Finding "HIGH" "persistence/task" "Suspicious Scheduled Task: $($task.TaskName)" $task.TaskPath $actionStr
        } elseif ($actionStr -match '\\appdata\\|\\temp\\|\\tmp\\') {
            Add-Finding "CRITICAL" "persistence/task" "Task Runs From AppData/Temp: $($task.TaskName)" $task.TaskPath $actionStr
        }
    }
} catch { Write-Warning "Scheduled task scan failed: $_" }

# ════════════════════════════════════════════════════════════════════════
# 3. SERVICES
# ════════════════════════════════════════════════════════════════════════
Write-Host "[3/6] Scanning services..." -ForegroundColor Cyan
try {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
        $path = $_.PathName
        if ($path -match $suspPattern) {
            Add-Finding "CRITICAL" "persistence/service" "Suspicious Service: $($_.Name)" $path "Service binary matches suspicious pattern"
        } elseif ($path -match '\\appdata\\|\\temp\\|\\tmp\\') {
            Add-Finding "CRITICAL" "persistence/service" "Service in AppData/Temp: $($_.Name)" $path "Service running from user-writable location: $path"
        }
    }
} catch { Write-Warning "Service scan failed: $_" }

# ════════════════════════════════════════════════════════════════════════
# 4. RUNNING PROCESSES
# ════════════════════════════════════════════════════════════════════════
Write-Host "[4/6] Scanning running processes..." -ForegroundColor Cyan
$trustedPaths = @('C:\Windows','C:\Program Files','C:\Program Files (x86)')
try {
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | ForEach-Object {
        $proc = $_
        $path = $proc.ExecutablePath ?? ''
        $cmd  = $proc.CommandLine  ?? ''
        $name = $proc.Name

        if ($cmd -match $suspPattern) {
            Add-Finding "CRITICAL" "processes" "Suspicious Process Cmdline: $name (PID $($proc.ProcessId))" $path "Command: $($cmd.Substring(0,[Math]::Min(200,$cmd.Length)))"
        } elseif ($path -match '\\appdata\\|\\temp\\|\\tmp\\|\\downloads\\') {
            Add-Finding "HIGH" "processes" "Process in Unusual Location: $name (PID $($proc.ProcessId))" $path "Process running from: $path"
        }
        # openclaw specific
        if ($name -match 'openclaw|claw' -or $path -match 'openclaw') {
            Add-Finding "CRITICAL" "processes" "OpenClaw Process Detected! $name (PID $($proc.ProcessId))" $path "OpenClaw is running - check for Meta Quest auth requests at startup"
        }
    }
} catch { Write-Warning "Process scan failed: $_" }

# ════════════════════════════════════════════════════════════════════════
# 5. EVENT LOGS (Security + System)
# ════════════════════════════════════════════════════════════════════════
Write-Host "[5/6] Scanning event logs (last $Hours hours)..." -ForegroundColor Cyan
$cutoff = (Get-Date).AddHours(-$Hours)

$criticalEventIds = @{
    1102 = "Security Audit Log CLEARED - attacker technique"
    4697 = "New Service Installed"
    4698 = "Scheduled Task Created"
    4720 = "New User Account Created"
    4732 = "User Added to Admin Group"
    7045 = "New Service Installed (System)"
    4648 = "Explicit Credential Use (pass-the-hash?)"
    4104 = "PowerShell Script Block Logging"
}

$logNames = @('Security','System','Application','Microsoft-Windows-PowerShell/Operational',
              'Microsoft-Windows-TaskScheduler/Operational')

foreach ($logName in $logNames) {
    try {
        $events = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt $cutoff } |
            Where-Object {
                $criticalEventIds.ContainsKey($_.Id) -or
                $_.Message -match 'openclaw|metaquest|powershell.*-enc|mimikatz|invoke-expression|downloadstring|certutil.*decode|cline|xmrig|stratum'
            } |
            Select-Object -First 100

        foreach ($ev in $events) {
            $reason = if ($criticalEventIds.ContainsKey($ev.Id)) { $criticalEventIds[$ev.Id] } else { "Suspicious keyword in event message" }
            $msgPreview = ($ev.Message -replace '[\r\n]+',' ').Substring(0,[Math]::Min(150,$ev.Message.Length))
            $sev = if ($ev.Id -eq 1102) { "CRITICAL" } elseif ($criticalEventIds.ContainsKey($ev.Id)) { "HIGH" } else { "HIGH" }
            Add-Finding $sev "events/$logName" "[EventID:$($ev.Id)] $reason - $($ev.ProviderName)" "EventLog:$logName" $msgPreview
        }
    } catch {}
}

# ════════════════════════════════════════════════════════════════════════
# 6. npm SUPPLY CHAIN CHECK
# ════════════════════════════════════════════════════════════════════════
Write-Host "[6/6] Checking npm packages..." -ForegroundColor Cyan

# Look for openclaw in npm
try {
    $npmGlobal = & npm list -g --depth=0 2>$null
    if ($npmGlobal -match 'openclaw') {
        Add-Finding "CRITICAL" "npm" "OpenClaw found in global npm packages!" "npm global" "openclaw is globally installed via npm - this may be the source of Meta Quest requests"
    }
    if ($npmGlobal -match 'cline@') {
        # Check if it's a vulnerable version
        Add-Finding "HIGH" "npm" "cline npm package installed globally" "npm global" "cline detected - verify version is not from compromised supply chain attack"
    }
} catch {}

# Scan package.json files in common locations
$searchRoots = @($env:USERPROFILE, 'C:\dev', 'C:\projects') | Where-Object { Test-Path $_ }
foreach ($root in $searchRoots) {
    Get-ChildItem -Path $root -Filter "package.json" -Recurse -Depth 5 -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $pkg = Get-Content $_.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (!$pkg) { return }
            # Check scripts
            if ($pkg.scripts) {
                $pkg.scripts.PSObject.Properties | ForEach-Object {
                    if ($_.Value -match 'curl.*\|.*sh|wget.*\|.*sh|execSync|require.*child_process|base64') {
                        Add-Finding "CRITICAL" "npm/script" "Suspicious npm script: '$($_.Name)' in $($pkg.name)" $_.FullName "Script: $($_.Value.Substring(0,[Math]::Min(200,$_.Value.Length)))"
                    }
                }
            }
            # Check for openclaw dependency
            $allDeps = @()
            if ($pkg.dependencies)    { $allDeps += $pkg.dependencies.PSObject.Properties.Name }
            if ($pkg.devDependencies) { $allDeps += $pkg.devDependencies.PSObject.Properties.Name }
            if ($allDeps -match 'openclaw|xmrig|cryptominer') {
                Add-Finding "CRITICAL" "npm/dependency" "Suspicious dependency in $($pkg.name)" $_.FullName "Contains suspicious dependency: $($allDeps -match 'openclaw|xmrig|cryptominer')"
            }
        } catch {}
    }
}

# ════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════
$elapsed = (Get-Date) - $scanStart
$critical = ($findings | Where-Object Severity -eq 'CRITICAL').Count
$high     = ($findings | Where-Object Severity -eq 'HIGH').Count
$medium   = ($findings | Where-Object Severity -eq 'MEDIUM').Count
$low      = ($findings | Where-Object Severity -eq 'LOW').Count

Write-Host ""
Write-Host " ═══════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " WRAITH Quick Scan Complete  ($([Math]::Round($elapsed.TotalSeconds,1))s)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  CRITICAL : $critical" -ForegroundColor Red
Write-Host "  HIGH     : $high"     -ForegroundColor DarkRed
Write-Host "  MEDIUM   : $medium"   -ForegroundColor Yellow
Write-Host "  LOW      : $low"      -ForegroundColor Blue
Write-Host "  TOTAL    : $($findings.Count)"  -ForegroundColor White
Write-Host ""

if ($critical -gt 0) {
    Write-Host "  ⚠  CRITICAL THREATS FOUND — review findings above immediately!" -ForegroundColor Red
} elseif ($high -gt 0) {
    Write-Host "  ⚠  HIGH severity findings require investigation." -ForegroundColor DarkRed
} elseif ($findings.Count -eq 0) {
    Write-Host "  ✓  No suspicious indicators found in quick scan." -ForegroundColor Green
    Write-Host "     Run the full WRAITH GUI for YARA + heuristic analysis." -ForegroundColor DarkGray
} else {
    Write-Host "  ✓  No critical/high threats. Review medium/low as needed." -ForegroundColor Yellow
}

# Export JSON
$report = [PSCustomObject]@{
    Scanner   = "WRAITH-QuickScan"
    Timestamp = (Get-Date -f "s")
    DurationSec = [Math]::Round($elapsed.TotalSeconds, 2)
    Summary   = [PSCustomObject]@{ Critical=$critical; High=$high; Medium=$medium; Low=$low; Total=$findings.Count }
    Findings  = $findings
}
$report | ConvertTo-Json -Depth 5 | Out-File $OutPath -Encoding UTF8
Write-Host ""
Write-Host "  Report saved: $OutPath" -ForegroundColor DarkGray
Write-Host " ═══════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
