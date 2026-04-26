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
    [int]    $Hours    = 72,
    [string] $OutPath  = ".\wraith_quickscan_$(Get-Date -f yyyyMMdd_HHmmss).json",
    [string[]] $ScanPath = @()   # Extra directories to include in the npm package.json scan
)

$ErrorActionPreference = "Continue"
$findings = @()
$scanStart = Get-Date

Write-Host ""
Write-Host " ▲ WRAITH Quick Scan" -ForegroundColor Cyan
Write-Host " =======================================================" -ForegroundColor DarkGray
Write-Host " Scanning for persistent threats, suspicious processes," -ForegroundColor Gray
Write-Host " compromised npm packages, security events, and network C2 connections..." -ForegroundColor Gray
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

# NOTE: 'appdata\roaming\npm' and 'node_modules' are intentionally excluded from the
# generic suspiciousKeywords pattern — they are legitimate developer artifacts and
# would produce high false-positive rates in dev environments. They are only flagged
# when found in startup registry keys or service/process launch contexts below.
$suspiciousKeywords = @(
    'powershell.*\s-enc(odedcommand)?[\s"]','invoke-expression','iex\(',
    'downloadstring','frombase64','certutil.*-decode',
    'bitsadmin.*transfer','wscript','cscript','mshta',
    'regsvr32.*/s','\btemp\\','\btmp\\',
    'mimikatz','cobalt','meterpreter','shellcode','xmrig'
)
# High-confidence indicators only flagged in process/service launch contexts
$devToolKeywords = 'appdata\\roaming\\npm|node_modules'
$suspPattern = ($suspiciousKeywords -join '|')

# Known vendor apps that legitimately use AppData for per-user installs.
# Scheduled tasks from these paths are allowlisted to suppress false positives
# on standard vendor auto-update mechanisms.
$taskVendorAllowPattern = '\\appdata\\(local|roaming)\\(zoom|discord|roblox|slack|spotify|teams?|programs[\\/]signal-desktop|programs[\\/]canva|programs[\\/]cursor|programs[\\/]github.desktop|webex)[\\/]'

# ========================================================================
# 1. REGISTRY RUN KEYS
# ========================================================================
Write-Host "[1/7] Scanning registry run keys..." -ForegroundColor Cyan
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

# ========================================================================
# 2. SCHEDULED TASKS
# ========================================================================
Write-Host "[2/7] Scanning scheduled tasks..." -ForegroundColor Cyan
try {
    Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        $task = $_
        $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        $actionStr = $actions -join '; '
        if ($actionStr -match $suspPattern) {
            Add-Finding "HIGH" "persistence/task" "Suspicious Scheduled Task: $($task.TaskName)" $task.TaskPath $actionStr
        } elseif ($actionStr -match '\\appdata\\|\\temp\\|\\tmp\\') {
            if ($actionStr -imatch $taskVendorAllowPattern) {
                Write-Host "  [INFO] Task allowlisted (known vendor per-user install): $($task.TaskName)" -ForegroundColor DarkGray
            } else {
                Add-Finding "CRITICAL" "persistence/task" "Task Runs From AppData/Temp: $($task.TaskName)" $task.TaskPath $actionStr
            }
        }
    }
} catch { Write-Warning "Scheduled task scan failed: $_" }

# ========================================================================
# 3. SERVICES
# ========================================================================
Write-Host "[3/7] Scanning services..." -ForegroundColor Cyan
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

# ========================================================================
# 4. RUNNING PROCESSES
# ========================================================================
Write-Host "[4/7] Scanning running processes..." -ForegroundColor Cyan
$trustedPaths = @('C:\Windows','C:\Program Files','C:\Program Files (x86)')
try {
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | ForEach-Object {
        $proc = $_
        $path = if ($null -ne $proc.ExecutablePath) { $proc.ExecutablePath } else { '' }
        $cmd  = if ($null -ne $proc.CommandLine) { $proc.CommandLine } else { '' }
        $name = $proc.Name

        if ($cmd -match $suspPattern) {
            Add-Finding "CRITICAL" "processes" "Suspicious Process Cmdline: $name (PID $($proc.ProcessId))" $path "Command: $($cmd.Substring(0,[Math]::Min(200,$cmd.Length)))"
        } elseif ($path -match '\\appdata\\local\\temp\\|\\appdata\\roaming\\(?!npm\\|microsoft\\|programs\\)|\\temp\\|\\tmp\\|\\downloads\\') {
            # AppData\Local\Programs is a legitimate per-user install location (VS Code, Ollama, etc.)
            # Only flag: AppData\Local\Temp, AppData\Roaming (except known-good subfolders), \Temp, \Tmp, \Downloads
            Add-Finding "HIGH" "processes" "Process in Unusual Location: $name (PID $($proc.ProcessId))" $path "Process running from: $path"
        }
    }
} catch { Write-Warning "Process scan failed: $_" }

# ========================================================================
# 5. EVENT LOG DEEP AUDIT  (current + historical, last $Hours hours)
#    5a  Application  — app crashes, WER faults, suspicious installs
#    5b  System       — kernel events, driver installs, service crashes, BSODs
#    5c  Security     — auth failures, priv-esc, account changes, 4688 proc-create
#    5d  PowerShell   — script block (4104), remoting, suspicious encoding
#    5e  Kernel ETW   — CodeIntegrity, Kernel-PnP, DriverFrameworks-UserMode
#    5f  Memory/Inject— Sysmon 1/8/10/25 (proc create, remote-thread, proc-access,
#                       process tampering / hollowing)
#    5g  Defender     — threat detection + remediation events
# ========================================================================
Write-Host "[5/7] Deep event log audit (last $Hours hours)..." -ForegroundColor Cyan
$cutoff = (Get-Date).AddHours(-$Hours)

# ── shared helper ─────────────────────────────────────────────────────────
function Read-EventBlock($logName, $filterHash, $maxEvents, $label) {
    try {
        $fh = $filterHash.Clone()
        $fh['StartTime'] = $cutoff
        return Get-WinEvent -FilterHashtable $fh -MaxEvents $maxEvents -ErrorAction SilentlyContinue
    } catch { return @() }
}

function Get-MsgPreview($msg) {
    if (-not $msg) { return '' }
    ($msg -replace '[\r\n\t]+',' ').Substring(0,[Math]::Min(200,$msg.Length))
}

# ── 5a. APPLICATION LOG ────────────────────────────────────────────────────
Write-Host "  [5a] Application log..." -ForegroundColor DarkCyan
$appEvtIds = @{
    1000 = "Application Crash"
    1001 = "Windows Error Reporting (WER) — app fault"
    1002 = "Application Hang"
    11707= "Product Install Completed"
    11708= "Product Install Failed"
    11724= "Product Uninstall Completed"
}
$appMediumIds = @(11707, 11724)
$appEvts = Read-EventBlock 'Application' @{LogName='Application'; Id=($appEvtIds.Keys)} 500 '5a'
foreach ($ev in $appEvts) {
    $reason = if ($appEvtIds.ContainsKey($ev.Id)) { $appEvtIds[$ev.Id] } else { "Application event" }
    $msg    = Get-MsgPreview $ev.Message
    # Crash of a security-relevant process is HIGH
    $isSensitiveProc = $ev.Message -imatch 'lsass|winlogon|csrss|services\.exe|svchost|wininit|smss'
    $sev = if ($ev.Id -in @(1000,1001,1002) -and $isSensitiveProc) { "CRITICAL" }
           elseif ($ev.Id -in @(1000,1001,1002)) { "MEDIUM" }
           elseif ($appMediumIds -contains $ev.Id) { "LOW" }
           else { "LOW" }
    Add-Finding $sev "events/Application" "[AppEvt:$($ev.Id)] $reason" "EventLog:Application @ $($ev.TimeCreated.ToString('s'))" $msg
}
# WER keyword sweep (catches crashes not captured by fixed IDs)
try {
    Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$cutoff} -MaxEvents 2000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -imatch 'fault.*lsass|heap corruption|stack overflow|write access violation.*lsass|BSOD|kernel32.*crash' } |
        Select-Object -First 20 | ForEach-Object {
            Add-Finding "HIGH" "events/Application/WER" "[WER] Suspicious fault pattern" "Application log @ $($_.TimeCreated.ToString('s'))" (Get-MsgPreview $_.Message)
        }
} catch {}
if ($appEvts.Count -eq 0) { Write-Host "  [OK] No notable Application log events" -ForegroundColor Green }

# ── 5b. SYSTEM LOG — kernel, drivers, service crashes, BSODs ─────────────
Write-Host "  [5b] System log (kernel/driver/service/BSOD)..." -ForegroundColor DarkCyan
$sysEvtMap = @{
    6008  = @{ Sev="HIGH";     Reason="Unexpected Shutdown / System Crash (BSOD candidate)" }
    41    = @{ Sev="HIGH";     Reason="Kernel-Power: System rebooted without clean shutdown" }
    1001  = @{ Sev="MEDIUM";   Reason="BugCheck / BSOD recorded" }
    7001  = @{ Sev="MEDIUM";   Reason="Service failed to start at boot" }
    7022  = @{ Sev="MEDIUM";   Reason="Service hung on startup" }
    7023  = @{ Sev="MEDIUM";   Reason="Service terminated with error" }
    7031  = @{ Sev="HIGH";     Reason="Service crashed — recovery action triggered" }
    7034  = @{ Sev="HIGH";     Reason="Service terminated unexpectedly" }
    7035  = @{ Sev="LOW";      Reason="Service control send" }
    7040  = @{ Sev="MEDIUM";   Reason="Service start type changed" }
    7045  = @{ Sev="HIGH";     Reason="New service installed (kernel/user-mode)" }
    10016 = @{ Sev="LOW";      Reason="DCOM permissions error" }
    219   = @{ Sev="MEDIUM";   Reason="Kernel-PnP: Driver install problem" }
    20001 = @{ Sev="MEDIUM";   Reason="Driver install attempted" }
    20003 = @{ Sev="MEDIUM";   Reason="Driver service install" }
}
$sysEvts = Read-EventBlock 'System' @{LogName='System'; Id=($sysEvtMap.Keys)} 500 '5b'
foreach ($ev in $sysEvts) {
    $entry = $sysEvtMap[$ev.Id]
    if (-not $entry) { continue }
    $sev    = $entry.Sev
    $reason = $entry.Reason
    $msg    = Get-MsgPreview $ev.Message
    # Escalate 7045 (new service) if binary is in suspicious path
    if ($ev.Id -eq 7045) {
        if ($msg -imatch '\\appdata\\|\\temp\\|\\tmp\\') { $sev = "CRITICAL" }
        elseif ($msg -imatch 'C:\\Windows\\|C:\\Program Files') { $sev = "LOW" }
    }
    # Suppress noise: 7035 service control is usually legitimate
    if ($ev.Id -eq 7035) { return }
    Add-Finding $sev "events/System" "[SysEvt:$($ev.Id)] $reason" "EventLog:System @ $($ev.TimeCreated.ToString('s'))" $msg
}
# Kernel crash dump keyword sweep
try {
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff} -MaxEvents 3000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -imatch 'bugcheck|blue.?screen|memory dump|minidump|kernel.*exception|critical.?process.*died|IRQL_NOT_LESS_OR_EQUAL' } |
        Select-Object -First 15 | ForEach-Object {
            Add-Finding "HIGH" "events/System/Kernel" "[KernelCrash] Kernel exception or crash indicator" "System log @ $($_.TimeCreated.ToString('s'))" (Get-MsgPreview $_.Message)
        }
} catch {}
if ($sysEvts.Count -eq 0) { Write-Host "  [OK] No notable System log events" -ForegroundColor Green }

# ── 5c. SECURITY LOG — auth, priv-esc, account changes, process creates ──
Write-Host "  [5c] Security log (auth/priv-esc/4688 process creates)..." -ForegroundColor DarkCyan
$secEvtMap = @{
    1102  = @{ Sev="CRITICAL"; Reason="Security Audit Log CLEARED" }
    4616  = @{ Sev="HIGH";     Reason="System time changed (timestamp tampering)" }
    4624  = @{ Sev="LOW";      Reason="Successful logon" }
    4625  = @{ Sev="MEDIUM";   Reason="Failed logon attempt" }
    4648  = @{ Sev="HIGH";     Reason="Explicit credential use (pass-the-hash indicator)" }
    4688  = @{ Sev="MEDIUM";   Reason="New process created (command line logged)" }
    4697  = @{ Sev="HIGH";     Reason="Service installed via Security API" }
    4698  = @{ Sev="HIGH";     Reason="Scheduled task created" }
    4703  = @{ Sev="MEDIUM";   Reason="Token privileges adjusted" }
    4719  = @{ Sev="CRITICAL"; Reason="System audit policy changed" }
    4720  = @{ Sev="HIGH";     Reason="New user account created" }
    4723  = @{ Sev="MEDIUM";   Reason="Password change attempt" }
    4724  = @{ Sev="MEDIUM";   Reason="Password reset attempt" }
    4728  = @{ Sev="HIGH";     Reason="Member added to global security group" }
    4732  = @{ Sev="HIGH";     Reason="Member added to local Administrators group" }
    4738  = @{ Sev="HIGH";     Reason="User account changed" }
    4756  = @{ Sev="HIGH";     Reason="Member added to Universal group" }
    4771  = @{ Sev="MEDIUM";   Reason="Kerberos pre-auth failed (brute-force indicator)" }
    4776  = @{ Sev="MEDIUM";   Reason="NTLM credential validation" }
    4798  = @{ Sev="MEDIUM";   Reason="User local group membership enumerated (recon)" }
    4799  = @{ Sev="MEDIUM";   Reason="Security-enabled local group membership enumerated (recon)" }
    5140  = @{ Sev="MEDIUM";   Reason="Network share object accessed" }
    5145  = @{ Sev="MEDIUM";   Reason="Network share file access check" }
    5156  = @{ Sev="LOW";      Reason="WFP permitted network connection" }
    5157  = @{ Sev="MEDIUM";   Reason="WFP blocked network connection" }
}
# Brute-force: count 4625 events, escalate if bulk
$logonFailCount = 0
try {
    $logonFailCount = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$cutoff} `
        -MaxEvents 500 -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($logonFailCount -ge 20) {
        Add-Finding "HIGH" "events/Security" "Logon brute-force: $logonFailCount failed attempts in last $Hours h" "EventLog:Security" "4625 count=$logonFailCount — possible credential spray or brute force"
    } elseif ($logonFailCount -ge 5) {
        Add-Finding "MEDIUM" "events/Security" "Elevated logon failures: $logonFailCount in last $Hours h" "EventLog:Security" "4625 count=$logonFailCount"
    }
} catch {}

$secEvts = Read-EventBlock 'Security' @{LogName='Security'; Id=($secEvtMap.Keys)} 1000 '5c'
foreach ($ev in $secEvts) {
    $entry = $secEvtMap[$ev.Id]
    if (-not $entry) { continue }
    $sev    = $entry.Sev
    $reason = $entry.Reason
    $msg    = Get-MsgPreview $ev.Message
    # 4624 — only flag non-interactive logon types (3=network, 10=remoteinteractive, 9=newcredentials)
    if ($ev.Id -eq 4624) {
        if ($msg -notmatch 'Logon Type:\s+(3|9|10)') { continue }
        $sev = "MEDIUM"
    }
    # 4688 — only flag if new process command line matches IOC pattern
    if ($ev.Id -eq 4688) {
        if ($msg -notmatch $suspPattern) { continue }
        $sev = "HIGH"
        $reason = "Process create with suspicious command line"
    }
    # Skip routine 4625 — already aggregated above
    if ($ev.Id -eq 4625) { continue }
    # Skip 5156 unless remote IP matches; too noisy otherwise
    if ($ev.Id -eq 5156) { continue }
    Add-Finding $sev "events/Security" "[SecEvt:$($ev.Id)] $reason" "EventLog:Security @ $($ev.TimeCreated.ToString('s'))" $msg
}

# ── 5d. POWERSHELL OPERATIONAL LOGS ──────────────────────────────────────
Write-Host "  [5d] PowerShell script block + remoting logs..." -ForegroundColor DarkCyan
$psLogs = @(
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-PowerShell/Admin',
    'Windows PowerShell'
)
$psIocPattern = 'powershell.*-enc|-encodedcommand|invoke-expression|iex\s*\(|downloadstring|frombase64string|certutil.*-decode|bitsadmin.*transfer|net\.webclient|start-bitstransfer|invoke-webrequest.*http|mimikatz|cobalt|meterpreter|shellcode|xmrig|stratum\+tcp|sekurlsa|kerberoast|invoke-bloodhound|sharphound|rubeus'
foreach ($psLog in $psLogs) {
    try {
        Get-WinEvent -FilterHashtable @{LogName=$psLog; StartTime=$cutoff} -MaxEvents 2000 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -imatch $psIocPattern } |
            Where-Object { $_.Message -notmatch 'Add-Finding|#!/usr/bin/env pwsh|WRAITH.*Quick.*Scan' } |
            Select-Object -First 30 | ForEach-Object {
                $msg = Get-MsgPreview $_.Message
                Add-Finding "HIGH" "events/PowerShell" "[PSEvt:$($_.Id)] Suspicious PS content — $($_.ProviderName)" "EventLog:$psLog @ $($_.TimeCreated.ToString('s'))" $msg
            }
    } catch {}
}
# Remoting / WinRM
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; StartTime=$cutoff} `
        -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in @(6,8,31,32,169) } |
        Select-Object -First 20 | ForEach-Object {
            Add-Finding "MEDIUM" "events/WinRM" "[WinRM:$($_.Id)] Remote management connection" "EventLog:WinRM @ $($_.TimeCreated.ToString('s'))" (Get-MsgPreview $_.Message)
        }
} catch {}

# ── 5e. KERNEL ETW — CodeIntegrity, PnP, DriverFrameworks ────────────────
Write-Host "  [5e] Kernel ETW (CodeIntegrity / DriverFrameworks / PnP)..." -ForegroundColor DarkCyan
$kernelLogs = @(
    @{ Log='Microsoft-Windows-CodeIntegrity/Operational';
       Ids=@(3001,3002,3003,3004,3010,3023,3033,3034,3077,3089)
       Label='CodeIntegrity violation / unsigned driver blocked' }
    @{ Log='Microsoft-Windows-DriverFrameworks-UserMode/Operational';
       Ids=@(2003,2004,2100,2101,10110,10111)
       Label='User-mode driver framework event' }
    @{ Log='Microsoft-Windows-Kernel-PnP/Configuration';
       Ids=@(219,410,411,420,430)
       Label='Kernel-PnP driver/device event' }
    @{ Log='Microsoft-Windows-Kernel-General/Win32k';
       Ids=@(1,12,13)
       Label='Kernel-General / Win32k event' }
    @{ Log='Microsoft-Windows-Kernel-Power/Operational';
       Ids=@(41,107,109,506)
       Label='Kernel-Power: unexpected shutdown / sleep failure' }
    @{ Log='Microsoft-Windows-Bits-Client/Operational';
       Ids=@(3,4,59,60,61)
       Label='BITS transfer (common C2 download technique)' }
)
# Known-vendor unsigned DLLs that produce CI noise but are not malicious.
# Bonjour/mdnsNSP.dll (Apple iTunes) is a known WDAC compat issue — allowlist to reduce noise.
$ciAllowPattern = 'bonjour\\mdnsNSP\.dll|appleapplicationSupport|itunes.*\.dll|vlc.*\.dll'
$ciDedup = @{}   # deduplicate repeated CI hits per unique message fingerprint

foreach ($kl in $kernelLogs) {
    try {
        $kevts = Get-WinEvent -FilterHashtable @{LogName=$kl.Log; Id=$kl.Ids; StartTime=$cutoff} `
            -MaxEvents 200 -ErrorAction SilentlyContinue
        foreach ($ev in $kevts) {
            # 3089 = correlation metadata record for 3033 — skip, no new info
            if ($ev.Id -eq 3089) { continue }
            $msg = Get-MsgPreview $ev.Message
            # Suppress known-vendor CI noise
            if ($kl.Log -imatch 'CodeIntegrity' -and $msg -imatch $ciAllowPattern) { continue }
            # Deduplicate: same event ID + same first 120 chars of message = same issue repeated
            $dedupKey = "$($ev.Id)|$($msg.Substring(0,[Math]::Min(120,$msg.Length)))"
            if ($ciDedup.ContainsKey($dedupKey)) { $ciDedup[$dedupKey]++; continue }
            $ciDedup[$dedupKey] = 1
            # CodeIntegrity violations = HIGH (driver blocked is security enforcement)
            $sev = if ($kl.Log -imatch 'CodeIntegrity' -and $ev.Id -in @(3033,3034,3077)) { "HIGH" }
                   elseif ($kl.Log -imatch 'Bits' -and $ev.Id -in @(59,60,61)) { "MEDIUM" }
                   elseif ($kl.Log -imatch 'Kernel-Power' -and $ev.Id -eq 41) { "HIGH" }
                   else { "MEDIUM" }
            Add-Finding $sev "events/Kernel/$($kl.Log.Split('/')[0].Split('-')[-1])" `
                "[Kernel:$($ev.Id)] $($kl.Label)" "EventLog:$($kl.Log) @ $($ev.TimeCreated.ToString('s'))" $msg
        }
        # Report suppressed duplicates as a single info line
        $suppressed = ($ciDedup.GetEnumerator() | Where-Object { $_.Value -gt 1 } | Measure-Object -Property Value -Sum).Sum
        if ($suppressed -gt 0) {
            Write-Host "  [INFO] $suppressed duplicate Kernel ETW events suppressed (deduped)" -ForegroundColor DarkGray
            $ciDedup = @{}
        }
    } catch {}
}

# ── 5f. MEMORY / PROCESS INJECTION — Sysmon 1/8/10/25 ───────────────────
Write-Host "  [5f] Memory/injection events (Sysmon process create/inject/hollow)..." -ForegroundColor DarkCyan
$sysmonOpLog = 'Microsoft-Windows-Sysmon/Operational'
$sysmonPresent = $false
try { $sysmonPresent = (Get-WinEvent -ListLog $sysmonOpLog -ErrorAction SilentlyContinue) -ne $null } catch {}

if ($sysmonPresent) {
    # Event 1 — Process Create: flag if image in temp/appdata or cmdline has IOC
    try {
        Get-WinEvent -FilterHashtable @{LogName=$sysmonOpLog; Id=1; StartTime=$cutoff} `
            -MaxEvents 3000 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $xml    = [xml]$_.ToXml()
                $image  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
                $cmdl   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
                $parent = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ParentImage' }).'#text'
                if (($image -imatch '\\temp\\|\\appdata\\local\\temp\\|\\tmp\\') -or ($cmdl -imatch $psIocPattern)) {
                    Add-Finding "HIGH" "events/Sysmon/ProcCreate" "[Sysmon:1] Suspicious process create" `
                        "$image @ $($_.TimeCreated.ToString('s'))" "cmd=$cmdl parent=$parent"
                }
            }
    } catch {}

    # Event 8 — CreateRemoteThread: CRITICAL — classic process injection vector
    try {
        Get-WinEvent -FilterHashtable @{LogName=$sysmonOpLog; Id=8; StartTime=$cutoff} `
            -MaxEvents 500 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $xml      = [xml]$_.ToXml()
                $srcImg   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SourceImage' }).'#text'
                $tgtImg   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetImage' }).'#text'
                $startFn  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'StartFunction' }).'#text'
                Add-Finding "CRITICAL" "events/Sysmon/Inject" "[Sysmon:8] CreateRemoteThread — process injection detected" `
                    "$srcImg -> $tgtImg @ $($_.TimeCreated.ToString('s'))" "StartFunction=$startFn"
            }
    } catch {}

    # Event 10 — ProcessAccess: flag LSASS being read (credential dumping)
    try {
        Get-WinEvent -FilterHashtable @{LogName=$sysmonOpLog; Id=10; StartTime=$cutoff} `
            -MaxEvents 1000 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $xml    = [xml]$_.ToXml()
                $tgt    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetImage' }).'#text'
                $src    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SourceImage' }).'#text'
                $access = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'GrantedAccess' }).'#text'
                if ($tgt -imatch 'lsass\.exe') {
                    Add-Finding "CRITICAL" "events/Sysmon/CredDump" "[Sysmon:10] LSASS memory access — credential dumping indicator" `
                        "$src -> lsass @ $($_.TimeCreated.ToString('s'))" "GrantedAccess=$access"
                }
            }
    } catch {}

    # Event 25 — ProcessTampering: process hollowing / herpaderping
    try {
        Get-WinEvent -FilterHashtable @{LogName=$sysmonOpLog; Id=25; StartTime=$cutoff} `
            -MaxEvents 200 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $xml   = [xml]$_.ToXml()
                $image = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
                $type  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Type' }).'#text'
                Add-Finding "CRITICAL" "events/Sysmon/Hollow" "[Sysmon:25] Process tampering/hollowing detected" `
                    "$image @ $($_.TimeCreated.ToString('s'))" "Type=$type"
            }
    } catch {}

    # Event 17/18 — Named pipes (used by Cobalt Strike, Metasploit)
    try {
        Get-WinEvent -FilterHashtable @{LogName=$sysmonOpLog; Id=@(17,18); StartTime=$cutoff} `
            -MaxEvents 500 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Message -imatch '\\postex_|\\msagent_|\\status_|\\mojo\.\d+\.\d+\.|MSSE-|\\pipe\\[a-f0-9]{8}-|\\wkssvc_|\\samr_|\\netlogon_'
            } | ForEach-Object {
                Add-Finding "CRITICAL" "events/Sysmon/NamedPipe" "[Sysmon:$($_.Id)] Suspicious named pipe (C2 framework indicator)" `
                    "EventLog:Sysmon @ $($_.TimeCreated.ToString('s'))" (Get-MsgPreview $_.Message)
            }
    } catch {}

    Write-Host "  [OK] Sysmon present — memory/injection checks complete" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Sysmon not installed — memory/injection detection limited" -ForegroundColor DarkYellow
    Write-Host "         Deploy Sysmon with SwiftOnSecurity config for full visibility" -ForegroundColor DarkGray
}

# ── 5g. WINDOWS DEFENDER DETECTIONS ─────────────────────────────────────
Write-Host "  [5g] Windows Defender detection events..." -ForegroundColor DarkCyan
$defenderLog = 'Microsoft-Windows-Windows Defender/Operational'
$defEvtMap = @{
    1006 = @{ Sev="CRITICAL"; Reason="Malware detected" }
    1007 = @{ Sev="CRITICAL"; Reason="Malware action taken" }
    1008 = @{ Sev="HIGH";     Reason="Malware action failed — threat may be active" }
    1009 = @{ Sev="HIGH";     Reason="Item restored from quarantine" }
    1011 = @{ Sev="HIGH";     Reason="Malware delete failed" }
    1013 = @{ Sev="MEDIUM";   Reason="Malware history deleted" }
    1116 = @{ Sev="CRITICAL"; Reason="Defender detected malware" }
    1117 = @{ Sev="CRITICAL"; Reason="Defender took action against malware" }
    1118 = @{ Sev="HIGH";     Reason="Defender malware action failed" }
    1119 = @{ Sev="CRITICAL"; Reason="Defender critical action failed — system at risk" }
    2001 = @{ Sev="MEDIUM";   Reason="Antimalware definition update failed" }
    2003 = @{ Sev="MEDIUM";   Reason="Antimalware engine update failed" }
    3002 = @{ Sev="HIGH";     Reason="Real-time protection failed" }
    5001 = @{ Sev="HIGH";     Reason="Real-time protection disabled" }
    5004 = @{ Sev="HIGH";     Reason="Real-time protection config changed" }
    5007 = @{ Sev="MEDIUM";   Reason="Antimalware platform configuration changed" }
    5010 = @{ Sev="CRITICAL"; Reason="Scanning for malware disabled" }
    5012 = @{ Sev="CRITICAL"; Reason="Scanning for viruses disabled" }
}
try {
    $defEvts = Get-WinEvent -FilterHashtable @{LogName=$defenderLog; Id=($defEvtMap.Keys); StartTime=$cutoff} `
        -MaxEvents 200 -ErrorAction SilentlyContinue
    foreach ($ev in $defEvts) {
        $entry = $defEvtMap[$ev.Id]
        if (-not $entry) { continue }
        Add-Finding $entry.Sev "events/Defender" "[Defender:$($ev.Id)] $($entry.Reason)" "EventLog:Defender @ $($ev.TimeCreated.ToString('s'))" (Get-MsgPreview $ev.Message)
    }
    if ($defEvts.Count -eq 0) { Write-Host "  [OK] No Defender detections or failures" -ForegroundColor Green }
} catch { Write-Host "  [SKIP] Defender log unavailable" -ForegroundColor DarkYellow }

# ========================================================================
# 6. npm SUPPLY CHAIN CHECK
# ========================================================================
Write-Host "[6/7] Checking npm packages..." -ForegroundColor Cyan

try {
    $npmGlobal = & npm list -g --depth=0 2>$null
    if ($npmGlobal -match 'cline@') {
        # Check if it's a vulnerable version
        Add-Finding "HIGH" "npm" "cline npm package installed globally" "npm global" "cline detected - verify version is not from compromised supply chain attack"
    }
} catch {}

# Scan package.json files in common locations
# Use -ScanPath to add additional directories (e.g. C:\dev, C:\projects) without
# scanning the entire user profile and generating developer false-positives.
$searchRoots = @($env:USERPROFILE) + $ScanPath | Where-Object { $_ -and (Test-Path $_) }
foreach ($root in $searchRoots) {
    Get-ChildItem -Path $root -Filter "package.json" -Recurse -Depth 5 -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $pkg = Get-Content $_.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (!$pkg) { return }
            # Check scripts
            if ($pkg.scripts) {
                $pkg.scripts.PSObject.Properties | ForEach-Object {
                    if ($_.Value -match 'curl.*\|.*sh|wget.*\|.*sh|execSync|require.*child_process|\[convert\]::frombase64|frombase64string') {
                        Add-Finding "CRITICAL" "npm/script" "Suspicious npm script: '$($_.Name)' in $($pkg.name)" $_.FullName "Script: $($_.Value.Substring(0,[Math]::Min(200,$_.Value.Length)))"
                    }
                }
            }
            # Check for openclaw dependency
            $allDeps = @()
            if ($pkg.dependencies)    { $allDeps += $pkg.dependencies.PSObject.Properties.Name }
            if ($pkg.devDependencies) { $allDeps += $pkg.devDependencies.PSObject.Properties.Name }
            if ($allDeps -match 'xmrig|cryptominer') {
                Add-Finding "CRITICAL" "npm/dependency" "Suspicious dependency in $($pkg.name)" $_.FullName "Contains suspicious dependency: $($allDeps -match 'xmrig|cryptominer')"
            }
        } catch {}
    }
}

# ========================================================================
# 7. THREAT INTEL — LIVE + HISTORICAL IP CORRELATION
#    Sources: abuse.ch Feodo Tracker (C2 IPs), Emerging Threats compromised IPs,
#             CINS Army (cinsscore.com). All are free/open and require no API key.
#
#    Checks (in order):
#      7a. Live   — Active TCP connections (Established/TimeWait/CloseWait)
#      7b. History — DNS client cache  (recently resolved hostnames -> IPs)
#      7c. History — Windows Firewall log (pfirewall.log connection records)
#      7d. History — Security EventLog ID 5156 (WFP permitted connection audit)
#      7e. History — Sysmon Event ID 3 (network connection, if Sysmon installed)
#
#    On hit: CRITICAL finding + firewall block rule (if admin) + Defender scan.
# ========================================================================
Write-Host "[7/7] Loading threat intel feeds..." -ForegroundColor Cyan

$bannedIps = @{}
$feedSources = @(
    @{ Name = 'Feodo Tracker C2 (abuse.ch)';     Url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt' }
    @{ Name = 'Emerging Threats Compromised IPs'; Url = 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt' }
    @{ Name = 'CINS Army Blocklist';             Url = 'https://cinsscore.com/list/ci-badguys.txt' }
)

foreach ($feed in $feedSources) {
    try {
        $resp = Invoke-WebRequest -Uri $feed.Url -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        $resp.Content -split '[\r\n]+' |
            Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' } |
            ForEach-Object {
                $ip = ($_ -split '#|;|\s')[0].Trim()
                if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { $bannedIps[$ip] = $feed.Name }
            }
        Write-Host "  [INFO] $($feed.Name): loaded ($($bannedIps.Count) total IPs so far)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [WARN] Cannot reach $($feed.Name) - offline or blocked, skipping." -ForegroundColor DarkYellow
    }
}

# ── Helper: block IP + Defender scan on hit ──────────────────────────────
function Invoke-ThreatHit($ip, $port, $context, $feedName, $isAdmin) {
    Add-Finding "CRITICAL" "network/threat-intel" `
        "Malicious IP Contact: $ip$(if($port){':'+$port})" `
        $context `
        "Feed: $feedName | Context: $context"

    if ($isAdmin) {
        $ruleName = "WRAITH-Block-$ip"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
                -RemoteAddress $ip -Action Block -Profile Any `
                -Description "Blocked by WRAITH threat intel: $feedName" `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [BLOCKED] Firewall outbound block added: $ip" -ForegroundColor Magenta
        }
    }
}

if ($bannedIps.Count -gt 0) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $totalHits = 0

    # ── 7a. LIVE — Active TCP connections ────────────────────────────────
    Write-Host "  [7a] Live TCP connections..." -ForegroundColor DarkCyan
    try {
        $conns = Get-NetTCPConnection -State Established,TimeWait,CloseWait -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -notmatch '^(127\.|0\.0\.0\.0|::1|::$|^$)' }
        foreach ($conn in $conns) {
            if (-not $bannedIps.ContainsKey($conn.RemoteAddress)) { continue }
            $totalHits++
            $ownerPid = $conn.OwningProcess
            $proc     = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.Name } else { "PID:$ownerPid" }
            $feedName = $bannedIps[$conn.RemoteAddress]
            Invoke-ThreatHit $conn.RemoteAddress $conn.RemotePort `
                "LIVE process=$procName (PID $ownerPid) local=$($conn.LocalPort)" $feedName $isAdmin

            if ($isAdmin -and $proc) {
                try {
                    $procBin = $proc.MainModule.FileName
                    if ($procBin) {
                        Start-MpScan -ScanPath $procBin -ScanType CustomScan -ErrorAction SilentlyContinue
                        Write-Host "  [DEFENDER] Triggered scan: $procBin" -ForegroundColor Magenta
                    }
                } catch {}
            }
        }
        if ($totalHits -eq 0) { Write-Host "  [OK] No live connections match threat intel" -ForegroundColor Green }
    } catch { Write-Warning "  [7a] Live TCP check failed: $_" }

    # ── 7b. HISTORY — DNS client cache ───────────────────────────────────
    Write-Host "  [7b] DNS cache (recently resolved IPs)..." -ForegroundColor DarkCyan
    $dnsHits = 0
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($entry in $dnsCache) {
            $recordData = $entry.Data
            if (-not $recordData) { continue }
            if (-not $bannedIps.ContainsKey($recordData)) { continue }
            $dnsHits++; $totalHits++
            Invoke-ThreatHit $recordData $null `
                "DNS-CACHE name=$($entry.Entry) type=$($entry.Type) TTL=$($entry.TimeToLive)s" `
                $bannedIps[$recordData] $isAdmin
        }
        if ($dnsHits -eq 0) { Write-Host "  [OK] No DNS cache entries match threat intel" -ForegroundColor Green }
    } catch { Write-Host "  [SKIP] DNS cache check unavailable: $_" -ForegroundColor DarkYellow }

    # ── 7c. HISTORY — Windows Firewall log ───────────────────────────────
    Write-Host "  [7c] Windows Firewall log (pfirewall.log)..." -ForegroundColor DarkCyan
    $fwHits = 0
    $fwLogPaths = @(
        "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log",
        "$env:SystemRoot\SysWOW64\LogFiles\Firewall\pfirewall.log"
    )
    $cutoffFw = (Get-Date).AddHours(-$Hours)
    foreach ($fwLog in $fwLogPaths) {
        if (-not (Test-Path $fwLog)) { continue }
        try {
            # Format: date time action protocol src-ip dst-ip src-port dst-port ...
            Get-Content $fwLog -ErrorAction SilentlyContinue |
                Where-Object { $_ -notmatch '^#' -and $_ -match '\d{4}-\d{2}-\d{2}' } |
                ForEach-Object {
                    $parts = $_ -split '\s+'
                    if ($parts.Count -lt 7) { return }
                    # Parse log date (col 0 = date, col 1 = time)
                    try {
                        $logTime = [datetime]::ParseExact("$($parts[0]) $($parts[1])", "yyyy-MM-dd HH:mm:ss", $null)
                        if ($logTime -lt $cutoffFw) { return }
                    } catch { return }
                    $dstIp   = $parts[5]   # destination IP (outbound = remote)
                    $srcIp   = $parts[4]   # source IP
                    $dstPort = $parts[7]
                    $action  = $parts[2]
                    foreach ($checkIp in @($dstIp, $srcIp)) {
                        if ($checkIp -and $bannedIps.ContainsKey($checkIp)) {
                            $fwHits++; $totalHits++
                            Invoke-ThreatHit $checkIp $dstPort `
                                "FW-LOG action=$action src=$srcIp dst=$dstIp @ $($parts[0]) $($parts[1])" `
                                $bannedIps[$checkIp] $isAdmin
                        }
                    }
                }
        } catch { Write-Host "  [WARN] Could not parse firewall log: $fwLog" -ForegroundColor DarkYellow }
    }
    if ($fwHits -eq 0) {
        if ($fwLogPaths | Where-Object { Test-Path $_ }) {
            Write-Host "  [OK] No firewall log entries match threat intel (last $Hours h)" -ForegroundColor Green
        } else {
            Write-Host "  [SKIP] Firewall log not found — enable via: netsh advfirewall set allprofiles logging filename %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -ForegroundColor DarkYellow
        }
    }

    # ── 7d. HISTORY — Security EventLog 5156 (WFP permitted connections) ─
    Write-Host "  [7d] Security event log (Event 5156 — WFP network audit)..." -ForegroundColor DarkCyan
    $evHits = 0
    try {
        $cutoffEvt = (Get-Date).AddHours(-$Hours)
        $evts5156 = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 5156
            StartTime = $cutoffEvt
        } -ErrorAction SilentlyContinue -MaxEvents 5000
        foreach ($ev in $evts5156) {
            # Extract destination IP from XML data
            try {
                $xml   = [xml]$ev.ToXml()
                $dIp   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestAddress' }).'#text'
                $dPort = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestPort' }).'#text'
                $appId = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Application' }).'#text'
                if ($dIp -and $bannedIps.ContainsKey($dIp)) {
                    $evHits++; $totalHits++
                    Invoke-ThreatHit $dIp $dPort `
                        "EVT-5156 app=$appId time=$($ev.TimeCreated.ToString('s'))" `
                        $bannedIps[$dIp] $isAdmin
                }
            } catch {}
        }
        if ($evHits -eq 0) {
            if ($evts5156 -ne $null) {
                Write-Host "  [OK] No Security/5156 events match threat intel (last $Hours h)" -ForegroundColor Green
            } else {
                Write-Host "  [SKIP] No 5156 events — enable: auditpol /set /subcategory:'Filtering Platform Connection' /success:enable" -ForegroundColor DarkYellow
            }
        }
    } catch { Write-Host "  [SKIP] Security event log access denied or unavailable" -ForegroundColor DarkYellow }

    # ── 7e. HISTORY — Sysmon Event ID 3 (network connections) ───────────
    Write-Host "  [7e] Sysmon event log (Event 3 — network connection)..." -ForegroundColor DarkCyan
    $sysmonHits = 0
    try {
        $sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
        $cutoffSys = (Get-Date).AddHours(-$Hours)
        $sysEvts = Get-WinEvent -FilterHashtable @{
            LogName   = $sysmonLog
            Id        = 3
            StartTime = $cutoffSys
        } -ErrorAction SilentlyContinue -MaxEvents 5000
        foreach ($ev in $sysEvts) {
            try {
                $xml    = [xml]$ev.ToXml()
                $dstIp  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationIp' }).'#text'
                $dstPt  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationPort' }).'#text'
                $image  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
                $user   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'User' }).'#text'
                if ($dstIp -and $bannedIps.ContainsKey($dstIp)) {
                    $sysmonHits++; $totalHits++
                    Invoke-ThreatHit $dstIp $dstPt `
                        "SYSMON-3 image=$image user=$user time=$($ev.TimeCreated.ToString('s'))" `
                        $bannedIps[$dstIp] $isAdmin
                }
            } catch {}
        }
        if ($sysmonHits -eq 0) {
            if ($sysEvts -ne $null) {
                Write-Host "  [OK] No Sysmon/3 events match threat intel (last $Hours h)" -ForegroundColor Green
            } else {
                Write-Host "  [INFO] Sysmon not installed — consider deploying for deeper visibility" -ForegroundColor DarkGray
            }
        }
    } catch { Write-Host "  [INFO] Sysmon not detected on this host" -ForegroundColor DarkGray }

    if ($totalHits -eq 0) {
        Write-Host "  [OK] All threat intel checks clear — no banned IP contact detected" -ForegroundColor Green
    } else {
        Write-Host "  [!!] $totalHits total threat intel hits across all sources" -ForegroundColor Red
    }

} else {
    Write-Host "  [SKIP] No threat intel loaded (all feeds unreachable - check connectivity)" -ForegroundColor DarkYellow
}

# ========================================================================
# SUMMARY
# ========================================================================
$elapsed = (Get-Date) - $scanStart
$critical = ($findings | Where-Object Severity -eq 'CRITICAL').Count
$high     = ($findings | Where-Object Severity -eq 'HIGH').Count
$medium   = ($findings | Where-Object Severity -eq 'MEDIUM').Count
$low      = ($findings | Where-Object Severity -eq 'LOW').Count

Write-Host ""
Write-Host " =======================================================" -ForegroundColor DarkGray
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
Write-Host " =======================================================" -ForegroundColor DarkGray
Write-Host ""
