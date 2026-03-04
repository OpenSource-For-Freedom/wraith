"""
WRAITH - Windows Event Log Parser
Scans Security, System, Application, and PowerShell logs
for indicators of compromise.
"""

import sys
import os
import datetime
from typing import List, Dict, Any

try:
    import win32evtlog
    import win32con
    import win32evtlogutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

try:
    import subprocess
    SUBPROCESS_AVAILABLE = True
except ImportError:
    SUBPROCESS_AVAILABLE = False

# ── Event ID mappings (Windows Security / Sysmon style) ─────────────────
CRITICAL_EVENT_IDS = {
    # Security log
    4624: ("Logon Success",           "INFO",    "Account logged on"),
    4625: ("Failed Logon",            "MEDIUM",  "Failed login attempt"),
    4648: ("Explicit Credential Use", "HIGH",    "Logon with explicit credentials (pass-the-hash?)"),
    4672: ("Special Privileges",      "MEDIUM",  "Admin privileges assigned at logon"),
    4688: ("New Process Created",     "LOW",     "Process creation event"),
    4697: ("Service Installed",       "HIGH",    "New service installed on system"),
    4698: ("Schtask Created",         "HIGH",    "Scheduled task created"),
    4699: ("Schtask Deleted",         "MEDIUM",  "Scheduled task deleted"),
    4700: ("Schtask Enabled",         "MEDIUM",  "Scheduled task enabled"),
    4702: ("Schtask Modified",        "MEDIUM",  "Scheduled task modified"),
    4720: ("Account Created",         "HIGH",    "New user account created"),
    4732: ("Group Membership Change", "HIGH",    "User added to local admin group"),
    4756: ("Group Membership Change", "HIGH",    "User added to universal group"),
    1102: ("Audit Log Cleared",       "CRITICAL","Security audit log was cleared — common attacker technique"),
    4104: ("PS Script Block",         "MEDIUM",  "PowerShell script block logging"),
    4103: ("PS Module Logging",       "MEDIUM",  "PowerShell module logging"),
    # System log
    7045: ("Service Installed",       "HIGH",    "New service installed"),
    7040: ("Service Start Changed",   "MEDIUM",  "Service start type changed"),
    7034: ("Service Crashed",         "LOW",     "Service terminated unexpectedly"),
    # Application log
    1000: ("App Crash",               "LOW",     "Application crash"),
    1001: ("WER Report",              "LOW",     "Windows Error Reporting"),
    # PowerShell / WMI
    400:  ("PS Engine State",         "MEDIUM",  "PowerShell engine started"),
    403:  ("PS Engine Stopped",       "LOW",     "PowerShell engine stopped"),
    800:  ("PS Pipeline Exec",        "MEDIUM",  "PowerShell pipeline execution"),
}

# Suspicious keywords to look for in event messages
SUSPICIOUS_MESSAGE_KEYWORDS = [
    "openclaw", "metaquest", "oculus", "ovrservice", "airlink",
    "powershell -e", "powershell -enc", "encoded",
    "invoke-expression", "iex", "downloadstring", "webclient",
    "mshta", "wscript", "cscript", "regsvr32 /s /u",
    "certutil -decode", "bitsadmin /transfer",
    "mimikatz", "sekurlsa", "lsadump", "hashdump",
    "cobalt strike", "beacon", "meterpreter",
    "base64", "frombase64", "-nop -w hidden",
    "sc create", "schtasks /create",
    "netsh advfirewall", "wmic process call create",
    "npm install", "node_modules", "cline", "package.json",
    "curl.*pipe.*bash", "wget.*pipe.*sh",
]

LOG_NAMES = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational",
]


def _keyword_check(msg: str) -> tuple[bool, str]:
    msg_lower = msg.lower()
    for kw in SUSPICIOUS_MESSAGE_KEYWORDS:
        if kw in msg_lower:
            return True, kw
    return False, ""


def scan_events_win32(hours: int) -> List[Dict]:
    findings = []
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)

    for log_name in LOG_NAMES:
        try:
            server = None
            hand = win32evtlog.OpenEventLog(server, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for ev in events:
                    # Time filter
                    ev_time = ev.TimeGenerated
                    if hasattr(ev_time, 'timestamp'):
                        ev_dt = datetime.datetime.fromtimestamp(ev_time.timestamp())
                    else:
                        ev_dt = datetime.datetime.now()

                    if ev_dt < cutoff:
                        break  # events are in reverse order, stop when past cutoff

                    ev_id = ev.EventID & 0xFFFF
                    source = ev.SourceName
                    computer = ev.ComputerName

                    # Get event info
                    info = CRITICAL_EVENT_IDS.get(ev_id)

                    try:
                        msg = win32evtlogutil.SafeFormatMessage(ev, log_name)
                    except Exception:
                        msg = str(ev.StringInserts) if ev.StringInserts else ""

                    # Check for suspicious keywords in message
                    suspicious, kw = _keyword_check(msg or "")

                    if info and info[1] in ("HIGH", "CRITICAL"):
                        findings.append({
                            "category": "events",
                            "subcategory": log_name.split("/")[0].replace("Microsoft-Windows-",""),
                            "severity": info[1],
                            "title": f"[ID:{ev_id}] {info[0]} - {source}",
                            "path": f"EventLog:{log_name}",
                            "event_id": ev_id,
                            "log": log_name,
                            "source": source,
                            "computer": computer,
                            "time": str(ev_dt),
                            "message_preview": (msg or "")[:300],
                            "reason": info[2]
                        })
                    elif suspicious:
                        findings.append({
                            "category": "events",
                            "subcategory": "suspicious_keyword",
                            "severity": "HIGH",
                            "title": f"[ID:{ev_id}] Suspicious Keyword in Event: '{kw}'",
                            "path": f"EventLog:{log_name}",
                            "event_id": ev_id,
                            "log": log_name,
                            "source": source,
                            "computer": computer,
                            "time": str(ev_dt),
                            "message_preview": (msg or "")[:300],
                            "reason": f"Event message contains suspicious keyword: '{kw}'"
                        })

            win32evtlog.CloseEventLog(hand)

        except Exception as ex:
            findings.append({
                "category": "events",
                "subcategory": "error",
                "severity": "INFO",
                "title": f"Event log scan error: {log_name}",
                "path": f"EventLog:{log_name}",
                "reason": str(ex)
            })

    return findings


def scan_events_powershell(hours: int) -> List[Dict]:
    """Fallback: use PowerShell Get-WinEvent if win32 not available."""
    findings = []
    ps_cmd = f"""
$cutoff = (Get-Date).AddHours(-{hours})
$logs = @('Security','System','Application','Microsoft-Windows-PowerShell/Operational',
          'Microsoft-Windows-TaskScheduler/Operational')
$criticalIds = @(4697,4698,4720,4732,1102,7045,4648,4104)
$results = @()
foreach ($log in $logs) {{
    try {{
        $events = Get-WinEvent -LogName $log -ErrorAction SilentlyContinue |
            Where-Object {{ $_.TimeCreated -gt $cutoff -and
                ($criticalIds -contains $_.Id -or
                 $_.Message -match 'openclaw|metaquest|powershell.*-enc|mimikatz|invoke-expression|downloadstring|certutil.*decode|base64|cline|npm.*install') }} |
            Select-Object Id,LevelDisplayName,TimeCreated,ProviderName,Message -First 200
        foreach ($e in $events) {{
            $obj = [PSCustomObject]@{{
                Id=$e.Id; Level=$e.LevelDisplayName; Time=$e.TimeCreated.ToString('s');
                Provider=$e.ProviderName; Log=$log;
                Msg=($e.Message -replace '[\\r\\n]+',' ').Substring(0,[Math]::Min(300,$e.Message.Length))
            }}
            $results += $obj
        }}
    }} catch {{}}
}}
$results | ConvertTo-Json -Depth 2
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout.strip():
            import json
            events_raw = json.loads(result.stdout)
            if isinstance(events_raw, dict):
                events_raw = [events_raw]
            for ev in events_raw:
                ev_id = ev.get("Id", 0)
                info = CRITICAL_EVENT_IDS.get(ev_id, ("Event", "MEDIUM", "Notable event"))
                msg = ev.get("Msg","")
                suspicious, kw = _keyword_check(msg)
                findings.append({
                    "category": "events",
                    "subcategory": ev.get("Log",""),
                    "severity": "CRITICAL" if suspicious and kw in ("openclaw","metaquest","mimikatz") else info[1],
                    "title": f"[ID:{ev_id}] {info[0]} - {ev.get('Provider','')}",
                    "path": f"EventLog:{ev.get('Log','')}",
                    "event_id": ev_id,
                    "log": ev.get("Log",""),
                    "source": ev.get("Provider",""),
                    "time": ev.get("Time",""),
                    "message_preview": msg[:300],
                    "reason": f"Keyword match: '{kw}'" if suspicious else info[2]
                })
    except Exception as ex:
        findings.append({
            "category": "events", "subcategory": "error",
            "severity": "INFO", "title": "PowerShell event scan error",
            "path": "EventLog", "reason": str(ex)
        })
    return findings


def scan_events(hours: int = 72) -> Dict[str, Any]:
    if WIN32_AVAILABLE:
        findings = scan_events_win32(hours)
    else:
        findings = scan_events_powershell(hours)

    return {
        "module": "events",
        "hours_back": hours,
        "findings_count": len(findings),
        "findings": findings
    }
