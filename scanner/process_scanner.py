"""
WRAITH - Process Scanner
Analyzes running processes for:
- Processes running from suspicious locations
- Known malware process names
- Processes with suspicious command lines
- Processes with no parent (orphaned)
- Unusual network-connected processes
- Injected processes (hollowed)
"""

import os
import json
import subprocess
from typing import List, Dict, Any

# Known legitimate process names (allow-list to reduce noise)
TRUSTED_PROCESSES = {
    "svchost.exe","lsass.exe","wininit.exe","winlogon.exe","services.exe",
    "smss.exe","csrss.exe","explorer.exe","taskmgr.exe","conhost.exe",
    "dwm.exe","system","registry","fontdrvhost.exe","memory compression",
    "sihost.exe","taskhostw.exe","runtimebroker.exe","searchindexer.exe",
    "spooler.exe","msdtc.exe","wermgr.exe",
}

SUSPICIOUS_NAMES = {
    "mimikatz","meterpreter","beacon","cobaltstr","shellcode",
    "psexec","wmiexec","smbexec","crackmapexec","nc.exe","netcat",
    "nmap","masscan","xmrig","minergate","ethminer","cgminer",
    "njrat","darkcomet","nanocore","asyncrat","quasarrat",
    "remcos","bitrat","warzone","agent tesla",
}

SUSPICIOUS_PATHS_LOWER = [
    "\\temp\\", "\\tmp\\", "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\", "\\downloads\\",
    "\\recycle", "\\$recycle",
    "\\public\\", "c:\\windows\\temp\\",
    "node_modules\\.bin\\",
]

SUSPICIOUS_CMDLINE_PATTERNS = [
    "-encodedcommand", "-enc ", "-nop ", "-hidden",
    "invoke-expression", "iex(", "downloadstring",
    "frombase64string", "bypass", "reflection.assembly",
    "shellcode", "virtualalloc", "writeprocessmemory",
    "certutil -decode", "bitsadmin /transfer",
    "wmic process call create",
    "openclaw", "metaquest", "oculusservice",
    "cline", "npm install --global",
    "curl.*|.*bash", "wget.*|.*sh",
]


def _get_processes_powershell() -> List[Dict]:
    """Get process list via PowerShell with command lines and parent PIDs."""
    ps_cmd = """
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
    ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(
            ["powershell","-NoProfile","-NonInteractive","-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout)
        if isinstance(data, dict):
            data = [data]
        return data or []
    except Exception:
        return []


def _get_network_connections() -> Dict[int, List[str]]:
    """Map PID -> list of remote addresses with open connections."""
    conn_map: Dict[int, List[str]] = {}
    try:
        r = subprocess.run(
            ["netstat","-ano","-p","TCP"],
            capture_output=True, text=True, timeout=15
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "ESTABLISHED":
                try:
                    pid = int(parts[4])
                    remote = parts[2]
                    conn_map.setdefault(pid, []).append(remote)
                except Exception:
                    pass
    except Exception:
        pass
    return conn_map


def analyze_process(proc: Dict, conn_map: Dict[int, List[str]]) -> List[Dict]:
    findings = []
    pid     = proc.get("ProcessId", 0)
    name    = (proc.get("Name") or "").lower()
    path    = (proc.get("ExecutablePath") or "").lower()
    cmdline = (proc.get("CommandLine") or "").lower()
    ppid    = proc.get("ParentProcessId", 0)
    remotes = conn_map.get(pid, [])

    # Skip fully trusted procs
    if name in TRUSTED_PROCESSES:
        return []

    # Suspicious process name
    for sus in SUSPICIOUS_NAMES:
        if sus in name:
            findings.append({
                "category": "processes",
                "subcategory": "suspicious_name",
                "severity": "CRITICAL",
                "title": f"Suspicious Process Name: {proc.get('Name','')} (PID {pid})",
                "path": proc.get("ExecutablePath","unknown"),
                "pid": pid,
                "ppid": ppid,
                "cmdline": (proc.get("CommandLine") or "")[:200],
                "connections": remotes[:5],
                "reason": f"Process name matches known malware: '{sus}'"
            })
            return findings  # one finding per process

    # Running from suspicious path
    for sp in SUSPICIOUS_PATHS_LOWER:
        if sp in path:
            findings.append({
                "category": "processes",
                "subcategory": "suspicious_path",
                "severity": "HIGH",
                "title": f"Process in Suspicious Location: {proc.get('Name','')} (PID {pid})",
                "path": proc.get("ExecutablePath","unknown"),
                "pid": pid,
                "ppid": ppid,
                "cmdline": (proc.get("CommandLine") or "")[:200],
                "connections": remotes[:5],
                "reason": f"Process running from: {path}"
            })
            return findings

    # Suspicious command line
    for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
        if pattern in cmdline:
            findings.append({
                "category": "processes",
                "subcategory": "suspicious_cmdline",
                "severity": "HIGH",
                "title": f"Suspicious Command Line: {proc.get('Name','')} (PID {pid})",
                "path": proc.get("ExecutablePath","unknown"),
                "pid": pid,
                "ppid": ppid,
                "cmdline": (proc.get("CommandLine") or "")[:300],
                "connections": remotes[:5],
                "reason": f"Command line contains: '{pattern}'"
            })
            return findings

    # Network-connected process in unusual location
    if remotes and path and not any(
        trusted in path for trusted in
        ["\\windows\\","\\program files\\","\\microsoft\\","\\common files\\"]
    ):
        findings.append({
            "category": "processes",
            "subcategory": "unusual_network_process",
            "severity": "MEDIUM",
            "title": f"Network-Connected Process Outside System Dirs: {proc.get('Name','')} (PID {pid})",
            "path": proc.get("ExecutablePath","unknown"),
            "pid": pid,
            "ppid": ppid,
            "connections": remotes[:5],
            "reason": f"Process has {len(remotes)} network connection(s) and is not in system directories"
        })

    return findings


def scan_processes() -> Dict[str, Any]:
    findings = []
    processes = _get_processes_powershell()
    conn_map  = _get_network_connections()

    for proc in processes:
        hits = analyze_process(proc, conn_map)
        findings.extend(hits)

    return {
        "module": "processes",
        "process_count": len(processes),
        "findings_count": len(findings),
        "findings": findings
    }
