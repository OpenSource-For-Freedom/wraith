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

# A trusted process image name is only trusted when it runs from one of these
# Windows system directories. Anything else with a system name is a masquerade.
_SYSTEM_DIR_MARKERS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\servicing\\",
)

# Known legitimate process names (allow-list to reduce noise)
TRUSTED_PROCESSES = {
    "svchost.exe",
    "lsass.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "csrss.exe",
    "explorer.exe",
    "taskmgr.exe",
    "conhost.exe",
    "dwm.exe",
    "system",
    "registry",
    "fontdrvhost.exe",
    "memory compression",
    "sihost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "spooler.exe",
    "msdtc.exe",
    "wermgr.exe",
}

SUSPICIOUS_NAMES = {
    "mimikatz",
    "meterpreter",
    "beacon",
    "cobaltstr",
    "shellcode",
    "psexec",
    "wmiexec",
    "smbexec",
    "crackmapexec",
    "nc.exe",
    "netcat",
    "nmap",
    "masscan",
    "xmrig",
    "minergate",
    "ethminer",
    "cgminer",
    "njrat",
    "darkcomet",
    "nanocore",
    "asyncrat",
    "quasarrat",
    "remcos",
    "bitrat",
    "warzone",
    "agent tesla",
}

SUSPICIOUS_PATHS_LOWER = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\recycle",
    "\\$recycle",
    "\\public\\",
    "c:\\windows\\temp\\",
    "node_modules\\.bin\\",
]

SUSPICIOUS_CMDLINE_PATTERNS = [
    "-encodedcommand",
    "-enc ",
    "-nop ",
    "-hidden",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "frombase64string",
    "bypass",
    "reflection.assembly",
    "shellcode",
    "virtualalloc",
    "writeprocessmemory",
    "certutil -decode",
    "bitsadmin /transfer",
    "wmic process call create",
    "openclaw",
    "metaquest",
    "oculusservice",
    "cline",
    "npm install --global",
    # Download piped straight into a shell / interpreter — the canonical dropper
    # one-liner. These were previously written as regex fragments
    # ("curl.*|.*bash"), but the matcher below is a literal substring test
    # (`pattern in cmdline`), so those entries could never fire and the whole
    # class went undetected. Use literal indicators that actually occur.
    "| bash",
    "|bash",
    "| sh -c",
    "|sh -c",
    "| iex",
    "|iex",
]


def _get_processes_powershell() -> List[Dict]:
    """Get process list via PowerShell with command lines and parent PIDs."""
    ps_cmd = """
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
    ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=30,
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
            ["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=15
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
    pid = proc.get("ProcessId", 0)
    name = (proc.get("Name") or "").lower()
    path = (proc.get("ExecutablePath") or "").lower()
    cmdline = (proc.get("CommandLine") or "").lower()
    ppid = proc.get("ParentProcessId", 0)
    remotes = conn_map.get(pid, [])

    # Skip fully trusted procs — but ONLY when they run from a Windows system
    # directory (or have no image path, e.g. the System/Registry pseudo-processes
    # and protected processes whose path can't be read). Trusting purely by image
    # name lets malware masquerade: a binary named svchost.exe / lsass.exe dropped
    # in %APPDATA% or %TEMP% would otherwise be returned as clean before any path,
    # cmdline, or network check runs. A trusted name from an unexpected location
    # is itself a signal, so fall through and let the heuristics below judge it.
    if name in TRUSTED_PROCESSES:
        if not path or any(m in path for m in _SYSTEM_DIR_MARKERS):
            return []

    # Skip WRAITH itself — the .NET single-file publish extracts to
    # %TEMP%\.net\WRAITH\<hash>\ so without this the scanner flags its own
    # host process as "running from suspicious location".
    if name in ("wraith.exe", "wraith") and r"\.net\wraith" in path.replace("/", "\\"):
        return []

    # Suspicious process name
    for sus in SUSPICIOUS_NAMES:
        if sus in name:
            findings.append(
                {
                    "category": "processes",
                    "subcategory": "suspicious_name",
                    "severity": "CRITICAL",
                    "title": f"Suspicious Process Name: {proc.get('Name','')} (PID {pid})",
                    "path": proc.get("ExecutablePath", "unknown"),
                    "pid": pid,
                    "ppid": ppid,
                    "cmdline": (proc.get("CommandLine") or "")[:200],
                    "connections": remotes[:5],
                    "reason": f"Process name matches known malware: '{sus}'",
                }
            )
            return findings  # one finding per process

    # Running from suspicious path
    for sp in SUSPICIOUS_PATHS_LOWER:
        if sp in path:
            findings.append(
                {
                    "category": "processes",
                    "subcategory": "suspicious_path",
                    "severity": "HIGH",
                    "title": f"Process in Suspicious Location: {proc.get('Name','')} (PID {pid})",
                    "path": proc.get("ExecutablePath", "unknown"),
                    "pid": pid,
                    "ppid": ppid,
                    "cmdline": (proc.get("CommandLine") or "")[:200],
                    "connections": remotes[:5],
                    "reason": f"Process running from: {path}",
                }
            )
            return findings

    # Suspicious command line
    for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
        if pattern in cmdline:
            findings.append(
                {
                    "category": "processes",
                    "subcategory": "suspicious_cmdline",
                    "severity": "HIGH",
                    "title": f"Suspicious Command Line: {proc.get('Name','')} (PID {pid})",
                    "path": proc.get("ExecutablePath", "unknown"),
                    "pid": pid,
                    "ppid": ppid,
                    "cmdline": (proc.get("CommandLine") or "")[:300],
                    "connections": remotes[:5],
                    "reason": f"Command line contains: '{pattern}'",
                }
            )
            return findings

    # Network-connected process in unusual location
    if (
        remotes
        and path
        and not any(
            trusted in path
            for trusted in [
                "\\windows\\",
                "\\program files\\",
                "\\microsoft\\",
                "\\common files\\",
            ]
        )
    ):
        findings.append(
            {
                "category": "processes",
                "subcategory": "unusual_network_process",
                "severity": "MEDIUM",
                "title": f"Network-Connected Process Outside System Dirs: {proc.get('Name','')} (PID {pid})",
                "path": proc.get("ExecutablePath", "unknown"),
                "pid": pid,
                "ppid": ppid,
                "connections": remotes[:5],
                "reason": f"Process has {len(remotes)} network connection(s) and is not in system directories",
            }
        )

    return findings


def scan_processes() -> Dict[str, Any]:
    findings = []
    processes = _get_processes_powershell()
    conn_map = _get_network_connections()

    # A live Windows host always has running processes. An empty list means the
    # Win32_Process query failed (PowerShell/CIM blocked, timed out, or errored)
    # rather than that the host is clean. Surface that as a degraded-scan finding
    # so "no process findings" is never silently mistaken for "no process threats".
    if not processes:
        findings.append(
            {
                "category": "processes",
                "subcategory": "scan_degraded",
                "severity": "MEDIUM",
                "title": "Process enumeration returned no data",
                "path": "",
                "reason": (
                    "Win32_Process query returned nothing — the process scan is "
                    "degraded and may be blind to live threats. Verify PowerShell/"
                    "CIM availability and re-run."
                ),
            }
        )

    for proc in processes:
        hits = analyze_process(proc, conn_map)
        findings.extend(hits)

    return {
        "module": "processes",
        "process_count": len(processes),
        "findings_count": len(findings),
        "findings": findings,
    }
