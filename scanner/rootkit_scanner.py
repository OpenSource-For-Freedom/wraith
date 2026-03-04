"""
WRAITH rootkit_scanner.py
Module 3 of 7 — Rootkit & Stealth Malware Detection

Checks:
  1. Ghost process detection  — WMI process list vs psutil; PID gaps
  2. Unsigned kernel drivers  — sc query type=driver + Get-AuthenticodeSignature
  3. Hidden service detection — WMI Win32_Service vs sc query type=all state=all
  4. Kernel module anomalies  — driver loaded from unexpected path
  5. Suspicious prefetch      - known attack tools in C:\\Windows\\Prefetch
  6. Raw disk access          - processes with open handle to \\\\.\\PhysicalDriveN
  7. Hook indicators          - critical system DLL out of expected path (DLL hijack)
  8. SSDT-like: critical svchost without required modules
"""

import json
import os
import re
import subprocess
import sys
import glob
from pathlib import Path
from typing import List, Dict, Any

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

# Prefetch filenames (uppercase, no path) known for attack/pentest tools
MALICIOUS_PREFETCH = {
    "MIMIKATZ.EXE",
    "MIMI.EXE",
    "PYPYKATZ.EXE",
    "PROCDUMP.EXE",
    "PROCDUMP64.EXE",
    "LAZAGNE.EXE",
    "WCESVR.EXE",
    "FGDUMP.EXE",
    "PWDUMP.EXE",
    "PWDUMP7.EXE",
    "GSECDUMP.EXE",
    "LSADUMP.EXE",
    "NISHANG.PS1",
    "INVOKE-MIMIKATZ.PS1",
    "PWNDROP.EXE",
    "COBALT.EXE",
    "COBALTSTRIKE.EXE",
    "BEACON.EXE",
    "METERPRETER.EXE",
    "MSFDEPLOY.EXE",
    "PSENCODE.EXE",
    "INVOKE-OBFUSCATION.PS1",
    "RUBEUS.EXE",
    "KEKEO.EXE",
    "SHARPHOUND.EXE",
    "SHARPHOUND3.EXE",
    "BLOODHOUND.EXE",
    "ADFIND.EXE",
    "ADRECON.EXE",
    "PSEXEC.EXE",
    "PSEXEC64.EXE",
    "PAEXEC.EXE",
    "WMIEXEC.PY",
    "SMBEXEC.PY",
    "SECRETSDUMP.PY",
    "NETCAT.EXE",
    "NC.EXE",
    "NC64.EXE",
    "NCAT.EXE",
    "SOCAT.EXE",
    "POWERCAT.EXE",
    "PLINK.EXE",
    "CHISEL.EXE",
    "LIGOLO.EXE",
    "FSCAN.EXE",
    "NBTSCAN.EXE",
    "WINPEAS.EXE",
    "WINPEASX64.EXE",
    "WINPEASX86.EXE",
    "SEATBELT.EXE",
    "WATSON.EXE",
    "PRIVESCCHECK.PS1",
    "POWERUP.PS1",
    "EMPIRE.EXE",
    "COVENANT.EXE",
    "HAVOC.EXE",
    "SLIVER.EXE",
    "BRUTE.EXE",
    "NIMSCAN.EXE",
    "HACKTOOLS.EXE",
    "CREDDUMP.EXE",
    "CREDPHISHER.EXE",
}

# Legitimate kernel-mode driver directories
VALID_DRIVER_PATHS = [
    r"c:\windows\system32\drivers",
    r"c:\windows\syswow64\drivers",
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\windows\inf",
    r"c:\windows\winsxs",
]

# System-critical DLLs that must load from System32
CRITICAL_DLLS = [
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "advapi32.dll",
    "msvcrt.dll",
    "sechost.dll",
    "rpcrt4.dll",
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


def _run_ps(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _run_cmd(cmd: str, timeout: int = 20) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=True
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ──────────────────────────────────────────────
# Check 1: Ghost process detection
# ──────────────────────────────────────────────


def check_ghost_processes() -> List[Dict]:
    """
    Compare WMI Win32_Process PIDs against the OS task list.
    A hidden process won't appear in WMI even though its PID is
    detectable via other means. We flip this: use tasklist and WMI
    and flag processes visible in one but not the other.
    """
    findings = []

    # Get PIDs+names from WMI
    wmi_out = _run_ps(
        "Get-WmiObject Win32_Process | Select-Object ProcessId,Name | "
        "ConvertTo-Json -Compress"
    )
    wmi_procs: dict[int, str] = {}
    try:
        items = json.loads(wmi_out)
        if isinstance(items, dict):
            items = [items]
        for p in items:
            pid = int(p.get("ProcessId", 0))
            name = str(p.get("Name", ""))
            if pid:
                wmi_procs[pid] = name
    except Exception:
        pass

    # Get PIDs+names from tasklist (different Win32 API path)
    task_out = _run_cmd("tasklist /FO CSV /NH")
    task_procs: dict[int, str] = {}
    for line in task_out.splitlines():
        parts = line.strip().split(",")
        if len(parts) >= 2:
            name = parts[0].strip('"')
            try:
                pid = int(parts[1].strip('"'))
                task_procs[pid] = name
            except ValueError:
                continue

    # Processes in tasklist but NOT in WMI → potentially hidden from WMI
    # Filter transient names that appear only because they ran during the scan
    TRANSIENT_NAMES = {
        "cmd.exe",
        "tasklist.exe",
        "conhost.exe",
        "python.exe",
        "python3.exe",
        "powershell.exe",
        "wmic.exe",
        "wmiprvse.exe",
        "dllhost.exe",
    }
    if wmi_procs and task_procs:
        for pid, name in task_procs.items():
            if name.lower() in TRANSIENT_NAMES:
                continue
            if pid not in wmi_procs and pid not in (0, 4):  # skip Idle/System
                findings.append(
                    {
                        "title": f"Process hidden from WMI: {name} (PID {pid})",
                        "path": f"PID:{pid}",
                        "reason": (
                            f"Process '{name}' (PID {pid}) is visible in tasklist but "
                            "absent from WMI Win32_Process enumeration. Rootkits often "
                            "hook WMI providers to conceal themselves while the underlying "
                            "process remains scheduled by the kernel."
                        ),
                        "severity": "CRITICAL",
                        "category": "rootkit",
                        "subcategory": "ghost_process",
                        "pid": pid,
                    }
                )

    return findings


# ──────────────────────────────────────────────
# Check 2: Unsigned kernel drivers
# ──────────────────────────────────────────────


def check_unsigned_drivers() -> List[Dict]:
    """
    Enumerate running kernel-mode drivers and check their Authenticode signature.
    Unsigned or revoked drivers are a strong rootkit indicator on modern Windows.
    """
    findings = []

    # List running services of type=kernel driver
    sc_out = _run_cmd("sc query type= driver state= all")
    driver_names = re.findall(r"SERVICE_NAME:\s*(\S+)", sc_out)

    if not driver_names:
        return findings

    # Batch signature check via PowerShell for all driver names at once
    # Get-WmiObject Win32_SystemDriver gives us the path
    sys_drivers_ps = (
        "Get-WmiObject Win32_SystemDriver | "
        "Select-Object Name,PathName | ConvertTo-Json -Compress"
    )
    sys_out = _run_ps(sys_drivers_ps, timeout=40)
    path_map: dict[str, str] = {}
    try:
        items = json.loads(sys_out)
        if isinstance(items, dict):
            items = [items]
        for d in items:
            n = str(d.get("Name", "")).lower()
            p = str(d.get("PathName", ""))
            if n and p:
                path_map[n] = p
    except Exception:
        pass

    for name in driver_names[:60]:  # cap to avoid timeout
        driver_path = path_map.get(name.lower(), "")
        if not driver_path:
            continue

        # Skip kernel-embedded paths
        if driver_path.lower().startswith(r"\systemroot"):
            driver_path = driver_path.lower().replace(r"\systemroot", r"c:\windows")

        # Check if path is outside normal driver dirs
        norm = driver_path.lower().replace("/", "\\")
        in_valid = any(norm.startswith(vp) for vp in VALID_DRIVER_PATHS)

        # Check signature
        sig_cmd = (
            f"(Get-AuthenticodeSignature -FilePath '{driver_path}' "
            f"-ErrorAction SilentlyContinue).Status"
        )
        sig_status = _run_ps(sig_cmd)

        if sig_status in ("", "UnknownError"):
            continue  # file not found or can't check

        if (
            sig_status not in ("Valid", "NotSigned")
            and "valid" not in sig_status.lower()
        ):
            findings.append(
                {
                    "title": f"Driver with invalid signature: {name}",
                    "path": driver_path,
                    "reason": (
                        f"Kernel driver '{name}' has Authenticode status '{sig_status}'. "
                        "Revoked, tampered, or forged driver signatures are used by "
                        "sophisticated rootkits (e.g., UEFI implants, bootkits) to "
                        "load malicious kernel code while evading basic integrity checks."
                    ),
                    "severity": "CRITICAL",
                    "category": "rootkit",
                    "subcategory": "unsigned_driver",
                }
            )
        elif sig_status == "NotSigned":
            severity = "HIGH" if not in_valid else "MEDIUM"
            findings.append(
                {
                    "title": f"Unsigned kernel driver: {name}",
                    "path": driver_path,
                    "reason": (
                        f"Kernel driver '{name}' is not Authenticode signed. On 64-bit "
                        "Windows, all kernel drivers must be signed. Unsigned drivers "
                        "loaded via a test-signing or exploit bypass indicate potential "
                        "rootkit installation. Path: {driver_path}"
                    ),
                    "severity": severity,
                    "category": "rootkit",
                    "subcategory": "unsigned_driver",
                }
            )
        elif not in_valid:
            findings.append(
                {
                    "title": f"Driver loaded from non-standard path: {name}",
                    "path": driver_path,
                    "reason": (
                        f"Driver '{name}' is signed but loaded from an unusual path: "
                        f"'{driver_path}'. Legitimate Windows drivers load from "
                        r"System32\drivers or a vendor-registered Program Files location. "
                        "Rootkits may copy themselves to temp dirs and register as services."
                    ),
                    "severity": "HIGH",
                    "category": "rootkit",
                    "subcategory": "driver_path",
                }
            )

    return findings


# ──────────────────────────────────────────────
# Check 3: Hidden service detection
# ──────────────────────────────────────────────


def check_hidden_services() -> List[Dict]:
    """
    Compare WMI Win32_Service list vs 'sc query type=all state=all'.
    A service visible in sc but absent from WMI indicates provider hooking.
    """
    findings = []

    # WMI service names
    wmi_svc_out = _run_ps("Get-WmiObject Win32_Service | Select-Object -Expand Name")
    wmi_services = set(s.strip().lower() for s in wmi_svc_out.splitlines() if s.strip())

    # sc query — restrict to type=service to match WMI Win32_Service scope
    # Parse the full sc output to only include WIN32_*_PROCESS services,
    # filtering out kernel/filesystem driver entries and group bundle names.
    sc_all_out = _run_cmd("sc query type= service state= all")
    sc_services: set[str] = set()
    current_name = ""
    for line in sc_all_out.splitlines():
        line = line.strip()
        m = re.match(r"SERVICE_NAME:\s*(\S+)", line)
        if m:
            current_name = m.group(1).lower()
        elif re.search(r"TYPE\s*:\s*\d+\s+WIN32", line, re.IGNORECASE):
            if current_name:
                sc_services.add(current_name)
                current_name = ""

    if not wmi_services or not sc_services:
        return findings

    # Known-legitimate services / vendor-registered service short names that
    # sc reports but WMI Win32_Service enumerates under a different full name
    # or not at all. Keeping this list prevents noisy false positives.
    KNOWN_SAFE_SERVICES = {
        # Common vendor short names
        "amd",
        "apple",
        "bonjour",
        "razer",
        "steam",
        "tenable",
        "nvidia",
        "intel",
        "lenovo",
        "dell",
        "hp",
        "realtek",
        "qualcomm",
        "onedrive",
        "dropbox",
        "googledrive",
        "google",
        "microsoft",
        "adobe",
        "vmware",
        "virtualbox",
        "vbox",
        "citrix",
        "symantec",
        "mcafee",
        "trend",
        "kaspersky",
        "malwarebytes",
        "cylance",
        "crowdstrike",
        "sentinelone",
        "carbon",
        "docker",
        "kubernetes",
        # Legacy/compatibility store artifacts
        "appreadiness",
        "ndu",
        "ndis",
        "tcpip",
        "netbt",
        "afunix",
        "afd",
        "beep",
        "null",
        "dam",
        "pdc",
        "pcw",
        "rdyboost",
        "wfplwfs",
        "wanarpv6",
        "wanarap",
        "mslldp",
    }

    # In sc but not WMI → hidden from WMI
    hidden = sc_services - wmi_services
    for svc in sorted(hidden):
        if svc in KNOWN_SAFE_SERVICES:
            continue
        # Also skip by known-safe prefix
        if any(
            svc.startswith(p)
            for p in (
                "amd",
                "nvidia",
                "intel",
                "razer",
                "steam",
                "apple",
                "tenable",
                "google",
                "microsoft",
                "adobe",
            )
        ):
            continue
        findings.append(
            {
                "title": f"Service hidden from WMI: {svc}",
                "path": f"Service:{svc}",
                "reason": (
                    f"Service '{svc}' appears in sc query output but is absent from "
                    "WMI Win32_Service enumeration. This discrepancy is a classic sign "
                    "of a WMI provider hook used by rootkits (e.g., ZeroAccess, TDL4) "
                    "to hide malicious services from management tools."
                ),
                "severity": "CRITICAL",
                "category": "rootkit",
                "subcategory": "hidden_service",
            }
        )

    return findings


# ──────────────────────────────────────────────
# Check 4: Suspicious prefetch artifacts
# ──────────────────────────────────────────────


def check_prefetch() -> List[Dict]:
    """
    Scan C:\\Windows\\Prefetch for filenames matching known attack tools.
    Prefetch files persist even after the binary is deleted, revealing
    that an attack tool was executed on this system.
    """
    findings = []
    prefetch_dir = Path(r"C:\Windows\Prefetch")
    if not prefetch_dir.exists():
        return findings

    try:
        for pf_file in prefetch_dir.iterdir():
            name = pf_file.name.upper()
            # Prefetch format: <EXENAME>-<HASH>.pf
            exe_part = name.split("-")[0]
            if exe_part in MALICIOUS_PREFETCH or any(
                m in name for m in MALICIOUS_PREFETCH
            ):
                try:
                    mtime = pf_file.stat().st_mtime
                    import datetime

                    last_run = datetime.datetime.fromtimestamp(mtime).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                except Exception:
                    last_run = "unknown"

                findings.append(
                    {
                        "title": f"Attack tool prefetch found: {pf_file.name}",
                        "path": str(pf_file),
                        "reason": (
                            f"Prefetch entry '{pf_file.name}' was last updated {last_run}. "
                            "Windows Prefetch records execution of binaries and persists "
                            "for 10-30 days even if the attacker deletes the source file. "
                            "This file matches known attack/credential-harvesting tools."
                        ),
                        "severity": "CRITICAL",
                        "category": "rootkit",
                        "subcategory": "prefetch_artifact",
                        "last_run": last_run if last_run != "unknown" else None,
                    }
                )
    except PermissionError:
        pass  # requires elevation for full prefetch access

    return findings


# ──────────────────────────────────────────────
# Check 5: Driver loaded from temp / user dirs
# ──────────────────────────────────────────────


def check_driver_paths() -> List[Dict]:
    """
    Look specifically for any loaded driver whose path contains
    temp, appdata, public, or recycler — these are strong rootkit IOCs.
    """
    findings = []
    SUSPICIOUS_PATH_FRAGMENTS = [
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\",
        "\\public\\",
        "\\recycl",
        "\\downloads\\",
        "\\desktop\\",
        "\\users\\",
    ]

    wmi_out = _run_ps(
        "Get-WmiObject Win32_SystemDriver | "
        "Select-Object Name,PathName | ConvertTo-Json -Compress",
        timeout=30,
    )
    try:
        items = json.loads(wmi_out)
        if isinstance(items, dict):
            items = [items]
        for d in items:
            path = str(d.get("PathName", "")).lower()
            name = str(d.get("Name", ""))
            for frag in SUSPICIOUS_PATH_FRAGMENTS:
                if frag in path:
                    findings.append(
                        {
                            "title": f"Driver in suspicious directory: {name}",
                            "path": str(d.get("PathName", "")),
                            "reason": (
                                f"Kernel driver '{name}' is registered with a path "
                                f"'{d.get('PathName','')}' containing '{frag}'. "
                                "Legitimate kernel drivers are never installed in user "
                                "temp directories. This is a strong indicator of a "
                                "manually-loaded rootkit or kernel exploit payload."
                            ),
                            "severity": "CRITICAL",
                            "category": "rootkit",
                            "subcategory": "driver_path",
                        }
                    )
                    break
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Check 6: Test-signing mode enabled
# ──────────────────────────────────────────────


def check_test_signing() -> List[Dict]:
    """
    Test-signing mode bypasses Windows driver signature enforcement (DSE),
    allowing any unsigned driver to load. Rootkits enable this during install.
    """
    findings = []
    out = _run_cmd("bcdedit /enum {current}")
    # Look for 'testsigning Yes'
    if re.search(r"testsigning\s+yes", out, re.IGNORECASE):
        findings.append(
            {
                "title": "Test-Signing Mode Enabled (DSE Bypass)",
                "path": "BCD:{current}",
                "reason": (
                    "Boot Configuration Data shows 'testsigning Yes'. This disables "
                    "Driver Signature Enforcement (DSE), allowing unsigned and "
                    "attacker-supplied kernel drivers to load. This setting is used "
                    "by rootkits such as TDL4, Necurs, and ZeroAccess to persist in "
                    "the kernel without a valid Authenticode certificate."
                ),
                "severity": "CRITICAL",
                "category": "rootkit",
                "subcategory": "test_signing",
            }
        )

    # Also check kernel debug mode (also allows unsigned driver load)
    if re.search(r"debug\s+yes", out, re.IGNORECASE):
        findings.append(
            {
                "title": "Kernel Debug Mode Enabled",
                "path": "BCD:{current}",
                "reason": (
                    "Boot Configuration Data shows 'debug Yes'. Kernel debug mode "
                    "disables DSE and allows live kernel patching. While legitimate "
                    "for developers, it is also used by rootkits to disable driver "
                    "signature enforcement on compromised systems."
                ),
                "severity": "HIGH",
                "category": "rootkit",
                "subcategory": "kernel_debug",
            }
        )

    return findings


# ──────────────────────────────────────────────
# Check 7: Known rootkit registry keys
# ──────────────────────────────────────────────


def check_rootkit_registry() -> List[Dict]:
    """
    Check for registry keys associated with known rootkit families.
    """
    findings = []
    import winreg

    ROOTKIT_KEYS = [
        # ZeroAccess (GUID-named service key — should never exist legitimately)
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\{GUID}",
            "ZeroAccess",
        ),
        # Necurs rootkit service
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\necurs",
            "Necurs",
        ),
        # Shamoon wiper driver
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\hdv_725x",
            "Shamoon",
        ),
        # Azazel / Adore rootkit
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\adore",
            "Adore/Azazel",
        ),
        # WannaCry / NotPetya remnant
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\mssecsvc2.0",
            "WannaCry",
        ),
        # Cobalt Strike named-pipe default
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\MSDTC Bridge",
            "CobaltStrike",
        ),
    ]

    for hive, subkey, family in ROOTKIT_KEYS:
        try:
            with winreg.OpenKey(hive, subkey):
                findings.append(
                    {
                        "title": f"Known Rootkit Registry Key: {family}",
                        "path": f"HKLM\\{subkey}",
                        "reason": (
                            f"Registry key associated with the '{family}' rootkit/malware "
                            f"family was found at 'HKLM\\{subkey}'. This key is "
                            "created by the malware during installation and typically "
                            "persists even after process termination."
                        ),
                        "severity": "CRITICAL",
                        "category": "rootkit",
                        "subcategory": "known_rootkit_key",
                    }
                )
        except FileNotFoundError:
            pass
        except PermissionError:
            pass  # key exists but we can't read it — still suspicious
        except Exception:
            pass

    # Check IFEO for svchost.exe specifically — legit but very abused
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe",
        ) as k:
            try:
                debugger, _ = winreg.QueryValueEx(k, "Debugger")
                if debugger:
                    findings.append(
                        {
                            "title": "IFEO Debugger Set on svchost.exe",
                            "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe",
                            "reason": (
                                f"Image File Execution Options 'Debugger' value is set to "
                                f"'{debugger}' for svchost.exe. This causes every svchost "
                                "invocation to launch the attacker-specified executable "
                                "instead, enabling persistent code execution with SYSTEM "
                                "privileges. This technique is used by ZeroAccess and "
                                "other rootkits."
                            ),
                            "severity": "CRITICAL",
                            "category": "rootkit",
                            "subcategory": "ifeo_hook",
                        }
                    )
            except FileNotFoundError:
                pass
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Check 8: PID gap analysis (DKOM indicator)
# ──────────────────────────────────────────────


def check_pid_gaps() -> List[Dict]:
    """
    On Windows, PIDs are assigned in multiples of 4.
    A large gap (> 200) in the running PID sequence that does not
    correspond to a legitimate high-PID service is unusual and can
    indicate DKOM (Direct Kernel Object Manipulation) used to unlink
    a process from the doubly-linked EPROCESS list.
    This is a heuristic only — report as LOW.
    """
    findings = []

    wmi_out = _run_ps("Get-WmiObject Win32_Process | Select-Object -Expand ProcessId")
    pids = []
    for line in wmi_out.splitlines():
        try:
            pids.append(int(line.strip()))
        except ValueError:
            continue

    if len(pids) < 10:
        return findings

    pids_sorted = sorted(set(pids))
    for i in range(1, len(pids_sorted)):
        gap = pids_sorted[i] - pids_sorted[i - 1]
        # Only flag gaps in the lower PID range (< 5000) because high PIDs
        # are common for deferred/session processes
        if gap > 500 and pids_sorted[i - 1] < 5000:
            findings.append(
                {
                    "title": f"Suspicious PID gap: {pids_sorted[i-1]} → {pids_sorted[i]}",
                    "path": f"PID:{pids_sorted[i-1]}-{pids_sorted[i]}",
                    "reason": (
                        f"A gap of {gap} in the PID sequence between "
                        f"PID {pids_sorted[i-1]} and PID {pids_sorted[i]} was detected "
                        "in the low PID range. DKOM rootkits hide processes by unlinking "
                        "their EPROCESS structure from the kernel's process list while the "
                        "process continues to run, leaving a PID gap. This is a low-confidence "
                        "heuristic — verify with a memory forensics tool (e.g., Volatility)."
                    ),
                    "severity": "LOW",
                    "category": "rootkit",
                    "subcategory": "pid_gap",
                }
            )

    return findings


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────


def scan_rootkit() -> List[Dict]:
    findings: List[Dict] = []
    checks = [
        ("ghost_processes", check_ghost_processes),
        ("unsigned_drivers", check_unsigned_drivers),
        ("hidden_services", check_hidden_services),
        ("prefetch", check_prefetch),
        ("driver_paths", check_driver_paths),
        ("test_signing", check_test_signing),
        ("rootkit_registry", check_rootkit_registry),
        ("pid_gaps", check_pid_gaps),
    ]
    for name, fn in checks:
        try:
            results = fn()
            findings.extend(results)
        except Exception as e:
            sys.stderr.write(f"[WRAITH-ROOTKIT] check '{name}' error: {e}\n")

    return findings


if __name__ == "__main__":
    sys.stderr.write("[WRAITH-ROOTKIT] Rootkit & stealth malware scan starting...\n")
    results = scan_rootkit()
    sys.stderr.write(
        f"[WRAITH-ROOTKIT] Rootkit scan complete: {len(results)} findings\n"
    )
    output = {
        "scanner": "WRAITH-rootkit",
        "mode": "rootkit",
        "findings": results,
    }
    print(json.dumps(output, indent=2))
