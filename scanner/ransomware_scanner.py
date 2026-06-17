"""
WRAITH - Ransomware Detection Module
Behavioral and artifact-based ransomware detection without relying solely on signatures.

Checks:
  1.  Shadow copy / VSS deletion commands in process list and recent events
  2.  Backup catalog wipe (wbadmin delete catalog)
  3.  Event log clearing (wevtutil cl / Clear-EventLog)
  4.  Known ransomware file extensions in user-writable directories
  5.  Ransom note filenames on disk
  6.  Mass file rename activity via filesystem journal / recent file changes
  7.  Encryption API usage in suspicious processes
  8.  Firewall / recovery disable commands (bcdedit, netsh)
  9.  Known ransomware mutex names in running processes
 10.  Canary file tampering (honeypot detection)
 11.  Safe mode boot abuse (ransomware reboots into safe mode to bypass AV)
 12.  Windows Defender / AV disable commands
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set

try:
    import winreg

    _WINREG = True
except ImportError:
    _WINREG = False


def log(msg: str) -> None:
    import sys

    print(f"[WRAITH-RANSOM] {msg}", file=sys.stderr)


# ── PowerShell helper ─────────────────────────────────────────────────────────


def _ps(cmd: str, timeout: int = 20) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _ps_json(cmd: str, timeout: int = 20):
    raw = _ps(cmd, timeout)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


# ── Known ransomware encrypted-file extensions ────────────────────────────────
# Sources: ID Ransomware, NoMoreRansom, Bleeping Computer
RANSOM_EXTENSIONS: Set[str] = {
    # WannaCry / WannaCrypt
    ".wncry",
    ".wcry",
    ".wncryt",
    # Locky variants
    ".locky",
    ".zepto",
    ".odin",
    ".shit",
    ".thor",
    ".aesir",
    ".zzzzz",
    ".osiris",
    # Ryuk / Conti
    ".ryuk",
    ".RYK",
    # LockBit
    ".lockbit",
    ".lockbit2",
    ".lockbit3",
    ".abcd",
    # BlackCat / ALPHV
    ".sykffle",
    ".ttza",
    # Cl0p
    ".clop",
    ".Clop",
    # Maze / Egregor
    ".maze",
    # REvil / Sodinokibi
    ".sodinokibi",
    # Dharma / Crysis
    ".dharma",
    ".wallet",
    ".arena",
    ".cezar",
    ".cmb",
    ".java",
    ".adobe",
    ".com",
    # Phobos
    ".phobos",
    # Netwalker
    ".netwalker",
    # DarkSide
    ".darkside",
    # BlackMatter
    ".blackmatter",
    # Hive
    ".hive",
    # Generic ransomware extensions
    ".enc",
    ".encrypted",
    ".crypted",
    ".crypt",
    ".locked",
    ".crypz",
    ".cryp1",
    ".kraken",
    ".darkness",
    ".nochance",
    ".XRNT",
    ".XTBL",
    ".cryptolocker",
    ".ezz",
    ".exx",
    ".vvv",
    ".xxx",
    ".ttt",
    ".micro",
    ".mp3",
    ".fun",
    ".gws",
    ".btc",
    ".kimcilware",
    ".UCCU",
    ".harasom",
}

# ── Known ransom note filenames ───────────────────────────────────────────────
RANSOM_NOTE_NAMES: Set[str] = {
    "readme.txt",
    "read_me.txt",
    "read_me.html",
    "decrypt_instructions.txt",
    "how_to_decrypt.txt",
    "how_to_recover_files.txt",
    "how_to_restore_files.txt",
    "how_to_buy_bitcoin.txt",
    "recover_files.html",
    "your_files_are_encrypted.txt",
    "files_encrypted.txt",
    "!!!_warning_!!!.txt",
    "attention!!!.txt",
    "important!!!.txt",
    "!!!readme!!!.txt",
    "!!!recover_your_files.txt",
    "@please_read_me@.txt",
    "@decrypt_my_files@.txt",
    "@restore_my_files@.txt",
    "restore_my_files.txt",
    "@warning@.txt",
    "decrypt_your_files.html",
    "ransom_note.txt",
    "ransomnote.txt",
    "recovery.txt",
    "help_decrypt.html",
    "help_your_files.html",
    "help_restore_files.html",
    # Ryuk
    "ryukreademefirst.txt",
    "ryukreademefirst.html",
    # LockBit
    "lockbit-readme.txt",
    "restore-my-files.txt",
    # Cl0p
    "clop!_readme_!!!.txt",
    # BlackCat
    "recover-files.txt",
    # Hive
    "hive.readme.txt",
}

# ── Commands that ransomware runs before encrypting ───────────────────────────
RANSOM_PRECURSOR_PATTERNS = [
    # VSS / shadow copies
    (
        r"vssadmin\s+delete\s+shadows",
        "CRITICAL",
        "vss_delete",
        "VSS shadow copy deletion",
    ),
    (
        r"wmic\s+shadowcopy\s+delete",
        "CRITICAL",
        "vss_delete",
        "WMI shadow copy deletion",
    ),
    (
        r"Get-WmiObject\s+Win32_Shadowcopy.*Delete",
        "CRITICAL",
        "vss_delete",
        "PS shadow copy deletion",
    ),
    # Backup catalog
    (
        r"wbadmin\s+delete\s+catalog",
        "CRITICAL",
        "backup_wipe",
        "Windows backup catalog deletion",
    ),
    # Recovery / boot config
    (
        r"bcdedit\s+.*recoveryenabled\s+no",
        "CRITICAL",
        "recovery_disable",
        "Boot recovery disabled",
    ),
    (r"bcdedit\s+.*bootstatuspolicy", "HIGH", "recovery_disable", "Boot policy tamper"),
    # Event log clearing
    (
        r"wevtutil\s+cl\b",
        "HIGH",
        "log_clear",
        "Windows event logs cleared",
    ),
    (r"Clear-EventLog", "HIGH", "log_clear", "PowerShell event log clear"),
    # AV / Defender disable
    (
        r"Set-MpPreference\s+.*DisableRealtimeMonitoring\s+\$?true",
        "CRITICAL",
        "av_disable",
        "Windows Defender real-time disabled",
    ),
    (
        r"netsh\s+advfirewall\s+set\s+.*state\s+off",
        "HIGH",
        "firewall_disable",
        "Firewall disabled via netsh",
    ),
    # Safe-mode reboot abuse
    (r"bcdedit\s+.*safeboot", "CRITICAL", "safeboot_abuse", "Safe mode boot set"),
    # Cipher /w (wipes free space — used to hinder recovery)
    (r"cipher\s+/w:", "HIGH", "wipe_free", "cipher /w free-space wipe"),
]

# ── Known ransomware mutex substrings ─────────────────────────────────────────
RANSOM_MUTEX_SUBSTRINGS = [
    "wannacry",
    "wncry",
    "ryuk",
    "lockbit",
    "conti",
    "blackcat",
    "alphv",
    "clop",
    "revil",
    "sodinokibi",
    "netwalker",
    "darkside",
    "maze",
    "egregor",
    "hive",
]

# ── Directories to scan for encrypted files / ransom notes ───────────────────
SCAN_DIRS = [
    Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "Documents",
    Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "Desktop",
    Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "Downloads",
    Path("C:\\Users\\Public"),
    Path(os.environ.get("TEMP", "C:\\Windows\\Temp")),
]


# ── 1. Precursor command detection via recent processes ───────────────────────


def check_ransomware_precursor_processes(findings: List[Dict]) -> None:
    """Detect ransomware staging commands in running/recent process command lines."""
    raw = _ps_json(
        "Get-WmiObject Win32_Process | Select-Object Name, CommandLine, ProcessId "
        "| ConvertTo-Json -Depth 1 -Compress",
        timeout=30,
    )
    if not raw:
        return
    procs = raw if isinstance(raw, list) else [raw]

    for proc in procs:
        if not isinstance(proc, dict):
            continue
        cmdline = (proc.get("CommandLine") or "").lower()
        pid = proc.get("ProcessId", 0)
        name = proc.get("Name", "")
        if not cmdline:
            continue

        for pattern, sev, subcat, desc in RANSOM_PRECURSOR_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                findings.append(
                    {
                        "title": f"Ransomware Precursor: {desc}",
                        "path": f"PID {pid} — {name}",
                        "reason": (
                            f"Process '{name}' (PID {pid}) is running a command associated with "
                            f"ransomware pre-encryption staging: {desc}. "
                            f"Command: {cmdline[:200]}"
                        ),
                        "severity": sev,
                        "category": "ransomware",
                        "subcategory": subcat,
                        "pid": pid,
                    }
                )
                break


# ── 2. Precursor commands in recent Windows event logs ───────────────────────


def check_ransomware_precursor_events(findings: List[Dict]) -> None:
    """Scan Security/System/PowerShell event logs for precursor command evidence."""
    ps = (
        "$cutoff = (Get-Date).AddHours(-48);"
        "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.TimeCreated -gt $cutoff } | "
        "Select-Object -ExpandProperty Message -First 200"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=30,
        )
        combined = (r.stdout or "").lower()
        for pattern, sev, subcat, desc in RANSOM_PRECURSOR_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                findings.append(
                    {
                        "title": f"Ransomware Precursor in Event Log: {desc}",
                        "path": "Microsoft-Windows-PowerShell/Operational",
                        "reason": (
                            f"PowerShell event log contains evidence of '{desc}' within the "
                            f"last 48 hours — a known ransomware pre-encryption step. "
                            f"Pattern matched: {pattern}"
                        ),
                        "severity": sev,
                        "category": "ransomware",
                        "subcategory": f"event_{subcat}",
                    }
                )
    except Exception as e:
        log(f"Event log precursor check failed: {e}")


# ── 3. Encrypted file extension scan ─────────────────────────────────────────


def check_encrypted_file_extensions(findings: List[Dict]) -> None:
    """Scan user-writable dirs for files with known ransomware extensions."""
    hits: Dict[str, List[str]] = {}  # ext → sample paths

    for scan_dir in SCAN_DIRS:
        if not scan_dir.exists():
            continue
        try:
            for f in scan_dir.iterdir():
                if not f.is_file():
                    continue
                ext = f.suffix.lower()
                if ext in RANSOM_EXTENSIONS:
                    hits.setdefault(ext, []).append(str(f))
                    if len(hits[ext]) >= 5:
                        break
        except PermissionError:
            continue
        except Exception as e:
            log(f"Extension scan error in {scan_dir}: {e}")

    for ext, samples in hits.items():
        findings.append(
            {
                "title": f"Ransomware File Extension Found: {ext}",
                "path": samples[0],
                "reason": (
                    f"Found {len(samples)} file(s) with extension '{ext}', which is used "
                    f"by known ransomware families to rename encrypted victims' files. "
                    f"Samples: {', '.join(samples[:3])}"
                ),
                "severity": "CRITICAL",
                "category": "ransomware",
                "subcategory": "encrypted_files",
            }
        )


# ── 4. Ransom note detection ──────────────────────────────────────────────────


def check_ransom_notes(findings: List[Dict]) -> None:
    """Scan common directories for ransom note filenames."""
    for scan_dir in SCAN_DIRS:
        if not scan_dir.exists():
            continue
        try:
            for f in scan_dir.iterdir():
                if not f.is_file():
                    continue
                if f.name.lower() in RANSOM_NOTE_NAMES:
                    findings.append(
                        {
                            "title": f"Ransom Note Found: {f.name}",
                            "path": str(f),
                            "reason": (
                                f"File '{f.name}' in '{scan_dir}' matches known ransom note "
                                f"naming patterns. Ransomware drops these files after encryption "
                                f"to instruct victims on payment. Indicates active or recent "
                                f"ransomware infection."
                            ),
                            "severity": "CRITICAL",
                            "category": "ransomware",
                            "subcategory": "ransom_note",
                        }
                    )
        except PermissionError:
            continue
        except Exception as e:
            log(f"Ransom note scan error in {scan_dir}: {e}")


# ── 5. VSS snapshot status ────────────────────────────────────────────────────


def check_vss_snapshots(findings: List[Dict]) -> None:
    """Alert if no VSS shadow copies exist — ransomware typically deletes them first."""
    raw = _ps(
        "vssadmin list shadows 2>$null | Select-String 'Shadow Copy Volume'",
        timeout=20,
    )
    if not raw:
        findings.append(
            {
                "title": "No VSS Shadow Copies Found",
                "path": "vssadmin list shadows",
                "reason": (
                    "No Volume Shadow Service (VSS) shadow copies are present. "
                    "Ransomware deletes shadow copies as its first step to prevent file recovery. "
                    "Absence of shadow copies on a production system is a strong ransomware indicator "
                    "or indicates recovery capability has been deliberately removed."
                ),
                "severity": "HIGH",
                "category": "ransomware",
                "subcategory": "vss_missing",
            }
        )


# ── 6. Safe-mode boot configuration ──────────────────────────────────────────


def check_safeboot_registry(findings: List[Dict]) -> None:
    """Ransomware (Ryuk, BlackMatter) sets safeboot to bypass AV on reboot."""
    if not _WINREG:
        return
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SafeBoot\Option",
        )
        val = winreg.QueryValueEx(key, "OptionValue")[0]
        winreg.CloseKey(key)
        if val:
            findings.append(
                {
                    "title": "Safe Mode Boot Configured (Ransomware Indicator)",
                    "path": r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option",
                    "reason": (
                        "The SafeBoot\\Option registry key is set. Ryuk, BlackMatter, and "
                        "other ransomware families configure safe-mode boot to bypass AV/EDR "
                        "products that don't load in safe mode before encrypting. "
                        "Remove this key if not intentionally set: "
                        "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Option /f"
                    ),
                    "severity": "CRITICAL",
                    "category": "ransomware",
                    "subcategory": "safeboot_abuse",
                }
            )
    except OSError:
        pass


# ── 7. Ransomware service autorun entries ─────────────────────────────────────


def check_ransomware_autorun(findings: List[Dict]) -> None:
    """Check Run keys for ransomware-style autorun entries."""
    if not _WINREG:
        return
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]
    ransom_run_patterns = re.compile(
        r"vssadmin|wbadmin|bcdedit.*recover|wevtutil\s+cl|"
        r"cipher\s+/w|netsh.*firewall.*off|taskill.*defender",
        re.IGNORECASE,
    )
    for hive, path in run_keys:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    i += 1
                    if ransom_run_patterns.search(str(data)):
                        findings.append(
                            {
                                "title": f"Ransomware Command in Autorun: {name}",
                                "path": f"{path}\\{name}",
                                "reason": (
                                    f"Registry Run key '{name}' contains a command matching ransomware "
                                    f"staging patterns: {str(data)[:200]}"
                                ),
                                "severity": "CRITICAL",
                                "category": "ransomware",
                                "subcategory": "ransom_autorun",
                            }
                        )
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass


# ── 8. Mass file rename activity (filesystem journal) ────────────────────────


def check_mass_rename_activity(findings: List[Dict]) -> None:
    """Use PowerShell to detect mass file changes in the last hour via USN journal."""
    ps = (
        "$cutoff = (Get-Date).AddMinutes(-60);"
        "$drives = Get-PSDrive -PSProvider FileSystem | "
        "Where-Object { $_.Root -match '^[A-Z]:\\\\$' } | "
        "Select-Object -ExpandProperty Root -First 2;"
        "$count = 0;"
        "foreach ($d in $drives) {"
        "  try {"
        "    $j = fsutil usn readjournal $d.TrimEnd('\\') 2>$null;"
        "    $count += ($j | Select-String 'Rename' | Measure-Object).Count"
        "  } catch {}"
        "};"
        "$count"
    )
    try:
        raw = _ps(ps, timeout=30).strip()
        count = int(raw) if raw.isdigit() else 0
        if count > 500:
            findings.append(
                {
                    "title": f"Mass File Rename Activity: {count} renames in last hour",
                    "path": "NTFS USN Journal",
                    "reason": (
                        f"The NTFS change journal recorded {count} file rename operations in the "
                        f"past 60 minutes. Ransomware renames files after encryption to add its "
                        f"extension (e.g. document.docx → document.docx.wncry). "
                        f"Threshold: >500 renames/hour."
                    ),
                    "severity": "CRITICAL",
                    "category": "ransomware",
                    "subcategory": "mass_rename",
                }
            )
        elif count > 100:
            findings.append(
                {
                    "title": f"Elevated File Rename Activity: {count} renames in last hour",
                    "path": "NTFS USN Journal",
                    "reason": (
                        f"Unusually high file rename activity detected ({count} renames/hour). "
                        f"This may indicate early-stage ransomware encryption. Monitor and verify."
                    ),
                    "severity": "HIGH",
                    "category": "ransomware",
                    "subcategory": "mass_rename",
                }
            )
    except Exception as e:
        log(f"Mass rename check failed: {e}")


# ── 9. Canary file tampering ──────────────────────────────────────────────────

_CANARY_DIR = Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "Documents"
_CANARY_FILENAME = "~wraith_canary_do_not_delete.txt"
_CANARY_CONTENT = "WRAITH canary file — tampering with this file triggers ransomware detection."


def _canary_path() -> Path:
    return _CANARY_DIR / _CANARY_FILENAME


def ensure_canary() -> None:
    """Create the canary file if it doesn't exist. Called at startup."""
    try:
        p = _canary_path()
        if not p.exists():
            _CANARY_DIR.mkdir(parents=True, exist_ok=True)
            p.write_text(_CANARY_CONTENT, encoding="utf-8")
    except Exception as e:
        log(f"Canary creation failed: {e}")


def check_canary_tampering(findings: List[Dict]) -> None:
    """Alert if the canary file is missing, modified, or has a renamed extension."""
    p = _canary_path()

    # Check for renamed canary (ransomware appended an extension)
    try:
        canary_dir = _CANARY_DIR
        if canary_dir.exists():
            for f in canary_dir.iterdir():
                if f.stem == _CANARY_FILENAME or _CANARY_FILENAME in f.name:
                    if f.suffix.lower() in RANSOM_EXTENSIONS:
                        findings.append(
                            {
                                "title": "Canary File Encrypted by Ransomware",
                                "path": str(f),
                                "reason": (
                                    f"WRAITH canary file was renamed to '{f.name}' — "
                                    f"the extension '{f.suffix}' is a known ransomware-encrypted "
                                    f"file extension. This confirms active ransomware encryption."
                                ),
                                "severity": "CRITICAL",
                                "category": "ransomware",
                                "subcategory": "canary_encrypted",
                            }
                        )
                        return
    except Exception as e:
        log(f"Canary rename check failed: {e}")

    if not p.exists():
        findings.append(
            {
                "title": "Canary File Missing (Possible Ransomware Activity)",
                "path": str(p),
                "reason": (
                    "WRAITH honeypot canary file is missing. Ransomware or malware may have "
                    "deleted or encrypted it. The canary file is placed in the Documents folder "
                    "to act as an early-warning tripwire. Investigate recent file system changes."
                ),
                "severity": "HIGH",
                "category": "ransomware",
                "subcategory": "canary_missing",
            }
        )
        ensure_canary()
        return

    # Check if content was modified
    try:
        current = p.read_text(encoding="utf-8", errors="replace")
        if current.strip() != _CANARY_CONTENT.strip():
            findings.append(
                {
                    "title": "Canary File Modified (Ransomware Activity Suspected)",
                    "path": str(p),
                    "reason": (
                        "WRAITH honeypot canary file content has been altered. "
                        "Ransomware that partially encrypts files may modify canary content "
                        "before full extension rename. Investigate immediately."
                    ),
                    "severity": "CRITICAL",
                    "category": "ransomware",
                    "subcategory": "canary_modified",
                }
            )
    except Exception as e:
        log(f"Canary content check failed: {e}")


# ── 10. Backup service status ─────────────────────────────────────────────────


def check_backup_services(findings: List[Dict]) -> None:
    """Alert if VSS or Windows Backup services are disabled — ransomware disables them."""
    services = {"VSS": "Volume Shadow Copy", "SDRSVC": "Windows Backup"}
    for svc_name, friendly in services.items():
        raw = _ps(
            f"Get-Service -Name {svc_name} -ErrorAction SilentlyContinue "
            "| Select-Object Status, StartType | ConvertTo-Json -Compress"
        )
        if not raw:
            continue
        try:
            data = json.loads(raw)
            start_type = str(data.get("StartType", "")).lower()
            if start_type == "disabled":
                findings.append(
                    {
                        "title": f"{friendly} Service Disabled",
                        "path": f"Services — {svc_name}",
                        "reason": (
                            f"The '{friendly}' service ({svc_name}) is disabled. "
                            f"Ransomware disables backup and shadow copy services before "
                            f"encrypting to prevent recovery. Re-enable: "
                            f"Set-Service {svc_name} -StartupType Manual"
                        ),
                        "severity": "HIGH",
                        "category": "ransomware",
                        "subcategory": "backup_service_disabled",
                    }
                )
        except Exception:
            pass


# ── Main entry point ──────────────────────────────────────────────────────────


def scan_ransomware() -> List[Dict]:
    if platform.system() != "Windows":
        log("Ransomware scanner is Windows-only — skipping.")
        return []

    findings: List[Dict] = []

    checks = [
        ("Precursor processes", check_ransomware_precursor_processes),
        ("Precursor events", check_ransomware_precursor_events),
        ("Encrypted file extensions", check_encrypted_file_extensions),
        ("Ransom notes", check_ransom_notes),
        ("VSS snapshots", check_vss_snapshots),
        ("Safe-mode boot abuse", check_safeboot_registry),
        ("Ransomware autorun", check_ransomware_autorun),
        ("Mass file rename", check_mass_rename_activity),
        ("Canary file", check_canary_tampering),
        ("Backup services", check_backup_services),
    ]

    for name, fn in checks:
        try:
            fn(findings)
        except Exception as e:
            log(f"{name} check failed (non-fatal): {e}")

    log(f"Ransomware scan complete: {len(findings)} findings")
    return findings


if __name__ == "__main__":
    import sys
    import json as _json

    results = scan_ransomware()
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    results.sort(key=lambda f: sev_rank.get(f.get("severity", "INFO"), 0), reverse=True)
    print(_json.dumps({"findings": results, "total": len(results)}, indent=2))
