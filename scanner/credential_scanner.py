"""
WRAITH credential_scanner.py
Module 7 of 7 - Credential Theft Indicators

Checks for artifacts and conditions that indicate credential theft has
occurred or is being attempted on this system.

Checks:
  1. Credential Manager    - cmdkey /list for stored plaintext-accessible creds
  2. LSASS dump artifacts  - .dmp files in temp/current dirs matching LSASS
  3. SAM backup exposure   - C:\\Windows\\Repair\\SAM, unprotected SAM copies
  4. Cached logons         - CachedLogonsCount registry (offline cracking risk)
  5. WDigest plaintext     - UseLogonCredential registry value
  6. LSA protection        - LSASS RunAsPPL status
  7. Credential Guard      - HVCI / VBS credential isolation
  8. Kerberos anomalies    - klist output for suspicious tickets / delegation
  9. Remote credential use - Windows storing credentials for remote sessions
 10. PowerShell credential  - ConvertTo-SecureString in PS history (hardcoded)
 11. Startup cred scripts  - Credential-harvesting scripts in startup locations
 12. .NET config plaintext - web.config / app.config with plaintext passwords
"""

import json
import os
import re
import subprocess
import sys
import winreg
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

# File dump patterns that indicate LSASS dumping
LSASS_DUMP_PATTERNS = [
    "lsass",
    "lsas",
    "lsa_dump",
    "lsadump",
    "memory.dmp",
    "minidump",
    "procdump",
    "full_dump",
]

# Directories where attackers drop dump files
DUMP_SEARCH_DIRS = [
    Path(os.environ.get("TEMP", r"C:\Windows\Temp")),
    Path(r"C:\Windows\Temp"),
    Path(os.environ.get("USERPROFILE", "") + r"\Desktop"),
    Path(os.environ.get("USERPROFILE", "") + r"\Downloads"),
    Path(r"C:\Users\Public"),
    Path(r"C:\PerfLogs"),  # commonly abused staging dir
    Path(r"C:\Temp"),
    Path(r"C:\Windows"),
]

# Registry paths to check for WDigest / LSA protection
LSA_REG = r"SYSTEM\CurrentControlSet\Control\Lsa"

# Regex for password patterns in text files
PASSWORD_PATTERNS = [
    re.compile(r'password\s*[=:]\s*["\']?([^\s"\'<>]{6,})', re.IGNORECASE),
    re.compile(r'pwd\s*[=:]\s*["\']?([^\s"\'<>]{6,})', re.IGNORECASE),
    re.compile(r'passwd\s*[=:]\s*["\']?([^\s"\'<>]{6,})', re.IGNORECASE),
    re.compile(
        r'connectionstring\s*=\s*["\']?.*password\s*=\s*([^;>"\']+)', re.IGNORECASE
    ),
    re.compile(r'ConvertTo-SecureString\s+["\']([^"\']{6,})["\']', re.IGNORECASE),
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


def _run_cmd(cmd: str, timeout: int = 15) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=True
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _run_ps(cmd: str, timeout: int = 20) -> str:
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


# ──────────────────────────────────────────────
# Check 1: Windows Credential Manager
# ──────────────────────────────────────────────


def check_credential_manager() -> List[Dict]:
    """
    cmdkey /list shows credentials stored in Windows Credential Manager.
    Stored credentials for domain controllers, RDP targets, and web services
    can be extracted by local attackers with DPAPI + user context.
    """
    findings = []
    out = _run_cmd("cmdkey /list")
    if not out:
        return findings

    # Parse cmdkey /list output
    entries = []
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Target:"):
            if current:
                entries.append(current)
            current = {"Target": line.split("Target:", 1)[1].strip()}
        elif line.startswith("Type:") and current:
            current["Type"] = line.split("Type:", 1)[1].strip()
        elif line.startswith("User:") and current:
            current["User"] = line.split("User:", 1)[1].strip()
    if current:
        entries.append(current)

    # High-risk credential types
    HIGH_RISK_TARGETS = [
        "domain:",
        "TERMSRV/",
        "MicrosoftOffice",
        "OneDriveMicros",
        "WindowsLive",
        "git:",
        "github",
        "bitbucket",
        "gitlab",
        ".sharepoint.",
        ".office365.",
        "azure",
    ]
    CRED_TYPE_GENERIC = "Generic"

    # Standard platform SSO tokens that are expected and low value for threat hunting.
    # These are Windows OS / Microsoft identity infrastructure — not attacker persistence.
    BENIGN_CM_PREFIXES_LOWER = (
        "sso_pop_",  # Microsoft AAD/MSA SSO pop tokens
        "microsoftaccount:target=sso_pop",
        "xblgrts|",  # Xbox Live GRTS
        "xbl|",  # Xbox Live generic
        "msa_auth:",
        "msa_oauthadal:",
        "live:cid=",  # Microsoft Live / MSA account
        "windows live",
        "microsoftaccount:",  # Generic MSA entries
        "personalcertificate:",  # Certificate-backed entries
        "windowsvault:",
        "roblox.com",  # Roblox auth (browser game — not lateral movement risk)
        "roblox",
    )

    for entry in entries:
        target = entry.get("Target", "")
        cred_type = entry.get("Type", "")
        user = entry.get("User", "")

        target_lower = target.lower()

        # Skip known Microsoft/platform SSO infrastructure tokens — these are
        # normal OS behaviour and not useful threat-hunting signals.
        if any(
            target_lower.startswith(p) or p in target_lower
            for p in BENIGN_CM_PREFIXES_LOWER
        ):
            continue

        # Flag domain, RDP, and generic remote credentials
        is_high_risk = any(h.lower() in target.lower() for h in HIGH_RISK_TARGETS)
        is_domain = "domain:" in target.lower()

        if is_domain:
            findings.append(
                {
                    "title": f"Domain credential stored: {target}",
                    "path": f"CredentialManager:{target}",
                    "reason": (
                        f"Domain credential for '{target}' (user: {user}) is stored in "
                        "Windows Credential Manager. DPAPI-protected credentials can be "
                        "decrypted by any process running as the same user without prompting. "
                        "Attackers with user-level access use Mimikatz 'vault::cred' or "
                        "SharpDPAPI to extract these as plaintext."
                    ),
                    "severity": "HIGH",
                    "category": "credential",
                    "subcategory": "credential_manager",
                }
            )
        elif is_high_risk:
            findings.append(
                {
                    "title": f"Sensitive credential stored: {target}",
                    "path": f"CredentialManager:{target}",
                    "reason": (
                        f"Credential for '{target}' (user: {user}, type: {cred_type}) is "
                        "stored in Windows Credential Manager. Git/cloud service credentials "
                        "stored here can be exfiltrated via DPAPI decryption attacks. "
                        "Consider using a dedicated credential manager with YubiKey/FIDO2 "
                        "instead of the Windows built-in vault."
                    ),
                    "severity": "MEDIUM",
                    "category": "credential",
                    "subcategory": "credential_manager",
                }
            )
        else:
            findings.append(
                {
                    "title": f"Credential stored: {target}",
                    "path": f"CredentialManager:{target}",
                    "reason": (
                        f"Credential '{target}' (user: {user}, type: {cred_type}) is stored "
                        "in Windows Credential Manager. Review whether this credential is "
                        "still needed. Stored credentials are accessible to DPAPI-aware "
                        "tools running in your user context."
                    ),
                    "severity": "LOW",
                    "category": "credential",
                    "subcategory": "credential_manager",
                }
            )

    return findings


# ──────────────────────────────────────────────
# Check 2: LSASS dump files on disk
# ──────────────────────────────────────────────


def check_lsass_dumps() -> List[Dict]:
    """
    Scan common staging directories for .dmp / .bin files whose names
    suggest they contain LSASS memory dumps.
    """
    findings = []
    threshold = datetime.now() - timedelta(days=30)

    for dump_dir in DUMP_SEARCH_DIRS:
        if not dump_dir.exists():
            continue
        try:
            for f in dump_dir.iterdir():
                if not f.is_file():
                    continue
                name_lower = f.name.lower()
                # Check extension
                if f.suffix.lower() not in (".dmp", ".bin", ".mdmp", ".txt"):
                    continue
                # Check name pattern
                if any(pat in name_lower for pat in LSASS_DUMP_PATTERNS):
                    try:
                        mtime = datetime.fromtimestamp(f.stat().st_mtime)
                        size_kb = f.stat().st_size // 1024
                        mod_str = mtime.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        mod_str = "unknown"
                        size_kb = 0

                    findings.append(
                        {
                            "title": f"Potential LSASS dump file: {f.name}",
                            "path": str(f),
                            "reason": (
                                f"File '{f}' ({size_kb} KB, modified {mod_str}) matches "
                                "LSASS memory dump naming patterns. LSASS dumps contain "
                                "all cached Windows credentials including NTLM hashes, "
                                "Kerberos tickets, and (if WDigest enabled) plaintext "
                                "passwords. Tools: ProcDump, Task Manager, comsvcs.dll. "
                                "If this file is not from legitimate crash analysis, it "
                                "should be deleted and an incident investigation begun."
                            ),
                            "severity": "CRITICAL",
                            "category": "credential",
                            "subcategory": "lsass_dump",
                        }
                    )
        except PermissionError:
            pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 3: SAM backup file exposure
# ──────────────────────────────────────────────


def check_sam_backups() -> List[Dict]:
    """
    Windows keeps old SAM/SYSTEM/SECURITY copies in C:\\Windows\\Repair
    and C:\\Windows\\System32\\config\\RegBack. These are not protected by
    the live in-use lock and can be copied/cracked offline.
    """
    findings = []
    SAM_BACKUP_PATHS = [
        Path(r"C:\Windows\Repair\SAM"),
        Path(r"C:\Windows\Repair\SYSTEM"),
        Path(r"C:\Windows\Repair\SECURITY"),
        Path(r"C:\Windows\System32\config\RegBack\SAM"),
        Path(r"C:\Windows\System32\config\RegBack\SYSTEM"),
        Path(r"C:\Windows\System32\config\RegBack\SECURITY"),
    ]
    for p in SAM_BACKUP_PATHS:
        try:
            if p.exists() and p.stat().st_size > 0:
                size_kb = p.stat().st_size // 1024
                findings.append(
                    {
                        "title": f"SAM/SECURITY backup accessible: {p.name}",
                        "path": str(p),
                        "reason": (
                            f"Registry hive backup '{p}' ({size_kb} KB) is present. "
                            "Unlike the live registry hive, backup copies do not have "
                            "a system-level read lock. Attackers use Volume Shadow Copies "
                            "or these backups to extract password hashes without admin "
                            "privileges: 'reg save HKLM\\SAM' equivalent. With SYSTEM + "
                            "SAM + SECURITY files, all local account NTLM hashes can "
                            "be extracted and cracked or used for Pass-the-Hash."
                        ),
                        "severity": "HIGH",
                        "category": "credential",
                        "subcategory": "sam_backup",
                    }
                )
        except PermissionError:
            pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 4: Cached domain logon count
# ──────────────────────────────────────────────


def check_cached_logons() -> List[Dict]:
    """
    CachedLogonsCount controls how many domain credential hashes are
    cached locally for offline logon. Each cached entry can be cracked
    using hashcat against the DCC2 (mscachev2) format.
    """
    findings = []
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        ) as k:
            try:
                count_str, _ = winreg.QueryValueEx(k, "CachedLogonsCount")
                count = int(str(count_str))
                if count > 0:
                    severity = "HIGH" if count > 5 else "MEDIUM"
                    findings.append(
                        {
                            "title": f"Domain credential caching enabled ({count} entries)",
                            "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount",
                            "reason": (
                                f"CachedLogonsCount is {count}. Windows caches the last "
                                f"{count} domain user logon hashes in the SECURITY hive "
                                r"(HKLM\SECURITY\Cache\NL$n) using the DCC2/msCacheV2 format. "
                                "These hashes can be extracted with Mimikatz (lsadump::cache) "
                                "or Creddump and cracked offline with hashcat mode 2100. "
                                "For non-laptop/offline systems, reduce to 0-2: "
                                "Set CachedLogonsCount=0 in registry."
                            ),
                            "severity": severity,
                            "category": "credential",
                            "subcategory": "cached_logons",
                        }
                    )
            except FileNotFoundError:
                pass
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Check 5: WDigest plaintext credentials
# ──────────────────────────────────────────────


def check_wdigest() -> List[Dict]:
    """
    WDigest forcing plaintext credentials in LSASS memory.
    This should be 0 (disabled) on all modern systems.
    """
    findings = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, LSA_REG) as k:
            try:
                val, _ = winreg.QueryValueEx(k, "UseLogonCredential")
                if int(val) == 1:
                    findings.append(
                        {
                            "title": "WDigest plaintext credential caching ENABLED",
                            "path": f"HKLM\\{LSA_REG}\\UseLogonCredential",
                            "reason": (
                                "UseLogonCredential=1 forces Windows to cache plaintext "
                                "user passwords in LSASS memory via the WDigest protocol. "
                                "Mimikatz 'sekurlsa::wdigest' extracts these as cleartext. "
                                "Microsoft disabled this by default in Windows 8.1/2012R2+ "
                                "(KB2871997). This value being set to 1 indicates either "
                                "a legacy application requirement or deliberate attacker "
                                "modification to enable credential harvesting at next logon."
                            ),
                            "severity": "CRITICAL",
                            "category": "credential",
                            "subcategory": "wdigest",
                        }
                    )
            except FileNotFoundError:
                pass
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Check 6: LSASS RunAsPPL protection
# ──────────────────────────────────────────────


def check_lsass_ppl() -> List[Dict]:
    """
    LSASS RunAsPPL (Protected Process Light) prevents non-PPL processes
    from reading LSASS memory. Without PPL, any local admin can dump LSASS.
    """
    findings = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, LSA_REG) as k:
            try:
                val, _ = winreg.QueryValueEx(k, "RunAsPPL")
                if int(val) == 0:
                    findings.append(
                        {
                            "title": "LSASS PPL protection disabled",
                            "path": f"HKLM\\{LSA_REG}\\RunAsPPL",
                            "reason": (
                                "RunAsPPL=0: LSASS does not run as a Protected Process. "
                                "Any local administrator process can open LSASS with "
                                "PROCESS_VM_READ and dump all credentials. Tools such as "
                                "ProcDump, Task Manager, comsvc.dll MiniDump, and Mimikatz "
                                "all rely on LSASS not being PPL-protected. Enable: "
                                "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=1 "
                                "and reboot."
                            ),
                            "severity": "HIGH",
                            "category": "credential",
                            "subcategory": "lsass_ppl",
                        }
                    )
            except FileNotFoundError:
                # Key absent = not configured = PPL disabled
                findings.append(
                    {
                        "title": "LSASS PPL protection not configured",
                        "path": f"HKLM\\{LSA_REG}",
                        "reason": (
                            "RunAsPPL registry value is absent from the LSA key. "
                            "LSASS is not running as a Protected Process Light, "
                            "leaving credential memory accessible to admin-level tools. "
                            "Add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=1 "
                            "and reboot to enable PPL protection."
                        ),
                        "severity": "MEDIUM",
                        "category": "credential",
                        "subcategory": "lsass_ppl",
                    }
                )
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Check 7: Credential Guard
# ──────────────────────────────────────────────


def check_credential_guard() -> List[Dict]:
    """
    Credential Guard (HVCI/VBS) isolates NTLM hashes and Kerberos tickets
    in a hardware-protected VM so they cannot be stolen even by SYSTEM-level code.
    """
    findings = []
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
        ) as k:
            try:
                lsacfgflags, _ = winreg.QueryValueEx(k, "LsaCfgFlags")
                if int(lsacfgflags) == 0:
                    findings.append(
                        {
                            "title": "Credential Guard not enabled via policy",
                            "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags",
                            "reason": (
                                "Credential Guard LsaCfgFlags=0 (disabled). Credential Guard "
                                "uses VBS (Virtualization Based Security) to isolate NTLM hashes "
                                "and Kerberos service tickets in a hypervisor-protected memory space. "
                                "Even domain admin or SYSTEM processes cannot read these secrets. "
                                "Highly recommended for domain-joined workstations."
                            ),
                            "severity": "MEDIUM",
                            "category": "credential",
                            "subcategory": "credential_guard",
                        }
                    )
            except FileNotFoundError:
                findings.append(
                    {
                        "title": "Credential Guard not configured",
                        "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                        "reason": (
                            "No Credential Guard (VBS) policy is configured. Without "
                            "Credential Guard, NTLM credential hashes and Kerberos tickets "
                            "in LSASS can be extracted even from a PPL-protected process "
                            "via kernel driver exploitation. Enable via Group Policy: "
                            "Computer Configuration > Administrative Templates > System > "
                            "Device Guard > Turn On Virtualization Based Security."
                        ),
                        "severity": "LOW",
                        "category": "credential",
                        "subcategory": "credential_guard",
                    }
                )
    except FileNotFoundError:
        findings.append(
            {
                "title": "Credential Guard not configured",
                "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                "reason": (
                    "DeviceGuard policy key is absent. Credential Guard is not configured. "
                    "VBS-based credential isolation is not active."
                ),
                "severity": "LOW",
                "category": "credential",
                "subcategory": "credential_guard",
            }
        )
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Check 8: PowerShell command history for hardcoded credentials
# ──────────────────────────────────────────────


def check_ps_history() -> List[Dict]:
    """
    Scan PowerShell history files for ConvertTo-SecureString or
    -Password flags with embedded credentials.
    """
    findings = []
    ps_history_paths = []

    # Per-user PSReadLine history
    userprofile = Path(os.environ.get("USERPROFILE", ""))
    default_history = (
        userprofile
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "PowerShell"
        / "PSReadLine"
        / "ConsoleHost_history.txt"
    )
    if default_history.exists():
        ps_history_paths.append(default_history)

    # Also check profiles for other users (if admin)
    users_dir = Path(r"C:\Users")
    if users_dir.exists():
        for user_dir in users_dir.iterdir():
            h = (
                user_dir
                / "AppData"
                / "Roaming"
                / "Microsoft"
                / "Windows"
                / "PowerShell"
                / "PSReadLine"
                / "ConsoleHost_history.txt"
            )
            if h.exists() and h not in ps_history_paths:
                ps_history_paths.append(h)

    for hist_file in ps_history_paths:
        try:
            content = hist_file.read_text(encoding="utf-8", errors="ignore")
            for pattern in PASSWORD_PATTERNS:
                for match in pattern.finditer(content):
                    # Find line context
                    line_start = content.rfind("\n", 0, match.start()) + 1
                    line_end = content.find("\n", match.end())
                    line_text = content[
                        line_start : line_end if line_end > 0 else len(content)
                    ].strip()
                    # Redact the actual password value
                    safe_line = line_text[:80] + ("..." if len(line_text) > 80 else "")
                    findings.append(
                        {
                            "title": f"Hardcoded credential in PS history: {hist_file.name}",
                            "path": str(hist_file),
                            "reason": (
                                f"PowerShell history file '{hist_file}' contains a "
                                "potential hardcoded credential pattern. Command context: "
                                f"'{safe_line}'. Credentials embedded in command history "
                                "persist in plaintext on disk and are readable by any process "
                                "with user-level file access. Delete history: "
                                "Remove-Item (Get-PSReadLineOption).HistorySavePath"
                            ),
                            "severity": "HIGH",
                            "category": "credential",
                            "subcategory": "ps_history",
                        }
                    )
                    if len(findings) > 10:
                        return findings  # cap noisy output
        except PermissionError:
            pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 9: .NET / web application config plaintext
# ──────────────────────────────────────────────


def check_config_passwords() -> List[Dict]:
    """
    Scan common web.config / app.config / *.config locations for
    plaintext password patterns in connection strings.
    """
    findings = []
    CONFIG_SEARCH_DIRS = [
        Path(r"C:\inetpub"),
        Path(r"C:\Websites"),
        Path(os.environ.get("APPDATA", "") + r"\IIS Express"),
    ]

    for search_dir in CONFIG_SEARCH_DIRS:
        if not search_dir.exists():
            continue
        try:
            for cfg_file in search_dir.rglob("*.config"):
                if cfg_file.stat().st_size > 1_000_000:  # skip files > 1 MB
                    continue
                try:
                    content = cfg_file.read_text(encoding="utf-8", errors="ignore")
                    for pattern in PASSWORD_PATTERNS[
                        :3
                    ]:  # only connection string patterns
                        if pattern.search(content):
                            findings.append(
                                {
                                    "title": f"Plaintext password in config: {cfg_file.name}",
                                    "path": str(cfg_file),
                                    "reason": (
                                        f"Configuration file '{cfg_file}' contains a pattern "
                                        "matching a plaintext password or connection string with "
                                        "embedded credentials. Web app config files with plaintext "
                                        "database or service passwords are a critical exposure — "
                                        "IIS worker process, application pool accounts, or any "
                                        "user with file read access can obtain the credentials. "
                                        "Use DPAPI-protected config sections or a secret manager."
                                    ),
                                    "severity": "HIGH",
                                    "category": "credential",
                                    "subcategory": "config_password",
                                }
                            )
                            break
                except Exception:
                    pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────


def scan_credentials() -> List[Dict]:
    findings: List[Dict] = []
    checks = [
        ("credential_manager", check_credential_manager),
        ("lsass_dumps", check_lsass_dumps),
        ("sam_backups", check_sam_backups),
        ("cached_logons", check_cached_logons),
        ("wdigest", check_wdigest),
        ("lsass_ppl", check_lsass_ppl),
        ("credential_guard", check_credential_guard),
        ("ps_history", check_ps_history),
        ("config_passwords", check_config_passwords),
    ]
    for name, fn in checks:
        try:
            results = fn()
            findings.extend(results)
        except Exception as e:
            sys.stderr.write(f"[WRAITH-CRED] check '{name}' error: {e}\n")

    return findings


if __name__ == "__main__":
    sys.stderr.write("[WRAITH-CRED] Credential theft indicators scan starting...\n")
    results = scan_credentials()
    sys.stderr.write(
        f"[WRAITH-CRED] Credential scan complete: {len(results)} findings\n"
    )
    output = {
        "scanner": "WRAITH-credential",
        "mode": "credential",
        "findings": results,
    }
    print(json.dumps(output, indent=2))
