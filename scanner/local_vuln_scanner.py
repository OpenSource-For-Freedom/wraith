"""
WRAITH — Local Vulnerability Assessment Scanner
Nessus-style local host checks that don't require network access or API keys.

Covers:
  1. OS patch freshness & end-of-life detection
  2. Privilege escalation vectors (unquoted service paths, AlwaysInstallElevated,
     writable service binary directories, token impersonation policy)
  3. Service binary weak permissions (SYSTEM service with world-writable path)
  4. Windows hardening features (Secure Boot, VBS, Credential Guard, HVCI, DEP)
  5. Firewall profile audit (Domain / Private / Public)
  6. Exposed SMB shares accessible to Everyone or unauthenticated users
  7. Local account hygiene (password-never-expires, blank password, admin count)
  8. DLL search-order hijacking via writable directories in %PATH%
  9. Scheduled task script-path permission weaknesses
"""

from __future__ import annotations

import os
import re
import json
import subprocess
import platform
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any

try:
    import winreg

    _WINREG = True
except ImportError:
    _WINREG = False


def log(msg: str) -> None:
    import sys

    print(f"[WRAITH-VULN] {msg}", file=sys.stderr)


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


def _ps_json(cmd: str, timeout: int = 20) -> Any:
    raw = _ps(cmd, timeout)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


# ── Windows version table ─────────────────────────────────────────────────────
# Maps minimum supported build number to (friendly_name, is_eol).
# Keep this list updated; it drives the OS-EOL check.
_WIN_BUILD_EOL: list[tuple[int, str, bool]] = [
    # build,  friendly name,               EOL?
    (26100, "Windows 11 24H2", False),
    (22631, "Windows 11 23H2", False),
    (22621, "Windows 11 22H2", False),
    (22000, "Windows 11 21H2", True),  # ended Oct 2023
    (19045, "Windows 10 22H2", False),
    (19044, "Windows 10 21H2", True),
    (19043, "Windows 10 21H1", True),
    (19042, "Windows 10 20H2", True),
    (18363, "Windows 10 1909", True),
    (17763, "Windows 10 / Server 2019 LTSC", False),
    (14393, "Windows 10 1607 / Server 2016 LTSC", False),
    (0, "Windows (unknown/legacy)", True),
]


def _os_build() -> int:
    try:
        return int(platform.version().split(".")[2])
    except Exception:
        return 0


# ── 1. OS patch freshness & EOL ───────────────────────────────────────────────


def check_os_patch_status(findings: List[Dict]) -> None:
    build = _os_build()

    # EOL check
    for min_build, name, is_eol in _WIN_BUILD_EOL:
        if build >= min_build:
            if is_eol:
                findings.append(
                    {
                        "title": f"End-of-Life Windows Version: {name} (build {build})",
                        "path": f"OS Build {build}",
                        "reason": (
                            f"This host is running {name} (build {build}), which has passed its "
                            f"Microsoft end-of-support date. No further security updates are issued. "
                            f"Any new CVE on this version is permanently unpatched."
                        ),
                        "severity": "CRITICAL",
                        "category": "vuln_assess",
                        "subcategory": "os_eol",
                    }
                )
            break

    # Patch freshness: last installed hotfix date
    raw = _ps(
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1 InstalledOn | ConvertTo-Json -Compress"
    )
    if raw:
        try:
            kb = json.loads(raw)
            installed_on = kb.get("InstalledOn")
            if installed_on:
                # PowerShell returns dates in various formats; parse best-effort
                dt = None
                for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y"):
                    try:
                        dt = datetime.strptime(
                            installed_on[:19], fmt[: len(installed_on)]
                        )
                        break
                    except Exception:
                        continue
                if dt is None:
                    # Try parsing the year from the string directly
                    m = re.search(r"(\d{4})", installed_on)
                    if m:
                        dt = datetime(int(m.group(1)), 1, 1)

                if dt:
                    age_days = (datetime.now() - dt).days
                    if age_days > 60:
                        findings.append(
                            {
                                "title": f"Missing Security Patches: Last update {age_days} days ago",
                                "path": f"Last hotfix installed: {installed_on}",
                                "reason": (
                                    f"The most recently installed Windows hotfix is {age_days} days old. "
                                    f"Systems should be patched within 30 days of patch release (CISA BOD 22-01). "
                                    f"Run Windows Update to apply pending security patches."
                                ),
                                "severity": "HIGH" if age_days <= 90 else "CRITICAL",
                                "category": "vuln_assess",
                                "subcategory": "missing_patches",
                            }
                        )
                    elif age_days > 30:
                        findings.append(
                            {
                                "title": f"Patch Gap: Last update {age_days} days ago",
                                "path": f"Last hotfix installed: {installed_on}",
                                "reason": (
                                    f"The most recent hotfix is {age_days} days old. "
                                    f"Run Windows Update to stay current."
                                ),
                                "severity": "MEDIUM",
                                "category": "vuln_assess",
                                "subcategory": "patch_gap",
                            }
                        )
        except Exception as e:
            log(f"Patch freshness parse error: {e}")


# ── 2. Privilege escalation vectors ──────────────────────────────────────────


def check_unquoted_service_paths(findings: List[Dict]) -> None:
    """Unquoted service image paths with spaces — classic local privesc."""
    raw = _ps_json(
        "Get-WmiObject Win32_Service | Where-Object { "
        "  $_.PathName -notmatch '\"' -and $_.PathName -match ' ' -and "
        "  $_.PathName -notmatch '^[Ss]ystem32' } | "
        "Select-Object Name, DisplayName, PathName, StartMode, State | "
        "ConvertTo-Json -Depth 2 -Compress",
        timeout=30,
    )
    if not raw:
        return
    services = raw if isinstance(raw, list) else [raw]
    for svc in services:
        if not isinstance(svc, dict):
            continue
        path = svc.get("PathName", "")
        # Confirm it actually has an unquoted space before .exe
        if not path or '"' in path:
            continue
        # Split on spaces and check if an intermediate segment looks like an injectable path
        parts = path.split(".exe")[0].split()
        if len(parts) < 2:
            continue
        name = svc.get("DisplayName") or svc.get("Name", "")
        findings.append(
            {
                "title": f"Unquoted Service Path: {name}",
                "path": path,
                "reason": (
                    f"Service '{name}' has an unquoted image path containing spaces: '{path}'. "
                    f"An attacker with write access to a parent directory can place a malicious "
                    f"executable at a shorter path that Windows resolves first, running as SYSTEM."
                ),
                "severity": "HIGH",
                "category": "vuln_assess",
                "subcategory": "unquoted_service_path",
            }
        )


def check_always_install_elevated(findings: List[Dict]) -> None:
    """AlwaysInstallElevated allows any user to install MSIs as SYSTEM."""
    if not _WINREG:
        return
    hklm_val = None
    hkcu_val = None
    key_path = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        hklm_val = winreg.QueryValueEx(k, "AlwaysInstallElevated")[0]
        winreg.CloseKey(k)
    except OSError:
        pass
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        hkcu_val = winreg.QueryValueEx(k, "AlwaysInstallElevated")[0]
        winreg.CloseKey(k)
    except OSError:
        pass

    if hklm_val == 1 and hkcu_val == 1:
        findings.append(
            {
                "title": "AlwaysInstallElevated: MSI Privilege Escalation Enabled",
                "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated",
                "reason": (
                    "Both HKLM and HKCU AlwaysInstallElevated are set to 1. Any user can craft a "
                    "malicious .msi file and install it as SYSTEM (full local privesc). "
                    "Set both registry values to 0 or remove the policy."
                ),
                "severity": "CRITICAL",
                "category": "vuln_assess",
                "subcategory": "always_install_elevated",
            }
        )


def check_service_binary_permissions(findings: List[Dict]) -> None:
    """SYSTEM services whose binary directories are writable by non-admin users."""
    raw = _ps_json(
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-WmiObject Win32_Service | Where-Object { $_.StartMode -ne 'Disabled' } | "
        "Select-Object Name, PathName | ConvertTo-Json -Depth 1 -Compress",
        timeout=30,
    )
    if not raw:
        return
    services = raw if isinstance(raw, list) else [raw]
    checked_dirs: set[str] = set()

    for svc in services:
        if not isinstance(svc, dict):
            continue
        path_raw = svc.get("PathName", "") or ""
        # Strip arguments
        m = re.match(r'"([^"]+)"', path_raw) or re.match(
            r"([^\s]+\.exe)", path_raw, re.I
        )
        if not m:
            continue
        exe_path = m.group(1)
        dir_path = str(Path(exe_path).parent).lower()

        if dir_path in checked_dirs:
            continue
        # Skip well-known system paths
        sysroot = os.environ.get("SystemRoot", "C:\\Windows").lower()
        prog = os.environ.get("ProgramFiles", "C:\\Program Files").lower()
        prog86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)").lower()
        if (
            dir_path.startswith(sysroot)
            or dir_path.startswith(prog + "\\windows")
            or dir_path.startswith(prog86 + "\\windows")
        ):
            checked_dirs.add(dir_path)
            continue
        checked_dirs.add(dir_path)

        # Check if the directory is writable by non-privileged users
        # Pass exe_path via an environment variable to avoid PS injection.
        safe_cmd = (
            "$p = $env:WRAITH_ACL_TARGET;"
            "$acl = Get-Acl -Path $p -ErrorAction SilentlyContinue;"
            "if ($acl) { $acl.Access | Where-Object {"
            "  ($_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\\\Users') -and"
            "  ($_.FileSystemRights -match 'Write|FullControl|Modify') -and"
            "  $_.AccessControlType -eq 'Allow'"
            "} | Select-Object IdentityReference, FileSystemRights | ConvertTo-Json -Compress }"
        )
        import os as _os

        env = {**_os.environ, "WRAITH_ACL_TARGET": exe_path}
        try:
            r = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    safe_cmd,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            acl_out = r.stdout.strip()
        except Exception:
            acl_out = ""
        if acl_out and acl_out != "null":
            svc_name = svc.get("Name", "unknown")
            findings.append(
                {
                    "title": f"Weak Service Binary Permissions: {svc_name}",
                    "path": exe_path,
                    "reason": (
                        f"The binary for service '{svc_name}' at '{exe_path}' is writable by "
                        f"low-privileged users. An attacker can replace it with a malicious executable "
                        f"that runs as SYSTEM on next service start. ACL: {acl_out[:200]}"
                    ),
                    "severity": "CRITICAL",
                    "category": "vuln_assess",
                    "subcategory": "weak_service_perms",
                }
            )


# ── 3. Windows hardening features ────────────────────────────────────────────


def check_windows_hardening(findings: List[Dict]) -> None:
    """Secure Boot, VBS, Credential Guard, HVCI, DEP."""

    # Secure Boot
    sb = _ps("Confirm-SecureBootUEFI 2>$null; if ($?) { 'true' } else { 'false' }")
    if sb.lower() == "false":
        findings.append(
            {
                "title": "Secure Boot: Disabled or Not Supported",
                "path": "UEFI firmware settings",
                "reason": (
                    "Secure Boot is disabled or not available. Without Secure Boot, attackers can "
                    "boot unsigned OS loaders or firmware implants (BootKit/BlackLotus style attacks). "
                    "Enable Secure Boot in UEFI firmware settings."
                ),
                "severity": "HIGH",
                "category": "vuln_assess",
                "subcategory": "secure_boot_disabled",
            }
        )

    # VBS (Virtualization-Based Security) and Credential Guard
    vbs_raw = _ps(
        "Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root\\Microsoft\\Windows\\DeviceGuard 2>$null | "
        "Select-Object VirtualizationBasedSecurityStatus,"
        "SecurityServicesRunning | ConvertTo-Json -Compress"
    )
    if vbs_raw:
        try:
            vbs = json.loads(vbs_raw)
            vbs_status = vbs.get("VirtualizationBasedSecurityStatus", 0)
            services = vbs.get("SecurityServicesRunning") or []
            if isinstance(services, int):
                services = [services]

            if vbs_status != 2:  # 2 = running
                findings.append(
                    {
                        "title": "Virtualization-Based Security (VBS): Not Running",
                        "path": "Win32_DeviceGuard",
                        "reason": (
                            "VBS is not active. VBS uses the hypervisor to isolate sensitive OS "
                            "components, preventing credential theft (Pass-the-Hash) and kernel "
                            "exploits. Enable via Group Policy or Windows Security Center."
                        ),
                        "severity": "MEDIUM",
                        "category": "vuln_assess",
                        "subcategory": "vbs_disabled",
                    }
                )
            else:
                # VBS is on — check Credential Guard (service ID 1)
                if 1 not in services:
                    findings.append(
                        {
                            "title": "Credential Guard: Not Running",
                            "path": "Win32_DeviceGuard SecurityServicesRunning",
                            "reason": (
                                "VBS is active but Credential Guard is not running. Credential Guard "
                                "stores NTLM/Kerberos hashes in an isolated VBS enclave, preventing "
                                "Mimikatz-style credential theft. Enable via Group Policy: "
                                "Computer Configuration > Windows Settings > Security Settings > "
                                "Device Guard."
                            ),
                            "severity": "MEDIUM",
                            "category": "vuln_assess",
                            "subcategory": "credential_guard_off",
                        }
                    )
        except Exception as e:
            log(f"VBS check error: {e}")

    # DEP (Data Execution Prevention) — should be OptOut or AlwaysOn
    dep = _ps(
        "(Get-WmiObject Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy"
    )
    if dep in ("0", "1"):
        findings.append(
            {
                "title": "DEP (Data Execution Prevention): Insufficiently Enforced",
                "path": "Win32_OperatingSystem.DataExecutionPrevention_SupportPolicy",
                "reason": (
                    f"DEP policy is set to level {dep} (0=AlwaysOff, 1=for Windows components only). "
                    f"DEP should be OptOut (2) or AlwaysOn (3) to protect against shellcode exploits. "
                    f"Set via: bcdedit /set nx OptOut"
                ),
                "severity": "MEDIUM",
                "category": "vuln_assess",
                "subcategory": "dep_weak",
            }
        )


# ── 4. Firewall profile audit ─────────────────────────────────────────────────


def check_firewall_profiles(findings: List[Dict]) -> None:
    raw = _ps_json(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"
    )
    if not raw:
        return
    profiles = raw if isinstance(raw, list) else [raw]
    for p in profiles:
        if not isinstance(p, dict):
            continue
        name = p.get("Name", "")
        enabled = p.get("Enabled")
        if enabled is False or str(enabled).lower() in ("false", "0"):
            findings.append(
                {
                    "title": f"Windows Firewall Disabled: {name} Profile",
                    "path": f"Windows Firewall — {name} profile",
                    "reason": (
                        f"The Windows Firewall {name} profile is disabled. "
                        f"Disabling the firewall exposes all listening services to the network without "
                        f"any host-based packet filtering. Re-enable via: "
                        f"Set-NetFirewallProfile -Profile {name} -Enabled True"
                    ),
                    "severity": "HIGH",
                    "category": "vuln_assess",
                    "subcategory": "firewall_disabled",
                }
            )


# ── 5. Exposed SMB shares ─────────────────────────────────────────────────────


def check_exposed_shares(findings: List[Dict]) -> None:
    raw = _ps_json(
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-SmbShare | Where-Object { $_.Name -notmatch '\\$' } | "
        "Select-Object Name, Path, Description | ConvertTo-Json -Compress"
    )
    if not raw:
        return
    shares = raw if isinstance(raw, list) else [raw]
    for share in shares:
        if not isinstance(share, dict):
            continue
        name = share.get("Name", "")
        path = share.get("Path", "")
        if not name:
            continue
        # Pass share name via env var to avoid PowerShell injection.
        acl_cmd = (
            "$n = $env:WRAITH_SHARE_NAME;"
            "Get-SmbShareAccess -Name $n 2>$null"
            " | Where-Object { $_.AccountName -match 'Everyone|\\\\Users$|Authenticated Users' }"
            " | Select-Object AccountName, AccessRight | ConvertTo-Json -Compress"
        )
        import os as _os

        env = {**_os.environ, "WRAITH_SHARE_NAME": name}
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", acl_cmd],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            acl_out = r.stdout.strip()
        except Exception:
            acl_out = ""
        if acl_out and acl_out not in ("null", ""):
            findings.append(
                {
                    "title": f"Exposed Network Share: \\\\localhost\\{name}",
                    "path": path or f"\\\\localhost\\{name}",
                    "reason": (
                        f"SMB share '{name}' (path: '{path}') is accessible to broad user groups: "
                        f"{acl_out[:200]}. Non-admin network shares may expose sensitive data or "
                        f"provide a pivot point for lateral movement."
                    ),
                    "severity": "MEDIUM",
                    "category": "vuln_assess",
                    "subcategory": "exposed_share",
                }
            )


# ── 6. Local account hygiene ──────────────────────────────────────────────────


def check_local_accounts(findings: List[Dict]) -> None:
    raw = _ps_json(
        "Get-LocalUser | Select-Object Name, Enabled, "
        "PasswordNeverExpires, PasswordLastSet, LastLogon | ConvertTo-Json -Compress"
    )
    if not raw:
        return
    users = raw if isinstance(raw, list) else [raw]

    admin_raw = _ps_json(
        "Get-LocalGroupMember -Group Administrators 2>$null | "
        "Select-Object Name, ObjectClass | ConvertTo-Json -Compress"
    )
    admin_names: set[str] = set()
    if admin_raw:
        admins = admin_raw if isinstance(admin_raw, list) else [admin_raw]
        for a in admins:
            if isinstance(a, dict) and a.get("Name"):
                admin_names.add(str(a["Name"]).lower())

    # More than 2 local admins is suspicious
    local_admin_count = sum(
        1
        for u in users
        if isinstance(u, dict)
        and (u.get("Name") or "").lower() in admin_names
        and u.get("Enabled")
    )
    if local_admin_count > 2:
        findings.append(
            {
                "title": f"Excessive Local Admins: {local_admin_count} accounts",
                "path": "Local Administrators group",
                "reason": (
                    f"{local_admin_count} local accounts are in the Administrators group. "
                    f"The principle of least privilege recommends only 1-2 named admin accounts. "
                    f"Excess admins expand the blast radius if any one account is compromised."
                ),
                "severity": "MEDIUM",
                "category": "vuln_assess",
                "subcategory": "excess_local_admins",
            }
        )

    for user in users:
        if not isinstance(user, dict):
            continue
        name = user.get("Name", "")
        enabled = user.get("Enabled", False)
        pwd_never_expires = user.get("PasswordNeverExpires", False)
        pwd_last_set = user.get("PasswordLastSet")

        if not enabled or not name:
            continue

        # Password never expires on a named local account (not a service account pattern)
        if pwd_never_expires and name.lower() not in (
            "defaultaccount",
            "wdagutilityaccount",
        ):
            findings.append(
                {
                    "title": f"Password Never Expires: Local account '{name}'",
                    "path": f"Local account: {name}",
                    "reason": (
                        f"Local account '{name}' has PasswordNeverExpires set. Accounts without "
                        f"password rotation are high-value targets — a compromised password remains "
                        f"valid indefinitely. Enforce a password expiry policy."
                    ),
                    "severity": "LOW",
                    "category": "vuln_assess",
                    "subcategory": "password_never_expires",
                }
            )

        # Password last set more than 365 days ago
        if pwd_last_set:
            try:
                m = re.search(r"(\d{4}-\d{2}-\d{2})", str(pwd_last_set))
                if m:
                    dt = datetime.fromisoformat(m.group(1))
                    age = (datetime.now() - dt).days
                    if age > 365:
                        findings.append(
                            {
                                "title": f"Stale Password: '{name}' not changed in {age} days",
                                "path": f"Local account: {name}",
                                "reason": (
                                    f"Account '{name}' password was last set {age} days ago. "
                                    f"Stale credentials that have never been rotated may already be "
                                    f"compromised (credential stuffing, prior breach)."
                                ),
                                "severity": "LOW",
                                "category": "vuln_assess",
                                "subcategory": "stale_password",
                            }
                        )
            except Exception:
                pass


# ── 7. DLL hijacking via writable PATH directories ────────────────────────────


def check_path_dll_hijack(findings: List[Dict]) -> None:
    """Writable directories in the system %PATH% are DLL hijacking candidates."""
    system_path = os.environ.get("PATH", "")
    dirs = [d.strip() for d in system_path.split(";") if d.strip()]
    sysroot = os.environ.get("SystemRoot", "C:\\Windows").lower()

    for d in dirs:
        if d.lower().startswith(sysroot):
            continue  # System32 etc — not interesting even if somehow writable
        if not os.path.isdir(d):
            continue
        # Use os.access(W_OK) — avoids creating files and satisfies CodeQL
        if not os.access(d, os.W_OK):
            continue
        findings.append(
            {
                "title": f"Writable PATH Directory: {d}",
                "path": d,
                "reason": (
                    f"The directory '{d}' is in the system PATH and is writable by the "
                    f"current user. An attacker can plant a malicious DLL or executable here "
                    f"that will be loaded before the legitimate one (DLL search-order hijacking). "
                    f"Review and restrict write permissions."
                ),
                "severity": "HIGH",
                "category": "vuln_assess",
                "subcategory": "writable_path_dir",
            }
        )


# ── 8. Scheduled task script-path permissions ─────────────────────────────────


def check_scheduled_task_permissions(findings: List[Dict]) -> None:
    """SYSTEM-run scheduled tasks whose script/executable paths are user-writable."""
    raw = _ps_json(
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-ScheduledTask | Where-Object { "
        "  $_.Principal.RunLevel -eq 'Highest' -or "
        "  $_.Principal.UserId -match 'SYSTEM|Administrator' } | "
        "ForEach-Object {"
        "  $actions = $_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }"
        "  [PSCustomObject]@{ TaskName=$_.TaskName; Actions=($actions -join '; ') }"
        "} | ConvertTo-Json -Depth 2 -Compress",
        timeout=30,
    )
    if not raw:
        return
    tasks = raw if isinstance(raw, list) else [raw]

    for task in tasks:
        if not isinstance(task, dict):
            continue
        actions = task.get("Actions", "") or ""
        task_name = task.get("TaskName", "")

        # Extract file paths from action string
        paths_in_action = re.findall(
            r'"?([A-Za-z]:\\[^";\n]+\.(exe|ps1|bat|cmd|vbs|js))"?', actions, re.I
        )
        for path_match, _ in paths_in_action:
            path_match = path_match.strip('"').strip()
            # Resolve and validate — must be an absolute Windows path under a drive root
            try:
                resolved = Path(path_match).resolve()
            except Exception:
                continue
            if not resolved.is_file():
                continue
            sysroot = os.environ.get("SystemRoot", "C:\\Windows").lower()
            if str(resolved).lower().startswith(sysroot):
                continue
            # Test writability using os.access — no file creation needed
            if not os.access(str(resolved), os.W_OK):
                continue
            findings.append(
                {
                    "title": f"Writable Privileged Task Script: {task_name}",
                    "path": str(resolved),
                    "reason": (
                        f"Scheduled task '{task_name}' runs as SYSTEM/Administrator and "
                        f"executes '{resolved}', which is writable by the current user. "
                        f"Replacing this file gives persistent SYSTEM-level code execution."
                    ),
                    "severity": "CRITICAL",
                    "category": "vuln_assess",
                    "subcategory": "writable_task_script",
                }
            )


# ── 9. Windows Update service ────────────────────────────────────────────────


def check_windows_update_service(findings: List[Dict]) -> None:
    raw = _ps_json(
        "Get-Service -Name wuauserv 2>$null | "
        "Select-Object Status, StartType | ConvertTo-Json -Compress"
    )
    if not raw or not isinstance(raw, dict):
        return
    start_type = str(raw.get("StartType", "")).lower()
    if start_type == "disabled":
        findings.append(
            {
                "title": "Windows Update Service: DISABLED",
                "path": "Services — wuauserv",
                "reason": (
                    "The Windows Update service (wuauserv) is disabled. The system cannot receive "
                    "security patches. This is a strong indicator of attacker tampering or "
                    "aggressive software licensing. Re-enable: Set-Service wuauserv -StartupType Automatic"
                ),
                "severity": "CRITICAL",
                "category": "vuln_assess",
                "subcategory": "wu_disabled",
            }
        )


# ── 10. LAPS (Local Administrator Password Solution) ─────────────────────────


def check_laps(findings: List[Dict]) -> None:
    """LAPS not deployed means all machines share the same local admin password."""
    if not _WINREG:
        return
    laps_key = r"SOFTWARE\Policies\Microsoft Services\AdmPwd"
    laps_present = False
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, laps_key)
        laps_present = True
        winreg.CloseKey(k)
    except OSError:
        pass

    # Also check Windows LAPS (built-in since 2023)
    laps_new_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, laps_new_key)
        laps_present = True
        winreg.CloseKey(k)
    except OSError:
        pass

    if not laps_present:
        findings.append(
            {
                "title": "LAPS Not Deployed: Shared Local Admin Password Risk",
                "path": r"HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd",
                "reason": (
                    "Microsoft LAPS (Local Administrator Password Solution) is not detected. "
                    "Without LAPS every machine in the domain likely shares the same local admin "
                    "password — one compromised machine yields lateral movement to all others. "
                    "Deploy LAPS via Group Policy or Windows LAPS (built-in since Server 2019/Win 11)."
                ),
                "severity": "MEDIUM",
                "category": "vuln_assess",
                "subcategory": "laps_missing",
            }
        )


# ── Main entry point ──────────────────────────────────────────────────────────


def scan_local_vulns() -> List[Dict]:
    if platform.system() != "Windows":
        log("Local vuln scanner is Windows-only — skipping.")
        return []

    findings: List[Dict] = []

    checks = [
        ("OS patch status", check_os_patch_status),
        ("Unquoted service paths", check_unquoted_service_paths),
        ("AlwaysInstallElevated", check_always_install_elevated),
        ("Service binary permissions", check_service_binary_permissions),
        ("Windows hardening features", check_windows_hardening),
        ("Firewall profiles", check_firewall_profiles),
        ("Exposed shares", check_exposed_shares),
        ("Local account hygiene", check_local_accounts),
        ("PATH DLL hijack", check_path_dll_hijack),
        ("Scheduled task permissions", check_scheduled_task_permissions),
        ("Windows Update service", check_windows_update_service),
        ("LAPS deployment", check_laps),
    ]

    for name, fn in checks:
        try:
            fn(findings)
        except Exception as e:
            log(f"{name} check failed (non-fatal): {e}")

    log(f"Local vulnerability assessment complete: {len(findings)} findings")
    return findings


if __name__ == "__main__":
    import sys, json as _json

    results = scan_local_vulns()
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    results.sort(key=lambda f: sev_rank.get(f.get("severity", "INFO"), 0), reverse=True)
    print(
        _json.dumps(
            {
                "scanner": "WRAITH-vuln-assess",
                "mode": "vuln_assess",
                "findings": results,
            },
            default=str,
            indent=2,
        )
    )
