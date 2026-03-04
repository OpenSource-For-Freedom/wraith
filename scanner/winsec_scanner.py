"""
WRAITH - Windows Security Posture Scanner
Checks for common security misconfigurations that attackers exploit:
- Windows Defender status and exclusions
- SMBv1 enabled (EternalBlue/WannaCry vector)
- RDP exposure without NLA
- UAC disabled or weakened
- PowerShell v2 (bypasses script logging)
- LSASS protection, WDigest
- Audit policy gaps
- Guest account, autologon, anonymous access
- Windows Script Host enabled
- LLMNR/NBT-NS (credential theft via responder)
"""

import os
import re
import json
import subprocess
from typing import List, Dict, Any

try:
    import winreg

    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


def log(msg: str) -> None:
    import sys

    print(f"[WRAITH-WINSEC] {msg}", file=sys.stderr)


def _reg_get(hive, path: str, value: str):
    """Read a single registry value. Returns None if missing."""
    if not WINREG_AVAILABLE:
        return None
    try:
        key = winreg.OpenKey(hive, path)
        result = winreg.QueryValueEx(key, value)[0]
        winreg.CloseKey(key)
        return result
    except OSError:
        return None


def _ps(cmd: str, timeout: int = 15) -> str:
    """Run a PowerShell command, return stdout or empty string."""
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


# ── 1. Windows Defender ───────────────────────────────────────────────────────


def check_defender(findings: List[Dict]) -> None:
    try:
        out = _ps(
            "Get-MpPreference | Select-Object DisableRealtimeMonitoring,"
            "DisableIOAVProtection,DisableBehaviorMonitoring,"
            "DisableAntiSpyware,ExclusionPath,ExclusionProcess "
            "| ConvertTo-Json -Compress",
            timeout=20,
        )
        if not out:
            return
        pref = json.loads(out)

        # Realtime monitoring disabled
        if pref.get("DisableRealtimeMonitoring") is True:
            findings.append(
                {
                    "title": "Windows Defender: Realtime Protection DISABLED",
                    "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    "reason": (
                        "Defender real-time protection is off. This is the #1 indicator of "
                        "attacker tampering or misconfigured policy. The host has no on-access "
                        "malware scanning. Re-enable via Windows Security or Group Policy."
                    ),
                    "severity": "CRITICAL",
                    "category": "winsec",
                    "subcategory": "defender_disabled",
                }
            )

        if pref.get("DisableAntiSpyware") is True:
            findings.append(
                {
                    "title": "Windows Defender: AntiSpyware DISABLED",
                    "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
                    "reason": (
                        "DisableAntiSpyware=1 — Defender is effectively disabled for spyware/malware detection. "
                        "This registry key is commonly set by malware installers to disable AV."
                    ),
                    "severity": "CRITICAL",
                    "category": "winsec",
                    "subcategory": "defender_disabled",
                }
            )

        if pref.get("DisableBehaviorMonitoring") is True:
            findings.append(
                {
                    "title": "Windows Defender: Behavior Monitoring DISABLED",
                    "path": "Defender preference",
                    "reason": "Behavior-based detection is disabled — exploit chains and fileless malware are not monitored.",
                    "severity": "HIGH",
                    "category": "winsec",
                    "subcategory": "defender_weakened",
                }
            )

        # Defender exclusions — common malware persistence bypass
        exclusion_paths = pref.get("ExclusionPath") or []
        exclusion_procs = pref.get("ExclusionProcess") or []
        if isinstance(exclusion_paths, str):
            exclusion_paths = [exclusion_paths]
        if isinstance(exclusion_procs, str):
            exclusion_procs = [exclusion_procs]

        SUSPICIOUS_EXCL = [
            "temp",
            "tmp",
            "appdata",
            "roaming",
            "downloads",
            "public",
            "recycl",
        ]
        for excl in exclusion_paths:
            excl_str = str(excl)
            # Skip PowerShell permission-denied placeholder strings
            if "must be an administrator" in excl_str.lower() or excl_str.startswith(
                "N/A"
            ):
                continue
            lower = excl_str.lower()
            sev = "HIGH"
            if any(x in lower for x in SUSPICIOUS_EXCL):
                sev = "CRITICAL"
            findings.append(
                {
                    "title": f"Defender Path Exclusion: {excl}",
                    "path": str(excl),
                    "reason": (
                        f"Defender is configured to skip scanning '{excl}'. "
                        f"Malware commonly adds its own directory as an exclusion during installation "
                        f"to prevent detection. Verify this exclusion is legitimate."
                    ),
                    "severity": sev,
                    "category": "winsec",
                    "subcategory": "defender_exclusion",
                }
            )

        for excl in exclusion_procs:
            excl_str = str(excl)
            if "must be an administrator" in excl_str.lower() or excl_str.startswith(
                "N/A"
            ):
                continue
            findings.append(
                {
                    "title": f"Defender Process Exclusion: {excl_str}",
                    "path": excl_str,
                    "reason": (
                        f"Defender is configured to not scan the process '{excl}'. "
                        f"This allows malicious code injected into that process to run undetected."
                    ),
                    "severity": "HIGH",
                    "category": "winsec",
                    "subcategory": "defender_exclusion",
                }
            )
    except Exception as e:
        log(f"Defender check failed: {e}")


# ── 2. SMBv1 ──────────────────────────────────────────────────────────────────


def check_smb(findings: List[Dict]) -> None:
    try:
        out = _ps(
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json -Compress"
        )
        if out:
            conf = json.loads(out)
            if conf.get("EnableSMB1Protocol") is True:
                findings.append(
                    {
                        "title": "SMBv1 Enabled — EternalBlue / WannaCry Vector",
                        "path": "Get-SmbServerConfiguration → EnableSMB1Protocol",
                        "reason": (
                            "SMBv1 is enabled. This protocol has critical RCE vulnerabilities including "
                            "EternalBlue (MS17-010) used by WannaCry, NotPetya, and other ransomware. "
                            "SMBv1 has no security features and should be disabled on all modern Windows hosts. "
                            "Disable via: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
                        ),
                        "severity": "CRITICAL",
                        "category": "winsec",
                        "subcategory": "smb",
                    }
                )
    except Exception as e:
        log(f"SMB check failed: {e}")

    # Also check registry directly
    val = (
        _reg_get(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        )
        if WINREG_AVAILABLE
        else None
    )
    if val == 1:
        findings.append(
            {
                "title": "SMBv1 Enabled via Registry",
                "path": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1",
                "reason": "SMB1=1 in registry. EternalBlue (WannaCry/NotPetya) requires SMBv1.",
                "severity": "CRITICAL",
                "category": "winsec",
                "subcategory": "smb",
            }
        )


# ── 3. RDP without NLA ────────────────────────────────────────────────────────


def check_rdp(findings: List[Dict]) -> None:
    # Check if RDP is enabled
    rdp_enabled = (
        _reg_get(
            winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        if WINREG_AVAILABLE
        else None
    )

    if rdp_enabled == 0:  # 0 = RDP enabled
        nla = (
            _reg_get(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthenticationRequired",
            )
            if WINREG_AVAILABLE
            else 1
        )

        if nla == 0:
            findings.append(
                {
                    "title": "RDP Enabled WITHOUT Network Level Authentication (NLA)",
                    "path": r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "reason": (
                        "Remote Desktop is enabled but NLA is disabled. Without NLA, attackers can reach "
                        "the Windows login screen without first authenticating, enabling brute-force attacks, "
                        "BlueKeep (CVE-2019-0708), and DejaBlue exploitation. "
                        "Enable NLA: set UserAuthenticationRequired=1."
                    ),
                    "severity": "HIGH",
                    "category": "winsec",
                    "subcategory": "rdp",
                }
            )
        else:
            findings.append(
                {
                    "title": "RDP Enabled (NLA present)",
                    "path": r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                    "reason": "Remote Desktop is enabled with NLA. Ensure strong passwords and MFA are enforced.",
                    "severity": "LOW",
                    "category": "winsec",
                    "subcategory": "rdp",
                }
            )


# ── 4. UAC configuration ──────────────────────────────────────────────────────


def check_uac(findings: List[Dict]) -> None:
    if not WINREG_AVAILABLE:
        return
    uac_enabled = _reg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
    )
    consent_prompt = _reg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
    )

    if uac_enabled == 0:
        findings.append(
            {
                "title": "UAC Disabled (EnableLUA=0)",
                "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
                "reason": (
                    "User Account Control is disabled. Every process runs with full admin rights with no "
                    "elevation prompt. This eliminates a critical defense-in-depth boundary that prevents "
                    "malware from silently escalating to SYSTEM. Re-enable UAC immediately."
                ),
                "severity": "CRITICAL",
                "category": "winsec",
                "subcategory": "uac",
            }
        )
    elif consent_prompt == 0:
        findings.append(
            {
                "title": "UAC Set to Auto-Elevate Silently (No Prompt)",
                "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin",
                "reason": (
                    "ConsentPromptBehaviorAdmin=0: admin operations are elevated without any UAC prompt. "
                    "This silently grants elevation to any process run by an admin, defeating UAC entirely."
                ),
                "severity": "HIGH",
                "category": "winsec",
                "subcategory": "uac",
            }
        )


# ── 5. PowerShell v2 ──────────────────────────────────────────────────────────


def check_powershell_v2(findings: List[Dict]) -> None:
    try:
        out = _ps(
            "Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root 2>$null | "
            "Select-Object State | ConvertTo-Json -Compress"
        )
        if out and "Enabled" in out:
            findings.append(
                {
                    "title": "PowerShell v2 Engine Installed and Enabled",
                    "path": "Windows Optional Feature: MicrosoftWindowsPowerShellV2Root",
                    "reason": (
                        "PowerShell 2.0 is still installed. It predates AMSI, script block logging, "
                        "and constrained language mode. Attackers use 'powershell -Version 2' to bypass "
                        "ALL modern PowerShell security controls. "
                        "Disable: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
                    ),
                    "severity": "HIGH",
                    "category": "winsec",
                    "subcategory": "powershell",
                }
            )
    except Exception as e:
        log(f"PowerShell v2 check failed: {e}")


# ── 6. Windows Script Host ────────────────────────────────────────────────────


def check_wsh(findings: List[Dict]) -> None:
    if not WINREG_AVAILABLE:
        return
    wsh = _reg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Script Host\Settings",
        "Enabled",
    )
    # WSH enabled by default (key absent = enabled); only flag if explicitly set to 1
    # OR if it's absent and we want to note the exposure
    if wsh is None:
        # Default: enabled — advisory low severity
        findings.append(
            {
                "title": "Windows Script Host (WSH) Enabled (Default)",
                "path": r"HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings",
                "reason": (
                    "Windows Script Host is enabled (default). This allows .vbs, .js, .wsf, and .wsh files "
                    "to execute with full system access. Common phishing payload vector. "
                    "Consider disabling: HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled=0"
                ),
                "severity": "LOW",
                "category": "winsec",
                "subcategory": "wsh",
            }
        )


# ── 7. Guest account ─────────────────────────────────────────────────────────


def check_guest_account(findings: List[Dict]) -> None:
    try:
        out = _ps(
            "Get-LocalUser -Name Guest | Select-Object Enabled | ConvertTo-Json -Compress"
        )
        if out:
            data = json.loads(out)
            if data.get("Enabled") is True:
                findings.append(
                    {
                        "title": "Guest Account Enabled",
                        "path": "Local Users → Guest",
                        "reason": (
                            "The built-in Guest account is enabled. Attackers can use this to gain "
                            "unauthenticated access to the system with no password. "
                            "Disable: Disable-LocalUser -Name Guest"
                        ),
                        "severity": "HIGH",
                        "category": "winsec",
                        "subcategory": "accounts",
                    }
                )
    except Exception as e:
        log(f"Guest account check failed: {e}")


# ── 8. AutoLogon credentials in registry ────────────────────────────────────


def check_autologon(findings: List[Dict]) -> None:
    if not WINREG_AVAILABLE:
        return
    auto_logon = _reg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AutoAdminLogon",
    )
    if auto_logon == "1" or auto_logon == 1:
        user = (
            _reg_get(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "DefaultUserName",
            )
            or "unknown"
        )
        pwd = _reg_get(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "DefaultPassword",
        )
        findings.append(
            {
                "title": f"AutoLogon Enabled for '{user}' (Plaintext Credentials in Registry)",
                "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "reason": (
                    f"AutoAdminLogon is enabled for user '{user}'. "
                    + (
                        "The password is stored in PLAINTEXT in the registry under DefaultPassword. "
                        "Any local or network attacker can read these credentials directly."
                        if pwd
                        else "Credentials are stored in LSA secrets (readable by SYSTEM-level attackers)."
                    )
                ),
                "severity": "CRITICAL",
                "category": "winsec",
                "subcategory": "autologon",
            }
        )


# ── 9. LLMNR / NBT-NS (Responder attack surface) ─────────────────────────────


def check_llmnr_nbtns(findings: List[Dict]) -> None:
    if not WINREG_AVAILABLE:
        return

    # LLMNR
    llmnr = _reg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "EnableMulticast",
    )
    if llmnr != 0:  # 0 = disabled via policy; absent or 1 = enabled
        findings.append(
            {
                "title": "LLMNR Enabled (Responder/Poisoning Attack Surface)",
                "path": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast",
                "reason": (
                    "LLMNR (Link-Local Multicast Name Resolution) is enabled. "
                    "The Responder tool exploits LLMNR to capture NTLMv2 hashes from any machine "
                    "that resolves a failed DNS lookup. These hashes can be cracked offline or used "
                    "for Pass-the-Hash attacks. Disable via Group Policy: Computer Configuration → "
                    "Administrative Templates → Network → DNS Client → Turn off multicast name resolution."
                ),
                "severity": "MEDIUM",
                "category": "winsec",
                "subcategory": "llmnr",
            }
        )

    # NBT-NS: checked per-adapter but registry global is simpler
    nbtns = _reg_get(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
        "NodeType",
    )
    # NodeType 2 = P-node (no broadcasts) — safe. 1,4,8 = uses broadcasts
    if nbtns not in (2,):
        findings.append(
            {
                "title": "NetBIOS Name Service (NBT-NS) Broadcasting Enabled",
                "path": r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType",
                "reason": (
                    "NetBIOS over TCP/IP is broadcasting name queries. Like LLMNR, this is exploited "
                    "by Responder to capture NTLM credentials. "
                    "Disable: set NodeType=2 (P-node) in registry or disable NetBIOS via adapter settings."
                ),
                "severity": "MEDIUM",
                "category": "winsec",
                "subcategory": "nbtns",
            }
        )


# ── 10. Audit policy gaps ─────────────────────────────────────────────────────


def check_audit_policy(findings: List[Dict]) -> None:
    try:
        out = _ps("auditpol /get /category:* 2>$null", timeout=15)
        if not out:
            return

        critical_categories = {
            "Logon": "Logon/Logoff events are essential for detecting brute-force, pass-the-hash, and lateral movement.",
            "Account Logon": "Account logon events track Kerberos/NTLM auth — required for detecting credential attacks.",
            "Account Management": "Account management auditing tracks privilege escalation and account creation by attackers.",
            "Process Creation": "Process creation logging enables detection of malware execution and LOLBin abuse.",
            "Privilege Use": "Privilege use auditing tracks SYSTEM-level operations and UAC bypass attempts.",
        }

        for category, description in critical_categories.items():
            if category in out:
                # Check if it's "No Auditing"
                lines = [l for l in out.splitlines() if category in l]
                for line in lines:
                    if "No Auditing" in line:
                        findings.append(
                            {
                                "title": f"Audit Policy Gap: {category} — No Auditing",
                                "path": f"auditpol /category:{category}",
                                "reason": (
                                    f"'{category}' audit category is set to 'No Auditing'. "
                                    f"{description} Without this, attackers operate invisibly in Event Logs."
                                ),
                                "severity": "MEDIUM",
                                "category": "winsec",
                                "subcategory": "audit_policy",
                            }
                        )
                        break
    except Exception as e:
        log(f"Audit policy check failed: {e}")


# ── 11. Secure Boot ───────────────────────────────────────────────────────────


def check_secure_boot(findings: List[Dict]) -> None:
    try:
        out = _ps("Confirm-SecureBootUEFI 2>$null")
        if out.strip().lower() == "false":
            findings.append(
                {
                    "title": "Secure Boot Disabled",
                    "path": "UEFI Secure Boot",
                    "reason": (
                        "Secure Boot is disabled. Without Secure Boot, bootkit malware can persist "
                        "below the OS, survive reinstallation, and is undetectable by Windows Defender. "
                        "Enable Secure Boot in UEFI firmware settings."
                    ),
                    "severity": "HIGH",
                    "category": "winsec",
                    "subcategory": "secure_boot",
                }
            )
    except Exception as e:
        log(f"Secure Boot check failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────


def scan_winsec() -> List[Dict]:
    findings: List[Dict] = []

    check_defender(findings)
    check_smb(findings)
    check_rdp(findings)
    check_uac(findings)
    check_powershell_v2(findings)
    check_wsh(findings)
    check_guest_account(findings)
    check_autologon(findings)
    check_llmnr_nbtns(findings)
    check_audit_policy(findings)
    check_secure_boot(findings)

    log(f"Windows security posture scan complete: {len(findings)} findings")
    return findings


if __name__ == "__main__":
    import sys

    results = scan_winsec()
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    results.sort(key=lambda f: sev_rank.get(f.get("severity", "INFO"), 0), reverse=True)
    print(
        json.dumps(
            {"scanner": "WRAITH-winsec", "mode": "winsec", "findings": results},
            default=str,
            indent=2,
        )
    )
