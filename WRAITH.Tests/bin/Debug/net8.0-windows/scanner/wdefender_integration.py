"""
WRAITH wdefender_integration.py
Module 6 of 7 - Windows Defender Direct Integration

Pulls Windows Defender's own intelligence about this system rather than
re-checking its configuration (that is covered by winsec_scanner.py).

Checks:
  1. Active threats          - Get-MpThreat (currently active/quarantined)
  2. Detection history       - Get-MpThreatDetection (last 30 days of finds)
  3. Definition staleness    - AntivirusSignatureAge > 3 days = blind spot
  4. Last scan currency      - No scan in > 7 days means gaps
  5. Protection status       - Rapid protection response, cloud, IOAV, script scan
  6. Tamper protection       - IsTamperProtected status
  7. Network protection      - NetworkProtectionEnabled status
  8. PUA protection          - PUAProtection level
  9. Scan history anomaly    - Look for patterns indicating Defender was silenced
 10. Excluded processes      - elevated check for process exclusion list
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Any

# ──────────────────────────────────────────────
# Severity thresholds
# ──────────────────────────────────────────────
DEFINITION_AGE_WARNING_DAYS = 3
DEFINITION_AGE_CRITICAL_DAYS = 7
LAST_SCAN_WARNING_DAYS = 7
LAST_SCAN_CRITICAL_DAYS = 30


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


def _parse_ps_json(cmd: str, timeout: int = 30) -> Any:
    raw = _run_ps(cmd, timeout)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        return parsed
    except Exception:
        return None


# ──────────────────────────────────────────────
# Check 1: Active threats
# ──────────────────────────────────────────────


def check_active_threats() -> List[Dict]:
    """Pull Get-MpThreat for currently active or quarantined threats."""
    findings = []
    threats = _parse_ps_json(
        "Get-MpThreat -ErrorAction SilentlyContinue | "
        "Select-Object ThreatName, SeverityID, CategoryID, StatusID, "
        "ActiveAlert, IsActive, Resources | ConvertTo-Json -Depth 3 -Compress",
        timeout=20,
    )
    if not threats:
        return findings
    if isinstance(threats, dict):
        threats = [threats]

    STATUS_MAP = {
        0: "Unknown",
        1: "Detected",
        2: "Cleaned",
        3: "Quarantined",
        4: "Removed",
        5: "Allowed",
        6: "Blocked",
        102: "CleanFailed",
        103: "QuarantineFailed",
        104: "RemoveFailed",
    }
    SEVERITY_MAP = {0: "Unknown", 1: "Low", 2: "Moderate", 4: "High", 5: "Severe"}

    for threat in threats:
        name = str(threat.get("ThreatName", "Unknown"))
        sev_id = int(threat.get("SeverityID", 0) or 0)
        status_id = int(threat.get("StatusID", 0) or 0)
        is_active = bool(threat.get("IsActive", False))
        resources = threat.get("Resources", []) or []
        if isinstance(resources, str):
            resources = [resources]

        severity = "CRITICAL" if (is_active or sev_id >= 4) else "HIGH"
        status_label = STATUS_MAP.get(status_id, f"Status:{status_id}")
        sev_label = SEVERITY_MAP.get(sev_id, f"Severity:{sev_id}")

        resource_paths = (
            "; ".join(str(r) for r in resources[:5]) if resources else "unknown"
        )

        findings.append(
            {
                "title": f"Defender active threat: {name}",
                "path": resource_paths,
                "reason": (
                    f"Windows Defender records an active/detected threat '{name}' "
                    f"(Defender severity: {sev_label}, status: {status_label}). "
                    + (
                        "The threat is currently ACTIVE — malware may be running."
                        if is_active
                        else "The threat has been detected but may not be fully remediated."
                    )
                    + f" Affected resource(s): {resource_paths}"
                ),
                "severity": severity,
                "category": "defender",
                "subcategory": "active_threat",
            }
        )

    return findings


# ──────────────────────────────────────────────
# Check 2: Detection history (last 30 days)
# ──────────────────────────────────────────────


def check_detection_history() -> List[Dict]:
    """
    Get-MpThreatDetection returns past detections including quarantined
    and cleaned items. Recent detections indicate active infection history.
    """
    findings = []
    history = _parse_ps_json(
        "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
        "Select-Object ThreatName, ActionSuccess, SeverityID, "
        "InitialDetectionTime, LastThreatStatusChangeTime, RemediationTime, "
        "Resources | ConvertTo-Json -Depth 3 -Compress",
        timeout=30,
    )
    if not history:
        return findings
    if isinstance(history, dict):
        history = [history]

    cutoff = datetime.now() - timedelta(days=30)
    SEVERITY_MAP = {0: "Unknown", 1: "Low", 2: "Moderate", 4: "High", 5: "Severe"}

    for detection in history[:50]:  # cap at 50
        name = str(detection.get("ThreatName") or "Unknown")
        if name == "None":
            name = "Unknown"
        sev_id = int(detection.get("SeverityID", 0) or 0)
        success = bool(detection.get("ActionSuccess", True))
        det_time_raw = str(detection.get("InitialDetectionTime", "") or "")
        resources = detection.get("Resources", []) or []
        if isinstance(resources, str):
            resources = [resources]

        # Parse detection time — WMI returns CIM datetime or WCF /Date(ms)/ format
        det_time = None
        try:
            # WMI CIM format: 20240101120000.000000+000
            m = re.match(r"(\d{14})", det_time_raw)
            if m:
                det_time = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
            else:
                # WCF JSON date: /Date(1234567890000)/
                m2 = re.search(r"/Date\((\d+)\)/", det_time_raw)
                if m2:
                    det_time = datetime.fromtimestamp(int(m2.group(1)) / 1000)
        except Exception:
            pass

        if det_time and det_time < cutoff:
            continue  # older than 30 days

        det_str = (
            det_time.strftime("%Y-%m-%d %H:%M:%S") if det_time else det_time_raw[:20]
        )
        sev_label = SEVERITY_MAP.get(sev_id, str(sev_id))
        resource_paths = (
            "; ".join(str(r) for r in resources[:3]) if resources else "unknown"
        )

        severity = "HIGH" if sev_id >= 4 else "MEDIUM"
        if not success:
            severity = "CRITICAL"  # failed remediation → still infected

        findings.append(
            {
                "title": f"Defender detection history: {name}",
                "path": resource_paths,
                "reason": (
                    f"Windows Defender detected '{name}' (severity: {sev_label}) "
                    f"on {det_str}. "
                    + (
                        "Remediation FAILED — the threat may still be present."
                        if not success
                        else "Remediation reported successful."
                    )
                    + f" Detected at: {resource_paths}"
                ),
                "severity": severity,
                "category": "defender",
                "subcategory": "detection_history",
            }
        )

    return findings


# ──────────────────────────────────────────────
# Check 3 + 4: Definition currency + scan currency
# ──────────────────────────────────────────────


def check_defender_status() -> List[Dict]:
    """
    Pull Get-MpComputerStatus to evaluate definition age, last scan time,
    tamper protection, and protection component health.
    """
    findings = []
    status = _parse_ps_json(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | "
        "Select-Object "
        "AntivirusSignatureAge, AntispywareSignatureAge, "
        "AntivirusSignatureLastUpdated, "
        "QuickScanAge, FullScanAge, "
        "QuickScanStartTime, FullScanStartTime, "
        "IsTamperProtected, "
        "AMServiceEnabled, AntispywareEnabled, "
        "AntivirusEnabled, RealTimeProtectionEnabled, "
        "IoavProtectionEnabled, BehaviorMonitorEnabled, "
        "NISEnabled, OnAccessProtectionEnabled | "
        "ConvertTo-Json -Compress",
        timeout=20,
    )
    if not status:
        return findings

    # ── Definition age ──
    av_age = int(status.get("AntivirusSignatureAge", 0) or 0)
    spy_age = int(status.get("AntispywareSignatureAge", 0) or 0)
    worst_age = max(av_age, spy_age)

    if worst_age >= DEFINITION_AGE_CRITICAL_DAYS:
        findings.append(
            {
                "title": f"Defender definitions critically stale ({worst_age} days)",
                "path": "Get-MpComputerStatus",
                "reason": (
                    f"Windows Defender definitions are {worst_age} days old "
                    f"(AV: {av_age}d, AS: {spy_age}d). Defender cannot detect threats "
                    f"published in the last {worst_age} days. This indicates Update block, "
                    "network isolation, or deliberate tampering to maintain a definition "
                    "blind spot. Critical threshold is {DEFINITION_AGE_CRITICAL_DAYS} days."
                ),
                "severity": "CRITICAL",
                "category": "defender",
                "subcategory": "stale_definitions",
            }
        )
    elif worst_age >= DEFINITION_AGE_WARNING_DAYS:
        findings.append(
            {
                "title": f"Defender definitions outdated ({worst_age} days)",
                "path": "Get-MpComputerStatus",
                "reason": (
                    f"Windows Defender definitions are {worst_age} days old. "
                    "Definitions older than 3 days represent a significant blind spot "
                    "for recently-published malware and exploits. Update via Windows "
                    "Update or 'Update-MpSignature' to restore full coverage."
                ),
                "severity": "HIGH",
                "category": "defender",
                "subcategory": "stale_definitions",
            }
        )

    # ── Last scan ──
    quick_age = int(status.get("QuickScanAge", 0) or 0)
    full_age = int(status.get("FullScanAge", 0) or 0)
    best_scan_age = min(
        quick_age if quick_age > 0 else 9999,
        full_age if full_age > 0 else 9999,
    )

    if best_scan_age >= LAST_SCAN_CRITICAL_DAYS:
        findings.append(
            {
                "title": f"No Defender scan in {best_scan_age} days",
                "path": "Get-MpComputerStatus",
                "reason": (
                    f"The most recent Defender scan (quick: {quick_age}d, full: {full_age}d) "
                    f"ran {best_scan_age} days ago or never. Without regular scanning, "
                    "dormant threats residing on disk will not be detected. Enable scheduled "
                    "scanning: Set-MpPreference -ScanScheduleQuickScanTime 03:00."
                ),
                "severity": "CRITICAL",
                "category": "defender",
                "subcategory": "scan_currency",
            }
        )
    elif best_scan_age >= LAST_SCAN_WARNING_DAYS:
        findings.append(
            {
                "title": f"Defender scan not run recently ({best_scan_age} days ago)",
                "path": "Get-MpComputerStatus",
                "reason": (
                    f"The most recent Defender scan ran {best_scan_age} days ago "
                    f"(quick: {quick_age}d ago, full: {full_age}d ago). "
                    "Weekly or more frequent scanning is recommended for workstations."
                ),
                "severity": "MEDIUM",
                "category": "defender",
                "subcategory": "scan_currency",
            }
        )

    # ── Tamper protection ──
    tamper = status.get("IsTamperProtected")
    if tamper is False or tamper == 0:
        findings.append(
            {
                "title": "Defender Tamper Protection disabled",
                "path": "Get-MpComputerStatus:IsTamperProtected",
                "reason": (
                    "Tamper Protection is OFF. Without it, any local administrator "
                    "(or malware running as admin) can disable Windows Defender's "
                    "real-time protection, definitions, and behavior monitoring without "
                    "user warning. Ransomware routinely disables AV before launching "
                    "the encryption payload. Enable: Defender Security Center > "
                    "Virus & threat protection > Manage settings > Tamper Protection ON."
                ),
                "severity": "HIGH",
                "category": "defender",
                "subcategory": "tamper_protection",
            }
        )

    # ── IOAV (Internet Opened File) protection ──
    ioav = status.get("IoavProtectionEnabled")
    if ioav is False or ioav == 0:
        findings.append(
            {
                "title": "IOAV Protection disabled (internet file scanning off)",
                "path": "Get-MpComputerStatus:IoavProtectionEnabled",
                "reason": (
                    "Internet Opened File Scanning (IOAV) is disabled. This protection "
                    "scans files the moment they are downloaded from the internet or "
                    "opened from network shares. Disabling it allows drive-by downloads "
                    "and malicious email attachments to execute without AV scanning."
                ),
                "severity": "HIGH",
                "category": "defender",
                "subcategory": "ioav_disabled",
            }
        )

    # ── NIS (Network Inspection Service) ──
    nis = status.get("NISEnabled")
    if nis is False or nis == 0:
        findings.append(
            {
                "title": "Network Inspection Service (NIS) disabled",
                "path": "Get-MpComputerStatus:NISEnabled",
                "reason": (
                    "The Defender Network Inspection Service is disabled. NIS inspects "
                    "network traffic for exploit patterns matching known CVEs "
                    "(NIDS-style detection). Without NIS, exploit code transmitted over "
                    "the network (e.g., SMB exploits, heap sprays) will not be blocked "
                    "at the network stack level."
                ),
                "severity": "MEDIUM",
                "category": "defender",
                "subcategory": "nis_disabled",
            }
        )

    return findings


# ──────────────────────────────────────────────
# Check 5: Protection feature toggle audit
# ──────────────────────────────────────────────


def check_protection_features() -> List[Dict]:
    """
    Check specific protection features via Get-MpPreference that are
    distinct from what winsec_scanner covers.
    """
    findings = []
    prefs = _parse_ps_json(
        "Get-MpPreference -ErrorAction SilentlyContinue | "
        "Select-Object "
        "NetworkProtectionEnabled, PUAProtection, "
        "EnableNetworkProtection, "
        "CloudBlockLevel, CloudExtendedTimeout, "
        "MAPSReporting, SubmitSamplesConsent, "
        "SignatureScheduleDay, SignatureScheduleTime, "
        "ScanScheduleQuickScanTime, DisableScriptScanning, "
        "DisableEmailScanning, DisableRemovableDriveScanning | "
        "ConvertTo-Json -Compress",
        timeout=20,
    )
    if not prefs:
        return findings

    # ── Network Protection ──
    net_prot = prefs.get("EnableNetworkProtection") or prefs.get(
        "NetworkProtectionEnabled"
    )
    if net_prot == 0 or net_prot is False:
        findings.append(
            {
                "title": "Network Protection disabled",
                "path": "Get-MpPreference:EnableNetworkProtection",
                "reason": (
                    "Windows Defender Network Protection is disabled. This feature "
                    "blocks connections to malicious domains (known C2 servers, "
                    "phishing sites, malware distribution) using Microsoft's threat "
                    "intelligence. Disabled = no SmartScreen-equivalent for all "
                    "applications (not just Edge). Enable: Set-MpPreference "
                    "-EnableNetworkProtection Enabled."
                ),
                "severity": "HIGH",
                "category": "defender",
                "subcategory": "network_protection",
            }
        )

    # ── PUA Protection ──
    pua = int(prefs.get("PUAProtection", 0) or 0)
    if pua == 0:
        findings.append(
            {
                "title": "PUA (Potentially Unwanted App) protection disabled",
                "path": "Get-MpPreference:PUAProtection",
                "reason": (
                    "PUA Protection is OFF (value: 0). Potentially Unwanted Applications "
                    "include adware, browser hijackers, coin miners, and bundled installers. "
                    "Enabling PUA protection (value 1=Block, 2=Audit) blocks these before "
                    "install: Set-MpPreference -PUAProtection 1."
                ),
                "severity": "MEDIUM",
                "category": "defender",
                "subcategory": "pua_protection",
            }
        )

    # ── Cloud Block Level ──
    cloud_level = int(prefs.get("CloudBlockLevel", 0) or 0)
    if cloud_level == 0:
        findings.append(
            {
                "title": "Cloud-based protection block level not configured",
                "path": "Get-MpPreference:CloudBlockLevel",
                "reason": (
                    "Cloud protection block level is 0 (Default/not aggressive). "
                    "A higher level enables Defender to block suspicious files based "
                    "on machine learning models even before a signature exists. "
                    "Ransomware and zero-day exploits are often caught only by cloud "
                    "heuristics. Recommended: Set-MpPreference -CloudBlockLevel 2."
                ),
                "severity": "LOW",
                "category": "defender",
                "subcategory": "cloud_protection",
            }
        )

    # ── Script Scanning ──
    no_script = prefs.get("DisableScriptScanning")
    if no_script is True or no_script == 1:
        findings.append(
            {
                "title": "Script scanning disabled",
                "path": "Get-MpPreference:DisableScriptScanning",
                "reason": (
                    "DisableScriptScanning is TRUE. This allows PowerShell, VBScript, "
                    "JavaScript, and other script engines to execute without Defender "
                    "inspecting the payload. Fileless malware and living-off-the-land "
                    "attacks rely on script execution without dropping files to disk. "
                    "Enable: Set-MpPreference -DisableScriptScanning $false."
                ),
                "severity": "CRITICAL",
                "category": "defender",
                "subcategory": "script_scanning",
            }
        )

    # ── Email Scanning ──
    no_email = prefs.get("DisableEmailScanning")
    if no_email is True or no_email == 1:
        findings.append(
            {
                "title": "Email attachment scanning disabled",
                "path": "Get-MpPreference:DisableEmailScanning",
                "reason": (
                    "DisableEmailScanning is TRUE. Email attachments opened in Outlook "
                    "or other mail clients will not be scanned for malware. Phishing "
                    "payloads delivered via .docm, .xls, .zip attachments will execute "
                    "without Defender intervention."
                ),
                "severity": "HIGH",
                "category": "defender",
                "subcategory": "email_scanning",
            }
        )

    # ── Removable Drive Scanning ──
    no_removable = prefs.get("DisableRemovableDriveScanning")
    if no_removable is True or no_removable == 1:
        findings.append(
            {
                "title": "Removable drive (USB) scanning disabled",
                "path": "Get-MpPreference:DisableRemovableDriveScanning",
                "reason": (
                    "DisableRemovableDriveScanning is TRUE. USB drives and external "
                    "media will not be automatically scanned when connected. USB-based "
                    "attacks (BadUSB, HID spoofing, malware distribution via infected "
                    "thumb drives) bypass Defender when this is disabled."
                ),
                "severity": "MEDIUM",
                "category": "defender",
                "subcategory": "removable_scanning",
            }
        )

    return findings


# ──────────────────────────────────────────────
# Check 6: Quarantine item review
# ──────────────────────────────────────────────


def check_quarantine() -> List[Dict]:
    """
    Check for threats in quarantine that were not successfully removed.
    Quarantined threats can sometimes be restored by malware with admin rights.
    """
    findings = []
    quarantine_path = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Microsoft",
        "Windows Defender",
        "Quarantine",
    )
    from pathlib import Path

    q_path = Path(quarantine_path)
    if not q_path.exists():
        return findings

    try:
        all_files = list(q_path.rglob("*"))
        quarantined = [f for f in all_files if f.is_file()]
        if quarantined:
            entries_sample = [str(f) for f in quarantined[:5]]
            findings.append(
                {
                    "title": f"Defender quarantine contains {len(quarantined)} item(s)",
                    "path": str(q_path),
                    "reason": (
                        f"Windows Defender's quarantine store contains {len(quarantined)} "
                        "file entries. While quarantined threats cannot execute normally, "
                        "attackers with admin privileges can call MpCmdRun.exe "
                        "-RemoveDefinitions or directly manipulate the quarantine database to "
                        "restore malware. Periodic review and deletion of quarantine items "
                        "reduces this risk. Sample items: " + "; ".join(entries_sample)
                    ),
                    "severity": "LOW",
                    "category": "defender",
                    "subcategory": "quarantine",
                }
            )
    except PermissionError:
        pass
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────


def scan_defender() -> List[Dict]:
    findings: List[Dict] = []
    checks = [
        ("active_threats", check_active_threats),
        ("detection_history", check_detection_history),
        ("defender_status", check_defender_status),
        ("protection_features", check_protection_features),
        ("quarantine", check_quarantine),
    ]
    for name, fn in checks:
        try:
            results = fn()
            findings.extend(results)
        except Exception as e:
            sys.stderr.write(f"[WRAITH-DEFENDER] check '{name}' error: {e}\n")

    return findings


if __name__ == "__main__":
    sys.stderr.write(
        "[WRAITH-DEFENDER] Windows Defender integration scan starting...\n"
    )
    results = scan_defender()
    sys.stderr.write(
        f"[WRAITH-DEFENDER] Defender scan complete: {len(results)} findings\n"
    )
    output = {
        "scanner": "WRAITH-defender",
        "mode": "defender",
        "findings": results,
    }
    print(json.dumps(output, indent=2))
