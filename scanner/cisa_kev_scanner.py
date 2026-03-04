"""
WRAITH - CISA Known Exploited Vulnerabilities (KEV) Scanner
Downloads the live CISA KEV catalog and checks this Windows host for:
  - Unpatched Windows OS / component CVEs (via installed KB cross-reference)
  - Vulnerable third-party software (via registry uninstall enumeration)
  - Recent high-priority CVEs with ransomware links (flagged CRITICAL)

API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
No API key required - public domain data.
"""

import os
import json
import subprocess
import re
import platform
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────────────────

KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_FILE = Path(os.environ.get("TEMP", "C:\\Temp")) / "wraith_kev_cache.json"
CACHE_MAX_AGE  = timedelta(hours=12)   # Re-download if cache older than 12 h

# How far back to look for "recently added" KEV entries when no patch check exists
RECENT_DAYS = 180

# Microsoft product names to treat as Windows-host relevant
WINDOWS_VENDOR = "Microsoft"
WINDOWS_PRODUCTS: Set[str] = {
    "Windows", "Win32k", "SMBv1", "SMBv1 server", "MSHTML",
    "Internet Explorer", "Edge", "Edge and Internet Explorer",
    "Exchange Server", "Office", "Office Outlook", "SharePoint",
    ".NET Framework", ".NET Framework, SharePoint, Visual Studio",
    "Ancillary Function Driver (afd.sys)", "Netlogon",
    "Client-Server Run-time Subsystem (CSRSS)",
    "DirectX Graphics Kernel (DXGKRNL)", "DWM Core Library",
    "Enhanced Cryptographic Provider", "Print Spooler", "Publisher",
    "Task Scheduler", "Update Notification Manager",
    "WinVerifyTrust function", "XML Core Services",
    "Defender", "Excel", "PowerPoint", "Silverlight",
    "Internet Information Services (IIS)", "Windows Server",
    "Update Notification Manager", "Multiple Products",
}

# Third-party products to match against registry display names (lowercase → registry keyword)
THIRD_PARTY_MATCH: Dict[str, str] = {
    "7-zip":                "7-zip",
    "winrar":               "winrar",
    "vmware":               "vmware",
    "cisco anyconnect":     "anyconnect",
    "cisco webex":          "webex",
    "teamviewer":           "teamviewer",
    "zoom":                 "zoom",
    "adobe acrobat":        "adobe acrobat",
    "adobe reader":         "adobe reader",
    "adobe flash":          "adobe flash",
    "coldfusion":           "coldfusion",
    "oracle java":          "java",
    "java se":              "java",
    "java runtime":         "java",
    "chrome":               "google chrome",
    "chromium":             "chromium",
    "mozilla firefox":      "firefox",
    "mozilla thunderbird":  "thunderbird",
    "veeam":                "veeam",
    "solarwinds":           "solarwinds",
    "papercut":             "papercut",
    "commvault":            "commvault",
    "grafana":              "grafana",
    "docker desktop":       "docker desktop",
    "github desktop":       "github desktop",
    "atlassian":            "atlassian",
    "confluence":           "confluence",
    "jira":                 "jira",
    "ivanti":               "ivanti",
    "sonicwall":            "sonicwall",
    "fortinet":             "fortinet",
    "forticlient":          "forticlient",
    "pulsesecure":          "pulse secure",
    "connectwise":          "connectwise",
    "screenconnect":        "screenconnect",
    "manage engine":        "manageengine",
    "manageengine":         "manageengine",
    "progress":             "progress",
}

# ── WRAITH Priority CVE Watchlist ─────────────────────────────────────────────
# CVEs tracked by WRAITH independently of CISA KEV (zero-days, freshly disclosed,
# or critical enough to warrant explicit patch confirmation checks).
# Fields: name, description, severity, product, fixing_kbs (empty = no patch yet),
#         min_build (dict of os_build → min_ubr required), patch_url
PRIORITY_CVES: List[Dict[str, Any]] = [
    {
        "cve_id":      "CVE-2026-25592",
        "name":        "Windows Kernel Privilege Escalation Vulnerability",
        "description": (
            "A race condition in the Windows kernel memory manager (ntoskrnl.exe) allows a "
            "local authenticated attacker to escalate privileges to SYSTEM without user interaction. "
            "Exploitable from standard user context — requires no special permissions or account privileges. "
            "Actively exploited in targeted attacks against enterprise environments."
        ),
        "severity":    "CRITICAL",
        "product":     "Windows Kernel (ntoskrnl.exe)",
        "vendor":      "Microsoft",
        # KBs will be released March 10, 2026 Patch Tuesday — update when available
        "fixing_kbs":  [],
        # Minimum UBR (Update Build Revision) per OS build once patch ships
        # These are populated after Patch Tuesday ships; pre-PT = all vulnerable
        "min_ubr_by_build": {
            "26100": None,   # Win11 24H2 — patch not yet released
            "22631": None,   # Win11 23H2 — patch not yet released
            "22621": None,   # Win11 22H2 — patch not yet released
            "19045": None,   # Win10 22H2 — patch not yet released
            "17763": None,   # Win Server 2019 — patch not yet released
        },
        "patch_tuesday":   "2026-03-10",
        "patch_url":       "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-25592",
        "nvd_url":         "https://nvd.nist.gov/vuln/detail/CVE-2026-25592",
        "ransomware":      False,
        "exploitation":    "Active exploitation observed in the wild",
    },
]


def log(msg: str) -> None:
    import sys
    print(f"[WRAITH-KEV] {msg}", file=sys.stderr)


# ── KEV catalog fetch / cache ─────────────────────────────────────────────────

def _load_kev_catalog() -> List[Dict]:
    """Return KEV entries, using a local cache where fresh."""
    # Try cache first
    if KEV_CACHE_FILE.exists():
        age = datetime.now() - datetime.fromtimestamp(KEV_CACHE_FILE.stat().st_mtime)
        if age < CACHE_MAX_AGE:
            try:
                with open(KEV_CACHE_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                    log(f"Loaded KEV catalog from cache ({len(data.get('vulnerabilities',[]))} entries)")
                    return data.get("vulnerabilities", [])
            except Exception:
                pass

    # Download live
    log("Downloading CISA KEV catalog...")
    try:
        req = urllib.request.Request(
            KEV_URL,
            headers={"User-Agent": "WRAITH-Scanner/1.0 (security research)"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])
        log(f"Downloaded {len(vulns)} KEV entries")
        # Save cache
        try:
            KEV_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(KEV_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception as e:
            log(f"Cache write failed: {e}")
        return vulns
    except Exception as e:
        log(f"Failed to download KEV catalog: {e}")
        # Fall back to stale cache if available
        if KEV_CACHE_FILE.exists():
            log("Using stale cache as fallback")
            try:
                with open(KEV_CACHE_FILE, encoding="utf-8") as f:
                    return json.load(f).get("vulnerabilities", [])
            except Exception:
                pass
        return []


# ── Windows update / KB enumeration ──────────────────────────────────────────

def _get_installed_kbs() -> Set[str]:
    """Return set of installed KB numbers (e.g. 'KB5034765') via Get-HotFix."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-HotFix | Select-Object -ExpandProperty HotFixID | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            raw = result.stdout.strip()
            if raw.startswith("["):
                items = json.loads(raw)
            else:
                items = json.loads(f"[{raw}]")
            kbs = {str(k).upper().strip() for k in items if k}
            log(f"Found {len(kbs)} installed KBs")
            return kbs
    except Exception as e:
        log(f"Get-HotFix failed: {e}")
    return set()


def _get_windows_version() -> Dict[str, Any]:
    """Return Windows version info: name, build, version string."""
    info: Dict[str, Any] = {
        "name": platform.system(),
        "version": platform.version(),
        "release": platform.release(),
        "build": 0,
    }
    try:
        # Get UBR (Update Build Revision) from registry for exact patch level
        if WINREG_AVAILABLE:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            )
            try:
                info["ProductName"]   = winreg.QueryValueEx(key, "ProductName")[0]
                info["DisplayVersion"] = winreg.QueryValueEx(key, "DisplayVersion")[0]
                info["CurrentBuild"]  = winreg.QueryValueEx(key, "CurrentBuild")[0]
                info["build"]         = int(info["CurrentBuild"])
                info["UBR"]           = winreg.QueryValueEx(key, "UBR")[0]
                info["ReleaseId"]     = winreg.QueryValueEx(key, "ReleaseId")[0]
            except Exception:
                pass
            finally:
                winreg.CloseKey(key)
    except Exception as e:
        log(f"Registry version read failed: {e}")
    return info


# ── Installed software enumeration ───────────────────────────────────────────

def _get_installed_software() -> List[Dict[str, str]]:
    """Enumerate installed software from both 32-bit and 64-bit uninstall registry keys."""
    if not WINREG_AVAILABLE:
        return []

    software: List[Dict[str, str]] = []
    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,  r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    seen: Set[str] = set()
    for root, path in uninstall_paths:
        try:
            key = winreg.OpenKey(root, path)
            i = 0
            while True:
                try:
                    subname = winreg.EnumKey(key, i)
                    subkey  = winreg.OpenKey(key, subname)
                    try:
                        name    = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        version = ""
                        try:
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        except Exception:
                            pass
                        dedup_key = name.lower().strip()
                        if name and dedup_key not in seen:
                            seen.add(dedup_key)
                            software.append({"name": name, "version": version})
                    except OSError:
                        pass
                    finally:
                        winreg.CloseKey(subkey)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    log(f"Enumerated {len(software)} installed software entries")
    return software


# ── Matching helpers ──────────────────────────────────────────────────────────

def _extract_kbs_from_notes(notes: str) -> List[str]:
    """Pull any KB\d+ references from KEV notes field."""
    return re.findall(r"KB\d{6,8}", notes, flags=re.IGNORECASE)


def _severity_for_entry(entry: Dict) -> str:
    """Map KEV entry to WRAITH severity."""
    ransomware = entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"
    added      = _parse_date(entry.get("dateAdded", ""))
    recent     = added and (datetime.now() - added).days <= RECENT_DAYS

    if ransomware:
        return "CRITICAL"
    if recent:
        return "HIGH"
    return "MEDIUM"


def _parse_date(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None


def _msrc_url(entry: Dict) -> str:
    """Extract first MSRC URL from notes."""
    for part in entry.get("notes", "").split(";"):
        p = part.strip()
        if "msrc.microsoft.com" in p:
            return p
    return entry.get("notes", "").split(";")[0].strip()


def _nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


# ── Priority CVE watchlist check ──────────────────────────────────────────────

def _check_priority_cves(installed_kbs: Set[str], win_version: Dict[str, Any]) -> List[Dict]:
    """
    Check the WRAITH PRIORITY_CVES watchlist against the current host.
    These are critical/zero-day CVEs tracked independently of CISA KEV timing.
    """
    findings: List[Dict] = []
    os_build = str(win_version.get("CurrentBuild", ""))
    os_ubr   = win_version.get("UBR", 0)
    os_name  = win_version.get("ProductName", "Windows")

    for entry in PRIORITY_CVES:
        cve_id      = entry["cve_id"]
        fixing_kbs  = entry.get("fixing_kbs", [])
        min_ubr_map = entry.get("min_ubr_by_build", {})
        patch_date  = entry.get("patch_tuesday", "")

        # 1. Check if a known fixing KB is installed
        if fixing_kbs:
            if any(kb.upper() in installed_kbs for kb in fixing_kbs):
                continue  # Patched — skip

        # 2. Check UBR-based patch confirmation
        min_ubr = min_ubr_map.get(os_build)
        if min_ubr is not None and os_ubr >= min_ubr:
            continue  # Build revision indicates patch is present

        # 3. Determine patch availability status
        patch_available = bool(fixing_kbs) or any(v is not None for v in min_ubr_map.values())

        if patch_available:
            patch_note = (
                f"Patch IS available but NOT installed on this host. "
                f"Required KB(s): {', '.join(fixing_kbs) if fixing_kbs else 'see Patch Tuesday ' + patch_date}. "
                f"Apply immediately via Windows Update."
            )
            sev = "CRITICAL"
        else:
            patch_note = (
                f"No patch available yet — expected Patch Tuesday {patch_date}. "
                f"This system IS VULNERABLE. Mitigations: restrict local user access, enable "
                f"Credential Guard + Secure Boot, monitor for privilege escalation indicators "
                f"(Event IDs 4672, 4673, 4674 — special privilege assignment)."
            )
            sev = "CRITICAL"

        reason_parts = [
            entry["description"],
            f"Exploitation status: {entry.get('exploitation', 'Unknown')}",
            patch_note,
            f"Reference: {entry.get('patch_url', entry.get('nvd_url', ''))}",
        ]
        if entry.get("ransomware"):
            reason_parts.insert(0, "⚠ LINKED TO RANSOMWARE CAMPAIGNS")

        findings.append({
            "title":       f"{cve_id} — {entry['name']} [WATCHLIST]",
            "path":        entry.get("patch_url", entry.get("nvd_url", "")),
            "reason":      " | ".join(reason_parts),
            "severity":    sev,
            "category":    "vulnerability",
            "subcategory": "priority_cve_watchlist",
            "cve":         cve_id,
            "patch_status": "patch_missing" if patch_available else "no_patch_yet",
            "product":     entry.get("product", "Windows"),
            "ransomware":  entry.get("ransomware", False),
        })

    return findings


# ── Main scan function ────────────────────────────────────────────────────────

def scan_cisa_kev() -> List[Dict]:
    findings: List[Dict] = []

    # 1. Load KEV catalog
    vulns = _load_kev_catalog()
    if not vulns:
        findings.append({
            "title":    "CISA KEV catalog unavailable",
            "path":     KEV_URL,
            "reason":   "Could not download or load CISA KEV catalog. No internet connectivity or cache expired.",
            "severity": "INFO",
            "category": "vulnerability",
            "subcategory": "kev_catalog",
        })
        return findings

    # 2. Gather host context
    installed_kbs  = _get_installed_kbs()
    win_version    = _get_windows_version()
    installed_soft = _get_installed_software()
    installed_names_lower = [s["name"].lower() for s in installed_soft]

    date_cutoff = datetime.now() - timedelta(days=RECENT_DAYS)

    # 2b. WRAITH Priority CVE watchlist — checked before CISA catalog
    #     These are critical CVEs tracked even if not yet in KEV (zero-days, fresh disclosures)
    priority_findings = _check_priority_cves(installed_kbs, win_version)
    findings.extend(priority_findings)
    # Track CVE IDs already reported so the CISA loop doesn't duplicate them
    reported_cves: Set[str] = {f["cve"] for f in priority_findings if f.get("cve")}

    # -- Summary info finding ------------------------------------------------
    ms_windows_entries = [v for v in vulns
                          if v.get("vendorProject") == WINDOWS_VENDOR
                          and v.get("product") in WINDOWS_PRODUCTS]

    findings.append({
        "title":    f"CISA KEV Catalog: {len(vulns)} Active Exploited CVEs",
        "path":     KEV_URL,
        "reason":   (
            f"CISA tracks {len(vulns)} actively exploited CVEs. "
            f"{len(ms_windows_entries)} are Microsoft Windows/component CVEs. "
            f"Windows host: {win_version.get('ProductName','Unknown')} "
            f"Build {win_version.get('CurrentBuild','?')} "
            f"({win_version.get('DisplayVersion','?')}) "
            f"with {len(installed_kbs)} KBs installed."
        ),
        "severity":    "INFO",
        "category":    "vulnerability",
        "subcategory": "kev_summary",
        "cve":         None,
    })

    # ── 3. Windows OS / component CVEs ─────────────────────────────────────
    for entry in vulns:
        vendor  = entry.get("vendorProject", "")
        product = entry.get("product", "")
        cve_id  = entry.get("cveID", "")
        added   = _parse_date(entry.get("dateAdded", ""))

        # Skip if already reported by priority watchlist
        if cve_id in reported_cves:
            continue

        # Only Microsoft Windows-host relevant entries
        if vendor != WINDOWS_VENDOR:
            continue
        if product not in WINDOWS_PRODUCTS:
            continue

        ransomware = entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"
        sev        = _severity_for_entry(entry)

        # Try to find an associated KB in the notes
        kbs_in_entry = _extract_kbs_from_notes(entry.get("notes", ""))

        patch_status = "patch_status_unknown"
        patch_note   = "No KB identifier found in KEV entry — verify manually via Windows Update."

        if kbs_in_entry:
            installed_any = any(kb.upper() in installed_kbs for kb in kbs_in_entry)
            if installed_any:
                # Patch installed — skip (don't create noise for patched CVEs)
                continue
            else:
                patch_status = "patch_missing"
                patch_note   = (
                    f"Required patch(es) {', '.join(kbs_in_entry)} NOT found in installed KBs. "
                    "Apply Windows Updates immediately."
                )
                # Elevate severity if patch is confirmed missing
                if sev == "MEDIUM":
                    sev = "HIGH"

        # Skip old entries where we have no KB info and no ransomware link (too noisy)
        if patch_status == "patch_status_unknown" and not ransomware:
            if added and added < date_cutoff:
                continue   # Old entry, no KB ref, no ransomware — skip to reduce noise

        reference_url = _msrc_url(entry) or _nvd_url(cve_id)

        reason_parts = [
            f"{entry.get('vulnerabilityName', cve_id)}",
            f"Added to KEV: {entry.get('dateAdded','unknown')}",
        ]
        if ransomware:
            reason_parts.append("⚠ LINKED TO RANSOMWARE CAMPAIGNS")
        reason_parts.append(patch_note)
        reason_parts.append(f"Required action: {entry.get('requiredAction','Apply updates per vendor instructions.')}")

        findings.append({
            "title":       f"{cve_id} — {product} ({entry.get('dateAdded','')})",
            "path":        reference_url,
            "reason":      " | ".join(reason_parts),
            "severity":    sev,
            "category":    "vulnerability",
            "subcategory": "cisa_kev_windows",
            "cve":         cve_id,
            "ransomware":  ransomware,
            "patch_status": patch_status,
            "product":     product,
            "date_added":  entry.get("dateAdded", ""),
        })

    # ── 4. Third-party software CVEs ────────────────────────────────────────
    for entry in vulns:
        vendor  = entry.get("vendorProject", "")
        product = entry.get("product", "")
        cve_id  = entry.get("cveID", "")

        if cve_id in reported_cves:
            continue

        if vendor == WINDOWS_VENDOR:
            continue  # Already handled above

        # Build a combined search string from vendor+product
        search_str = f"{vendor} {product}".lower()
        matched_install: Optional[str] = None

        # Check against third-party match table
        for kev_keyword, registry_keyword in THIRD_PARTY_MATCH.items():
            if kev_keyword in search_str:
                # Check if we have this installed
                for name_lower in installed_names_lower:
                    if registry_keyword in name_lower:
                        matched_install = name_lower
                        break
                if matched_install:
                    break

        if not matched_install:
            continue  # Software not detected on this host

        sev       = _severity_for_entry(entry)
        ransomware = entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"
        reference_url = _nvd_url(cve_id)

        # Try to get installed version for context
        installed_version = ""
        for sw in installed_soft:
            if registry_keyword in sw["name"].lower():   # type: ignore[possibly-undefined]
                installed_version = sw.get("version", "")
                break

        reason_parts = [
            f"{entry.get('vulnerabilityName', cve_id)}",
            f"Detected installed: {matched_install}" + (f" v{installed_version}" if installed_version else ""),
            f"Added to KEV: {entry.get('dateAdded','unknown')}",
        ]
        if ransomware:
            reason_parts.append("⚠ LINKED TO RANSOMWARE CAMPAIGNS")
        reason_parts.append(entry.get("shortDescription", ""))
        reason_parts.append(f"Required action: {entry.get('requiredAction','Apply vendor patches immediately.')}")

        findings.append({
            "title":       f"{cve_id} — {product} (installed on host)",
            "path":        reference_url,
            "reason":      " | ".join(reason_parts),
            "severity":    sev,
            "category":    "vulnerability",
            "subcategory": "cisa_kev_software",
            "cve":         cve_id,
            "ransomware":  ransomware,
            "installed_version": installed_version,
            "product":     product,
            "date_added":  entry.get("dateAdded", ""),
        })

    # ── 5. Windows patching posture summary ─────────────────────────────────
    confirmed_missing = [f for f in findings if f.get("patch_status") == "patch_missing"]
    if confirmed_missing:
        findings.append({
            "title":    f"Windows: {len(confirmed_missing)} KEV patches confirmed missing",
            "path":     "ms-settings:windowsupdate",
            "reason":   (
                f"{len(confirmed_missing)} KEV CVEs have identifiable KB patches that are NOT present "
                f"in this system's installed hotfix list. Run Windows Update immediately. "
                f"CVEs: {', '.join(f['cve'] for f in confirmed_missing[:10])}"
                + (" ..." if len(confirmed_missing) > 10 else "")
            ),
            "severity":    "CRITICAL",
            "category":    "vulnerability",
            "subcategory": "patch_posture",
        })

    # ── 6. WDigest / LSA protection checks (bonus - credential theft enablers) ──
    try:
        if WINREG_AVAILABLE:
            # WDigest enabled = cleartext passwords in LSASS memory
            try:
                lsa_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
                )
                use_logon_cred = winreg.QueryValueEx(lsa_key, "UseLogonCredential")[0]
                winreg.CloseKey(lsa_key)
                if use_logon_cred == 1:
                    findings.append({
                        "title":    "WDigest Authentication Enabled (Cleartext LSASS Caching)",
                        "path":     r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
                        "reason":   (
                            "WDigest UseLogonCredential=1: Windows will cache user credentials in cleartext in LSASS memory. "
                            "This directly enables tools like Mimikatz to extract plaintext passwords after initial access. "
                            "CVE-linked: several KEV entries for LPE + credential theft assume this is enabled. "
                            "Fix: set UseLogonCredential=0 or remove the value."
                        ),
                        "severity":    "CRITICAL",
                        "category":    "vulnerability",
                        "subcategory": "credential_exposure",
                    })
            except OSError:
                pass  # Key doesn't exist = WDigest not explicitly enabled (safe)

            # LSASS RunAsPPL (protected process) check
            try:
                lsa_key2 = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Lsa"
                )
                try:
                    run_as_ppl = winreg.QueryValueEx(lsa_key2, "RunAsPPL")[0]
                    if run_as_ppl != 1:
                        raise ValueError("not set to 1")
                except (OSError, ValueError):
                    findings.append({
                        "title":    "LSASS Not Running as Protected Process (PPL)",
                        "path":     r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL",
                        "reason":   (
                            "LSASS RunAsPPL is not enabled. Without PPL, any process running as SYSTEM "
                            "can open LSASS and dump credentials — the core technique behind dozens of KEV-listed "
                            "privilege escalation exploits that pivot to credential theft. "
                            "Fix: set RunAsPPL=1 (requires Secure Boot + reboot)."
                        ),
                        "severity":    "HIGH",
                        "category":    "vulnerability",
                        "subcategory": "credential_exposure",
                    })
                finally:
                    winreg.CloseKey(lsa_key2)
            except Exception:
                pass

    except Exception as e:
        log(f"LSA registry checks failed: {e}")

    log(f"CISA KEV scan complete: {len(findings)} findings")
    return findings


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    results = scan_cisa_kev()
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    results.sort(key=lambda f: sev_rank.get(f.get("severity", "INFO"), 0), reverse=True)
    print(json.dumps({"scanner": "WRAITH-kev", "mode": "kev", "findings": results}, default=str, indent=2))
