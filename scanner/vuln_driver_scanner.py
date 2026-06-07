"""
Vulnerable / known-malicious driver scanner.

Cross-references currently loaded kernel drivers against Microsoft's
recommended driver blocklist (the same data that drives Windows
Defender's "Vulnerable Driver Blocklist"). Catches the BYOVD ("Bring
Your Own Vulnerable Driver") attack pattern — an attacker side-loading
a signed-but-vulnerable driver to escalate privileges or disable EDR.

Feed source: https://aka.ms/VulnerableDriverBlockList
The blocklist is a SiPolicy.p7b binary, but Microsoft also publishes
the parsed FileRules (and their SHA256/Authenticode hashes) in
driver-block-list.xml inside the bundle. We read that XML.

The scanner:
1. Loads the parsed blocklist into a {sha256: rule_name} map.
2. Enumerates loaded kernel drivers via Win32_SystemDriver +
   Authenticode hash extraction.
3. Reports any match as CRITICAL.

If the feed isn't on disk yet (FeedRefreshService hasn't run), the
scanner exits with a single INFO finding so the operator knows why
this check produced no data.
"""

from __future__ import annotations

import hashlib
import platform
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

from feed_store import FEED_VULN_DRIVERS, feed_path, get_feed_status


def _load_blocklist() -> Dict[str, str]:
    """Parses Microsoft's driver-block-list.xml into {sha256_hex: rule_name}.

    The XML schema (SiPolicy) puts hashes inside FileRules/Deny elements.
    We extract the Hash attribute, normalise to lowercase hex, and key by
    that. Authenticode SHA256 and file SHA256 are both present in the
    bundle; we accept both and merge.
    """
    xml_path = feed_path(FEED_VULN_DRIVERS, "driver_blocklist.xml")
    if not xml_path.exists():
        return {}

    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, OSError):
        return {}

    root = tree.getroot()
    # SiPolicy uses an XML namespace; strip it for simpler XPath.
    namespaces = {
        "": "urn:schemas-microsoft-com:sipolicy",
    }

    out: Dict[str, str] = {}

    # FileRules/Deny[@Hash][@FriendlyName]
    for deny in root.iter("{urn:schemas-microsoft-com:sipolicy}Deny"):
        h = deny.get("Hash") or ""
        name = (
            deny.get("FriendlyName")
            or deny.get("ID")
            or "Microsoft vulnerable driver blocklist"
        )
        if not h:
            continue
        out[h.lower()] = name

    # Some bundles also use the unprefixed form when namespace fallback hits
    for deny in root.iter("Deny"):
        h = deny.get("Hash") or ""
        if not h:
            continue
        out.setdefault(
            h.lower(),
            deny.get("FriendlyName") or "Microsoft vulnerable driver blocklist",
        )

    # Avoid an unused-var warning when running under static analysers
    _ = namespaces
    return out


def _enumerate_loaded_drivers() -> List[Dict[str, str]]:
    """Returns currently loaded drivers via PowerShell Get-CimInstance.

    Each entry: {Name, PathName, State, StartMode}. PathName is the file
    we need to hash; the rest is context for the finding's reason field.
    """
    if platform.system() != "Windows":
        return []

    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-CimInstance Win32_SystemDriver | "
        "Select-Object Name, PathName, State, StartMode | "
        "ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    import json as _json

    try:
        data = _json.loads(result.stdout)
    except _json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []

    out: List[Dict[str, str]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        out.append(
            {
                "name": str(entry.get("Name") or ""),
                "path": str(entry.get("PathName") or ""),
                "state": str(entry.get("State") or ""),
                "start_mode": str(entry.get("StartMode") or ""),
            }
        )
    return out


def _normalise_driver_path(raw: str) -> Optional[Path]:
    """PathName can be '\\??\\C:\\...' or 'system32\\drivers\\foo.sys'.

    Strip the NT-prefix and resolve relative-to-system32 paths so we can
    actually open the file to hash it.
    """
    if not raw:
        return None
    p = raw
    for prefix in ("\\??\\", "\\SystemRoot\\", "\\\\?\\"):
        if p.startswith(prefix):
            p = p[len(prefix) :]
            break
    # Some drivers report 'system32\\drivers\\foo.sys' without a drive letter.
    if p.lower().startswith("system32\\"):
        # Best-effort: prepend the windir.
        import os as _os

        windir = _os.environ.get("WINDIR") or r"C:\Windows"
        p = str(Path(windir) / p)
    try:
        candidate = Path(p)
    except (TypeError, ValueError):
        return None
    return candidate if candidate.exists() else None


def _sha256(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower()
    except OSError:
        return None


def scan() -> List[Dict]:
    """Entry point invoked by scanner.py's --mode=vuln_drivers and --mode=all.

    Returns a list of finding dicts in the standard WRAITH schema.
    """
    blocklist = _load_blocklist()
    if not blocklist:
        # Surface a one-line INFO finding so the user understands why
        # vuln-driver coverage is empty: the feed file isn't on disk yet.
        status = get_feed_status(FEED_VULN_DRIVERS)
        reason = (
            "Microsoft vulnerable-driver blocklist not yet downloaded — "
            "run 'Refresh Threat Feeds' from the WRAITH menu."
        )
        if status and status.error:
            reason = f"Vulnerable-driver feed last refresh failed: {status.error}"
        return [
            {
                "title": "Vulnerable driver blocklist unavailable",
                "path": "",
                "reason": reason,
                "severity": "INFO",
                "category": "vuln_driver",
                "subcategory": "feed_missing",
            }
        ]

    findings: List[Dict] = []
    for drv in _enumerate_loaded_drivers():
        resolved = _normalise_driver_path(drv["path"])
        if resolved is None:
            continue
        sha = _sha256(resolved)
        if sha is None:
            continue
        rule_name = blocklist.get(sha)
        if rule_name is None:
            continue
        findings.append(
            {
                "title": f"Known-vulnerable driver loaded: {drv['name']}",
                "path": str(resolved),
                "reason": (
                    f"{rule_name} — driver matches Microsoft's vulnerable driver "
                    f"blocklist (SHA256 {sha[:16]}…). BYOVD attack vector."
                ),
                "severity": "CRITICAL",
                "category": "vuln_driver",
                "subcategory": "byovd",
                "extra": {
                    "service_name": drv["name"],
                    "state": drv["state"],
                    "start_mode": drv["start_mode"],
                    "sha256": sha,
                    "blocklist_rule": rule_name,
                },
            }
        )
    return findings


if __name__ == "__main__":
    import json as _json

    for f in scan():
        print(_json.dumps(f))
