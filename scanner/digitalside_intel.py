"""
DigitalSide OSINT threat-intel correlation.

DigitalSide (https://osint.digitalside.it/) publishes daily IOC feeds
under a free CC-BY licence with no API key:

    latestdomains.txt  — newline-delimited malicious domains
    latestips.txt      — newline-delimited malicious IPv4s
    latesturls.txt     — newline-delimited malicious URLs
    latestmd5.txt /
    latestsha256.txt   — file hashes

We correlate:
    - active outbound connections against the IP feed
    - DNS cache + hosts file against the domain feed
    - YARA finding paths (any file the scanner has already touched)
      against the hash feed
"""

from __future__ import annotations

import hashlib
import ipaddress
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Set

from feed_store import FEED_DIGITALSIDE, feed_path, get_feed_status, read_lines


def _load_set(filename: str) -> Set[str]:
    return {line.lower() for line in read_lines(feed_path(FEED_DIGITALSIDE, filename))}


def _load_ip_set() -> Set[str]:
    out: Set[str] = set()
    for line in read_lines(feed_path(FEED_DIGITALSIDE, "ips.txt")):
        try:
            ipaddress.ip_address(line)
            out.add(line)
        except ValueError:
            continue
    return out


def _active_remote_ips() -> List[Dict[str, str]]:
    if platform.system() != "Windows":
        return []
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-NetTCPConnection -State Established | "
        "Select-Object RemoteAddress, RemotePort, OwningProcess | "
        "ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=20,
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
        ra = str(entry.get("RemoteAddress") or "")
        if not ra:
            continue
        out.append(
            {
                "remote_ip": ra,
                "remote_port": str(entry.get("RemotePort") or ""),
                "pid": str(entry.get("OwningProcess") or ""),
            }
        )
    return out


def _dns_cache_domains() -> Set[str]:
    """Pulls active DNS cache entries (Get-DnsClientCache) as a domain set."""
    if platform.system() != "Windows":
        return set()
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-DnsClientCache | Select-Object -ExpandProperty Entry | "
        "Sort-Object -Unique"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if result.returncode != 0:
        return set()
    return {
        line.strip().lower()
        for line in (result.stdout or "").splitlines()
        if line.strip()
    }


def _hosts_file_entries() -> Set[str]:
    """Domains explicitly mapped in %WINDIR%\\System32\\drivers\\etc\\hosts."""
    import os as _os

    windir = _os.environ.get("WINDIR") or r"C:\Windows"
    hosts = Path(windir) / "System32" / "drivers" / "etc" / "hosts"
    out: Set[str] = set()
    if not hosts.exists():
        return out
    try:
        with hosts.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                # Skip the IP, take every host alias on the line
                for host in parts[1:]:
                    if host:
                        out.add(host.lower())
    except OSError:
        return out
    return out


def _missing_feed_finding(reason_detail: str) -> Dict:
    return {
        "title": "DigitalSide OSINT correlation unavailable",
        "path": "",
        "reason": reason_detail,
        "severity": "INFO",
        "category": "intel",
        "subcategory": "feed_missing",
    }


def scan() -> List[Dict]:
    """Entry point — invoked by scanner.py's --mode=intel and --mode=all."""
    domains = _load_set("domains.txt")
    ips = _load_ip_set()

    if not domains and not ips:
        status = get_feed_status(FEED_DIGITALSIDE)
        if status and status.error:
            return [
                _missing_feed_finding(
                    f"DigitalSide feed last refresh failed: {status.error}"
                )
            ]
        return [
            _missing_feed_finding(
                "DigitalSide intel feeds not yet downloaded — "
                "run 'Refresh Threat Feeds' from the WRAITH menu."
            )
        ]

    findings: List[Dict] = []

    # IP correlation
    if ips:
        for conn in _active_remote_ips():
            if conn["remote_ip"] not in ips:
                continue
            findings.append(
                {
                    "title": f"Active connection to flagged IP: {conn['remote_ip']}",
                    "path": "",
                    "reason": (
                        f"PID {conn['pid']} has an established connection to "
                        f"{conn['remote_ip']}:{conn['remote_port']}, which appears "
                        "in DigitalSide's OSINT malicious IP feed."
                    ),
                    "severity": "HIGH",
                    "category": "intel",
                    "subcategory": "ip_match",
                    "pid": int(conn["pid"]) if conn["pid"].isdigit() else None,
                    "extra": {
                        "remote_ip": conn["remote_ip"],
                        "remote_port": conn["remote_port"],
                        "feed": "digitalside",
                    },
                }
            )

    # Domain correlation (DNS cache + hosts file)
    if domains:
        for d in _dns_cache_domains():
            if d in domains:
                findings.append(
                    {
                        "title": f"DNS resolution of flagged domain: {d}",
                        "path": "",
                        "reason": (
                            f"{d} resolved recently (present in DNS client cache) "
                            "and appears in DigitalSide's OSINT malicious domain "
                            "feed. Investigate which process triggered the lookup."
                        ),
                        "severity": "HIGH",
                        "category": "intel",
                        "subcategory": "domain_match",
                        "extra": {
                            "domain": d,
                            "source": "dns_cache",
                            "feed": "digitalside",
                        },
                    }
                )
        for d in _hosts_file_entries():
            if d in domains:
                findings.append(
                    {
                        "title": f"hosts file maps flagged domain: {d}",
                        "path": str(Path(r"C:\Windows\System32\drivers\etc\hosts")),
                        "reason": (
                            f"{d} is explicitly mapped in the hosts file and "
                            "appears in DigitalSide's OSINT malicious domain feed."
                        ),
                        "severity": "CRITICAL",
                        "category": "intel",
                        "subcategory": "hosts_pin",
                        "extra": {
                            "domain": d,
                            "source": "hosts_file",
                            "feed": "digitalside",
                        },
                    }
                )

    return findings


def hash_match(path_or_hash: str) -> Dict[str, str]:
    """Convenience helper for other scanners.

    Returns {} if the path/hash isn't flagged, or {'feed': 'digitalside', 'hash': 'sha256...'}
    when it is. Lets yara_scanner / heuristics correlate their candidate
    files against the DigitalSide hash feed without each one re-parsing.
    """
    sha256_set = _load_set("hashes_sha256.txt")
    md5_set = _load_set("hashes_md5.txt")

    candidate = path_or_hash.lower()
    if candidate in sha256_set:
        return {"feed": "digitalside", "kind": "sha256", "hash": candidate}
    if candidate in md5_set:
        return {"feed": "digitalside", "kind": "md5", "hash": candidate}

    p = Path(path_or_hash)
    if p.exists() and p.is_file():
        try:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha = h.hexdigest().lower()
            if sha in sha256_set:
                return {"feed": "digitalside", "kind": "sha256", "hash": sha}
        except OSError:
            pass
    return {}


if __name__ == "__main__":
    import json as _json

    for f in scan():
        print(_json.dumps(f))
