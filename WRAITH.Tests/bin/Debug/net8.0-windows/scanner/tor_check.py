"""
Tor exit-node correlation.

Cross-references active outbound TCP connections against the live Tor
exit-node list (https://check.torproject.org/torbulkexitlist). Catches
C2 channels and data-exfil endpoints that hide behind Tor.

The feed is a plaintext newline-delimited IPv4 list (~1500 entries),
refreshed daily by Tor Project. No API key.
"""

from __future__ import annotations

import ipaddress
import platform
import subprocess
from typing import Dict, List, Set

from feed_store import FEED_TOR, feed_path, get_feed_status, read_lines


def _load_exit_nodes() -> Set[str]:
    """Returns the set of Tor exit-node IPv4 addresses on disk.

    Invalid lines are silently skipped — the feed is well-formed in
    practice, but defensive parsing avoids one bad line breaking the
    whole correlation.
    """
    out: Set[str] = set()
    for line in read_lines(feed_path(FEED_TOR, "exit_nodes.txt")):
        try:
            ipaddress.ip_address(line)
            out.add(line)
        except ValueError:
            continue
    return out


def _active_remote_ips() -> List[Dict[str, str]]:
    """Enumerates active outbound TCP connections via PowerShell.

    Returns [{remote_ip, remote_port, owning_process_id, owning_process}].
    """
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


def _process_name(pid: str) -> str:
    if not pid or platform.system() != "Windows":
        return ""
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue).ProcessName",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return (result.stdout or "").strip()


def scan() -> List[Dict]:
    """Entry point — invoked by scanner.py's --mode=tor and --mode=all."""
    exit_nodes = _load_exit_nodes()
    if not exit_nodes:
        status = get_feed_status(FEED_TOR)
        reason = (
            "Tor exit-node list not yet downloaded — "
            "run 'Refresh Threat Feeds' from the WRAITH menu."
        )
        if status and status.error:
            reason = f"Tor exit-node feed last refresh failed: {status.error}"
        return [
            {
                "title": "Tor exit-node correlation unavailable",
                "path": "",
                "reason": reason,
                "severity": "INFO",
                "category": "network",
                "subcategory": "tor_feed_missing",
            }
        ]

    findings: List[Dict] = []
    for conn in _active_remote_ips():
        if conn["remote_ip"] not in exit_nodes:
            continue
        proc = _process_name(conn["pid"]) or "<unknown>"
        findings.append(
            {
                "title": f"Active connection to Tor exit node: {conn['remote_ip']}",
                "path": "",
                "reason": (
                    f"Process '{proc}' (PID {conn['pid']}) has an established TCP "
                    f"connection to {conn['remote_ip']}:{conn['remote_port']}, "
                    "which is a known Tor exit relay. Legitimate Tor use is rare "
                    "on managed endpoints — investigate for C2 or data-exfil."
                ),
                "severity": "HIGH",
                "category": "network",
                "subcategory": "tor_exit_node",
                "pid": int(conn["pid"]) if conn["pid"].isdigit() else None,
                "extra": {
                    "remote_ip": conn["remote_ip"],
                    "remote_port": conn["remote_port"],
                    "process_name": proc,
                },
            }
        )
    return findings


if __name__ == "__main__":
    import json as _json

    for f in scan():
        print(_json.dumps(f))
