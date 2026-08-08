"""
WRAITH - Network Scanner Module
Detects C2 beaconing, hosts file tampering, suspicious listening ports,
unexpected outbound connections, and DNS cache anomalies.
"""

import os
import re
import json
import socket
import struct
import subprocess
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Set

try:
    from feed_store import (
        FEED_FEODO,
        FEED_IPSUM,
        FEED_ET_COMPROMISED,
        FEED_BOTVRIJ,
        FEED_URLHAUS,
        FEED_OPENPHISH,
        feed_path,
        read_lines,
    )

    _FEEDS_AVAILABLE = True
except ImportError:
    _FEEDS_AVAILABLE = False

# ── Known-bad / suspicious infrastructure ────────────────────────────────────
# Tor exit node ranges, common C2 ports, bulletproof ASN ranges, etc.
# We keep this small to avoid false positives; primary detection is behavioral.

C2_PORTS = {
    4444,
    4445,
    4446,  # Metasploit default listeners
    5555,
    5554,  # Android debug / some RATs
    6666,
    6667,
    6668,  # IRC-based botnets
    7777,  # Common RAT port
    8080,
    8443,
    8888,  # Alt-HTTP common C2 tunnels (flagged only with suspicious process)
    31337,  # "Elite" legacy backdoor port
    12345,
    54321,  # Legacy trojans
    65535,  # Unusually high port common in custom implants
    1337,  # Leet port
    9001,
    9030,  # Tor default
}

# Ports in C2_PORTS that also carry heavy *legitimate* traffic (alt-HTTP, HTTPS
# proxies, Tor relays). Per the note on 8080/8443/8888 above, these must only be
# treated as C2 when paired with a suspicious process — the suspicious-outbound
# check already covers that case. Flagging them for *any* process turns every
# browser hit to an ":8443" API or dev server on ":8080" into a HIGH/CRITICAL
# false positive.
AMBIGUOUS_C2_PORTS = {8080, 8443, 8888, 9001, 9030}
# Ports that are unambiguous RAT/backdoor indicators regardless of process.
UNAMBIGUOUS_C2_PORTS = C2_PORTS - AMBIGUOUS_C2_PORTS

SUSPICIOUS_PROCESS_NAMES = {
    "powershell",
    "powershell_ise",
    "pwsh",
    "cmd",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "certutil",
    "bitsadmin",
    "msiexec",
    "wmic",
    "installutil",
    "cmstp",
    "msbuild",
    "nc",
    "ncat",
    "netcat",
    "nmap",
    "socat",
    "python",
    "python3",
    "ruby",
    "perl",
}

TRUSTED_LISTENER_PROCESSES = {
    "svchost",
    "lsass",
    "system",
    "wininit",
    "services",
    "dns",
    "spoolsv",
    "searchindexer",
    "sqlservr",
    "mysqld",
    "httpd",
    "nginx",
    "node",
    "iisw3adm",
    "w3wp",
}

# Legitimate domains that should point to expected IP ranges — if hosts file overrides these, flag it
SENSITIVE_HOSTS = [
    "windowsupdate.com",
    "update.microsoft.com",
    "google.com",
    "microsoft.com",
    "windows.com",
    "defender.microsoft.com",
    "smartscreen.microsoft.com",
    "ocsp.digicert.com",
    "ocsp.msocsp.com",
    "login.microsoftonline.com",
    "login.live.com",
]

# Private / loopback / link-local ranges — connections to these are OK
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def log(msg: str) -> None:
    import sys

    print(f"[WRAITH-NET] {msg}", file=sys.stderr)


def _is_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


# ── 1. Active TCP connections ─────────────────────────────────────────────────


def _get_connections() -> List[Dict]:
    """Use netstat / PowerShell to enumerate active TCP connections with owning PID."""
    connections: List[Dict] = []
    try:
        ps_cmd = r"""
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' } |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
    ConvertTo-Json -Depth 2 -Compress
"""
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode == 0 and result.stdout.strip():
            raw = result.stdout.strip()
            data = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
            connections = data
    except Exception as e:
        log(f"Get-NetTCPConnection failed: {e}")
        # Fallback: netstat
        try:
            r = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=15
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5 or parts[0] not in ("TCP",):
                    continue
                try:
                    local = parts[1]
                    remote = parts[2]
                    state = parts[3]
                    pid = int(parts[4])
                    lhost, lport = local.rsplit(":", 1)
                    rhost, rport = remote.rsplit(":", 1)
                    connections.append(
                        {
                            "LocalAddress": lhost,
                            "LocalPort": int(lport),
                            "RemoteAddress": rhost,
                            "RemotePort": int(rport),
                            "State": state,
                            "OwningProcess": pid,
                        }
                    )
                except Exception:
                    pass
        except Exception as e2:
            log(f"netstat fallback failed: {e2}")
    return connections


def _get_pid_to_name() -> Dict[int, str]:
    try:
        ps_cmd = (
            "Get-Process | Select-Object Id,ProcessName | "
            "ConvertTo-Json -Compress -Depth 1"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            procs = json.loads(result.stdout.strip())
            if isinstance(procs, dict):
                procs = [procs]
            return {
                p["Id"]: p.get("ProcessName", "") for p in procs if isinstance(p, dict)
            }
    except Exception as e:
        log(f"Process name lookup failed: {e}")
    return {}


def scan_connections(findings: List[Dict], pid_map: Dict[int, str]) -> None:
    connections = _get_connections()
    seen_remote_ips: Set[str] = set()

    for conn in connections:
        remote_ip = str(conn.get("RemoteAddress", ""))
        remote_port = int(conn.get("RemotePort", 0))
        local_port = int(conn.get("LocalPort", 0))
        state = str(conn.get("State", ""))
        pid = int(conn.get("OwningProcess", 0))
        proc_name = pid_map.get(pid, "unknown").lower()

        # ── Suspicious C2 listening ports ────────────────────────────────
        # Unambiguous RAT/backdoor ports only — listening on :8080 / :8443 is
        # ordinary for dev servers and proxies and must not be a CRITICAL.
        if state.lower() in ("listen", "bound") and local_port in UNAMBIGUOUS_C2_PORTS:
            if proc_name not in TRUSTED_LISTENER_PROCESSES:
                findings.append(
                    {
                        "title": f"Suspicious Listener: port {local_port} ({proc_name})",
                        "path": f"PID {pid} → {proc_name}",
                        "reason": (
                            f"Process '{proc_name}' (PID {pid}) is listening on port {local_port}, "
                            f"which is associated with RAT/backdoor/C2 frameworks (Metasploit, "
                            f"legacy trojans, Tor). Legitimate software rarely binds these ports."
                        ),
                        "severity": "CRITICAL",
                        "category": "network",
                        "subcategory": "suspicious_listener",
                        "pid": pid,
                    }
                )

        if state.lower() != "established":
            continue

        if not remote_ip or remote_ip in ("0.0.0.0", "::", ""):
            continue

        # ── Established connections from suspicious processes ─────────────
        if proc_name in SUSPICIOUS_PROCESS_NAMES and not _is_private(remote_ip):
            key = f"{proc_name}:{remote_ip}"
            if key not in seen_remote_ips:
                seen_remote_ips.add(key)
                sev = (
                    "CRITICAL"
                    if proc_name
                    in {"powershell", "pwsh", "mshta", "wscript", "cscript"}
                    else "HIGH"
                )
                findings.append(
                    {
                        "title": f"Suspicious Outbound: {proc_name} → {remote_ip}:{remote_port}",
                        "path": f"PID {pid} → {proc_name}",
                        "reason": (
                            f"'{proc_name}' (PID {pid}) has an established connection to external IP "
                            f"{remote_ip}:{remote_port}. Scripting engines and LOLBins making outbound "
                            f"connections are a primary C2 beaconing indicator."
                        ),
                        "severity": sev,
                        "category": "network",
                        "subcategory": "suspicious_outbound",
                        "pid": pid,
                    }
                )

        # ── Connections to C2 ports from any process ──────────────────────
        # Only the unambiguous RAT/backdoor ports fire for any process; the
        # alt-HTTP/proxy/Tor ports (8080/8443/8888/9001/9030) are handled by the
        # suspicious-outbound check above and must not flag ordinary web traffic.
        if remote_port in UNAMBIGUOUS_C2_PORTS and not _is_private(remote_ip):
            findings.append(
                {
                    "title": f"C2 Port Connection: {proc_name} → {remote_ip}:{remote_port}",
                    "path": f"PID {pid}",
                    "reason": (
                        f"Process '{proc_name}' (PID {pid}) connected to {remote_ip}:{remote_port}. "
                        f"Port {remote_port} is commonly used by C2 frameworks, RATs, and backdoors."
                    ),
                    "severity": "HIGH",
                    "category": "network",
                    "subcategory": "c2_port",
                    "pid": pid,
                }
            )


# ── 2. Listening ports audit ──────────────────────────────────────────────────


def scan_listeners(findings: List[Dict], pid_map: Dict[int, str]) -> None:
    """Flag unexpected high-privilege listeners and bind-shells."""
    try:
        ps_cmd = r"""
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress,LocalPort,OwningProcess |
    ConvertTo-Json -Depth 2 -Compress
"""
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return
        raw = result.stdout.strip()
        listeners = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]

        for entry in listeners:
            port = int(entry.get("LocalPort", 0))
            pid = int(entry.get("OwningProcess", 0))
            addr = str(entry.get("LocalAddress", ""))
            proc_name = pid_map.get(pid, "unknown").lower()

            # Bind-shell / RAT ports. Use the unambiguous set only: a dev server
            # or Java app listening on :8080 / :8443 is not a bind shell, and the
            # all-interface-listener block below already covers odd high ports.
            if port in UNAMBIGUOUS_C2_PORTS and proc_name not in TRUSTED_LISTENER_PROCESSES:
                sev = "CRITICAL"
                reason = (
                    f"Port {port} is a well-known RAT/backdoor port. "
                    f"Process: '{proc_name}' PID {pid}."
                )
                findings.append(
                    {
                        "title": f"Bind Shell Indicator: {proc_name} listening on :{port}",
                        "path": f"PID {pid} → {proc_name}",
                        "reason": reason,
                        "severity": sev,
                        "category": "network",
                        "subcategory": "bind_shell",
                        "pid": pid,
                    }
                )

            # 0.0.0.0 listener from non-system process on unexpected port
            if (
                addr in ("0.0.0.0", "::")
                and port > 1024
                and port not in {3389, 5985, 5986, 8080, 8443, 80, 443, 445}
            ):
                if proc_name not in TRUSTED_LISTENER_PROCESSES and proc_name not in {
                    "unknown",
                    "",
                }:
                    findings.append(
                        {
                            "title": f"All-Interface Listener: {proc_name}:{port}",
                            "path": f"PID {pid}",
                            "reason": (
                                f"'{proc_name}' is listening on all interfaces (0.0.0.0:{port}). "
                                f"This exposes the service to the entire network, potentially allowing "
                                f"remote exploitation if the service is vulnerable."
                            ),
                            "severity": "MEDIUM",
                            "category": "network",
                            "subcategory": "exposed_listener",
                            "pid": pid,
                        }
                    )
    except Exception as e:
        log(f"Listener scan failed: {e}")


# ── 3. Hosts file tampering ───────────────────────────────────────────────────


def scan_hosts_file(findings: List[Dict]) -> None:
    hosts_path = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32"
        / "drivers"
        / "etc"
        / "hosts"
    )
    try:
        content = hosts_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        log(f"Could not read hosts file: {e}")
        return

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip, *hostnames = parts

        for hostname in hostnames:
            hostname_lower = hostname.lower()
            for sensitive in SENSITIVE_HOSTS:
                # Exact host or a subdomain of it — NOT an unanchored substring.
                # Substring matching flagged benign internal names like
                # "windows.company.local" (contains "windows.com") as hosts-file
                # tampering.
                if hostname_lower == sensitive or hostname_lower.endswith(
                    "." + sensitive
                ):
                    # Redirecting Windows Update / Microsoft / security domains = CRITICAL
                    is_loopback = ip in ("127.0.0.1", "0.0.0.0", "::1")
                    sev = "HIGH" if is_loopback else "CRITICAL"
                    reason = f"Hosts file overrides '{hostname}' → {ip}. " + (
                        "Redirecting to loopback blocks the service (update blocking / AV evasion)."
                        if is_loopback
                        else "Redirecting to a non-standard IP may indicate DNS hijacking or MITM proxy."
                    )
                    findings.append(
                        {
                            "title": f"Hosts File Override: {hostname} → {ip}",
                            "path": str(hosts_path),
                            "reason": reason,
                            "severity": sev,
                            "category": "network",
                            "subcategory": "hosts_tampering",
                        }
                    )
                    break  # one finding per hostname


# ── 4. Proxy settings (MITM agent check) ─────────────────────────────────────


def scan_proxy_settings(findings: List[Dict]) -> None:
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        try:
            proxy_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            if proxy_enable:
                try:
                    proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0]
                    # Local proxy = possible MITM agent (Burp, Fiddler for bad actors, mitmproxy)
                    is_local = any(
                        x in str(proxy_server)
                        for x in ("127.0.0.1", "localhost", "0.0.0.0", "::1")
                    )
                    sev = "MEDIUM" if is_local else "LOW"
                    findings.append(
                        {
                            "title": f"Proxy Configured: {proxy_server}",
                            "path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                            "reason": (
                                f"WinInet proxy is set to '{proxy_server}'. "
                                + (
                                    "A localhost proxy intercepts all HTTP/HTTPS traffic — "
                                    "this is the configuration used by MITM tools to capture credentials "
                                    "and inject content. Verify this proxy is intentional."
                                    if is_local
                                    else "An external proxy routes your traffic through a third-party server."
                                )
                            ),
                            "severity": sev,
                            "category": "network",
                            "subcategory": "proxy_mitm",
                        }
                    )
                except OSError:
                    pass
        except OSError:
            pass
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        log(f"Proxy check failed: {e}")


# ── 5. DNS cache anomalies ────────────────────────────────────────────────────


def scan_dns_cache(findings: List[Dict]) -> None:
    """Look for suspicious domains in the DNS cache (DGA patterns, known bad TLDs)."""
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-DnsClientCache | Select-Object -ExpandProperty Entry | Sort-Object -Unique | ConvertTo-Json -Compress",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return
        raw = result.stdout.strip()
        entries = json.loads(raw) if raw.startswith("[") else [raw.strip('"')]
        if not isinstance(entries, list):
            entries = [entries]

        # DGA heuristic: long random-looking hostname, not common TLD pattern
        dga_re = re.compile(
            r"^[a-z0-9]{12,}\.(?:com|net|org|info|biz|cc|pw|ru|cn|tk|top|xyz|gq|ml|cf|ga)$",
            re.I,
        )
        suspicious_tld = re.compile(
            r"\.(tk|top|gq|ml|cf|ga|pw|cc|buzz|work|click|link|live|stream)$", re.I
        )

        flagged: Set[str] = set()
        for entry in entries:
            if not isinstance(entry, str):
                continue
            entry = entry.strip().rstrip(".")
            if entry in flagged:
                continue

            if dga_re.match(entry):
                flagged.add(entry)
                findings.append(
                    {
                        "title": f"DGA-Pattern Domain in DNS Cache: {entry}",
                        "path": entry,
                        "reason": (
                            f"DNS cache contains '{entry}' which matches Domain Generation Algorithm (DGA) "
                            f"patterns — long random-looking hostnames are characteristic of malware C2 "
                            f"beaconing. DGA domains rotate automatically to evade blocklists."
                        ),
                        "severity": "HIGH",
                        "category": "network",
                        "subcategory": "dns_dga",
                    }
                )
            elif suspicious_tld.search(entry):
                flagged.add(entry)
                findings.append(
                    {
                        "title": f"Suspicious TLD in DNS Cache: {entry}",
                        "path": entry,
                        "reason": (
                            f"DNS cache contains '{entry}' with a TLD commonly abused for phishing/C2 "
                            f"(.tk, .ml, .gq, .cf, .ga are free domains heavily used by attackers). "
                            f"Investigate what process resolved this domain."
                        ),
                        "severity": "MEDIUM",
                        "category": "network",
                        "subcategory": "dns_suspicious_tld",
                    }
                )
    except Exception as e:
        log(f"DNS cache scan failed: {e}")


# ── 6. Certificate store pollution ───────────────────────────────────────────


def scan_cert_store(findings: List[Dict]) -> None:
    """Flag non-Microsoft root CAs in the system trust store (MITM injection)."""
    try:
        ps_cmd = (
            "Get-ChildItem -Path Cert:\\LocalMachine\\Root | "
            "Select-Object Subject,Thumbprint,NotAfter | "
            "ConvertTo-Json -Depth 2 -Compress"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return
        raw = result.stdout.strip()
        certs = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]

        # Known legitimate root CA subjects (partial match)
        TRUSTED_CA_KEYWORDS = {
            "microsoft",
            "digicert",
            "verisign",
            "entrust",
            "globalsign",
            "comodo",
            "sectigo",
            "baltimore",
            "godaddy",
            "thawte",
            "affirmtrust",
            "buypass",
            "usertrust",
            "starfield",
            "geotrust",
            "rapidssl",
            "cybertrust",
            "amazon",
            "lets encrypt",
            "isrg",
            "dst root",
            "comodoca",
            "certigna",
            "actalis",
            "trustwave",
            "swisssign",
            "quovadis",
            "deutschetelekom",
            "telekom",
            "telia",
            "secom",
            "taiwan",
            "accv",
            "cnnic",
            "certum",
            "asseco",
            "belgian",
            "chunghwa",
            "harica",
        }

        for cert in certs:
            subject = str(cert.get("Subject", "")).lower()
            thumbprint = str(cert.get("Thumbprint", ""))

            # If subject doesn't match any known CA keyword, flag it
            if not any(kw in subject for kw in TRUSTED_CA_KEYWORDS):
                findings.append(
                    {
                        "title": f"Unknown Root CA in Trust Store: {cert.get('Subject','?')[:80]}",
                        "path": f"Cert:\\LocalMachine\\Root\\{thumbprint}",
                        "reason": (
                            f"An unrecognized root certificate authority was found in the system trust store. "
                            f"Subject: {cert.get('Subject','?')} | Thumbprint: {thumbprint}. "
                            f"Malware and corporate MITM proxies inject root CAs to intercept TLS traffic "
                            f"without browser warnings. Verify this certificate is legitimate."
                        ),
                        "severity": "HIGH",
                        "category": "network",
                        "subcategory": "cert_store_pollution",
                    }
                )
    except Exception as e:
        log(f"Certificate store scan failed: {e}")


# ── Main entry ────────────────────────────────────────────────────────────────


# ── 7. Feed-based IOC correlation ────────────────────────────────────────────


def _load_ip_feed(feed_id: str, filename: str) -> Set[str]:
    """Load a newline-delimited IP feed, skipping comments and invalid lines."""
    if not _FEEDS_AVAILABLE:
        return set()
    out: Set[str] = set()
    for line in read_lines(feed_path(feed_id, filename)):
        # IPsum format: "1.2.3.4\t7" — take first token only
        token = line.split()[0] if line else ""
        try:
            ipaddress.ip_address(token)
            out.add(token)
        except ValueError:
            pass
    return out


def _load_text_feed(feed_id: str, filename: str) -> Set[str]:
    """Load a newline-delimited text feed (domains, URLs) as a lowercase set."""
    if not _FEEDS_AVAILABLE:
        return set()
    return {line.lower() for line in read_lines(feed_path(feed_id, filename))}


def scan_feed_intel(findings: List[Dict], pid_map: Dict[int, str]) -> None:
    """Cross-reference active connections against downloaded threat-intel feeds."""
    # ── Load feed sets (degrade gracefully if any feed hasn't been downloaded) ──
    feodo_ips = _load_ip_feed(FEED_FEODO, "c2_ips.txt")
    ipsum_ips = _load_ip_feed(FEED_IPSUM, "ips.txt")
    et_ips = _load_ip_feed(FEED_ET_COMPROMISED, "compromised_ips.txt")
    botvrij = _load_text_feed(FEED_BOTVRIJ, "domains.txt")
    urlhaus = _load_text_feed(FEED_URLHAUS, "urls.txt")
    openphish = _load_text_feed(FEED_OPENPHISH, "urls.txt")

    # IPsum includes scores — only flag IPs appearing in ≥3 lists (score token ≥ 3)
    ipsum_filtered: Set[str] = set()
    if _FEEDS_AVAILABLE:
        for line in read_lines(feed_path(FEED_IPSUM, "ips.txt")):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    if int(parts[1]) >= 3:
                        ipsum_filtered.add(parts[0])
                except ValueError:
                    pass
            elif len(parts) == 1:
                ipsum_filtered.add(parts[0])

    if not any([feodo_ips, ipsum_filtered, et_ips, botvrij, urlhaus, openphish]):
        return

    connections = _get_connections()
    seen: Set[str] = set()

    for conn in connections:
        remote_ip = str(conn.get("RemoteAddress", ""))
        remote_port = int(conn.get("RemotePort", 0))
        state = str(conn.get("State", ""))
        pid = int(conn.get("OwningProcess", 0))
        proc_name = pid_map.get(pid, "unknown")

        if state.lower() != "established" or not remote_ip or _is_private(remote_ip):
            continue

        key = f"{remote_ip}:{remote_port}"
        if key in seen:
            continue

        if remote_ip in feodo_ips:
            seen.add(key)
            findings.append(
                {
                    "title": f"Active Botnet C2 Connection: {proc_name} → {remote_ip}:{remote_port}",
                    "path": f"PID {pid} → {proc_name}",
                    "reason": (
                        f"'{proc_name}' (PID {pid}) is connected to {remote_ip}:{remote_port}, "
                        f"which is listed in the abuse.ch Feodo Tracker botnet C2 blocklist."
                    ),
                    "severity": "CRITICAL",
                    "category": "network",
                    "subcategory": "feed_c2_ip",
                    "pid": pid,
                }
            )
            continue

        if remote_ip in ipsum_filtered:
            seen.add(key)
            findings.append(
                {
                    "title": f"Known-Bad IP Connection: {proc_name} → {remote_ip}:{remote_port}",
                    "path": f"PID {pid} → {proc_name}",
                    "reason": (
                        f"'{proc_name}' (PID {pid}) is connected to {remote_ip}, "
                        f"which appears in 3 or more threat-intel block lists (IPsum aggregate)."
                    ),
                    "severity": "HIGH",
                    "category": "network",
                    "subcategory": "feed_ipsum_ip",
                    "pid": pid,
                }
            )
            continue

        if remote_ip in et_ips:
            seen.add(key)
            findings.append(
                {
                    "title": f"Compromised Host Connection: {proc_name} → {remote_ip}:{remote_port}",
                    "path": f"PID {pid} → {proc_name}",
                    "reason": (
                        f"'{proc_name}' (PID {pid}) is connected to {remote_ip}, "
                        f"listed in the EmergingThreats compromised hosts blocklist."
                    ),
                    "severity": "HIGH",
                    "category": "network",
                    "subcategory": "feed_et_ip",
                    "pid": pid,
                }
            )

    # ── DNS cache correlation against Botvrij malicious domains ──────────────
    if botvrij:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-DnsClientCache | Select-Object -ExpandProperty Entry",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for entry in result.stdout.splitlines():
                domain = entry.strip().lower().rstrip(".")
                if not domain:
                    continue
                # Check exact match and parent domains
                parts = domain.split(".")
                for i in range(len(parts) - 1):
                    candidate = ".".join(parts[i:])
                    if candidate in botvrij:
                        key = f"dns:{domain}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                {
                                    "title": f"DNS Cache: Malicious Domain {domain}",
                                    "path": domain,
                                    "reason": (
                                        f"The domain '{domain}' (or a parent) was found in the DNS "
                                        f"resolver cache and matches the Botvrij.eu malicious domain feed."
                                    ),
                                    "severity": "HIGH",
                                    "category": "network",
                                    "subcategory": "feed_malicious_domain",
                                }
                            )
                        break
        except Exception as e:
            log(f"Botvrij DNS correlation failed: {e}")

    # ── URLhaus / OpenPhish: flag if any cached URL/domain matches ────────────
    combined_url_feeds = urlhaus | openphish
    if combined_url_feeds:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-DnsClientCache | Select-Object -ExpandProperty Entry",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for entry in result.stdout.splitlines():
                domain = entry.strip().lower().rstrip(".")
                if not domain:
                    continue
                for url in combined_url_feeds:
                    if domain in url:
                        key = f"urlhit:{domain}"
                        if key not in seen:
                            seen.add(key)
                            src = (
                                "URLhaus"
                                if urlhaus and any(domain in u for u in urlhaus)
                                else "OpenPhish"
                            )
                            findings.append(
                                {
                                    "title": f"DNS Cache: {src} Malicious URL Match — {domain}",
                                    "path": domain,
                                    "reason": (
                                        f"The domain '{domain}' was found in the DNS cache and matches "
                                        f"a known malicious URL in the {src} feed."
                                    ),
                                    "severity": "HIGH",
                                    "category": "network",
                                    "subcategory": "feed_malicious_url",
                                }
                            )
                        break
        except Exception as e:
            log(f"URLhaus/OpenPhish DNS correlation failed: {e}")


def scan_network() -> List[Dict]:
    findings: List[Dict] = []
    pid_map = _get_pid_to_name()

    scan_connections(findings, pid_map)
    scan_listeners(findings, pid_map)
    scan_hosts_file(findings)
    scan_proxy_settings(findings)
    scan_dns_cache(findings)
    scan_cert_store(findings)
    if _FEEDS_AVAILABLE:
        scan_feed_intel(findings, pid_map)

    log(f"Network scan complete: {len(findings)} findings")
    return findings


if __name__ == "__main__":
    import sys

    results = scan_network()
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    results.sort(key=lambda f: sev_rank.get(f.get("severity", "INFO"), 0), reverse=True)
    print(
        json.dumps(
            {"scanner": "WRAITH-network", "mode": "network", "findings": results},
            default=str,
            indent=2,
        )
    )
