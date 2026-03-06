"""
WRAITH — ATT&CK Mapper
Tags every finding with a MITRE ATT&CK technique ID and name based on
category, subcategory, and keyword analysis of title + reason fields.

No network calls — mapping is pure static lookup against two tables:
  CATEGORY_MAP   exact (category, subcategory) → technique
  KEYWORD_MAP    keyword list → technique (fallback when subcategory is fuzzy)

Reference: https://attack.mitre.org/
"""

from typing import Any, Dict, List, Optional

# ── Primary map: (category, subcategory) → (technique_id, technique_name) ─
CATEGORY_MAP: Dict[tuple, tuple] = {
    # Persistence
    ("persistence", "registry_run"): (
        "T1547.001",
        "Boot or Logon Autostart: Registry Run Keys",
    ),
    ("persistence", "startup_folder"): (
        "T1547.001",
        "Boot or Logon Autostart: Startup Folder",
    ),
    ("persistence", "scheduled_task"): (
        "T1053.005",
        "Scheduled Task/Job: Scheduled Task",
    ),
    ("persistence", "service"): (
        "T1543.003",
        "Create or Modify System Process: Windows Service",
    ),
    ("persistence", "wmi_subscription"): (
        "T1546.003",
        "Event Triggered Execution: WMI Event Subscription",
    ),
    # Heuristics
    ("heuristics", "suspicious_cmdline"): (
        "T1059",
        "Command and Scripting Interpreter",
    ),
    ("heuristics", "high_entropy"): ("T1027", "Obfuscated Files or Information"),
    ("heuristics", "double_extension"): (
        "T1036.007",
        "Masquerading: Double File Extension",
    ),
    ("heuristics", "suspicious_name"): ("T1036", "Masquerading"),
    ("heuristics", "suspicious_parent"): ("T1055", "Process Injection"),
    # Processes
    ("processes", "pe_anomaly"): ("T1055", "Process Injection"),
    ("processes", "suspicious_string"): ("T1055", "Process Injection"),
    ("processes", "suspicious_cmdline"): ("T1059", "Command and Scripting Interpreter"),
    ("processes", "unbacked_memory"): (
        "T1055.001",
        "Process Injection: Dynamic-link Library Injection",
    ),
    ("processes", "hollowed_image"): (
        "T1055.012",
        "Process Injection: Process Hollowing",
    ),
    # Network
    ("network", "suspicious_outbound"): ("T1041", "Exfiltration Over C2 Channel"),
    ("network", "c2_port"): ("T1071", "Application Layer Protocol"),
    ("network", "bind_shell"): ("T1059", "Command and Scripting Interpreter"),
    ("network", "suspicious_listener"): ("T1090", "Proxy"),
    ("network", "dns_anomaly"): ("T1071.004", "Application Layer Protocol: DNS"),
    # Credentials
    ("credential", "sam_lsa"): ("T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("credential", "dpapi"): ("T1555", "Credentials from Password Stores"),
    ("credential", "plaintext"): ("T1552", "Unsecured Credentials"),
    ("credential", "sam"): (
        "T1003.002",
        "OS Credential Dumping: Security Account Manager",
    ),
    # Rootkit
    ("rootkit", "ssdt_hook"): ("T1014", "Rootkit"),
    ("rootkit", "hidden_driver"): ("T1014", "Rootkit"),
    ("rootkit", "dkom"): ("T1014", "Rootkit"),
    ("rootkit", "idt_hook"): ("T1014", "Rootkit"),
    # ADS
    ("ads", "alternate_data_stream"): (
        "T1564.004",
        "Hide Artifacts: NTFS File Attributes",
    ),
    # Browser
    ("browser", "extension"): ("T1176", "Browser Extensions"),
    ("browser", "hosts_file"): (
        "T1565.001",
        "Data Manipulation: Stored Data Manipulation",
    ),
    ("browser", "malicious_bookmark"): ("T1176", "Browser Extensions"),
    # NPM / supply chain
    ("npm", "typosquat"): (
        "T1195.001",
        "Supply Chain Compromise: Compromise Software Dependencies",
    ),
    ("npm", "dependency_confusion"): (
        "T1195.001",
        "Supply Chain Compromise: Compromise Software Dependencies",
    ),
    # Events
    ("events", "logon_anomaly"): ("T1078", "Valid Accounts"),
    ("events", "privilege_escalation"): (
        "T1068",
        "Exploitation for Privilege Escalation",
    ),
    ("events", "account_creation"): ("T1136", "Create Account"),
    ("events", "audit_log_cleared"): (
        "T1070.001",
        "Indicator Removal: Clear Windows Event Logs",
    ),
    # YARA
    ("yara", "yara_match"): ("T1203", "Exploitation for Client Execution"),
    # Defender
    ("defender", "quarantine"): (
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
    ),
    # Windows Security
    ("winsec", "firewall_disabled"): (
        "T1562.004",
        "Impair Defenses: Disable or Modify System Firewall",
    ),
    ("winsec", "defender_disabled"): (
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
    ),
    ("winsec", "uac_disabled"): (
        "T1548.002",
        "Abuse Elevation Control Mechanism: Bypass User Account Control",
    ),
    ("winsec", "audit_gap"): (
        "T1562.002",
        "Impair Defenses: Disable Windows Event Logging",
    ),
    # KEV
    ("kev", "kev_match"): ("T1190", "Exploit Public-Facing Application"),
}

# ── Keyword fallback: list of keywords → (technique_id, technique_name) ──
KEYWORD_MAP: List[tuple] = [
    (
        ["powershell", "ps1", "encoded command", "encodedcommand", "-enc "],
        ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ),
    (
        ["wscript", "cscript", "vbscript", ".vbs", "jscript"],
        ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    ),
    (["mshta", ".hta"], ("T1218.005", "Signed Binary Proxy Execution: Mshta")),
    (["regsvr32"], ("T1218.010", "Signed Binary Proxy Execution: Regsvr32")),
    (["rundll32"], ("T1218.011", "Signed Binary Proxy Execution: Rundll32")),
    (["certutil"], ("T1140", "Deobfuscate/Decode Files or Information")),
    (["bitsadmin", "bits transfer"], ("T1197", "BITS Jobs")),
    (
        ["inject", "hollowing", "reflective load", "dll inject"],
        ("T1055", "Process Injection"),
    ),
    (
        ["mimikatz", "sekurlsa", "lsass dump"],
        ("T1003.001", "OS Credential Dumping: LSASS Memory"),
    ),
    (
        ["meterpreter", "beacon", "cobalt strike"],
        ("T1071", "Application Layer Protocol"),
    ),
    (["shellcode"], ("T1055", "Process Injection")),
    (
        ["scheduled task", "schtasks"],
        ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    ),
    (
        ["entropy", "obfuscat", "base64", "xor encode", "xor decode"],
        ("T1027", "Obfuscated Files or Information"),
    ),
    (
        ["autorun", "run key", "currentversion\\run"],
        ("T1547.001", "Boot or Logon Autostart: Registry Run Keys"),
    ),
    (
        ["wmi event", "wmic", "__eventfilter", "__eventconsumer"],
        ("T1546.003", "Event Triggered Execution: WMI Event Subscription"),
    ),
    (["shadow copy", "vssadmin", "wbadmin"], ("T1490", "Inhibit System Recovery")),
    (["taskkill", "net stop", "sc stop"], ("T1489", "Service Stop")),
    (
        ["alternate data stream", ":$data", "zone.identifier"],
        ("T1564.004", "Hide Artifacts: NTFS File Attributes"),
    ),
    (
        ["supply chain", "typosquat", "dependency confusion"],
        ("T1195.001", "Supply Chain Compromise: Compromise Software Dependencies"),
    ),
    (
        ["browser extension", "chrome extension", "firefox addon"],
        ("T1176", "Browser Extensions"),
    ),
    (
        ["wget", "curl", "invoke-webrequest", "downloadfile", "downloadstring"],
        ("T1105", "Ingress Tool Transfer"),
    ),
    (
        ["uac bypass", "fodhelper", "eventvwr", "sdclt"],
        ("T1548.002", "Abuse Elevation Control Mechanism: Bypass UAC"),
    ),
    (["token impersonat", "impersonat"], ("T1134", "Access Token Manipulation")),
    (["net user", "net localgroup", "dsadd user"], ("T1136", "Create Account")),
    (
        ["wevtutil cl", "clear-eventlog", "remove-eventlog"],
        ("T1070.001", "Indicator Removal: Clear Windows Event Logs"),
    ),
    (["ntds.dit", "ntdsutil"], ("T1003.003", "OS Credential Dumping: NTDS")),
    (
        ["dpapi", "masterkeyfile", "credentialfile"],
        ("T1555", "Credentials from Password Stores"),
    ),
    (
        ["pass-the-hash", "pth", "overpass-the-hash"],
        ("T1550.002", "Use Alternate Authentication Material: Pass the Hash"),
    ),
    (
        ["kerberoast", "asrep", "as-rep"],
        ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    ),
]


def _map_technique(finding: Dict[str, Any]) -> Optional[tuple]:
    """
    Return (technique_id, technique_name) for a finding.
    Returns None if already tagged or no mapping found.
    """
    # Don't overwrite a tag already set (e.g. by ioc_enricher from ThreatFox)
    if finding.get("technique_id"):
        return None

    category = str(finding.get("category", "")).lower()
    subcategory = str(finding.get("subcategory", "")).lower()
    title = str(finding.get("title", "")).lower()
    reason = str(finding.get("reason", "")).lower()
    combined = f"{title} {reason}"

    # 1. Exact (category, subcategory) match
    hit = CATEGORY_MAP.get((category, subcategory))
    if hit:
        return hit

    # 2. Keyword scan across title + reason
    for keywords, tech in KEYWORD_MAP:
        if any(kw in combined for kw in keywords):
            return tech

    # 3. Category-only fallback — pick first entry with matching category
    for (cat, _sub), tech in CATEGORY_MAP.items():
        if cat == category:
            return tech

    return None


def tag_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add `technique_id` and `technique_name` to every finding that can be mapped.
    Existing tags are never overwritten.
    """
    for f in findings:
        result = _map_technique(f)
        if result:
            f["technique_id"], f["technique_name"] = result
    return findings
