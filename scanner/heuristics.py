"""
WRAITH - Heuristic Analysis Module
Detects suspicious characteristics without signature matching:
- High entropy (packed/encrypted executables)
- Suspicious strings in binaries
- Double-extension filenames
- Files in unusual locations
- PE anomalies
"""

import os
import math
import struct
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

# ── Suspicious string patterns ──────────────────────────────────────────
SUSPICIOUS_STRINGS = [
    # C2 / remote access patterns
    rb"CreateRemoteThread",
    rb"VirtualAllocEx",
    rb"WriteProcessMemory",
    rb"NtCreateThreadEx",
    rb"RtlCreateUserThread",
    rb"SetWindowsHookEx",
    # Crypto / obfuscation
    rb"FromBase64String",
    rb"Convert\.FromBase64",
    rb"XORKey",
    rb"RC4",
    # Downloaders
    rb"DownloadString",
    rb"WebClient",
    rb"HttpWebRequest",
    rb"bitsadmin",
    rb"certutil\s+-decode",
    # Persistence
    rb"CurrentVersion\\Run",
    rb"schtasks.*create",
    rb"sc.*create.*binpath",
    rb"bcdedit.*disable",
    # npm supply chain attack patterns (cline/similar)
    rb"npm\s+install.*--global.*&&",
    rb"process\.env\.npm_lifecycle",
    rb"require\(['\"]child_process['\"]\)",
    rb"execSync.*rm\s+-rf",
    rb"execSync.*curl",
    rb"spawn.*powershell",
    rb"Buffer\.from.*base64",
    # PowerShell evasion
    rb"-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]",
    rb"-[Nn][Oo][Pp][Rr][Oo][Ff][Ii][Ll][Ee]",
    rb"bypass.*executionpolicy",
    rb"Invoke-Shellcode",
    rb"Invoke-Mimikatz",
    rb"Invoke-ReflectivePEInjection",
]

# Double extension patterns
DOUBLE_EXT_RE = re.compile(
    r"\.(txt|pdf|doc|docx|jpg|png|zip|rar)\.(exe|bat|cmd|vbs|ps1|scr|com)$",
    re.IGNORECASE,
)

# Paths worth scanning heuristically
HEURISTIC_SCAN_PATHS = [
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    r"C:\Windows\Temp",
    r"C:\ProgramData",
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
]

SKIP_DIRS_LOWER = {"winsxs", "assembly", "microsoft.net", "installer", "$recycle.bin"}
SCAN_EXT = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".hta",
    ".com",
}


def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for f in freq:
        if f:
            p = f / total
            entropy -= p * math.log2(p)
    return entropy


def check_pe_header(data: bytes) -> Tuple[bool, str]:
    """Check for PE anomalies."""
    if len(data) < 64:
        return False, ""
    if data[:2] != b"MZ":
        return False, ""
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 > len(data):
            return True, "Invalid PE offset"
        sig = data[pe_offset : pe_offset + 4]
        if sig != b"PE\x00\x00":
            return (
                True,
                f"Missing PE signature (got {sig!r}) – possibly corrupted or hollowed",
            )
    except Exception:
        return True, "PE header parse error"
    return False, ""


def scan_file_heuristics(filepath: str) -> List[Dict]:
    findings = []
    fname = os.path.basename(filepath)
    ext = Path(filepath).suffix.lower()

    # Double extension check
    if DOUBLE_EXT_RE.search(fname):
        findings.append(
            {
                "category": "heuristics",
                "subcategory": "double_extension",
                "severity": "HIGH",
                "title": f"Double Extension: {fname}",
                "path": filepath,
                "reason": "Filename uses double extension to disguise executable",
            }
        )

    # Read file for analysis
    try:
        with open(filepath, "rb") as f:
            data = f.read(1024 * 1024)  # read up to 1MB
    except Exception:
        return findings

    # Entropy check
    if ext in (".exe", ".dll", ".sys", ".scr"):
        entropy = calc_entropy(data)
        if entropy > 7.2:
            findings.append(
                {
                    "category": "heuristics",
                    "subcategory": "high_entropy",
                    "severity": "HIGH",
                    "title": f"High Entropy Binary: {fname}",
                    "path": filepath,
                    "entropy": round(entropy, 4),
                    "reason": f"Entropy={entropy:.3f} (>7.2 indicates packing/encryption)",
                }
            )

        # PE anomaly check
        anomaly, reason = check_pe_header(data)
        if anomaly:
            findings.append(
                {
                    "category": "heuristics",
                    "subcategory": "pe_anomaly",
                    "severity": "CRITICAL",
                    "title": f"PE Anomaly: {fname}",
                    "path": filepath,
                    "reason": reason,
                }
            )

    # Suspicious strings in ALL scanned file types
    lower_data = data.lower()
    for pattern in SUSPICIOUS_STRINGS:
        if pattern.lower() in lower_data:
            findings.append(
                {
                    "category": "heuristics",
                    "subcategory": "suspicious_string",
                    "severity": "HIGH",
                    "title": f"Suspicious String in {fname}",
                    "path": filepath,
                    "pattern": pattern.decode("utf-8", errors="replace"),
                    "reason": f"Contains suspicious indicator: {pattern.decode('utf-8', errors='replace')}",
                }
            )
            break  # One finding per file to avoid noise; track all in detail field

    return findings


def scan_heuristics(scan_path: str) -> Dict[str, Any]:
    findings = []
    files_scanned = 0
    scanned = set()

    def scan_dir(base: str):
        nonlocal files_scanned
        if not os.path.exists(base):
            return
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS_LOWER]
            for fname in files:
                fpath = os.path.join(root, fname)
                if fpath in scanned:
                    continue
                if Path(fpath).suffix.lower() not in SCAN_EXT:
                    # Still check for double extension even if not primary ext
                    if DOUBLE_EXT_RE.search(fname):
                        pass
                    else:
                        continue
                scanned.add(fpath)
                files_scanned += 1
                hits = scan_file_heuristics(fpath)
                findings.extend(hits)

    for p in HEURISTIC_SCAN_PATHS:
        if p:
            scan_dir(p)

    return {
        "module": "heuristics",
        "findings_count": len(findings),
        "files_scanned": files_scanned,
        "findings": findings,
    }
