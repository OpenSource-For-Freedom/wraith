"""
WRAITH ads_scanner.py
Module 4 of 7 - Alternate Data Streams (ADS) & NTFS Forensics

Checks:
  1. ADS on files in temp/download dirs   - hidden payloads in non-standard streams
  2. Executable content in ADS            - PE headers (.exe/.dll) inside a stream
  3. System32 binaries with Zone.Id       - shouldn't be "downloaded" files
  4. ADS on startup folder files          - persistence via stream hiding
  5. Large ADS (> 50 KB)                  - likely hidden payload
  6. Directory ADS                        - rootkits sometimes hide in dir ADS
  7. Recently modified system binaries    - timestomping / binary patching indicator
  8. Suspicious file-in-file (polyglot)   - ADS named like an executable extension
"""

import json
import os
import re
import subprocess
import sys
import winreg
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

# Streams that are always benign
BENIGN_STREAMS = {
    ":$DATA",
    "Zone.Identifier",
    "SummaryInformation",  # Office legacy
    "DocumentSummaryInformation",
    "com.dropbox.attributes",  # Dropbox
    "com.apple.quarantine",
    "AFP_AfpInfo",
    "SmartScreen",
    "Afp_AfpInfo",
    "OECustomProperty",
    "TASKICON",
    "encryptable",
    "Win32App_1",
    "Win32App_2",
    "Win32App_3",
    "StreamedFileState",  # Windows Shell: incomplete/streamed download marker
    "ThumbnailCacheIndex",  # Explorer thumbnail cache
    "favicon",  # Browser favicon cache
    "KernelValidation",  # Windows kernel file validation
    "CERTIFICATE",  # Signed file certificate block
    "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",  # NTFS crypto key ref
    "LjpMetadataAttributes",  # LibreOffice/OpenOffice
}

# Extensions that should NEVER appear as ADS names on normal files
SUSPICIOUS_STREAM_EXTENSIONS = (
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jar",
    ".hta",
    ".scr",
    ".pif",
    ".com",
    ".cpl",
    ".msi",
    ".py",
    ".rb",
    ".sh",
    ".elf",
    ".so",
)


# User-writable temp / landing zones where malware drops payloads
def _get_scan_dirs() -> List[Path]:
    dirs = []
    # Per-user temp
    temp = Path(os.environ.get("TEMP", r"C:\Windows\Temp"))
    if temp.exists():
        dirs.append(temp)
    # SystemRoot temp
    sys_temp = Path(r"C:\Windows\Temp")
    if sys_temp.exists() and sys_temp != temp:
        dirs.append(sys_temp)
    # User profile dirs
    userprofile = Path(os.environ.get("USERPROFILE", ""))
    for sub in ("Downloads", "Desktop", "AppData\\Roaming", "AppData\\Local\\Temp"):
        p = userprofile / sub
        if p.exists():
            dirs.append(p)
    # Public dirs
    for pub in (
        r"C:\Users\Public",
        r"C:\Users\Public\Desktop",
        r"C:\Users\Public\Downloads",
    ):
        p = Path(pub)
        if p.exists():
            dirs.append(p)
    # Startup folders
    startup = Path(
        os.environ.get("APPDATA", "")
        + r"\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    if startup.exists():
        dirs.append(startup)
    common_startup = Path(
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    if common_startup.exists():
        dirs.append(common_startup)
    return dirs


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


def _get_ads_for_dir(directory: Path, recurse: bool = False) -> List[Dict]:
    """
    Use PowerShell Get-Item -Stream to enumerate NTFS ADS on files in
    a directory. Returns raw stream records.
    """
    depth = "-Recurse" if recurse else ""
    # Limit depth to avoid slow traversal
    cmd = (
        f"Get-ChildItem -Path '{directory}' {depth} -Force -ErrorAction SilentlyContinue "
        f"| Get-Item -Stream * -ErrorAction SilentlyContinue "
        f"| Where-Object {{$_.Stream -notin @(':$DATA')}} "
        f"| Select-Object FileName, Stream, Length "
        f"| ConvertTo-Json -Compress"
    )
    out = _run_ps(cmd, timeout=45)
    if not out:
        return []
    try:
        items = json.loads(out)
        if isinstance(items, dict):
            items = [items]
        return [i for i in items if isinstance(i, dict)]
    except Exception:
        return []


def _is_pe_header(data: bytes) -> bool:
    """Return True if the bytes start with DOS MZ header (PE executable)."""
    return data[:2] == b"MZ"


def _read_stream_bytes(filepath: str, stream: str, max_bytes: int = 512) -> bytes:
    """Read first max_bytes of an NTFS ADS via PowerShell."""
    cmd = (
        f"$b = Get-Content -Path '{filepath}:{stream}' -Encoding Byte "
        f"-ReadCount 0 -TotalCount {max_bytes} -ErrorAction SilentlyContinue; "
        f"[System.Convert]::ToBase64String($b)"
    )
    b64 = _run_ps(cmd).strip()
    if not b64:
        return b""
    try:
        import base64

        return base64.b64decode(b64)
    except Exception:
        return b""


# ──────────────────────────────────────────────
# Check 1 + 2 + 4 + 5: ADS in hot directories
# ──────────────────────────────────────────────


def check_ads_in_hot_dirs() -> List[Dict]:
    """
    Enumerate non-standard ADS on files in temp, downloads, desktop,
    startup, and public directories.
    """
    findings = []
    scan_dirs = _get_scan_dirs()

    for directory in scan_dirs:
        streams = _get_ads_for_dir(directory, recurse=False)
        for item in streams:
            stream_name = str(item.get("Stream", ""))
            filepath = str(item.get("FileName", ""))
            length = int(item.get("Length", 0) or 0)

            # Skip always-benign streams
            if stream_name in BENIGN_STREAMS:
                continue

            # === Heuristic A: stream extension looks like an executable ===
            lower_stream = stream_name.lower()
            if any(lower_stream.endswith(ext) for ext in SUSPICIOUS_STREAM_EXTENSIONS):
                findings.append(
                    {
                        "title": f"Executable-named ADS: {stream_name}",
                        "path": f"{filepath}:{stream_name}",
                        "reason": (
                            f"File '{filepath}' has an Alternate Data Stream named "
                            f"'{stream_name}' ({length} bytes). Stream names ending in "
                            "executable extensions (.exe, .dll, .ps1, etc.) are used by "
                            "malware to hide binaries inside innocent-looking files. "
                            "NTFS ADS are invisible to Explorer and most file managers."
                        ),
                        "severity": "CRITICAL",
                        "category": "ads",
                        "subcategory": "exec_stream",
                    }
                )
                continue

            # === Heuristic B: large stream (>50 KB) ===
            if length > 51200:
                findings.append(
                    {
                        "title": f"Large ADS ({length // 1024} KB): {stream_name}",
                        "path": f"{filepath}:{stream_name}",
                        "reason": (
                            f"File '{filepath}' has a {length // 1024} KB Alternate Data "
                            f"Stream named '{stream_name}'. Streams larger than 50 KB in "
                            "temp or user-writable directories often conceal full payloads, "
                            "archives, or encrypted shellcode."
                        ),
                        "severity": "HIGH",
                        "category": "ads",
                        "subcategory": "large_stream",
                    }
                )
                continue

            # === Heuristic C: any unknown stream in startup folders ===
            fp_lower = filepath.lower()
            if "startup" in fp_lower or "start menu" in fp_lower:
                findings.append(
                    {
                        "title": f"ADS in Startup folder: {stream_name}",
                        "path": f"{filepath}:{stream_name}",
                        "reason": (
                            f"A startup folder entry '{filepath}' has an Alternate Data "
                            f"Stream '{stream_name}' ({length} bytes). Persistence via ADS "
                            "in the startup folder allows code execution at logon while "
                            "remaining invisible in the folder's normal directory listing."
                        ),
                        "severity": "HIGH",
                        "category": "ads",
                        "subcategory": "startup_ads",
                    }
                )
                continue

            # === Heuristic D: any other unknown stream in hot dirs ===
            findings.append(
                {
                    "title": f"Unknown ADS: {stream_name}",
                    "path": f"{filepath}:{stream_name}",
                    "reason": (
                        f"File '{filepath}' has an Alternate Data Stream '{stream_name}' "
                        f"({length} bytes) in a user-writable directory. Legitimate ADS "
                        "are limited to Zone.Identifier and a few application-managed "
                        "streams. Unknown streams in temp/download dirs warrant inspection."
                    ),
                    "severity": "MEDIUM",
                    "category": "ads",
                    "subcategory": "unknown_stream",
                }
            )

    return findings


# ──────────────────────────────────────────────
# Check 3: System32 binaries with Zone.Identifier
# ──────────────────────────────────────────────


def check_system32_zone_id() -> List[Dict]:
    """
    System32 files should never have been 'downloaded' from the internet.
    A Zone.Identifier stream on a system binary indicates it was replaced by
    a downloaded file — a strong Trojan/binary replacement indicator.
    """
    findings = []
    sys32 = Path(r"C:\Windows\System32")
    if not sys32.exists():
        return findings

    cmd = (
        "Get-ChildItem -Path 'C:\\Windows\\System32' -Filter '*.exe' "
        "-ErrorAction SilentlyContinue "
        "| Get-Item -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue "
        "| Select-Object FileName, Stream, Length "
        "| ConvertTo-Json -Compress"
    )
    out = _run_ps(cmd, timeout=45)
    if not out:
        return findings

    try:
        items = json.loads(out)
        if isinstance(items, dict):
            items = [items]
        for item in items[:20]:  # cap
            filepath = str(item.get("FileName", ""))
            length = int(item.get("Length", 0) or 0)
            if filepath:
                findings.append(
                    {
                        "title": f"System32 binary has Zone.Identifier: {Path(filepath).name}",
                        "path": filepath,
                        "reason": (
                            f"'{filepath}' has a Zone.Identifier ADS ({length} bytes), "
                            "indicating it was downloaded from the internet. Legitimate "
                            "Windows system binaries in System32 are installed via Windows "
                            "Update and never carry this mark. This indicates the binary "
                            "was replaced with a file downloaded from an external source — "
                            "a strong Trojan/backdoor indicator."
                        ),
                        "severity": "CRITICAL",
                        "category": "ads",
                        "subcategory": "system32_zone_id",
                    }
                )
    except Exception:
        pass

    return findings


# ──────────────────────────────────────────────
# Check 6: ADS on directories
# ──────────────────────────────────────────────


def check_directory_ads() -> List[Dict]:
    """
    NTFS ADS can be attached to directories as well as files.
    Rootkits use directory ADS to hide configuration, payloads, or
    scheduled task definitions outside normal file system enumeration.
    """
    findings = []

    SUSPICIOUS_DIRS = [
        r"C:\Windows",
        r"C:\Windows\System32",
        r"C:\Windows\Temp",
        r"C:\Users\Public",
        os.environ.get("TEMP", ""),
    ]

    cmd_template = (
        "Get-Item -Path '{path}' -Stream * -ErrorAction SilentlyContinue "
        "| Where-Object {{$_.Stream -ne ':$DATA'}} "
        "| Select-Object FileName, Stream, Length "
        "| ConvertTo-Json -Compress"
    )

    for dpath in SUSPICIOUS_DIRS:
        if not dpath or not Path(dpath).exists():
            continue
        out = _run_ps(cmd_template.format(path=dpath), timeout=15)
        if not out:
            continue
        try:
            items = json.loads(out)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                stream = str(item.get("Stream", ""))
                if stream in BENIGN_STREAMS:
                    continue
                length = int(item.get("Length", 0) or 0)
                findings.append(
                    {
                        "title": f"ADS on directory: {stream}",
                        "path": f"{dpath}:{stream}",
                        "reason": (
                            f"Directory '{dpath}' has an Alternate Data Stream '{stream}' "
                            f"({length} bytes). Directory ADS are not created by any "
                            "legitimate Windows component. They are used by rootkits and "
                            "advanced malware to store hidden configuration or payloads "
                            "that survive typical file system scans."
                        ),
                        "severity": "HIGH",
                        "category": "ads",
                        "subcategory": "directory_ads",
                    }
                )
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 7: Recently modified system binaries
# ──────────────────────────────────────────────


def check_recently_modified_sys_binaries() -> List[Dict]:
    """
    System binaries in System32/SysWOW64 should only change during
    Windows Update. Recent modifications outside update windows suggest
    binary patching (rootkit installation), Trojan replacement, or
    timestomping.
    """
    findings = []
    threshold = datetime.now() - timedelta(days=7)

    WATCH_DIRS = [
        Path(r"C:\Windows\System32"),
        Path(r"C:\Windows\SysWOW64"),
    ]

    # Key system binaries to spot-check (not scanning all ~4000 files)
    WATCHED_BINARIES = [
        # Core process infrastructure
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "advapi32.dll",
        "sechost.dll",
        "rpcrt4.dll",
        "combase.dll",
        # Authentication
        "lsass.exe",
        "lsasrv.dll",
        "msv1_0.dll",
        "kerberos.dll",
        "wdigest.dll",
        "tspkg.dll",
        "pku2u.dll",
        "livessp.dll",
        "samsrv.dll",
        "samlib.dll",
        # Core Windows processes
        "svchost.exe",
        "services.exe",
        "winlogon.exe",
        "wininit.exe",
        "csrss.exe",
        "smss.exe",
        "explorer.exe",
        # Network
        "netlogon.dll",
        "winsock.dll",
        "ws2_32.dll",
        "mswsock.dll",
        # Security
        "cryptdll.dll",
        "dpapi.dll",
        "wldap32.dll",
    ]

    for watch_dir in WATCH_DIRS:
        if not watch_dir.exists():
            continue
        for binary_name in WATCHED_BINARIES:
            bin_path = watch_dir / binary_name
            if not bin_path.exists():
                continue
            try:
                mtime = datetime.fromtimestamp(bin_path.stat().st_mtime)
                if mtime > threshold:
                    # Cross-check: if it was modified, was it within a Windows Update?
                    # Heuristic: check if there's a SideBySide manifest for this file
                    # (legitimate WU updates create CBS\Logs entries)
                    mod_str = mtime.strftime("%Y-%m-%d %H:%M:%S")
                    findings.append(
                        {
                            "title": f"Critical system binary recently modified: {binary_name}",
                            "path": str(bin_path),
                            "reason": (
                                f"'{bin_path}' was last modified {mod_str} (within the "
                                "last 7 days). Critical Windows system DLLs and executables "
                                "should only change during Windows Update. Recent modifications "
                                "to authentication libraries (lsasrv.dll, wdigest.dll, etc.) "
                                "are a strong indicator of pass-the-hash implant installation "
                                "or LSASS patching. Verify via CBS log: "
                                r"C:\Windows\Logs\CBS\CBS.log"
                            ),
                            "severity": "HIGH",
                            "category": "ads",
                            "subcategory": "modified_sys_binary",
                        }
                    )
            except (PermissionError, OSError):
                pass

    return findings


# ──────────────────────────────────────────────
# Check 8: PE header in any ADS (deep check on flagged files)
# ──────────────────────────────────────────────


def check_pe_in_ads() -> List[Dict]:
    """
    Scan temp dirs for any ADS that starts with a DOS MZ header (PE file).
    A PE inside an ADS means a full executable is hidden in a data file.
    """
    findings = []
    temp = Path(os.environ.get("TEMP", r"C:\Windows\Temp"))
    if not temp.exists():
        return findings

    # Get all non-standard ADS in temp dir
    streams = _get_ads_for_dir(temp, recurse=False)
    for item in streams:
        stream = str(item.get("Stream", ""))
        filepath = str(item.get("FileName", ""))
        length = int(item.get("Length", 0) or 0)

        if stream in BENIGN_STREAMS or length < 2:
            continue

        # Only check plausible-size streams (PE is at least 64 bytes)
        if length < 64:
            continue

        data = _read_stream_bytes(filepath, stream, max_bytes=256)
        if _is_pe_header(data):
            findings.append(
                {
                    "title": f"PE executable hidden in ADS: {stream}",
                    "path": f"{filepath}:{stream}",
                    "reason": (
                        f"An ADS '{stream}' on '{filepath}' begins with a DOS MZ header "
                        "(0x4D5A), indicating a valid Windows PE executable (EXE/DLL) is "
                        "embedded inside this data stream. This is a well-known technique "
                        "for hiding malware inside innocent-looking files while evading "
                        "directory-based scanners. The file can be executed directly via "
                        "wscript.exe or by patching the stream as a script resource."
                    ),
                    "severity": "CRITICAL",
                    "category": "ads",
                    "subcategory": "pe_in_ads",
                }
            )

    return findings


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────


def scan_ads() -> List[Dict]:
    findings: List[Dict] = []
    checks = [
        ("ads_hot_dirs", check_ads_in_hot_dirs),
        ("system32_zone_id", check_system32_zone_id),
        ("directory_ads", check_directory_ads),
        ("modified_sys_bins", check_recently_modified_sys_binaries),
        ("pe_in_ads", check_pe_in_ads),
    ]
    for name, fn in checks:
        try:
            results = fn()
            findings.extend(results)
        except Exception as e:
            sys.stderr.write(f"[WRAITH-ADS] check '{name}' error: {e}\n")

    return findings


if __name__ == "__main__":
    sys.stderr.write("[WRAITH-ADS] ADS & NTFS forensics scan starting...\n")
    results = scan_ads()
    sys.stderr.write(f"[WRAITH-ADS] ADS scan complete: {len(results)} findings\n")
    output = {
        "scanner": "WRAITH-ads",
        "mode": "ads",
        "findings": results,
    }
    print(json.dumps(output, indent=2))
