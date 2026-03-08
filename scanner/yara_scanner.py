"""
WRAITH - YARA Scanner Module
Downloads public YARA rules and scans files for known malware signatures.
"""

import os
import sys
import json
import glob
import hashlib
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ── YARA rule sources (public domain / open source) ─────────────────────
# Each entry is a list of candidate URLs tried in order; first success wins.
RULE_SOURCES: dict[str, list[str]] = {
    "apt_grizzlybear": [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_grizzlybear_uscert.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT29_Grizzly_Steppe.yar",
    ],
    "apt_apt28_sofacy": [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_apt28.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_fancybear_dnc.yar",
    ],
    "gen_webshells": [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_cn_webshells.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar",
    ],
    "gen_rats": [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_rats_malwareconfig.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RAT_Adwind.yar",
    ],
    "gen_mal_scripts": [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_mal_scripts.yar",
    ],
    "hacktools": [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-hacktools.yar",
    ],
    "apt_lazarus": [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_lazarus_dec20.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_HiddenCobra.yar",
    ],
    "ransom_wannacry": [
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_MS17-010_Wannacrypt.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_shamoon.yar",
    ],
}

# Extensions to scan
SCAN_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".drv",
    ".scr",
    ".cpl",
    ".ocx",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".hta",
    ".lnk",
    ".msi",
    ".jar",
    ".com",
}

# Paths to prioritize
PRIORITY_PATHS = [
    Path(os.environ.get("APPDATA", "")),
    Path(os.environ.get("LOCALAPPDATA", "")),
    Path(os.environ.get("TEMP", "")),
    Path(os.environ.get("TMP", "")),
    Path(os.environ.get("USERPROFILE", "")) / "Downloads",
    Path(os.environ.get("SystemRoot", "C:/Windows")) / "Temp",
    Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
    / "Microsoft"
    / "Windows"
    / "Start Menu"
    / "Programs"
    / "Startup",
]


def download_rules(rules_dir: Path) -> List[str]:
    """Download YARA rules from public sources, return list of downloaded files."""
    rules_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []

    for name, urls in RULE_SOURCES.items():
        dest = rules_dir / f"{name}.yar"
        if dest.exists():
            downloaded.append(str(dest))
            continue
        for url in urls:
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "WRAITH-Scanner/1.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as r:
                    content = r.read()
                dest.write_bytes(content)
                downloaded.append(str(dest))
                print(f"[YARA] Downloaded: {name} ({url})", file=sys.stderr)
                break  # success — no need to try fallbacks
            except Exception as e:
                print(f"[YARA] Skipping {url}: {e}", file=sys.stderr)
        else:
            print(f"[YARA] All sources failed for {name} — skipped", file=sys.stderr)

    return downloaded


def load_rules(rules_dir: Path) -> Optional[Any]:
    """Compile all YARA rules in rules_dir into one compiled ruleset."""
    if not YARA_AVAILABLE:
        return None

    rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    if not rule_files:
        return None

    # Build filepaths dict for yara.compile
    filepaths = {f.stem: str(f) for f in rule_files}
    try:
        rules = yara.compile(filepaths=filepaths)
        return rules
    except yara.SyntaxError as e:
        # Try loading one by one, skip broken files
        good_rules = {}
        for name, path in filepaths.items():
            try:
                yara.compile(filepath=path)
                good_rules[name] = path
            except Exception:
                print(f"[YARA] Skipping broken rule file: {path}", file=sys.stderr)
        if good_rules:
            return yara.compile(filepaths=good_rules)
        return None
    except Exception as e:
        print(f"[YARA] Rule compilation error: {e}", file=sys.stderr)
        return None


# ── Known-good path prefixes (case-insensitive) ─────────────────────────
# Files under these paths are almost always legitimate Windows / vendor
# binaries. YARA still scans them but findings are downgraded to INFO and
# only emitted when the matched rule is a named family (not generic).
_localappdata = os.environ.get("LOCALAPPDATA", "").lower()
_programfiles = os.environ.get("PROGRAMFILES", "C:\\Program Files").lower()
_programfiles86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)").lower()
_windir = os.environ.get("WINDIR", "C:\\Windows").lower()

KNOWN_GOOD_PATH_PREFIXES = [
    # Microsoft Edge (Chromium) — huge JS bundles legitimately contain many heuristic strings
    os.path.join(_localappdata, "microsoft", "edge"),
    os.path.join(_localappdata, "microsoft", "edgewebview"),
    # Windows Store / UWP app packages
    os.path.join(_localappdata, "packages"),
    # Windows system internals
    os.path.join(_windir, "system32"),
    os.path.join(_windir, "syswow64"),
    os.path.join(_windir, "winsxs"),
    # Vendor build caches (Rust cargo, Qt, npm from known locations)
    os.path.join(_localappdata, "temp", "cargo-install"),
    os.path.join(_localappdata, "temp", "cargo-update"),
    # Visual C++ / .NET runtimes
    os.path.join(_programfiles, "microsoft visual studio"),
    os.path.join(_programfiles86, "microsoft visual studio"),
    os.path.join(_localappdata, "microsoft", "windowsapps"),
    # Windows diagnostic infrastructure — SDIAG extracts system DLLs to Temp
    # for analysis; audiospew.dll, audiodiag.dll etc. are legitimate Windows files
    os.path.join(_windir, "temp"),
    os.path.join(os.environ.get("TEMP", "").lower(), ""),  # %TEMP%
]

# Rule names whose namespace/name signals a named family (high confidence).
# Findings from known-good paths are only kept if the rule is in this set
# OR the rule name contains one of these substrings.
_NAMED_FAMILY_SUBSTRINGS = (
    "mimikatz",
    "cobaltstrike",
    "cobalt_strike",
    "wannacry",
    "lazarus",
    "apt",
    "rat_",
    "njrat",
    "darkcomet",
    "nanocore",
    "asyncrat",
    "quasar",
    "remcos",
    "bitrat",
    "agentTesla",
    "xworm",
    "redline",
)

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _is_known_good_path(filepath: str) -> bool:
    fp = filepath.lower()
    return any(fp.startswith(pfx) for pfx in KNOWN_GOOD_PATH_PREFIXES if pfx)


def _rule_is_named_family(rule_name: str) -> bool:
    rn = rule_name.lower()
    return any(s in rn for s in _NAMED_FAMILY_SUBSTRINGS)


def scan_file_yara(rules, filepath: str) -> List[Dict]:
    """Scan a single file with compiled YARA rules."""
    findings = []
    known_good = _is_known_good_path(filepath)
    try:
        matches = rules.match(filepath, timeout=10)
        for m in matches:
            # Suppress noise from known-good paths unless it's a named family rule
            if known_good and not _rule_is_named_family(m.rule):
                continue

            # Use severity from rule meta when present; fall back to CRITICAL
            meta_severity = (m.meta.get("severity") or "").strip().upper()
            severity = _SEVERITY_MAP.get(meta_severity.lower(), "CRITICAL")

            findings.append(
                {
                    "category": "yara",
                    "subcategory": "signature_match",
                    "severity": severity,
                    "title": f"YARA Match: {m.rule}",
                    "path": filepath,
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "strings": [
                        {
                            "offset": s.instances[0].offset if s.instances else 0,
                            "identifier": s.identifier,
                            "data": (
                                repr(s.instances[0].matched_data[:64])
                                if s.instances
                                else ""
                            ),
                        }
                        for s in m.strings[:5]  # limit to first 5 string matches
                    ],
                    "reason": f"Matched YARA rule: {m.rule} (namespace: {m.namespace})",
                }
            )
    except yara.TimeoutError:
        pass  # skip timeout files
    except Exception:
        pass
    return findings


def scan_yara(scan_path: str, rules_dir_str: str) -> Dict[str, Any]:
    rules_dir = Path(rules_dir_str)

    # Download rules if needed
    download_rules(rules_dir)

    findings = []
    files_scanned = 0
    errors = 0

    if not YARA_AVAILABLE:
        return {
            "module": "yara",
            "error": "yara-python not installed. Run: pip install yara-python",
            "findings": [],
            "files_scanned": 0,
        }

    rules = load_rules(rules_dir)
    if not rules:
        return {
            "module": "yara",
            "error": "No YARA rules loaded",
            "findings": [],
            "files_scanned": 0,
        }

    # Scan priority paths first (fast, high-value)
    scanned_paths = set()

    def scan_directory(base: Path):
        nonlocal files_scanned, errors
        if not base.exists():
            return
        # Never scan WRAITH's own .NET single-file extraction folder — it is
        # a guaranteed false-positive source and contains only WRAITH itself.
        _self_prefix = os.path.join(
            os.environ.get("TEMP", ""), ".net", "wraith"
        ).lower()
        for root, dirs, files in os.walk(str(base)):
            root_lower = root.lower()
            # Skip WinSxS, WRAITH's own extraction dir, and known-good app dirs
            if root_lower.startswith(_self_prefix):
                dirs.clear()
                continue
            if any(root_lower.startswith(p) for p in KNOWN_GOOD_PATH_PREFIXES if p):
                # Still descend (scan_file_yara will suppress generic noise)
                # but skip massive JS-heavy browser cache subdirs entirely
                dirs[:] = [
                    d
                    for d in dirs
                    if d.lower()
                    not in {
                        "cache",
                        "code cache",
                        "gpucache",
                        "blob_storage",
                        "service worker",
                    }
                ]
            else:
                dirs[:] = [
                    d
                    for d in dirs
                    if d.lower()
                    not in {"winsxs", "assembly", "microsoft.net", "$recycle.bin"}
                ]
            for fname in files:
                fpath = os.path.join(root, fname)
                if fpath in scanned_paths:
                    continue
                if Path(fpath).suffix.lower() not in SCAN_EXTENSIONS:
                    continue
                scanned_paths.add(fpath)
                files_scanned += 1
                hits = scan_file_yara(rules, fpath)
                findings.extend(hits)

    for p in PRIORITY_PATHS:
        scan_directory(p)

    # Then scan the target path if different from priority
    if scan_path and scan_path != "C:\\":
        scan_directory(Path(scan_path))

    return {
        "module": "yara",
        "findings_count": len(findings),
        "files_scanned": files_scanned,
        "findings": findings,
    }
