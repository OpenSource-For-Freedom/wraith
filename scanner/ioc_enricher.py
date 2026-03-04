"""
WRAITH — IOC Enricher
Queries abuse.ch ThreatFox + MalwareBazaar for hash/IP/domain reputation.
Called post-scan on all collected findings to add corroboration and escalate
severity when an independent intel source confirms the indicator.

Network calls are gated behind the --enrich flag in scanner.py so offline
or air-gapped runs are unaffected.
"""

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
MALWARE_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
REQUEST_TIMEOUT = 10  # seconds; keep short so scans don't stall


def _load_api_key() -> str:
    """
    Load abuse.ch API key from (in priority order):
      1. ABUSECH_API_KEY environment variable
      2. abuse_ch_api_key field in wraith.env.json (repo root)
    Returns empty string if not configured — callers degrade gracefully.
    """
    env_key = os.environ.get("ABUSECH_API_KEY", "").strip()
    if env_key:
        return env_key
    # Walk up from this file to find wraith.env.json
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "wraith.env.json"
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                key = str(data.get("abuse_ch_api_key", "")).strip()
                if key:
                    return key
            except Exception:
                pass
            break
    return ""


_API_KEY: str = _load_api_key()

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

# Severity escalation ladder
_SEV_UP: Dict[str, str] = {
    "INFO": "MEDIUM",
    "LOW": "HIGH",
    "MEDIUM": "HIGH",
    "HIGH": "CRITICAL",
    "CRITICAL": "CRITICAL",
}


# ── Helpers ───────────────────────────────────────────────────────────────

def _sha256_file(path: str) -> Optional[str]:
    """Compute SHA-256 of a file. Returns None on any error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _extract_indicator(finding: Dict[str, Any]) -> Optional[tuple]:
    """
    Return (ioc_value, ioc_type) for the most actionable indicator in a finding,
    or None if nothing extractable.

    Priority: file-path SHA256 > IP in path/reason/title > domain in path/reason.
    """
    path = str(finding.get("path", ""))
    reason = str(finding.get("reason", ""))
    title = str(finding.get("title", ""))

    # File on disk → compute hash (highest fidelity)
    if path and os.path.isfile(path):
        sha = _sha256_file(path)
        if sha:
            return sha, "sha256_hash"

    # Already have a hash stored
    existing_hash = finding.get("file_hash", "")
    if existing_hash and re.fullmatch(r"[0-9a-fA-F]{64}", existing_hash):
        return existing_hash, "sha256_hash"

    # IP address
    for field in (path, reason, title):
        m = _IP_RE.search(field)
        if m:
            ip = m.group(1)
            # Skip loopback / RFC-1918 ranges (not interesting to look up)
            if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                return ip, "ip:port"

    # Domain
    for field in (path, reason):
        m = _DOMAIN_RE.search(field)
        if m:
            dom = m.group(0)
            # Ignore common benign TLDs that appear in paths
            if not dom.endswith((".exe", ".dll", ".sys", ".ps1", ".bat", ".json")):
                return dom, "domain"

    return None


# ── API wrappers ──────────────────────────────────────────────────────────

def _auth_headers() -> Dict[str, str]:
    """Return Auth-Key header dict if a key is configured, else empty dict."""
    key = _API_KEY or _load_api_key()  # re-check in case set after module load
    return {"Auth-Key": key} if key else {}


def query_malware_bazaar(sha256: str) -> Optional[Dict]:
    """Look up a SHA-256 hash on MalwareBazaar. Returns the hit dict or None."""
    try:
        resp = requests.post(
            MALWARE_BAZAAR_API,
            data={"query": "get_info", "hash": sha256},
            headers=_auth_headers(),
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 401:
            return None  # No key configured — degrade silently
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("data"):
            return data["data"][0]
    except Exception:
        pass
    return None


def query_threatfox(ioc: str) -> Optional[Dict]:
    """Look up any IOC string on ThreatFox. Returns the first match or None."""
    try:
        resp = requests.post(
            THREATFOX_API,
            json={"query": "search_ioc", "search_term": ioc},
            headers=_auth_headers(),
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 401:
            return None  # No key configured — degrade silently
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("data"):
            return data["data"][0]
    except Exception:
        pass
    return None


# ── Main enrichment pass ──────────────────────────────────────────────────

def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    For every finding that has an extractable indicator (file hash, IP, domain):

      1. Query MalwareBazaar (hashes only) + ThreatFox (all types).
      2. Annotate the finding with:
           intel_sources   — list of source names that confirmed it
           malware_family  — best-guess family from intel feeds
           technique_id    — ATT&CK T-ID surfaced by ThreatFox (if present)
           file_hash       — SHA-256 if computed during this pass
      3. Escalate severity one tier when ≥1 source corroborates.
      4. Append corroboration note to `reason`.

    Courtesy rate-limit: 300 ms between calls (abuse.ch free tier).
    """
    for f in findings:
        indicator = _extract_indicator(f)
        if not indicator:
            continue

        ioc_value, ioc_type = indicator
        intel_sources: List[str] = []
        malware_family: Optional[str] = None
        technique_id: Optional[str] = None

        # ── MalwareBazaar (hashes only) ───────────────────────────────────
        if ioc_type == "sha256_hash":
            f["file_hash"] = ioc_value
            mb_hit = query_malware_bazaar(ioc_value)
            if mb_hit:
                intel_sources.append("MalwareBazaar")
                malware_family = (
                    mb_hit.get("signature")
                    or (mb_hit.get("tags") or [None])[0]
                )
            time.sleep(0.3)

        # ── ThreatFox (all types) ─────────────────────────────────────────
        tf_hit = query_threatfox(ioc_value)
        if tf_hit:
            intel_sources.append("ThreatFox")
            if not malware_family:
                malware_family = tf_hit.get("malware_printable") or tf_hit.get("malware")
            # Pull ATT&CK tag if ThreatFox supplied one
            for tag in tf_hit.get("tags") or []:
                if isinstance(tag, str) and re.match(r"T\d{4}", tag.upper()):
                    technique_id = tag.upper()
                    break
        time.sleep(0.3)

        if not intel_sources:
            continue

        # ── Annotate ──────────────────────────────────────────────────────
        f["intel_sources"] = intel_sources
        if malware_family:
            f["malware_family"] = malware_family
        # Only set technique_id if attack_mapper hasn't already set one
        if technique_id and not f.get("technique_id"):
            f["technique_id"] = technique_id

        # Escalate severity
        current = f.get("severity", "LOW")
        f["severity"] = _SEV_UP.get(current, current)

        # Boost anomaly score proportional to corroboration count
        boost = 15.0 * len(intel_sources)
        f["anomaly_score"] = round(min(100.0, float(f.get("anomaly_score", 0)) + boost), 2)

        # Append readable note to reason
        note_parts = [f"Corroborated by: {', '.join(intel_sources)}"]
        if malware_family:
            note_parts.append(f"Family: {malware_family}")
        f["reason"] = f"{f.get('reason', '')} | {' | '.join(note_parts)}".strip(" |")

    return findings
