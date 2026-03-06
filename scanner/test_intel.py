"""
WRAITH — Quick test harness for attack_mapper + ioc_enricher.
Run: python test_intel.py
Run with live API: python test_intel.py --live
"""

import sys
import json
import copy

sys.path.insert(0, ".")

# ─── 1. ATT&CK Mapper unit tests ────────────────────────────────────────────

from attack_mapper import tag_findings

MAPPER_CASES = [
    {
        "category": "persistence",
        "subcategory": "registry_run",
        "title": "Run key found",
        "reason": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },
    {
        "category": "heuristics",
        "subcategory": "suspicious_cmdline",
        "title": "Encoded PowerShell",
        "reason": "powershell -enc SQBFAFgA",
    },
    {
        "category": "processes",
        "subcategory": "hollowed_image",
        "title": "Hollowed svchost",
        "reason": "injection detected",
    },
    {
        "category": "network",
        "subcategory": "c2_port",
        "title": "Port 4444 listener",
        "reason": "meterpreter bind_shell",
    },
    {
        "category": "credential",
        "subcategory": "sam_lsa",
        "title": "LSASS read",
        "reason": "sekurlsa module call",
    },
    {
        "category": "winsec",
        "subcategory": "defender_disabled",
        "title": "Defender disabled",
        "reason": "tamper protection off",
    },
    {
        "category": "yara",
        "subcategory": "yara_match",
        "title": "WannaCry match",
        "reason": "rule ransom_wannacry",
    },
    {
        "category": "events",
        "subcategory": "unknown",
        "title": "VSS deleted",
        "reason": "vssadmin delete shadows",
    },
    {
        "category": "ads",
        "subcategory": "alternate_data_stream",
        "title": "ADS found",
        "reason": "Zone.Identifier stream",
    },
    {
        "category": "npm",
        "subcategory": "typosquat",
        "title": "Typosquat",
        "reason": "lodash vs 1odash",
    },
]

print("=" * 65)
print("  ATT&CK MAPPER — Unit Tests")
print("=" * 65)

tagged = tag_findings(copy.deepcopy(MAPPER_CASES))
pass_count = 0
for f in tagged:
    tid = f.get("technique_id", "NOT MAPPED")
    tname = f.get("technique_name", "")
    ok = "✓" if tid != "NOT MAPPED" else "✗"
    if ok == "✓":
        pass_count += 1
    print(f"  {ok} [{f['category']:12s}] {f['title']:28s} -> {tid}")
    if tname:
        print(f"    {tname}")

print()
print(f"  Result: {pass_count}/{len(tagged)} findings tagged")
print()

# ─── 2. IOC Enricher — offline sanity check ──────────────────────────────────

from ioc_enricher import _extract_indicator, _sha256_file

print("=" * 65)
print("  IOC ENRICHER — Offline indicator extraction tests")
print("=" * 65)

indicator_cases = [
    # IP in reason (non-RFC1918)
    {
        "path": "",
        "reason": "outbound to 185.220.101.5 on port 443",
        "title": "suspicious outbound",
    },
    # RFC-1918 IP should be skipped
    {"path": "", "reason": "connection to 192.168.1.1", "title": "local conn"},
    # Domain in reason
    {"path": "", "reason": "DNS query to evil-c2.ru", "title": "dns anomaly"},
    # File path (won't exist but covers branch)
    {"path": "C:\\Windows\\System32\\notepad.exe", "reason": "", "title": "pe scan"},
    # Pre-stored hash
    {
        "path": "",
        "reason": "",
        "title": "known malware",
        "file_hash": "db349b97c37d22f5ea1d1841e3c89eb4799f0203e46b2e779af4669fa154c271",
    },
    # No extractable IOC
    {"path": "", "reason": "general anomaly", "title": "unknown"},
]

for f in indicator_cases:
    result = _extract_indicator(f)
    ioc_display = f"{result[1]}:{result[0][:32]}..." if result else "None (skipped)"
    print(f"  title={f['title']!r:28s} -> {ioc_display}")

print()

# ─── 3. Live API tests (opt-in) ───────────────────────────────────────────────

if "--live" in sys.argv:
    from ioc_enricher import query_malware_bazaar, query_threatfox, _load_api_key

    print("=" * 65)
    print("  IOC ENRICHER — Live API tests (--live flag)")
    print("=" * 65)

    api_key = _load_api_key()
    if api_key:
        print(f"\n  Auth-Key: configured ({api_key[:6]}...)")
    else:
        print("\n  Auth-Key: NOT configured — set abuse_ch_api_key in wraith.env.json")
        print(
            "  Register free at: https://abuse.ch/blog/community-api-key-for-all-tools/"
        )
        print("  Skipping live calls.\n")
        sys.exit(0)

    # WannaCry SHA-256 — well-known, always in MalwareBazaar
    WANNACRY_SHA256 = "db349b97c37d22f5ea1d1841e3c89eb4799f0203e46b2e779af4669fa154c271"

    print("\n  [1] MalwareBazaar — WannaCry hash lookup")
    mb = query_malware_bazaar(WANNACRY_SHA256)
    if mb:
        print(f"      PASS — Family: {mb.get('signature') or mb.get('tags')}")
        print(f"             First seen: {mb.get('first_seen', 'n/a')}")
        print(f"             File type:  {mb.get('file_type', 'n/a')}")
    else:
        print("      FAIL — no result returned")

    print("\n  [2] ThreatFox — WannaCry hash IOC lookup")
    tf = query_threatfox(WANNACRY_SHA256)
    if tf:
        print(f"      PASS — Malware: {tf.get('malware_printable')}")
        print(f"             Confidence: {tf.get('confidence_level', 'n/a')}")
        print(f"             Tags: {tf.get('tags', [])}")
    else:
        print("      INFO — hash not in ThreatFox (expected for some known hashes)")

    print("\n  [3] ThreatFox — known C2 IP lookup")
    # Use a C2 IP commonly listed on ThreatFox
    TEST_IP = "185.220.101.5"
    tf_ip = query_threatfox(TEST_IP)
    if tf_ip:
        print(f"      PASS — Malware: {tf_ip.get('malware_printable')}")
        print(f"             IOC type: {tf_ip.get('ioc_type')}")
        print(f"             Confidence: {tf_ip.get('confidence_level', 'n/a')}")
    else:
        print(f"      INFO — {TEST_IP} not currently in ThreatFox feed")

    print("\n  [4] Full enrich_findings pass on synthetic data")
    from ioc_enricher import enrich_findings

    test_findings = [
        {
            "category": "network",
            "subcategory": "suspicious_outbound",
            "title": "Outbound C2 traffic",
            "reason": "connection to 185.220.101.5:443",
            "severity": "HIGH",
            "anomaly_score": 60.0,
        },
        {
            "category": "yara",
            "subcategory": "yara_match",
            "title": "WannaCry YARA hit",
            "reason": "ransom_wannacry rule matched",
            "file_hash": WANNACRY_SHA256,
            "severity": "HIGH",
            "anomaly_score": 65.0,
        },
    ]
    enriched = enrich_findings(test_findings)
    for f in enriched:
        sources = f.get("intel_sources", [])
        family = f.get("malware_family", "unknown")
        sev = f.get("severity", "?")
        score = f.get("anomaly_score", 0)
        print(f"      {f['title']}")
        print(
            f"        sources={sources}  family={family}  severity={sev}  score={score}"
        )

    print()

else:
    print("  Tip: run with --live to hit ThreatFox + MalwareBazaar APIs")
    print()

print("Done.")
