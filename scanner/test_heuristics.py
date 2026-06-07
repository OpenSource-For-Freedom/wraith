"""Tests for heuristics — entropy, PE header, file-content scoring.

These test the pure-Python helpers + the per-file scanner against
crafted byte sequences. No subprocess required.
"""

from __future__ import annotations

import math
import pytest

import heuristics

# ── Entropy ─────────────────────────────────────────────────────────────


def test_entropy_empty_is_zero():
    assert heuristics.calc_entropy(b"") == 0.0


def test_entropy_uniform_byte_is_zero():
    # A single repeating byte carries no information.
    assert heuristics.calc_entropy(b"A" * 1024) == pytest.approx(0.0, abs=1e-6)


def test_entropy_random_bytes_is_high():
    # 256 distinct bytes, each appearing once, gives entropy of log2(256) = 8.
    distinct = bytes(range(256))
    e = heuristics.calc_entropy(distinct)
    assert e == pytest.approx(8.0, abs=1e-6)


def test_entropy_two_byte_alphabet_is_one():
    # Half '\x00' half '\xff' → 1 bit of entropy.
    data = (b"\x00" * 512) + (b"\xff" * 512)
    e = heuristics.calc_entropy(data)
    assert e == pytest.approx(1.0, abs=1e-3)


# ── PE header anomaly detection ────────────────────────────────────────
# check_pe_header returns (is_anomalous, reason). A clean PE returns
# (False, ""); a malformed/hollowed one returns (True, "…").


def test_pe_header_valid_returns_no_anomaly():
    # 'MZ' + e_lfanew=0x40 pointing at 'PE\0\0'. Clean PE.
    data = bytearray(0x100)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"PE\x00\x00"
    is_anom, reason = heuristics.check_pe_header(bytes(data))
    assert is_anom is False
    assert reason == ""


def test_pe_header_missing_signature_flagged():
    # MZ present but no PE signature at e_lfanew → anomaly.
    data = bytearray(0x100)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"XXXX"  # wrong signature
    is_anom, reason = heuristics.check_pe_header(bytes(data))
    assert is_anom is True
    assert "PE signature" in reason or "hollowed" in reason


def test_pe_header_non_pe_returns_false():
    is_anom, _ = heuristics.check_pe_header(
        b"hello world, not an executable padded " * 4
    )
    assert is_anom is False


def test_pe_header_rejects_too_short():
    is_anom, _ = heuristics.check_pe_header(b"MZ")
    assert is_anom is False


# ── Per-file heuristic scan ────────────────────────────────────────────


def test_scan_file_missing_returns_empty(tmp_path):
    findings = heuristics.scan_file_heuristics(str(tmp_path / "nope.exe"))
    assert findings == []


def test_scan_file_uniform_low_entropy_returns_empty(tmp_path):
    # Low-entropy plain text — heuristics should NOT flag.
    p = tmp_path / "boring.txt"
    p.write_bytes(b"hello world\n" * 200)
    findings = heuristics.scan_file_heuristics(str(p))
    # No high-entropy / packed flags expected.
    assert all("high_entropy" not in (f.get("subcategory") or "") for f in findings)


def test_scan_file_high_entropy_data_flagged(tmp_path):
    """High-entropy data in an executable extension should produce a
    'high_entropy' / 'packed' finding. scan_file_heuristics only inspects
    .exe / .dll / .sys / .scr (see the gating in heuristics.py), so we
    write into a .exe to actually exercise the entropy branch."""
    import os as _os

    p = tmp_path / "random.exe"
    p.write_bytes(_os.urandom(64 * 1024))
    findings = heuristics.scan_file_heuristics(str(p))
    # Random bytes → entropy ~8.0 → must produce at least one finding.
    assert findings, "high-entropy .exe should produce at least one finding"
    joined = " ".join(f.get("subcategory") or "" for f in findings).lower()
    assert (
        "entropy" in joined or "packed" in joined
    ), f"expected entropy/packed subcategory, got {[f.get('subcategory') for f in findings]}"


# ── Directory-level scan ───────────────────────────────────────────────


def test_scan_heuristics_on_missing_dir_returns_dict():
    # The directory-level entry point should never raise; it should
    # return a dict-shaped result even for a non-existent root.
    result = heuristics.scan_heuristics("/nonexistent/path/xyz/123")
    assert isinstance(result, dict)


def test_scan_heuristics_returns_findings_key():
    result = heuristics.scan_heuristics("/nonexistent/path/xyz/123")
    # The orchestrator expects either a list-of-findings or a dict with one.
    assert isinstance(result, (list, dict))
    if isinstance(result, dict):
        # The result dict may use either key shape.
        assert any(k in result for k in ("findings", "summary", "results"))
