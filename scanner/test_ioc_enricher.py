"""Tests for ioc_enricher — abuse.ch corroboration of findings.

Mocks `requests.post` so the tests never hit the real abuse.ch API,
and so they run on Ubuntu CI without an API key. The real auth path
goes through wraith.env.json (abuse_ch_api_key) which we don't load
in tests — _auth_headers() falls back to no key, which is fine since
we never make a live call.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import ioc_enricher

# ── Sha256 extraction ──────────────────────────────────────────────────


def test_sha256_of_file_returns_hex(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"hello world")
    sha = ioc_enricher._sha256_file(str(p))
    assert sha == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_sha256_of_missing_returns_none(tmp_path):
    assert ioc_enricher._sha256_file(str(tmp_path / "nope")) is None


# ── Indicator extraction ───────────────────────────────────────────────


def test_extract_sha256_indicator_from_existing_file(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"hello")
    finding = {"path": str(p), "category": "yara", "title": "match"}
    indicator = ioc_enricher._extract_indicator(finding)
    assert indicator is not None
    # The function returns (value, type) — value first, type second.
    value, kind = indicator
    assert kind == "sha256_hash"
    assert len(value) == 64  # SHA256 hex


def test_extract_indicator_returns_none_for_pathless_finding():
    finding = {"path": "", "title": "noop"}
    assert ioc_enricher._extract_indicator(finding) is None


# ── MalwareBazaar query ─────────────────────────────────────────────────


def test_query_malware_bazaar_handles_ok_response():
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "query_status": "ok",
        "data": [{"file_name": "evil.exe"}],
    }
    with patch.object(
        ioc_enricher, "_load_api_key", return_value="fake-key"
    ), patch.object(ioc_enricher, "requests") as m_req:
        m_req.post.return_value = fake_resp
        result = ioc_enricher.query_malware_bazaar("a" * 64)
    # On success the function returns data["data"][0] — the first match.
    assert result is not None
    assert result["file_name"] == "evil.exe"


def test_query_malware_bazaar_returns_none_without_key():
    """Without an API key configured, abuse.ch is unreachable — degrade silently."""
    with patch.object(ioc_enricher, "_load_api_key", return_value=""):
        result = ioc_enricher.query_malware_bazaar("a" * 64)
    assert result is None


def test_query_malware_bazaar_handles_hash_unknown():
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"query_status": "hash_not_found"}
    with patch.object(ioc_enricher, "requests") as m_req:
        m_req.post.return_value = fake_resp
        result = ioc_enricher.query_malware_bazaar("a" * 64)
    # Function should still return something so the caller can decide.
    assert result is None or result.get("query_status") == "hash_not_found"


def test_query_malware_bazaar_handles_network_error():
    with patch.object(ioc_enricher, "requests") as m_req:
        m_req.post.side_effect = Exception("connection refused")
        result = ioc_enricher.query_malware_bazaar("a" * 64)
    assert result is None


# ── ThreatFox query ────────────────────────────────────────────────────


def test_query_threatfox_handles_ok_response():
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "query_status": "ok",
        "data": [{"threat_type_desc": "C2"}],
    }
    with patch.object(
        ioc_enricher, "_load_api_key", return_value="fake-key"
    ), patch.object(ioc_enricher, "requests") as m_req:
        m_req.post.return_value = fake_resp
        result = ioc_enricher.query_threatfox("192.0.2.1")
    assert result is not None
    assert result["threat_type_desc"] == "C2"


def test_query_threatfox_handles_network_error():
    with patch.object(ioc_enricher, "requests") as m_req:
        m_req.post.side_effect = Exception("dns failure")
        result = ioc_enricher.query_threatfox("192.0.2.1")
    assert result is None


# ── enrich_findings end-to-end ──────────────────────────────────────────


def test_enrich_findings_passes_through_empty_list():
    assert ioc_enricher.enrich_findings([]) == []


def test_enrich_findings_does_not_drop_findings(tmp_path):
    """No matter what the API says, findings must not disappear."""
    p = tmp_path / "x.exe"
    p.write_bytes(b"hello")
    findings = [
        {
            "path": str(p),
            "title": "yara hit",
            "category": "yara",
            "subcategory": "yara_match",
            "severity": "HIGH",
            "reason": "rule X",
        }
    ]
    with patch.object(ioc_enricher, "requests") as m_req:
        m_req.post.side_effect = Exception("offline")
        out = ioc_enricher.enrich_findings(findings)
    assert len(out) == 1
    assert out[0]["title"] == "yara hit"


def test_enrich_findings_survives_finding_without_path():
    findings = [{"path": "", "title": "log only", "category": "events"}]
    out = ioc_enricher.enrich_findings(findings)
    assert len(out) == 1
