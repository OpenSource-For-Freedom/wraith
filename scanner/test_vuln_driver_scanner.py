"""Tests for vuln_driver_scanner against a stub blocklist."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import feed_store
import vuln_driver_scanner

# Minimal SiPolicy XML with a single hash. Real blocklist has thousands.
SAMPLE_BLOCKLIST_XML = """<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <FileRules>
    <Deny ID="ID_DENY_TEST_1"
          FriendlyName="Vulnerable test driver xyz.sys"
          Hash="ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234567890" />
    <Deny ID="ID_DENY_TEST_2"
          FriendlyName="Another vulnerable driver"
          Hash="0011223344556677889900112233445566778899001122334455667788990011" />
  </FileRules>
</SiPolicy>
"""


@pytest.fixture(autouse=True)
def isolated_feeds(tmp_path, monkeypatch):
    monkeypatch.setenv("WRAITH_FEEDS_DIR", str(tmp_path))
    yield tmp_path


def _write_blocklist(feeds_root):
    target = feeds_root / "vuln_drivers" / "driver_blocklist.xml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(SAMPLE_BLOCKLIST_XML, encoding="utf-8")


def test_missing_feed_returns_info_finding(isolated_feeds):
    findings = vuln_driver_scanner.scan()
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["subcategory"] == "feed_missing"
    assert "not yet downloaded" in findings[0]["reason"].lower()


def test_blocklist_parse_normalises_hashes_lowercase(isolated_feeds):
    _write_blocklist(isolated_feeds)
    blocklist = vuln_driver_scanner._load_blocklist()
    assert len(blocklist) == 2
    # Hashes from the XML were mixed case; the parser lowercases.
    assert (
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" in blocklist
    )
    assert (
        "0011223344556677889900112233445566778899001122334455667788990011" in blocklist
    )


def test_corrupt_xml_returns_empty(isolated_feeds):
    target = isolated_feeds / "vuln_drivers" / "driver_blocklist.xml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("<not><valid xml")
    assert vuln_driver_scanner._load_blocklist() == {}


def test_match_against_loaded_driver_emits_critical(isolated_feeds, tmp_path):
    _write_blocklist(isolated_feeds)
    # Fake a driver on disk whose SHA256 matches one of the blocklist hashes.
    # We can't realistically produce a file with a chosen SHA256, so we
    # mock both the enumeration AND the hashing step instead.
    fake_driver_path = tmp_path / "fake.sys"
    fake_driver_path.write_bytes(b"not actually the vulnerable driver bytes")

    with patch.object(
        vuln_driver_scanner, "_enumerate_loaded_drivers"
    ) as m_drv, patch.object(
        vuln_driver_scanner, "_normalise_driver_path"
    ) as m_norm, patch.object(
        vuln_driver_scanner, "_sha256"
    ) as m_hash:
        m_drv.return_value = [
            {
                "name": "EvilDriver",
                "path": "\\??\\C:\\Windows\\System32\\drivers\\fake.sys",
                "state": "Running",
                "start_mode": "Auto",
            }
        ]
        m_norm.return_value = fake_driver_path
        m_hash.return_value = (
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )

        findings = vuln_driver_scanner.scan()

    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "CRITICAL"
    assert finding["category"] == "vuln_driver"
    assert finding["subcategory"] == "byovd"
    assert "EvilDriver" in finding["title"]
    assert finding["extra"]["blocklist_rule"] == "Vulnerable test driver xyz.sys"


def test_clean_driver_no_finding(isolated_feeds, tmp_path):
    _write_blocklist(isolated_feeds)
    fake_driver_path = tmp_path / "clean.sys"
    fake_driver_path.write_bytes(b"legitimate driver bytes")

    with patch.object(
        vuln_driver_scanner, "_enumerate_loaded_drivers"
    ) as m_drv, patch.object(
        vuln_driver_scanner, "_normalise_driver_path"
    ) as m_norm, patch.object(
        vuln_driver_scanner, "_sha256"
    ) as m_hash:
        m_drv.return_value = [
            {
                "name": "CleanDriver",
                "path": "\\??\\C:\\Windows\\System32\\drivers\\clean.sys",
                "state": "Running",
                "start_mode": "Auto",
            }
        ]
        m_norm.return_value = fake_driver_path
        m_hash.return_value = "deadbeef" * 8  # Not in blocklist

        findings = vuln_driver_scanner.scan()

    assert findings == []


def test_normalise_strips_nt_prefix(tmp_path, monkeypatch):
    # Make a real file we can resolve to
    f = tmp_path / "real.sys"
    f.write_text("x")
    # Pass an NT-prefixed path that resolves to the same file
    result = vuln_driver_scanner._normalise_driver_path(f"\\??\\{f}")
    assert result is not None
    assert result.exists()
