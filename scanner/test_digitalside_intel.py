"""Tests for the DigitalSide intel correlator."""

from __future__ import annotations

import hashlib
from unittest.mock import patch

import pytest

import digitalside_intel


@pytest.fixture(autouse=True)
def isolated_feeds(tmp_path, monkeypatch):
    monkeypatch.setenv("WRAITH_FEEDS_DIR", str(tmp_path))
    yield tmp_path


def _write_feed(feeds_root, filename, lines):
    target = feeds_root / "digitalside" / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# header\n" + "\n".join(lines) + "\n")


def test_missing_feeds_returns_info(isolated_feeds):
    findings = digitalside_intel.scan()
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["subcategory"] == "feed_missing"


def test_ip_match_emits_high(isolated_feeds):
    _write_feed(isolated_feeds, "ips.txt", ["198.51.100.42"])
    _write_feed(isolated_feeds, "domains.txt", [])
    with patch.object(digitalside_intel, "_active_remote_ips") as m_conn, patch.object(
        digitalside_intel, "_dns_cache_domains"
    ) as m_dns, patch.object(digitalside_intel, "_hosts_file_entries") as m_hosts:
        m_conn.return_value = [
            {"remote_ip": "198.51.100.42", "remote_port": "443", "pid": "999"}
        ]
        m_dns.return_value = set()
        m_hosts.return_value = set()
        findings = digitalside_intel.scan()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["subcategory"] == "ip_match"


def test_dns_cache_domain_match_emits_high(isolated_feeds):
    _write_feed(isolated_feeds, "ips.txt", [])
    _write_feed(isolated_feeds, "domains.txt", ["evil.example"])
    with patch.object(digitalside_intel, "_active_remote_ips") as m_conn, patch.object(
        digitalside_intel, "_dns_cache_domains"
    ) as m_dns, patch.object(digitalside_intel, "_hosts_file_entries") as m_hosts:
        m_conn.return_value = []
        m_dns.return_value = {"evil.example", "innocent.example"}
        m_hosts.return_value = set()
        findings = digitalside_intel.scan()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["subcategory"] == "domain_match"
    assert findings[0]["extra"]["domain"] == "evil.example"


def test_hosts_file_pin_is_critical(isolated_feeds):
    _write_feed(isolated_feeds, "ips.txt", [])
    _write_feed(isolated_feeds, "domains.txt", ["evil.example"])
    with patch.object(digitalside_intel, "_active_remote_ips") as m_conn, patch.object(
        digitalside_intel, "_dns_cache_domains"
    ) as m_dns, patch.object(digitalside_intel, "_hosts_file_entries") as m_hosts:
        m_conn.return_value = []
        m_dns.return_value = set()
        m_hosts.return_value = {"evil.example"}
        findings = digitalside_intel.scan()
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["subcategory"] == "hosts_pin"


def test_clean_environment_no_findings(isolated_feeds):
    _write_feed(isolated_feeds, "ips.txt", ["198.51.100.42"])
    _write_feed(isolated_feeds, "domains.txt", ["evil.example"])
    with patch.object(digitalside_intel, "_active_remote_ips") as m_conn, patch.object(
        digitalside_intel, "_dns_cache_domains"
    ) as m_dns, patch.object(digitalside_intel, "_hosts_file_entries") as m_hosts:
        m_conn.return_value = [
            {"remote_ip": "8.8.8.8", "remote_port": "443", "pid": "999"}
        ]
        m_dns.return_value = {"google.com"}
        m_hosts.return_value = set()
        findings = digitalside_intel.scan()
    assert findings == []


def test_hash_match_helper_finds_listed_sha256(isolated_feeds):
    sha = "a" * 64
    _write_feed(isolated_feeds, "hashes_sha256.txt", [sha])
    _write_feed(isolated_feeds, "hashes_md5.txt", [])
    result = digitalside_intel.hash_match(sha)
    assert result["kind"] == "sha256"
    assert result["hash"] == sha


def test_hash_match_helper_handles_unknown(isolated_feeds):
    _write_feed(isolated_feeds, "hashes_sha256.txt", ["b" * 64])
    _write_feed(isolated_feeds, "hashes_md5.txt", [])
    assert digitalside_intel.hash_match("c" * 64) == {}


def test_hash_match_helper_hashes_file_on_disk(isolated_feeds, tmp_path):
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"hello world")
    expected = hashlib.sha256(b"hello world").hexdigest()
    _write_feed(isolated_feeds, "hashes_sha256.txt", [expected])
    _write_feed(isolated_feeds, "hashes_md5.txt", [])
    result = digitalside_intel.hash_match(str(sample_path))
    assert result["kind"] == "sha256"
    assert result["hash"] == expected
