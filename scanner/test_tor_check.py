"""Tests for the Tor exit-node correlator."""

from __future__ import annotations

from unittest.mock import patch

import pytest

import tor_check


@pytest.fixture(autouse=True)
def isolated_feeds(tmp_path, monkeypatch):
    monkeypatch.setenv("WRAITH_FEEDS_DIR", str(tmp_path))
    yield tmp_path


def _write_exit_list(feeds_root, ips):
    target = feeds_root / "tor" / "exit_nodes.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# header comment\n" + "\n".join(ips) + "\n")


def test_missing_feed_returns_info(isolated_feeds):
    findings = tor_check.scan()
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["subcategory"] == "tor_feed_missing"


def test_load_exit_nodes_drops_invalid(isolated_feeds):
    _write_exit_list(isolated_feeds, ["192.0.2.1", "not-an-ip", "203.0.113.5"])
    nodes = tor_check._load_exit_nodes()
    assert nodes == {"192.0.2.1", "203.0.113.5"}


def test_connection_to_exit_node_emits_high(isolated_feeds):
    _write_exit_list(isolated_feeds, ["192.0.2.1"])
    with patch.object(tor_check, "_active_remote_ips") as m_conn, patch.object(
        tor_check, "_process_name"
    ) as m_proc:
        m_conn.return_value = [
            {
                "remote_ip": "192.0.2.1",
                "remote_port": "9001",
                "pid": "1234",
            }
        ]
        m_proc.return_value = "suspicious.exe"
        findings = tor_check.scan()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["category"] == "network"
    assert findings[0]["subcategory"] == "tor_exit_node"
    assert findings[0]["extra"]["remote_ip"] == "192.0.2.1"
    assert "suspicious.exe" in findings[0]["reason"]


def test_connection_to_clean_ip_no_finding(isolated_feeds):
    _write_exit_list(isolated_feeds, ["192.0.2.1"])
    with patch.object(tor_check, "_active_remote_ips") as m_conn:
        m_conn.return_value = [
            {
                "remote_ip": "8.8.8.8",
                "remote_port": "443",
                "pid": "1234",
            }
        ]
        findings = tor_check.scan()
    assert findings == []
