"""Tests for the shared feed-store helper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import feed_store


@pytest.fixture(autouse=True)
def isolated_feeds(tmp_path, monkeypatch):
    """Every test gets a private feeds_root via WRAITH_FEEDS_DIR."""
    monkeypatch.setenv("WRAITH_FEEDS_DIR", str(tmp_path))
    yield tmp_path


def test_feeds_root_override(isolated_feeds):
    assert feed_store.feeds_root() == isolated_feeds


def test_feed_path_joins_under_root(isolated_feeds):
    p = feed_store.feed_path("vuln_drivers", "driver_blocklist.xml")
    assert p == isolated_feeds / "vuln_drivers" / "driver_blocklist.xml"


def test_load_manifest_missing_returns_empty(isolated_feeds):
    assert feed_store.load_manifest() == {}


def test_load_manifest_parses_valid(isolated_feeds):
    (isolated_feeds / "manifest.json").write_text(
        json.dumps(
            {
                "vuln_drivers": {
                    "source_url": "https://aka.ms/x",
                    "last_refresh_utc": "2026-06-01T00:00:00Z",
                    "size_bytes": 12345,
                    "status": "ok",
                }
            }
        )
    )
    manifest = feed_store.load_manifest()
    assert "vuln_drivers" in manifest
    assert manifest["vuln_drivers"].size_bytes == 12345
    assert manifest["vuln_drivers"].status == "ok"


def test_load_manifest_corrupted_returns_empty(isolated_feeds):
    (isolated_feeds / "manifest.json").write_text("{ not valid json")
    assert feed_store.load_manifest() == {}


def test_is_fresh_true_when_recent(isolated_feeds):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (isolated_feeds / "manifest.json").write_text(
        json.dumps(
            {
                "tor": {
                    "source_url": "https://x",
                    "last_refresh_utc": now,
                    "size_bytes": 100,
                    "status": "ok",
                }
            }
        )
    )
    assert feed_store.get_feed_status("tor").is_fresh is True


def test_is_fresh_false_when_old(isolated_feeds):
    (isolated_feeds / "manifest.json").write_text(
        json.dumps(
            {
                "tor": {
                    "source_url": "https://x",
                    "last_refresh_utc": "2020-01-01T00:00:00Z",
                    "size_bytes": 100,
                    "status": "ok",
                }
            }
        )
    )
    assert feed_store.get_feed_status("tor").is_fresh is False


def test_read_lines_strips_blanks_and_comments(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("# header\n\n1.2.3.4\n# another\n5.6.7.8\n\n")
    assert feed_store.read_lines(p) == ["1.2.3.4", "5.6.7.8"]


def test_read_lines_keeps_comments_when_disabled(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("# header\n1.2.3.4\n")
    assert feed_store.read_lines(p, strip_comments=False) == ["# header", "1.2.3.4"]


def test_read_lines_missing_file(tmp_path):
    assert feed_store.read_lines(tmp_path / "nope.txt") == []
