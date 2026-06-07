"""
WRAITH local threat-intel feed store.

The C# FeedRefreshService downloads OSS feeds (no API key required) into
%ProgramData%\\WRAITH\\feeds\\ on a schedule. Python scanners read from
that same tree at scan time. This module centralises the path layout so
the scanners and the C# downloader agree on where each feed lives.

Layout:
    feeds/
        manifest.json
        vuln_drivers/driver_blocklist.xml
        tor/exit_nodes.txt
        digitalside/hashes.txt
        digitalside/ips.txt
        digitalside/urls.txt
        sigma/rules/
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def feeds_root() -> Path:
    """Returns the directory the feed store lives in.

    The %ProgramData% fallback uses C:\\ProgramData on Windows and
    /var/lib on POSIX, so tests can override via WRAITH_FEEDS_DIR.
    """
    override = os.environ.get("WRAITH_FEEDS_DIR")
    if override:
        return Path(override)

    program_data = os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA")
    if program_data:
        return Path(program_data) / "WRAITH" / "feeds"

    # POSIX fallback for test/dev environments
    return Path.home() / ".wraith" / "feeds"


def feed_path(feed_id: str, *segments: str) -> Path:
    """Resolves a path under <feeds_root>/<feed_id>/..."""
    return feeds_root().joinpath(feed_id, *segments)


@dataclass
class FeedStatus:
    """Single entry in feeds/manifest.json."""

    feed_id: str
    source_url: str
    last_refresh_utc: Optional[str]  # ISO 8601, None if never refreshed
    size_bytes: int
    status: str  # "ok" | "error" | "stale"
    error: Optional[str]

    @property
    def is_fresh(self) -> bool:
        """True if refreshed in the last 24 hours."""
        if not self.last_refresh_utc:
            return False
        try:
            ts = datetime.fromisoformat(self.last_refresh_utc.replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - ts
            return age.total_seconds() < 86400
        except ValueError:
            return False


def load_manifest() -> dict[str, FeedStatus]:
    """Reads feeds/manifest.json into a {feed_id: FeedStatus} map.

    Returns an empty dict if the manifest is missing or corrupt — scanners
    that depend on a feed they can't find should degrade gracefully, not
    fail the whole scan.
    """
    manifest_file = feeds_root() / "manifest.json"
    if not manifest_file.exists():
        return {}

    try:
        with manifest_file.open(encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    out: dict[str, FeedStatus] = {}
    for feed_id, payload in raw.items():
        if not isinstance(payload, dict):
            continue
        out[feed_id] = FeedStatus(
            feed_id=feed_id,
            source_url=str(payload.get("source_url", "")),
            last_refresh_utc=payload.get("last_refresh_utc"),
            size_bytes=int(payload.get("size_bytes", 0) or 0),
            status=str(payload.get("status", "unknown")),
            error=payload.get("error"),
        )
    return out


def get_feed_status(feed_id: str) -> Optional[FeedStatus]:
    """Convenience accessor for a single feed."""
    return load_manifest().get(feed_id)


def read_lines(path: Path, *, strip_comments: bool = True) -> list[str]:
    """Reads a feed file as lines, stripping blanks and (by default) comments.

    Many OSS feeds (Tor exit list, abuse.ch CSVs in their pre-auth era,
    DigitalSide IP lists) use plaintext with # comment lines and # provenance
    headers. Standardise the parse so each scanner doesn't re-implement it.
    """
    if not path.exists():
        return []
    out: list[str] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if strip_comments and line.startswith("#"):
                    continue
                out.append(line)
    except OSError:
        return []
    return out


# Canonical feed IDs used by both the C# downloader and the Python scanners.
# Keep in sync with WRAITH/Services/FeedRefreshService.cs.
FEED_VULN_DRIVERS = "vuln_drivers"
FEED_TOR = "tor"
FEED_DIGITALSIDE = "digitalside"
FEED_SIGMA = "sigma"


def _public_api() -> list[str]:
    """Re-export only the names the scanners should touch."""
    return [
        "feeds_root",
        "feed_path",
        "FeedStatus",
        "load_manifest",
        "get_feed_status",
        "read_lines",
        "FEED_VULN_DRIVERS",
        "FEED_TOR",
        "FEED_DIGITALSIDE",
        "FEED_SIGMA",
    ]


__all__ = _public_api()
