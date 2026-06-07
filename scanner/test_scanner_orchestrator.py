"""Tests for scanner.py — the orchestrator that fans out to per-module scans.

We patch every per-module scan function so the orchestrator runs as fast
as a unit test and we can assert on the output schema deterministically.
"""

from __future__ import annotations

import importlib
import io
import json
import sys
from unittest.mock import patch

import pytest


@pytest.fixture
def scanner_module():
    """Fresh import so previous patches don't bleed across tests."""
    if "scanner" in sys.modules:
        importlib.reload(sys.modules["scanner"])
    import scanner as _scanner

    return _scanner


# ── emit() output schema ────────────────────────────────────────────────


def test_emit_produces_well_formed_json(scanner_module, capsys):
    findings = [
        {
            "title": "x",
            "path": "",
            "reason": "y",
            "severity": "HIGH",
            "category": "yara",
            "subcategory": "match",
        },
    ]
    scanner_module.emit(findings, mode="yara")
    captured = capsys.readouterr().out

    # Find the JSON line — emit() prints one machine-readable JSON object
    # whose first key is "scanner". Other lines are human log output.
    json_line = next(
        line for line in captured.splitlines() if line.startswith('{"scanner"')
    )
    payload = json.loads(json_line)

    # The scanner key embeds the mode (e.g. "WRAITH-yara") for log routing.
    assert payload["scanner"].startswith("WRAITH")
    assert payload["mode"] == "yara"
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["high"] == 1
    assert payload["summary"]["critical"] == 0
    assert isinstance(payload["findings"], list)
    assert payload["findings"][0]["title"] == "x"


def test_emit_severity_buckets_count_correctly(scanner_module, capsys):
    findings = [
        {
            "category": "x",
            "subcategory": "x",
            "severity": "CRITICAL",
            "title": "a",
            "path": "",
            "reason": "",
        },
        {
            "category": "x",
            "subcategory": "x",
            "severity": "CRITICAL",
            "title": "b",
            "path": "",
            "reason": "",
        },
        {
            "category": "x",
            "subcategory": "x",
            "severity": "HIGH",
            "title": "c",
            "path": "",
            "reason": "",
        },
        {
            "category": "x",
            "subcategory": "x",
            "severity": "MEDIUM",
            "title": "d",
            "path": "",
            "reason": "",
        },
        {
            "category": "x",
            "subcategory": "x",
            "severity": "INFO",
            "title": "e",
            "path": "",
            "reason": "",
        },
    ]
    scanner_module.emit(findings, mode="all")
    captured = capsys.readouterr().out
    payload = json.loads(
        next(l for l in captured.splitlines() if l.startswith('{"scanner"'))
    )

    s = payload["summary"]
    assert s["critical"] == 2
    assert s["high"] == 1
    assert s["medium"] == 1
    assert s["info"] == 1
    assert s["total"] == 5


def test_emit_error_field_propagates(scanner_module, capsys):
    scanner_module.emit([], mode="yara", error="oh no")
    payload = json.loads(
        next(
            l
            for l in capsys.readouterr().out.splitlines()
            if l.startswith('{"scanner"')
        )
    )
    assert payload.get("error") == "oh no"


# ── Anomaly scoring ────────────────────────────────────────────────────


def test_anomaly_score_high_for_critical_with_path(scanner_module):
    finding = {
        "severity": "CRITICAL",
        "category": "yara",
        "subcategory": "yara_match",
        "path": "/x",
        "reason": "",
    }
    score = scanner_module.compute_anomaly_score(finding)
    assert isinstance(score, float)
    assert 50.0 <= score <= 100.0


def test_anomaly_score_lower_for_info(scanner_module):
    finding = {
        "severity": "INFO",
        "category": "events",
        "subcategory": "info",
        "path": "",
        "reason": "",
    }
    score = scanner_module.compute_anomaly_score(finding)
    assert score < 50.0


def test_anomaly_score_within_bounds(scanner_module):
    """0 ≤ score ≤ 100 for any valid finding."""
    samples = [
        {
            "severity": "CRITICAL",
            "category": "yara",
            "subcategory": "match",
            "path": "x",
            "reason": "",
        },
        {
            "severity": "INFO",
            "category": "",
            "subcategory": "",
            "path": "",
            "reason": "",
        },
        {
            "severity": "HIGH",
            "category": "network",
            "subcategory": "c2_port",
            "path": "",
            "reason": "4444",
        },
    ]
    for f in samples:
        assert 0.0 <= scanner_module.compute_anomaly_score(f) <= 100.0


def test_assign_anomaly_scores_writes_into_findings(scanner_module):
    findings = [
        {
            "severity": "HIGH",
            "category": "yara",
            "subcategory": "match",
            "path": "/x",
            "reason": "",
        },
    ]
    out = scanner_module.assign_anomaly_scores(findings)
    assert "anomaly_score" in out[0]
    assert isinstance(out[0]["anomaly_score"], (int, float))


# ── main() with mode dispatch ──────────────────────────────────────────


def test_main_unknown_mode_emits_error(scanner_module, capsys, monkeypatch):
    """An unknown --mode should produce an error in the JSON output."""
    monkeypatch.setattr("sys.argv", ["scanner.py", "--mode=bogus_xyz"])
    scanner_module.main()
    payload = json.loads(
        next(
            l
            for l in capsys.readouterr().out.splitlines()
            if l.startswith('{"scanner"')
        )
    )
    assert payload.get("error", "").startswith("Unknown mode")


def test_main_persistence_mode_invokes_scan_persistence(
    scanner_module, capsys, monkeypatch
):
    monkeypatch.setattr("sys.argv", ["scanner.py", "--mode=persistence"])
    with patch.object(scanner_module, "scan_persistence", return_value=[]) as m_pers:
        scanner_module.main()
    m_pers.assert_called_once()


def test_main_all_mode_invokes_every_module(scanner_module, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["scanner.py", "--mode=all", "--hours=1"])
    targets = [
        "scan_persistence",
        "scan_yara",
        "scan_heuristics",
        "scan_events",
        "scan_npm",
        "scan_processes",
        "scan_network_module",
        "scan_winsec_module",
        "scan_rootkit_module",
        "scan_ads_module",
        "scan_browser_module",
        "scan_defender_module",
        "scan_credential_module",
        "scan_kev_module",
        "scan_vuln_drivers_module",
        "scan_tor_module",
        "scan_intel_module",
    ]
    patches = [patch.object(scanner_module, name, return_value=[]) for name in targets]
    for p in patches:
        p.start()
    try:
        scanner_module.main()
    finally:
        for p in patches:
            p.stop()


def test_main_intel_mode_invokes_intel_scanner(scanner_module, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["scanner.py", "--mode=intel"])
    with patch.object(scanner_module, "scan_intel_module", return_value=[]) as m_intel:
        scanner_module.main()
    m_intel.assert_called_once()


def test_main_vuln_drivers_mode_invokes_scanner(scanner_module, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["scanner.py", "--mode=vuln_drivers"])
    with patch.object(
        scanner_module, "scan_vuln_drivers_module", return_value=[]
    ) as m_vd:
        scanner_module.main()
    m_vd.assert_called_once()


def test_main_tor_mode_invokes_scanner(scanner_module, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["scanner.py", "--mode=tor"])
    with patch.object(scanner_module, "scan_tor_module", return_value=[]) as m_tor:
        scanner_module.main()
    m_tor.assert_called_once()
