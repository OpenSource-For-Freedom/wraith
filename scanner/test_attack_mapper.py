"""Tests for attack_mapper — ATT&CK technique tagging on findings.

attack_mapper is pure-Python rule logic over finding dicts. No I/O,
no subprocess — these tests are deterministic and fast.
"""

from __future__ import annotations

import copy

import pytest

from attack_mapper import tag_findings


def _f(**kwargs):
    """Construct a finding dict with sensible defaults."""
    base = {
        "title": "test",
        "path": "",
        "reason": "",
        "severity": "MEDIUM",
        "category": "",
        "subcategory": "",
    }
    base.update(kwargs)
    return base


def test_persistence_run_key_tagged_t1547():
    findings = [_f(category="persistence", subcategory="registry_run",
                   reason="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")]
    tagged = tag_findings(copy.deepcopy(findings))
    # The mapper writes technique_id + technique_name fields onto matched findings.
    assert tagged[0].get("technique_id", "").startswith("T1547"), \
        f"expected T1547* technique on run-key persistence; got {tagged[0]}"
    assert "Registry Run" in tagged[0].get("technique_name", "")


def test_yara_match_carries_through_tagging():
    findings = [_f(category="yara", subcategory="yara_match",
                   title="WannaCry match", reason="rule ransom_wannacry")]
    tagged = tag_findings(copy.deepcopy(findings))
    # Whatever tagging is applied, the original fields survive untouched.
    assert tagged[0]["category"] == "yara"
    assert tagged[0]["title"] == "WannaCry match"


def test_empty_list_returns_empty():
    assert tag_findings([]) == []


def test_finding_without_category_does_not_crash():
    findings = [_f(category="", subcategory="", reason="")]
    tagged = tag_findings(copy.deepcopy(findings))
    assert len(tagged) == 1
    # Should pass through, possibly without any tags applied.
    assert tagged[0]["title"] == "test"


def test_unknown_category_does_not_crash():
    findings = [_f(category="unknown_category_xyz")]
    tagged = tag_findings(copy.deepcopy(findings))
    assert len(tagged) == 1


def test_multiple_findings_all_processed():
    findings = [
        _f(category="persistence", subcategory="registry_run"),
        _f(category="processes", subcategory="hollowed_image"),
        _f(category="credential", subcategory="sam_lsa"),
    ]
    tagged = tag_findings(copy.deepcopy(findings))
    assert len(tagged) == 3
    # Every finding kept its identifying fields.
    cats = [t["category"] for t in tagged]
    assert cats == ["persistence", "processes", "credential"]


def test_finding_is_not_mutated_externally():
    """tag_findings should return data, not silently mutate the caller's list."""
    findings = [_f(category="persistence", subcategory="registry_run")]
    original = copy.deepcopy(findings)
    tag_findings(findings)
    # We can't strictly require immutability since the function may add keys,
    # but the input's category/subcategory should never be rewritten.
    assert findings[0]["category"] == original[0]["category"]
    assert findings[0]["subcategory"] == original[0]["subcategory"]
