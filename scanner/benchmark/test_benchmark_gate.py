"""
Pytest wrapper so the detection benchmark runs in the existing test suite / CI.
The standalone scoreboard lives in gate.py:  python3 scanner/benchmark/gate.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from corpus import CORPUS, POSITIVE, SKIP, run_case  # noqa: E402


def test_no_missed_alerts_and_no_false_positives():
    results = [run_case(c) for c in CORPUS]
    executed = [r for r in results if r.status != SKIP]

    # A gate that tests nothing must fail (git_paca C-6): if every case skipped,
    # the corpus proved nothing.
    assert executed, "benchmark executed 0 cases (all skipped) - nothing tested"

    missed = [
        r.case.id for r in executed if r.case.expect == "flag" and r.status != POSITIVE
    ]
    false_pos = [
        r.case.id for r in executed if r.case.expect == "quiet" and r.status == POSITIVE
    ]

    assert not missed, f"MISSED ALERTS (real threats not caught): {missed}"
    assert not false_pos, f"FALSE POSITIVES (benign artifacts flagged): {false_pos}"
