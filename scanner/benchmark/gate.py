"""
WRAITH detection benchmark - scorer and gate.

Runs the labeled corpus in corpus.py against REAL scanner code and reports the
numbers that make "is detection getting better?" answerable instead of a guess:
recall (did we catch the real threats), false-positive rate (did we stay quiet on
benign artifacts), and precision. Prints a per-module scoreboard.

Gate semantics (exit non-zero on any of):
  * 0 executable cases           -> a gate that tests nothing must fail.
  * any FALSE NEGATIVE (a `flag` case the scanner missed).
  * any FALSE POSITIVE (a `quiet` case the scanner flagged).

The corpus is a controlled answer key we own, so the bar is strict: on this
corpus a serious build is 100% recall and 0% false positives. Cases that cannot
run here (missing yara / a Windows-only dependency) are reported as SKIP and do
not count as pass or fail, but if EVERYTHING skips the gate still fails.

Usage:
    python3 scanner/benchmark/gate.py            # score + gate, exit code is the verdict
    python3 scanner/benchmark/gate.py --verbose  # also list every case
"""

import argparse
import sys
from collections import defaultdict
from typing import Dict, List

from corpus import CORPUS, NEGATIVE, POSITIVE, SKIP, CaseResult, run_case


def _score(results: List[CaseResult]) -> Dict:
    tp = fn = fp = tn = skipped = 0
    false_negatives: List[CaseResult] = []
    false_positives: List[CaseResult] = []
    skips: List[CaseResult] = []
    per_module = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "skip": 0})

    for r in results:
        m = per_module[r.case.module]
        if r.status == SKIP:
            skipped += 1
            m["skip"] += 1
            skips.append(r)
            continue
        if r.case.expect == "flag":
            if r.status == POSITIVE:
                tp += 1
                m["tp"] += 1
            else:
                fn += 1
                m["fn"] += 1
                false_negatives.append(r)
        else:  # expect quiet
            if r.status == NEGATIVE:
                tn += 1
                m["tn"] += 1
            else:
                fp += 1
                m["fp"] += 1
                false_positives.append(r)

    executed = tp + fn + fp + tn
    recall = tp / (tp + fn) if (tp + fn) else None
    fp_rate = fp / (fp + tn) if (fp + tn) else None
    precision = tp / (tp + fp) if (tp + fp) else None
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "skipped": skipped,
        "executed": executed,
        "recall": recall,
        "fp_rate": fp_rate,
        "precision": precision,
        "per_module": per_module,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "skips": skips,
    }


def _pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def run(verbose: bool = False) -> int:
    results = [run_case(c) for c in CORPUS]
    s = _score(results)

    print("=" * 68)
    print("WRAITH DETECTION BENCHMARK")
    print("=" * 68)

    if verbose:
        for r in results:
            mark = {POSITIVE: "hit ", NEGATIVE: "quiet", SKIP: "skip"}[r.status]
            ok = (
                "SKIP"
                if r.status == SKIP
                else (
                    "PASS"
                    if (
                        (r.case.expect == "flag" and r.status == POSITIVE)
                        or (r.case.expect == "quiet" and r.status == NEGATIVE)
                    )
                    else "FAIL"
                )
            )
            print(
                f"  [{ok}] {r.case.id:<28} expect={r.case.expect:<5} got={mark} {r.detail}"
            )
        print("-" * 68)

    print(
        f"{'module':<14}{'recall':>10}{'fp-rate':>10}{'tp':>5}{'fn':>5}{'fp':>5}{'tn':>5}{'skip':>6}"
    )
    print("-" * 68)
    for module in sorted(s["per_module"]):
        m = s["per_module"][module]
        r = m["tp"] / (m["tp"] + m["fn"]) if (m["tp"] + m["fn"]) else None
        f = m["fp"] / (m["fp"] + m["tn"]) if (m["fp"] + m["tn"]) else None
        print(
            f"{module:<14}{_pct(r):>10}{_pct(f):>10}"
            f"{m['tp']:>5}{m['fn']:>5}{m['fp']:>5}{m['tn']:>5}{m['skip']:>6}"
        )
    print("-" * 68)
    print(
        f"{'OVERALL':<14}{_pct(s['recall']):>10}{_pct(s['fp_rate']):>10}"
        f"{s['tp']:>5}{s['fn']:>5}{s['fp']:>5}{s['tn']:>5}{s['skipped']:>6}"
    )
    print(
        f"executed={s['executed']}  precision={_pct(s['precision'])}  skipped={s['skipped']}"
    )
    print("=" * 68)

    verdict_ok = True

    if s["executed"] == 0:
        print(
            "GATE FAIL: 0 cases executed (all skipped). A gate that tests "
            "nothing is not a pass."
        )
        verdict_ok = False

    if s["false_negatives"]:
        verdict_ok = False
        print(
            f"GATE FAIL: {len(s['false_negatives'])} MISSED ALERT(S) "
            "(real threat not caught):"
        )
        for r in s["false_negatives"]:
            print(f"    - {r.case.id}: {r.case.note}")

    if s["false_positives"]:
        verdict_ok = False
        print(
            f"GATE FAIL: {len(s['false_positives'])} FALSE POSITIVE(S) "
            "(benign artifact flagged):"
        )
        for r in s["false_positives"]:
            print(f"    - {r.case.id}: {r.case.note}")

    if s["skips"]:
        print(
            f"note: {len(s['skips'])} case(s) skipped (dependency unavailable "
            "here); they will run where the dependency exists:"
        )
        for r in s["skips"]:
            print(f"    - {r.case.id} ({r.case.kind}): {r.detail}")

    if verdict_ok:
        print("GATE PASS: no missed alerts, no false positives on the corpus.")
        return 0
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="WRAITH detection benchmark gate")
    ap.add_argument("--verbose", action="store_true", help="list every case")
    args = ap.parse_args()
    return run(verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
