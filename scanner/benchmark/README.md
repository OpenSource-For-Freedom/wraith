# WRAITH detection benchmark

A scoreboard for detection quality. It turns "is detection getting better or
worse?" from a guess into two numbers, measured against a labeled corpus:

- **recall** - of the real threats, how many did WRAITH catch? (misses = missed alerts)
- **false-positive rate** - of the benign artifacts, how many did it wrongly flag?

Every case runs **real scanner code** (no reimplemented detection). The corpus is
a controlled answer key we own, so the bar is strict: on this corpus a healthy
build is **100% recall and 0% false positives**.

## Run it

```bash
python3 scanner/benchmark/gate.py            # scoreboard + gate (exit code = verdict)
python3 scanner/benchmark/gate.py --verbose  # list every case
```

It also runs inside the normal test suite:

```bash
cd scanner && python3 -m pytest benchmark/
```

## Gate rules (non-zero exit)

- **0 executable cases** -> fail. A gate that tests nothing is not a pass.
- **any missed alert** (a `flag` case the scanner did not catch) -> fail.
- **any false positive** (a `quiet` case the scanner flagged) -> fail.

Cases whose dependency is missing here (e.g. `yara`, or a Windows-only module)
report **SKIP** and run where the dependency exists. They never count as a fake
pass.

## Adding a case (this is the point)

Every false positive we fix should ship a `quiet` case; every missed alert we
fix should ship a `flag` case. That is the wall that stops a fix from silently
regressing. Add a `Case(...)` to `CORPUS` in `corpus.py`:

```python
Case(
    "id-kebab", "module", "flag" | "quiet", "<kind>", <payload>,
    "why this case exists / the incident it guards",
)
```

`kind` picks the runner that calls the real scanner function:

| kind | drives | payload |
|---|---|---|
| `file_heuristics` | `heuristics.scan_file_heuristics` | `{"name":..., "data": bytes}` |
| `process` | `process_scanner.analyze_process` | a Win32_Process-shaped dict |
| `npm` | `npm_check._check_package_json` | package.json text |
| `event` | `event_parser._keyword_check` | an event message string |
| `ioc` | `ioc_enricher._extract_indicator` | a finding dict (positive = extracted) |
| `network_conn` | `network_scanner.scan_connections` | `{"conn": {...}, "pid_map": {...}}` |
| `ransom_ext` | `ransomware_scanner.RANSOM_EXTENSIONS` | a filename |
| `ransom_note` | `ransomware_scanner.RANSOM_NOTE_NAMES` | a filename |
| `yara` | `yara_scanner.scan_file_yara` | `{"name":..., "data": bytes, "rules_dir":...}` |

## Safety - read before adding a case

- **No live malware, ever.** This repo is public and cloned on many machines.
  Every `flag` case is a **synthetic** artifact that reproduces the *signal*
  WRAITH keys on (a crafted filename, a deterministic high-entropy blob, a
  process dict, a package.json), never a real weaponized sample. Detonation
  belongs nowhere near this repo.
- **The corpus is read-only ground truth.** Flipping an expected label is a
  claim about reality; justify it in the case note.

## What this is not

This measures WRAITH's *own* detection logic against a curated corpus. It is not
a head-to-head lab test against commercial AV, and it does not make WRAITH a
real-time endpoint product. It is the instrument that lets a change to a
classifier be judged by a number instead of a hunch, and it grows every time a
real false positive or missed alert is found and fixed.
