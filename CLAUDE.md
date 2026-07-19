# CLAUDE.md

Guidance for AI assistants working in the WRAITH repository.

## What WRAITH is

WRAITH (**W**indows **R**untime **A**nalysis & **I**ntrusion **T**hreat **H**unter) is a
native **Windows** threat-hunting / malware-scanning desktop application. It orchestrates
~14 scan modules (YARA signatures, behavioral heuristics, persistence mechanisms,
supply-chain checks, live process/rootkit/credential analysis, CISA KEV lookups, etc.)
and surfaces findings — ranked by severity (CRITICAL / HIGH / MEDIUM / LOW / INFO) —
through a dark-themed WPF dashboard. It is designed to run alongside Windows Defender,
can auto-quarantine/auto-kill threats subject to a trust policy, and can push alerts to
Slack/Discord webhooks.

This is a **Windows-only runtime target**. The scanners call PowerShell, `winreg`,
`pywin32`, WMI/CIM, and the Windows Event Log. The app builds and runs on Windows;
most Python scanner modules only meaningfully execute on Windows (they self-skip or
are import-guarded elsewhere). CI runs the Python and .NET test suites on
`windows-latest`.

## Architecture — three languages, one pipeline

WRAITH is a multi-language system. Understand which layer owns what before editing:

1. **.NET 8 / C# WPF app (`WRAITH/`)** — the front-end and controller. MVVM WPF GUI plus
   all orchestration, quarantine, alerting, auto-response, reporting, and auto-update
   logic. This is what ships as `WRAITH.exe`.
2. **Python scan engine (`scanner/`)** — the actual detection logic. The C# app shells
   out to `python scanner.py --mode=<mode> ...` and parses a single JSON blob from
   stdout. Each module is a separate `*_scanner.py` / `*_check.py` file.
3. **PowerShell (`WRAITH.ps1`, `quick-scan.ps1`, `automation/*.ps1`, `LAUNCH.bat`,
   `SETUP.bat`)** — bootstrap/launcher glue (create venv, install deps, build, launch),
   a standalone headless scanner, and scheduled-task / persistence-listener automation.

### How the C# ↔ Python bridge works
- `WRAITH/Services/ScanOrchestrator.cs` is the bridge. `RunPythonScanAsync(mode, path, hours, ...)`
  invokes the Python interpreter with:
  `scanner.py --mode=<mode> --path=<path> --hours=<n> --rules=<dir>` and deserializes the
  JSON result into `ScanResult` / `ThreatFinding` (see `WRAITH/Models/ThreatFinding.cs`).
- Valid modes (from `scanner/scanner.py`): `persistence | yara | heuristics | events |
  npm | processes | network | winsec | rootkit | ads | browser | defender | credential |
  kev | all`. Optional `--enrich` queries ThreatFox/MalwareBazaar for IOC reputation.
- The interpreter path comes from `wraith.env.json` (written at bootstrap; points at the
  `.venv` python). `ScanOrchestrator` walks up from the exe dir to find it and the
  `scanner/` directory; falls back to system `python`.
- `WRAITH/Services/BootstrapService.cs` runs on first launch: detects Windows, locates
  Python 3.10+ (PATH → common dirs → registry), installs via winget if missing, creates
  `.venv`, pip-installs `scanner/requirements.txt`, and writes `wraith.env.json` (stored
  under `%ProgramData%\WRAITH\` so Velopack updates don't strand it).

## Directory / module layout

```
WRAITH/                     .NET 8 WPF app (AssemblyName WRAITH -> WRAITH.exe)
  App.xaml(.cs)             WPF entry point
  MainWindow / *Window      WPF windows: main dashboard, Quarantine, Feeds, Walkthrough,
                            SetupProgress, UpdateAvailable, PathConfirm
  ViewModels/               MainViewModel (MVVM binding target)
  Models/                   ThreatFinding, ScanResult, severity types
  Services/                 Core logic — see below
  Converters/               WPF value converters (severity -> colour, etc.)
  Themes/PatronusTheme.xaml Dark theme resource dictionary
  Assets/                   Icons/images (wraith.ico is the app icon)
  app.manifest             Requests Administrator (UAC) at launch
  WRAITH.csproj            net8.0-windows, UseWPF, Velopack + System.Text.Json refs
scanner/                    Python scan engine (invoked per-mode by ScanOrchestrator)
  scanner.py               Entry point / arg dispatcher; emits JSON to stdout
  *_scanner.py / *_check.py Individual modules (yara, rootkit, network, process, ads,
                            credential, winsec, vuln_driver, local_vuln, cisa_kev, npm,
                            tor, browser, ransomware, ...)
  heuristics.py, event_parser.py, attack_mapper.py (ATT&CK tagging),
  ioc_enricher.py, digitalside_intel.py, feed_store.py, wdefender_integration.py
  rules/*.yar              Bundled YARA rule sets (apt_*, gen_*, ransom_*, hacktools,
                            wraith_core)
  requirements.txt         Python deps (yara-python, pywin32, psutil, requests, colorama, black)
  test_*.py                pytest suites (NOT shipped to end users)
WRAITH.Tests/              xUnit + Moq tests for the C# services
automation/                PowerShell scheduled-scan + persistence-listener scripts
docs/                      rules-engine.md (detection logic), windows10.md
WRAITH.ps1                 Master launcher/bootstrap (venv, deps, build, shortcuts, launch)
LAUNCH.bat                 Thin wrapper: powershell -File WRAITH.ps1 %*
SETUP.bat                  One-time dependency installer + build
quick-scan.ps1             Standalone headless scanner (source tree only; not in release ZIP)
ThreatScanner.sln          Solution: WRAITH + WRAITH.Tests
wraith.policy.json         Auto-response trust policy (see below)
VERSION                    major.minor[.patch] seed used by the deploy workflow
```

### C# Services (`WRAITH/Services/`) — what each does
- `ScanOrchestrator.cs` — runs Python scan modes, streams findings, kills child procs.
- `BootstrapService.cs` — first-run Python/venv/deps setup; writes `wraith.env.json`.
- `AutomatedResponseService.cs` — loads/saves `wraith.policy.json`; applies the trust
  gates before any kill/quarantine.
- `QuarantineService.cs` / `LockedFileDeleter.cs` — quarantine vault + locked-file delete.
- `AlertingService.cs` — Slack/Discord webhook delivery (validates webhook host/URL).
- `ProtectionStatusEvaluator.cs`, `RealtimeMonitorService.cs`, `FeedRefreshService.cs`,
  `ReportExporter.cs` (JSON/CSV/HTML export), `UpdateService.cs` (Velopack auto-update),
  `AutomationMenuService.cs` (tray-menu → `automation/*.ps1`), `AlertingService`, etc.

## Setup, build, test, run

All of the following assume **Windows** with Administrator (UAC) unless noted.

### One-command dev flow (build from source)
```bat
LAUNCH.bat            :: (= powershell WRAITH.ps1) creates .venv, installs Python deps,
                      :: builds the .NET app (Release), makes shortcuts, launches the GUI
LAUNCH.bat -Close     :: stop a running WRAITH instance (self-elevates if needed)
LAUNCH.bat -ForceSetup:: launch with the first-run setup walkthrough
```
`SETUP.bat` is the alternate one-time installer: checks Python, `pip install -r scanner/requirements.txt`,
downloads YARA rules, then `dotnet restore` + `dotnet build ThreatScanner.sln -c Release`.
Both scripts auto-install Python and the .NET 8 SDK via winget if missing.

### Building the .NET app directly
```bat
dotnet restore ThreatScanner.sln
dotnet build   ThreatScanner.sln -c Release
```
Publishing (as CI does) is a self-contained single-file win-x64 build:
```
dotnet publish WRAITH/WRAITH.csproj -c Release --runtime win-x64 --self-contained true -p:PublishSingleFile=true
```
Note: `scanner/` and `automation/` are copied **next to** the exe (not inside the
single-file bundle) via `<Content>` includes in `WRAITH.csproj` — the Python engine must
sit alongside `WRAITH.exe` at runtime or every Python-backed scan fails.

### Tests
```bat
:: Python scanner tests
cd scanner && pytest -v          :: deps: pytest requests pywin32

:: C# service tests (xUnit)
dotnet test WRAITH.Tests/WRAITH.Tests.csproj -c Release
```

### Headless scan without building the GUI
```powershell
.\quick-scan.ps1
.\quick-scan.ps1 -Hours 168 -OutPath C:\wraith-report.json
```
This ships in the source tree only, not the release ZIP.

### Automation (scheduled scans / persistence listener)
Elevated PowerShell, from `automation/` — e.g.
`.\Register-WraithTimedScan.ps1 -IntervalMinutes 30 -ScanPath "C:\" -Hours 24 -Mode all -RunAsSystem`,
`.\Start-WraithPersistenceListener.ps1 -ScanPath "C:\" -PollSeconds 120 -AutoKillCritical`.
See `automation/README.md`. Output goes to `C:\ProgramData\WRAITH\ScheduledScans`.

## Conventions

### Python
- Formatted with **Black**, `line-length = 88` (`pyproject.toml`). The `Black` CI workflow
  runs `black . --check` on every push/PR — run `black .` before committing or CI fails.
- Every scanner module emits findings in a common dict schema
  (`category`, `subcategory`, `severity`, `title`, `path`, `reason`); `scanner.py` assigns
  anomaly scores, builds the summary, and prints one JSON object to stdout. Keep this
  contract stable — the C# side deserializes it.
- Windows-only imports (`winreg`, `pywin32`) should stay import-guarded so modules can be
  imported on non-Windows CI. New modules that shell out should degrade gracefully when a
  dependency (e.g. `yara-python`) is unavailable rather than hard-failing the whole scan.
- Tests are `scanner/test_*.py` (pytest). `test_*.py` is excluded from published output.

### C#
- Target `net8.0-windows`, `Nullable` enabled, `ImplicitUsings` enabled, WPF (+ WinForms
  interop). Tests use **xUnit** + **Moq**.
- Prefer testable services (constructor-injected dependencies) — mirror the existing
  `WRAITH.Tests/*Tests.cs` pattern when adding logic to `WRAITH/Services/`.

### PowerShell (from CONTRIBUTING.md)
- Use approved verbs (`Get-`, `Set-`, `Invoke-`, `Register-`, `Start-`…), avoid aliases in
  scripts. `PascalCase` for functions, `camelCase` for locals. Lines under ~120 chars, no
  trailing whitespace.

### Commits / branching (from CONTRIBUTING.md)
- Conventional Commits: `type(scope): summary` (`feat`, `fix`, `docs`, `refactor`, `test`,
  `chore`, `perf`).
- Branch off `dev`, not `main`; open PRs against `dev`. `main` is release-ready.

## The auto-response policy — `wraith.policy.json`

`AutomatedResponseService` loads this file (next to the exe) to decide whether to
auto-kill/auto-quarantine a finding. Key fields:
- `AutoContainmentEnabled`, `AutoKillLiveProcess`, `AutoQuarantineFile`,
  `AutoQuarantineCritical`, `MaxActionsPerScan`, `MinAnomalyScoreForAction`.
- **Two trust gates** — a finding is skipped (never contained, even CRITICAL) if EITHER:
  1. its path starts with a prefix in `TrustedPathPrefixes` (supports env tokens like
     `%USERPROFILE%`, `%SYSTEMROOT%`, expanded at runtime), or
  2. the file is signed by a subject keyword in `TrustedSignerKeywords`.
- `EnableSlackWebhook` / `SlackWebhookUrl` / `SlackNotifyOnHigh` and the Discord
  equivalents drive `AlertingService`. Slack URLs must start with
  `https://hooks.slack.com/`; Discord with `https://discord.com/api/webhooks/`.

Keep defaults conservative (`AutoQuarantineFile: false`). Auto-kill/quarantine can disrupt
a live system on false positives.

## CI / release gotchas

- Workflows in `.github/workflows/`: `pytest.yml` (scanner tests, windows-latest,
  triggered by `scanner/**` changes), `dotnet-tests.yml` (C# tests, windows-latest,
  triggered by `WRAITH/**` / `WRAITH.Tests/**` / `.sln`), `black.yml` (formatting gate,
  ubuntu), `deploy.yml` (build & release on push to `main` / `v*.*.*` tag).
- `deploy.yml` derives the release version from `VERSION` (auto-increments the patch from
  the highest existing tag). If `VERSION` lags behind the newest stable tag the build
  aborts — bump `VERSION` when needed. Doc-only (`**.md`, `docs/**`, `LICENSE`) pushes to
  main skip the deploy build.
- Release produces a self-contained single-file `WRAITH.exe`, a portable
  `WRAITH-<ver>-win-x64.zip` (must contain `scanner/` + `automation/` — there is a smoke
  test that fails the release if they're missing), and a Velopack installer
  (`Setup.exe`, auto-update). The Velopack `vpk` CLI version must match the `Velopack`
  package version in `WRAITH.csproj`.
- Both test suites (pytest + dotnet test) run as gates inside `deploy.yml` before any
  artifact is published.

## Where to look first

- Adding/altering a detection → `scanner/<module>.py` (+ `scanner.py` dispatch, a
  `test_*.py`, and `docs/rules-engine.md`).
- Changing scan orchestration / how modes are invoked → `WRAITH/Services/ScanOrchestrator.cs`.
- Changing quarantine/auto-response behavior → `WRAITH/Services/AutomatedResponseService.cs`
  + `wraith.policy.json`.
- First-run / Python setup issues → `WRAITH/Services/BootstrapService.cs`, `WRAITH.ps1`.
- YARA rules → `scanner/rules/*.yar`.
