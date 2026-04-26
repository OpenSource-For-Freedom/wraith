# Changelog

All notable changes to **WRAITH** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — versions are ordered newest-first.

---

## [Unreleased]

> Changes staged but not yet versioned.

---

## [1.0.1] — 2026-04-25

### Security
- **Auto-quarantine trust gate bypass fixed** — `forceCriticalContainment` was short-circuiting both `IsTrustedPath` and `IsTrustedSigner` checks for Critical-severity findings via `!forceCriticalContainment &&` guards in `AutomatedResponseService.cs`. Trusted path and signer gates now apply to **all** severity levels including Critical. This was the root cause of Windows system DLLs and signed Microsoft binaries being incorrectly quarantined.
- **False positive elimination** — `audiostreaming.dll` and `audiospew.dll` (Windows SDIAG diagnostic tools under `C:\Windows\Temp\SDIAG_*\analyze\amd64\`) and `Microsoft.CognitiveServices.Speech.core.dll` (UWP app container) were being quarantined by the `WRAITH_RAT_Generic` YARA rule at Critical severity. Resolved by the trust gate fix above — these paths now correctly match `TrustedPathPrefixes` and are skipped.

### Fixed
- `IsTrustedPath` now calls `Environment.ExpandEnvironmentVariables()` on each policy prefix before comparison — entries like `%USERPROFILE%\AppData\Local\Packages\Microsoft.*` in `wraith.policy.json` now resolve to the actual user path at runtime instead of matching literally.
- Scheduled task `RepetitionInterval` overflow in `automation/Register-WraithTimedScan.ps1` — `[TimeSpan]::MaxValue` serialized to `P99999999DT23H59M59S` (8-digit day count), which exceeds the Windows Task Scheduler hard limit of 7 digits. Fixed to `New-TimeSpan -Days 9999` across source, deployed `bin\Release\` copy, and `publish-fixed\` copy.
- ComboBox controls (Severity / Category / Live filters) rendered with a white system background in the Patronus dark theme — WPF's default `ComboBox` `ControlTemplate` ignores `Background` property setters entirely. Replaced with a full dark `ControlTemplate` in `PatronusTheme.xaml` using a custom `WraithComboToggle` `ToggleButton` style. Popup border and fill now match the Patronus palette (`#0D0D28`); hover state uses `#1A0D3D`.

### Added
- **Supply-chain scanner expanded to 200+ threat indicators** (`scanner/npm_check.py`):
  - AI/LLM API key harvester typosquats: `deepseek`, `deepseek-api`, `deepseek-sdk`, `deepseek-node`, `deepseek-client`, `anthropic-ai`, `anthropic-sdk`, `claude-ai`, `claude-sdk`, `openai-api`, `openai-node`, `chatgpt-api`, `chatgpt-wrapper`
  - AI ecosystem typosquats: `langchain-core`, `huggingface`, `transformers-js`, `ollama-js`, `ollama-node`, `copilot-sdk`, `github-copilot`, `cursor-ai`, `cursor-sdk`, `autogpt`, `auto-gpt`, `crewai-js`, `llamaindex`, `llama-index`
  - Additional AI provider packages: `mistral-node`, `mistral-client`, `gemini-ai`, `gemini-sdk`, `cohere-node`, `perplexity-sdk`, `grok-sdk`, `xai-sdk`, `together-ai`, `replicate-node`, `stability-sdk`, `elevenlabs-node`, `openrouter-sdk`
  - Generic credential lures: `ai-utils`, `llm-utils`, `env-config-helper`, `dotenv-defaults`, `dotenv2`, `secrets-manager`, `config-manager`
  - 2024 CVEs: `xz-utils` (CVE-2024-3094 backdoor), `vm2`, `semver`, `word-wrap`, `tough-cookie`
  - Cloud credential typosquats: `aws-sdk2`, `aws-cdk2`, `stripe-node`, `supabase-js`, `prisma-client`, `twilio-node`
  - Cryptomining drop payloads: `node-binaries`, `native-build-tools`
- **AI API key exfiltration detection in postinstall scripts** — `SUSPICIOUS_POSTINSTALL_PATTERNS` now covers `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `HF_TOKEN`, `MISTRAL_API_KEY`, `COHERE_API_KEY`, `GROQ_API_KEY`, `REPLICATE_API_TOKEN`, `GEMINI_API_KEY`, `XAI_API_KEY`, `PERPLEXITY_API_KEY`, `TOGETHER_API_KEY`, `OPENROUTER_API_KEY`, `CURSOR_*`, `COPILOT_*`, and literal key-format regexes (`sk-`, `sk-ant-`, `hf_`, `dsk-` prefixes with 20+ char suffix)
- **Levenshtein typosquat baseline expanded** — `POPULAR_PACKAGES` extended with 35+ AI/ML ecosystem packages: `openai`, `anthropic`, `langchain`, `llamaindex`, `ollama`, `transformers`, `huggingface`, `replicate`, `cohere`, `deepseek`, `mistral`, `together`, `groq`, `ai`, `vercel-ai`, `ai-sdk`, `crewai`, `autogpt`, `agentgpt`, `tiktoken`, `chromadb`, `pinecone`, `weaviate`, `qdrant`, `whisper`, `stability-ai`, `elevenlabs`, `langsmith`, `langfuse`, `helicone`, `llm`, `gpt4all`, `localai`
- Postinstall obfuscation detection: `String.fromCharCode`, hex escape sequences (`\x[0-9a-fA-F]{2}`)
- Exfiltration channel detection in postinstall: `requestbin.com`, `webhook.site`, `pipedream.net`
- `_KNOWN_LEGITIMATE_SIMILARS` updated — `ai`, `groq`, `cohere`, `ollama`, `replicate`, `whisper`, `tiktoken` whitelisted to suppress false positives on official packages that have short names similar to typosquats
- Discord / Slack SOC alert webhooks now emit bordered ASCII tables (`+---+---+` format) for cleaner readability in notification channels

### Changed
- `wraith.policy.json` trusted path prefixes expanded with UWP app container paths (`%USERPROFILE%\AppData\Local\Packages\MicrosoftWindows.*`, `%USERPROFILE%\AppData\Local\Packages\Microsoft.*`), `C:\ProgramData\Microsoft\`, and `%USERPROFILE%\AppData\Local\Microsoft\` — prevents quarantine of Microsoft-signed OS components and UWP runtime binaries
- Trusted path prefixes migrated from `C:\Users\%USERNAME%\...` format to `%USERPROFILE%\...` — `%USERPROFILE%` is the correct Windows environment variable for the current user profile path and expands reliably via `Environment.ExpandEnvironmentVariables()`
- MODULES panel label changed: `npm supply-chain (cline)` → `npm / .NET supply-chain` — reflects the scanner's full scope across npm, .NET/NuGet, Node.js, and AI/ML package ecosystems

---

## [1.0.0] — 2026-04-23

### Changed
- Bumped `softprops/action-gh-release` GitHub Action from v2 → v3 (via Dependabot PR #5)

---

## [1.0.0-rc3] — 2026-03-27

### Changed
- Bumped `System.Text.Json` NuGet from `10.0.3` → `10.0.5` (Dependabot PR #4)

---

## [1.0.0-rc2] — 2026-03-16

### Fixed
- Setup walkthrough and Python path prompt flow corrected — resolves path detection failures on systems with non-standard Python installs

### Changed
- Bumped `System.Text.Json` NuGet from `8.0.6` → `10.0.3` (Dependabot PR #3)

---

## [1.0.0-rc1] — 2026-03-09

### Added
- `CONTRIBUTING.md` — contributor guidelines and PR workflow
- `CODE_OF_CONDUCT.md` — community standards document

### Changed
- Bumped `actions/setup-python` GitHub Action from v4 → v6 (Dependabot PR #1)
- Bumped `actions/setup-dotnet` GitHub Action from v4 → v5 (Dependabot PR #2)
- Bumped `System.Text.Json` NuGet from `8.0.6` → `10.0.3`

---

## [1.0.0-beta3] — 2026-03-08

### Security
- Resolved all CodeQL static analysis alerts in scanner modules
- Removed over-privileged patterns flagged by CodeQL

### Fixed
- GitHub Actions release upload now uses `gh release upload` for Velopack assets — fixes broken asset attachment on multi-artifact releases

### Added
- Render-tier CPU protection guard in setup flow — prevents WRAITH from launching the full scan on low-resource / cloud render nodes
- Setup progress window with staged install feedback

### Changed
- Applied `black` auto-formatting across all Python scanner modules

---

## [1.0.0-beta2] — 2026-03-07

### Added
- **Velopack auto-update** — silent background download with amber notification button in the WPF title bar; no restart forced on the user
- `UpdateAvailableWindow.xaml` / `.cs` — update prompt dialog

### Fixed
- Separated Velopack publish (multi-file) from ZIP publish (single-file) in CI pipeline — fixes release artifact conflicts

### Changed
- Applied `black` formatting pass across scanner modules
- Multiple README clarity and badge updates

---

## [1.0.0-beta1] — 2026-03-06

### Fixed
- CISA KEV scanner and npm supply-chain scanner false-positive noise reduced — tighter matching thresholds
- Windows Event Log keyword deduplication — eliminates repeated findings from the same event source

---

## [1.0.0-alpha3] — 2026-03-05

### Fixed
- Bootstrap launcher OS detection corrected for Windows 10 vs 11 variants
- Package install sequencing fixed to prevent partial-install state on first run

---

## [1.0.0-alpha2] — 2026-03-04

### Added
- **ATT&CK Mapper** (`scanner/attack_mapper.py`) — maps each finding to MITRE ATT&CK technique IDs
- **IOC Enricher** (`scanner/ioc_enricher.py`) — enriches indicators via abuse.ch API with Auth-Key support
- **Test harness** (`scanner/test_intel.py`) — integration test suite for scanner modules
- **Header scan animation** — beam sweep, data fragments, phase label, and wraithlet sprites in the WPF header
- CUDA acceleration support for entropy-based data processing and binary audit
- Dependabot configuration for NuGet, pip, and GitHub Actions dependency tracking (`.github/dependabot.yml`)
- CI: auto-increment patch version on every push to `main`

### Fixed
- Batch UI updates to prevent WPF thread freeze during high-volume scan results
- Auth-Key handling for abuse.ch MalwareBazaar and URLhaus APIs
- Relative path reference for release body logo in CI workflow

### Changed
- Behavioral detection keywords refactored — replaced product-specific names with technique-based behavioral patterns for broader coverage
- Applied `black` auto-formatting to all Python scanner modules
- README: compact box-drawing ASCII banner replacing oversized version; Win10 guide, library reference table, and badges added; UI walkthrough screenshots added

---

## [1.0.0-dev] — 2026-03-04

### Added
- **Initial release: WRAITH v1.0.0-dev**
- 14 scan modules: YARA, Heuristics, Persistence, Processes, Network, Events, CISA KEV, NPM Supply Chain, Windows Security, Rootkit, ADS, Browser, Defender Integration, Credentials
- Dark-themed WPF dashboard (`WRAITH/`) with real-time finding stream, severity filter, and one-click process kill
- Python scan engine (`scanner/`) with bundled YARA rule sets (`scanner/rules/`)
- `LAUNCH.bat` — entry point; bootstraps venv, builds .NET app, creates desktop shortcut, launches WRAITH
- `SETUP.bat` — one-time dependency installer
- `WRAITH.ps1` — master PowerShell launcher / venv bootstrap
- `quick-scan.ps1` — headless scanner (no build required); supports `-Hours` and `-OutPath` parameters
- JSON / CSV / HTML report export from toolbar
- MVVM architecture: `MainViewModel`, `ScanOrchestrator`, `ReportExporter`
- Severity tiers: CRITICAL / HIGH / MEDIUM / LOW / INFO
- `wraith.policy.json` — configurable scan policy
- GitHub Actions CI/CD pipeline with deploy workflow

---

[Unreleased]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-rc3...v1.0.0
[1.0.0-rc3]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-rc2...v1.0.0-rc3
[1.0.0-rc2]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-rc1...v1.0.0-rc2
[1.0.0-rc1]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-beta3...v1.0.0-rc1
[1.0.0-beta3]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-beta2...v1.0.0-beta3
[1.0.0-beta2]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-beta1...v1.0.0-beta2
[1.0.0-beta1]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-alpha3...v1.0.0-beta1
[1.0.0-alpha3]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-alpha2...v1.0.0-alpha3
[1.0.0-alpha2]: https://github.com/OpenSource-For-Freedom/wraith/compare/v1.0.0-dev...v1.0.0-alpha2
[1.0.0-dev]: https://github.com/OpenSource-For-Freedom/wraith/releases/tag/v1.0.0-dev
