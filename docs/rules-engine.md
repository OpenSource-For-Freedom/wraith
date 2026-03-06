# WRAITH Rules Engine — Detection Logic & External Resources

This document explains how WRAITH identifies threats, where the rules come from, how severity is assigned, what external intelligence feeds are pulled at runtime, and how false-positive suppression works.

---

## Table of Contents

1. [Detection Architecture Overview](#1-detection-architecture-overview)
2. [Layer 1 — YARA Signature Matching](#2-layer-1--yara-signature-matching)
   - [Bundled Rules (wraith_core.yar)](#bundled-rules-wraith_coreyar)
   - [Community Rules (downloaded at runtime)](#community-rules-downloaded-at-runtime)
   - [How Rules Fire & Severity](#how-rules-fire--severity)
3. [Layer 2 — Heuristic Analysis](#3-layer-2--heuristic-analysis)
4. [Layer 3 — Behavioural & Telemetry Modules](#4-layer-3--behavioural--telemetry-modules)
5. [Layer 4 — Threat Intelligence Enrichment](#5-layer-4--threat-intelligence-enrichment)
6. [False-Positive Suppression](#6-false-positive-suppression)
7. [Severity Scale](#7-severity-scale)
8. [External Resources & References](#8-external-resources--references)
9. [Known Limitations & Tuning Log](#9-known-limitations--tuning-log)
10. [Adding or Modifying Rules](#10-adding-or-modifying-rules)

---

## 1. Detection Architecture Overview

WRAITH runs detections in four stacked layers. Every layer emits findings in a common schema (`category`, `subcategory`, `severity`, `title`, `path`, `reason`). Results from all layers are merged, deduplicated, and ranked before display.

```
┌────────────────────────────────────────────────────────┐
│  Scan trigger (Full / Quick / Module)                  │
└───────────────────────┬────────────────────────────────┘
                        │
          ┌─────────────▼─────────────┐
          │  Layer 1 — YARA           │  File signature matching
          │  yara_scanner.py          │  (wraith_core.yar + community .yar)
          └─────────────┬─────────────┘
                        │
          ┌─────────────▼─────────────┐
          │  Layer 2 — Heuristics     │  Entropy, PE anomalies,
          │  heuristics.py            │  double-extensions, suspicious strings
          └─────────────┬─────────────┘
                        │
          ┌─────────────▼─────────────┐
          │  Layer 3 — Behaviour      │  Live processes, network, events,
          │  (multiple modules)       │  ADS, registry, browser, credentials,
          │                           │  rootkit, Windows Defender status
          └─────────────┬─────────────┘
                        │
          ┌─────────────▼─────────────┐
          │  Layer 4 — TI Enrichment  │  MalwareBazaar + ThreatFox lookups
          │  ioc_enricher.py          │  on hashes, IPs, and domains
          └───────────────────────────┘
```

---

## 2. Layer 1 — YARA Signature Matching

### Bundled Rules (`wraith_core.yar`)

These rules ship with WRAITH and are always available offline. Each rule carries a `severity` field in its `meta` block that the scanner reads directly — no rule is automatically CRITICAL just by matching.

| Rule | Severity | What it detects | Condition notes |
|---|---|---|---|
| `WRAITH_PowerShell_EncodedCommand` | HIGH | `-EncodedCommand` / `-enc` with base64 payload | Requires `powershell` keyword + encoding flag + long base64 string |
| `WRAITH_PowerShell_DownloadCradle` | CRITICAL | Download-and-execute (WebClient + IEX) | Both download AND execution primitive must be present |
| `WRAITH_PowerShell_HiddenExecution` | HIGH | Hidden-window / bypass / no-profile PS invocations | 3 of 5 flags required |
| `WRAITH_ProcessInjection_Indicators` | CRITICAL | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread etc. | 2 of 7 APIs required |
| `WRAITH_Reflective_DLL_Injection` | CRITICAL | ReflectiveDLLInjection strings or Fewer's loader shellcode | Named strings OR canonical 18-byte shellcode stub — **bare MZ header removed** (was FP on every DLL) |
| `WRAITH_Mimikatz` | CRITICAL | Mimikatz credential dumper | 2 of 8 named strings |
| `WRAITH_Cobalt_Strike_Beacon` | CRITICAL | Cobalt Strike beacon artifacts | 2 of 6 named strings OR (http-get + sleep + named pipe) |
| `WRAITH_NPM_Supply_Chain_Attack` | CRITICAL | npm postinstall scripts embedding child_process + credential/SSH path access | Requires child_process spawn AND at least one steal/exfil indicator |
| `WRAITH_NPM_Exfiltration` | CRITICAL | npm packages encoding data and sending to remote URL | HTTP + Buffer.from + process.env + 2 credential keywords |
| `WRAITH_CryptoMiner` | HIGH | XMRig, stratum pools, NiceHash etc. | 2 named miner keywords OR (stratum + pool string) OR (wallet regex AND a miner keyword) — **bare wallet regex removed** (was FP on any 95-char base64/hash) |
| `WRAITH_RAT_Generic` | CRITICAL | Named RAT families (njRAT, AsyncRAT, …) or generic capability cluster | Named family: 1-of-10; Generic: 6-of-7 strings AND file must be a PE — **threshold raised from 4 to 6** (browser JS legitimately has screenshot/clipboard/webcam APIs) |
| `WRAITH_Registry_Persistence_Script` | HIGH | Scripts writing `CurrentVersion\Run` keys | Registry key string + write command both required |
| `WRAITH_OpenClaw_Suspicious` | HIGH | OpenClaw / MetaQuest-related injection patterns | Named strings or (MetaQuest + access/autostart/inject) |
| `WRAITH_Suspicious_LNK_Target` | HIGH | Shortcut files with suspicious targets | `.lnk` files analysed |
| `WRAITH_AMSI_Bypass` | CRITICAL | AMSI tampering (patch AmsiScanBuffer, bypass strings) | Multiple known bypass techniques |
| `WRAITH_ETW_Tampering` | CRITICAL | ETW provider disabling / trace session manipulation | Known ETW disable APIs |

### Community Rules (downloaded at runtime)

`yara_scanner.py` downloads additional rules from public sources the first time a scan runs. Files are cached in the `rules/` directory and are only re-downloaded if deleted.

| Local filename | Primary source | Fallback source |
|---|---|---|
| `apt_grizzlybear.yar` | Neo23x0/signature-base (APT29 / Grizzly Steppe) | Yara-Rules/rules |
| `apt_apt28_sofacy.yar` | Neo23x0/signature-base (APT28 / Fancy Bear) | Yara-Rules/rules |
| `gen_webshells.yar` | Neo23x0/signature-base (CN webshells) | Neo23x0 thor-webshells |
| `gen_rats.yar` | Neo23x0/signature-base (RAT config patterns) | Yara-Rules/rules (Adwind) |
| `gen_mal_scripts.yar` | Neo23x0/signature-base | — |
| `hacktools.yar` | Neo23x0 thor-hacktools | — |
| `apt_lazarus.yar` | Neo23x0/signature-base (Lazarus/DPRK) | Yara-Rules/rules (Hidden Cobra) |
| `ransom_wannacry.yar` | Yara-Rules/rules (WannaCry/MS17-010) | Neo23x0 (Shamoon fallback) |

### How Rules Fire & Severity

```
scan_file_yara(rules, filepath)
  ├─ known-good path?  (Edge, Store packages, System32, Cargo cache…)
  │     └─ YES → suppress unless rule is a named family (Mimikatz, APT, RAT_*)
  ├─ match.meta["severity"]  → maps to CRITICAL / HIGH / MEDIUM / LOW / INFO
  │     └─ missing meta → defaults to CRITICAL
  └─ emits finding with correct severity
```

---

## 3. Layer 2 — Heuristic Analysis

`heuristics.py` inspects files **without any signatures** — it looks for statistical anomalies.

| Check | Threshold | Severity | Notes |
|---|---|---|---|
| **Shannon entropy** | > 7.2 bits/byte on `.exe/.dll/.sys/.scr` | HIGH | Indicates packing or encryption. Legitimate system DLLs typically score 5.5–6.8. |
| **PE header anomaly** | Missing `PE\x00\x00` signature at offset found in DOS stub | CRITICAL | Can indicate a hollowed or corrupted binary. |
| **Double extension** | e.g. `invoice.pdf.exe` | HIGH | Regex: `\.(txt\|pdf\|doc\|docx\|jpg\|png\|zip\|rar)\.(exe\|bat\|cmd\|vbs\|ps1\|scr\|com)` |
| **Suspicious strings** | Pattern list (C2 APIs, PS evasion, downloaders, persistence, crypto) | HIGH | ~30 patterns searched in first 1 MB of any scanned file. |

Heuristics intentionally skip:
- WRAITH's own `.NET` single-file extraction folder (`%TEMP%\.net\wraith\`)
- `WinSxS`, `assembly`, `microsoft.net`, `$Recycle.Bin`

---

## 4. Layer 3 — Behavioural & Telemetry Modules

Each module is independent. Any module can be run standalone or as part of a full scan.

| Module | File | What it checks |
|---|---|---|
| **Process Scanner** | `process_scanner.py` | Running processes: injected DLLs, unsigned images, hollow process indicators, LIVE/TASK status |
| **Network Scanner** | `network_scanner.py` | Active connections, listeners on suspicious ports, hosts file tampering, rogue proxy settings, DNS cache anomalies, certificate store additions |
| **Event Parser** | `event_parser.py` | Windows Security / System / Application event log (last 72 h by default): 4624/4625 logon fails, 7045 service installs, PowerShell Script Block logging (4104) |
| **Windows Security** | `winsec_scanner.py` | UAC level, Secure Boot, LSA protection, credential guard, SMB signing, RDP exposure |
| **Rootkit Scanner** | `rootkit_scanner.py` | SSDT hooks, hidden processes (PEB vs WMI), hidden files, driver signing violations |
| **ADS Scanner** | `ads_scanner.py` | NTFS Alternate Data Streams on files in user-writable paths |
| **Browser Scanner** | `browser_scanner.py` | Malicious extensions, suspicious saved passwords, unusual startup pages across Chrome/Edge/Firefox |
| **Credential Scanner** | `credential_scanner.py` | Credentials stored in Windows Credential Manager, SAM hive access attempts, LSASS dump artefacts |
| **NPM Check** | `npm_check.py` | Globally installed npm packages; checks postinstall scripts for supply-chain patterns |
| **CISA KEV Scanner** | `cisa_kev_scanner.py` | Installed software versions vs. CISA Known Exploited Vulnerabilities catalogue (live feed) |
| **Windows Defender** | `wdefender_integration.py` | Defender real-time protection state, signature age, exclusion list anomalies |
| **Attack Mapper** | `attack_mapper.py` | Maps findings to MITRE ATT&CK techniques |

---

## 5. Layer 4 — Threat Intelligence Enrichment

After all scanners complete, `ioc_enricher.py` extracts indicators from findings and queries external TI APIs.

| API | What is queried | Rate limit handling |
|---|---|---|
| **MalwareBazaar** (abuse.ch) | SHA-256 file hashes | 0.3 s sleep between requests; returns malware family / tags |
| **ThreatFox** (abuse.ch) | SHA-256 hashes, IP addresses, domains | Returns malware family, confidence, MITRE ATT&CK tag if present |

Both APIs are free and require no key for basic queries. An optional `Auth-Key` in `wraith.env.json` unlocks higher rate limits. Findings are enriched in-place: `intel_sources`, `malware_family`, and `attack_technique` fields are added when a hit is returned.

---

## 6. False-Positive Suppression

### Known-Good Path Exclusions

Generic YARA rule hits (non-named-family rules) are **suppressed** for files under these path prefixes, which are populated from environment variables at runtime:

| Location | Reason |
|---|---|
| `%LOCALAPPDATA%\Microsoft\Edge` | Chromium JS bundles legitimately contain screenshot, clipboard, WebSocket, webcam APIs |
| `%LOCALAPPDATA%\Microsoft\EdgeWebView` | Same as Edge |
| `%LOCALAPPDATA%\Packages` | Windows Store / UWP apps are signed and sandboxed |
| `%WINDIR%\System32` | Microsoft-signed OS binaries |
| `%WINDIR%\SysWOW64` | Same |
| `%WINDIR%\WinSxS` | Side-by-side assembly store |
| `%LOCALAPPDATA%\Temp\cargo-install` | Rust build artefacts |
| `%LOCALAPPDATA%\Temp\cargo-update` | Rust build artefacts |
| `%PROGRAMFILES%\Microsoft Visual Studio` | VS build tools |
| `%LOCALAPPDATA%\Microsoft\WindowsApps` | Store app launchers |

Named-family rules (Mimikatz, Cobalt Strike, APT28, RAT families, etc.) **always fire** regardless of path — a Mimikatz string in System32 is more suspicious, not less.

### Directory Skip List (full walk exclusions)

These subdirectories are never descended into regardless of the base path:
`WinSxS`, `assembly`, `microsoft.net`, `$Recycle.Bin`

Under known-good paths, browser cache subdirectories are additionally skipped:
`cache`, `code cache`, `GPUCache`, `blob_storage`, `Service Worker`

### Self-Exclusion

WRAITH excludes its own .NET single-file extraction folder (`%TEMP%\.net\wraith\`) to prevent detecting itself.

---

## 7. Severity Scale

| Level | Score | Meaning |
|---|---|---|
| **CRITICAL** | 4 | Named malware family / high-confidence IOC / active injection / KEV exploit |
| **HIGH** | 3 | Strong indicator requiring investigation — may have benign explanation in specific context |
| **MEDIUM** | 2 | Suspicious but commonly found in legitimate software — review in context |
| **LOW** | 1 | Weak signal — flag for awareness only |
| **INFO** | 0 | Informational; context enrichment with no immediate threat implication |

Entropy score displayed in the UI is the raw Shannon entropy value (0–8 bits/byte), not the severity level.

---

## 8. External Resources & References

### Active intelligence feeds (pulled at scan time)

| Feed | URL | Used in |
|---|---|---|
| CISA KEV (Known Exploited Vulnerabilities) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | `cisa_kev_scanner.py` |
| MalwareBazaar query API | https://mb-api.abuse.ch/api/v1/ | `ioc_enricher.py` |
| ThreatFox query API | https://threatfox-api.abuse.ch/api/v1/ | `ioc_enricher.py` |

### YARA rule repositories (downloaded on first run)

| Repository | URL | Trust level |
|---|---|---|
| **Neo23x0/signature-base** (Florian Roth) | https://github.com/Neo23x0/signature-base | High — maintained by a professional threat researcher; used by commercial AV vendors |
| **Yara-Rules/rules** | https://github.com/Yara-Rules/rules | Medium-High — community project; large contributor base; some rules are broad |

### Reference resources for rule development

These are used to research, validate, and tune detection logic — not pulled automatically.

| Resource | URL | Purpose |
|---|---|---|
| **LOLBAS Project** | https://lolbas-project.github.io | Living-off-the-land binaries: what Windows tools are legitimately abused by attackers — essential for distinguishing real abuse from normal use |
| **MITRE ATT&CK (Windows)** | https://attack.mitre.org/matrices/enterprise/windows/ | Maps techniques to detectable artefacts; used by `attack_mapper.py` |
| **NIST NSRL** | https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl | Hash database of ~200M known-good software files; can pre-filter FPs before YARA |
| **Sigma Rules** | https://github.com/SigmaHQ/sigma | Behavioural detection rules with well-documented FP conditions; reference for path/process exclusion patterns |
| **yarGen** | https://github.com/Neo23x0/yarGen | Generates YARA rules from malware samples using a goodware database to auto-exclude common strings |
| **CAPE Sandbox** | https://capesandbox.com | Dynamic malware analysis; generates YARA rules from behaviour — useful for validating new rule strings |
| **Any.run** | https://any.run | Interactive sandbox; shows exactly which strings/APIs a sample uses |
| **VirusTotal Intelligence** | https://www.virustotal.com | Cross-reference rule match results against 70+ AV engines to gauge FP risk |

---

## 9. Known Limitations & Tuning Log

### Active known issues

| ID | Description | Status |
|---|---|---|
| FP-001 | Community rules from `gen_rats.yar` / `hacktools.yar` may still fire on Edge Chromium JIT compiler DLLs | Investigating path-based suppression extension |
| FP-002 | `WRAITH_ProcessInjection_Indicators` (2-of-7 APIs) can fire on legitimate DBI frameworks (Frida, DynamoRIO, Intel PIN) | May need a developer-tools context check |
| LIM-001 | YARA scanning is file-at-rest only — memory resident code is not scanned by Layer 1 | Process scanner (Layer 3) partially compensates |
| LIM-002 | TI enrichment requires internet access; air-gapped systems show enrichment as skipped | Offline hash database cache planned |

### Tuning history

| Date | Change | Reason |
|---|---|---|
| 2026-03-06 | `WRAITH_Reflective_DLL_Injection $r4`: replaced bare MZ header `{4D 5A 90 00 ...}` with Stephen Fewer's 18-byte reflective loader bootstrap bytes | Every legitimate DLL starts with MZ — the old pattern was a guaranteed FP on 100% of DLL files |
| 2026-03-06 | `WRAITH_CryptoMiner $wallet`: changed `/[0-9a-zA-Z]{95}/` to `/4[0-9A-Za-z]{94}/` + requires pairing with a miner keyword | 95-char alphanumeric matches base64, UUIDs, build hashes — fired on cargo scripts and Edge bundles |
| 2026-03-06 | `WRAITH_RAT_Generic` generic threshold: raised from `4 of 7` to `6 of 7` + added `$mz at 0` PE guard | Browser JS legitimately implements screenshot, clipboard, and webcam APIs; threshold of 4 fired on Edge shopping JS |
| 2026-03-06 | `scan_file_yara`: severity now read from `meta.severity` in each rule; was hardcoded to CRITICAL | All YARA matches appeared CRITICAL regardless of what the rule author intended |
| 2026-03-06 | Added `KNOWN_GOOD_PATH_PREFIXES` suppression for Edge, Store packages, System32, cargo cache, VS | Reduced FP volume from these predictable legitimate locations |

---

## 10. Adding or Modifying Rules

### Bundled rules (`scanner/rules/wraith_core.yar`)

All rules must include a complete `meta` block:

```yara
rule WRAITH_MyRule
{
    meta:
        description = "One-line explanation of what this detects"
        severity    = "CRITICAL"   // CRITICAL | HIGH | MEDIUM | LOW | INFO
        author      = "WRAITH"
        fp_note     = "Known false-positive scenarios and why the condition avoids them"
    strings:
        // ...
    condition:
        // ...
}
```

**Checklist before committing a new rule:**
- [ ] Tested on a clean Windows 10 and Windows 11 install (or at minimum against files in `System32`, `LOCALAPPDATA\Microsoft\Edge`, and `LOCALAPPDATA\Packages`)
- [ ] `fp_note` filled in, even if just "no known FPs"
- [ ] Condition requires at least **2 independent signals** for generic detections (1 string = too broad)
- [ ] PE-specific strings guard with `$mz at 0` if the rule should only fire on executables
- [ ] Black formatting applied (`black scanner/`) before commit

### Community rule sources (`yara_scanner.py`)

To add a new source, append to `RULE_SOURCES`:

```python
"my_rule_pack": [
    "https://raw.githubusercontent.com/author/repo/main/rules/mypack.yar",
    # fallback URL if first is unavailable
],
```

Rules are downloaded once and cached. Delete the `.yar` file from `scanner/rules/` to force a re-download.
