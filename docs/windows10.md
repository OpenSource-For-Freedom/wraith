# WRAITH on Windows 10

WRAITH runs fully on Windows 10 x64 with no code changes required. This guide covers the known differences from Windows 11 and how to handle them.

---

## Supported Builds

| Build | Version | Status |
|---|---|---|
| 21H1 (May 2021) | 19043 | ✅ Full support |
| 21H2 (Nov 2021) | 19044 | ✅ Full support |
| 22H2 (Oct 2022) | 19045 | ✅ Full support (latest Win10) |
| 20H2 / 2004 | 19042 / 19041 | ⚠️ See winget note below |
| 1903 / 1809 and older | — | ❌ Not supported (.NET 8 requires 1607+, but some WMI APIs were updated in 1903) |

Recommended minimum: **Windows 10 21H1 (build 19043)**.

---

## Installation

### Option A — App Image icon (easiest)
Download the release ZIP, extract, and double-click the WRAITH app image. It will:
1. Detect Python — install via `winget` if missing (see note below)
2. Create `.venv` and install all scanner dependencies
3. Launch `WRAITH.exe` (runtime is bundled — no .NET SDK needed)

### Option B — Manual setup
If `winget` is unavailable on your build:

1. **Install Python 3.11** manually from [python.org/downloads](https://www.python.org/downloads/) — check **Add to PATH**
2. Open an **elevated** (`Run as administrator`) PowerShell window
3. Run:
   ```powershell
   cd C:\path\to\WRAITH
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r scanner\requirements.txt
   .\WRAITH.exe
   ```

### Option C — LAUNCH.bat (build from source)
```bat
git clone https://github.com/OpenSource-For-Freedom/wraith.git
cd wraith
LAUNCH.bat
```
Requires .NET 8 SDK — [download here](https://dotnet.microsoft.com/download/dotnet/8.0).

---

## winget Availability

`winget` (Windows Package Manager) ships pre-installed on **Windows 10 21H1+**. On older builds it may be missing.

**Check if winget is available:**
```powershell
winget --version
```

**If it's missing on your build**, install the [App Installer package from the Microsoft Store](https://apps.microsoft.com/detail/9NBLGGH4NNS1) or install Python manually (Option B above). `START.bat` will fall back gracefully if winget is absent — it will print a message and pause so you can install Python yourself.

---

## Permissions

WRAITH requires **Administrator** rights. On Windows 10 the UAC prompt will appear on every launch unless you right-click → "Run as administrator" or create a scheduled task with highest privileges.

To avoid the UAC prompt on every run, create a shortcut:
1. Right-click `WRAITH.exe` → Create shortcut
2. Right-click the shortcut → Properties → Advanced → **Run as administrator**

---

## Event Log Access (Security Log)

Reading the **Security** event log requires Admin privileges — which WRAITH already requests. However, on some Win10 builds the Security log audit policy is disabled by default.

To enable full Security log coverage:
```powershell
# Run as Administrator
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

Without this, Event ID 4104 (PS script block logging) and 4688 (process creation) may be empty. Other modules are unaffected.

---

## PowerShell Version

Windows 10 ships **PowerShell 5.1** — all WRAITH scanner modules are written to target 5.1.

- `Get-CimInstance` ✅ (version 3.0+)
- `Get-WmiObject` ✅ (deprecated in PS 7 but works fine on built-in 5.1)
- `Get-WinEvent` ✅ (version 2.0+)
- `Get-ScheduledTask` ✅ (version 3.0+)

If you have **PowerShell 7** installed alongside 5.1, WRAITH uses the system `powershell.exe` (5.1) by default — not `pwsh.exe`.

---

## Windows Defender Integration

The `wdefender_integration.py` module calls `Get-MpThreatDetection` and `Get-MpComputerStatus`. These cmdlets are part of the **Windows Defender** module which ships on all Win10 editions. No extra setup needed.

> If you have a third-party AV that replaces Defender, these calls will return empty results — all other modules continue normally.

---

## Known Limitations vs Windows 11

| Feature | Win 10 | Win 11 |
|---|---|---|
| Smart App Control | ❌ Not available | ✅ Available |
| TPM 2.0 enforcement | Optional | Required |
| `Get-MpPreference -EnableControlledFolderAccess` | ✅ Available | ✅ Available |
| Mica / Acrylic window blur | ❌ Falls back to solid | ✅ Native |
| All 14 scan modules | ✅ Full | ✅ Full |

The window chrome on Win10 will not have the Mica blur effect — the background renders as a solid dark colour instead. All scanning functionality is identical.

---

## Troubleshooting

### "WRAITH.exe is not recognized" or won't start
- Ensure you extracted the **full ZIP** — not just the exe
- Run from an elevated PowerShell/CMD prompt

### Python venv fails to create
- Confirm Python is **on PATH**: `python --version` in a new terminal
- If you see `python3` but not `python`, add an alias or use `py -3`

### Scanner returns no results
- Confirm WRAITH is running as **Administrator** (title bar shows shield icon)
- Check that the scan root path exists and is accessible

### Antivirus flags WRAITH.exe
- WRAITH performs memory analysis and reads process memory — behaviours that some AV heuristics flag
- Add an exclusion for the WRAITH folder, or submit to your AV vendor as a false positive
- The release binary is signed and the SBOM is attached to every release

### Event log scan is slow
- On Win10 with large event logs (> 500k entries), the initial query can take 30–60 seconds
- Reduce the look-back window (e.g. `-Hours 24` instead of the default) for faster results

---

## Verify Your Build Number

```powershell
[System.Environment]::OSVersion.Version
# or
winver
```

If your build is below 19041, upgrading to Win10 22H2 is recommended — it is the last supported Win10 release (EOL Oct 2025 for Home/Pro).
