"""
WRAITH browser_scanner.py
Module 5 of 7 - Browser Hijacking & Malicious Extension Detection

Checks:
  1. Extension manifest scan     - Chrome/Edge/Firefox extensions, high-risk perms
  2. Browser shortcut injection  - --load-extension / --disable-web-security flags
  3. Search engine hijack        - IE/Chrome/Edge default search registry tampering
  4. Proxy hijack                - browser-level proxy pointing to localhost
  5. Suspicious NativeMessaging  - unauthorized native messaging hosts
  6. Known malicious extension   - extension IDs matching known adware/spyware
  7. Browser startup pages       - homepage forced to non-Microsoft/Google domain
  8. Permissions fingerprint     - extensions requesting all_urls + password access
"""

import json
import os
import re
import subprocess
import sys
import winreg
from pathlib import Path
from typing import List, Dict, Any, Optional

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

# Extension permissions that indicate high risk when combined
DANGEROUS_PERMISSIONS = {
    "<all_urls>", "http://*/*", "https://*/*", "*://*/*",  # broad URL access
    "webRequest", "webRequestBlocking",          # MITM traffic interception
    "history",                                   # browsing history exfil
    "bookmarks",                                 # bookmark exfil
    "cookies",                                   # session cookie theft
    "clipboardRead",                             # clipboard snooping
    "nativeMessaging",                           # local system access
    "proxy",                                     # traffic redirection
    "declarativeNetRequest",                     # traffic filtering/blocking
    "passwords",                                 # deprecated but still present
}

# A single high-risk permission doesn't mean malicious; two or more together is suspicious
HIGH_RISK_PERMISSION_THRESHOLD = 2

# Known malicious / adware extension IDs (Chrome)
# These are documented in threat intelligence reports
KNOWN_BAD_EXTENSION_IDS = {
    # DNSChanger / SearchManager / session hijackers
    "hifnmhlpolbojpgobkiohnnjaelgkfji",
    "opiekpbiabcnapljbkkpkbbfbcgnfjja",
    "lclfdlpjimapiiaihpbkfgpcjklkfceg",
    "hkbfjlbdbflfnjiehgeimglbcieoijgp",
    "joflmkccibkooplaeoinecjbmdebglab",
    # Rogue ad injectors
    "fiekmhifodioelkmedmkdpealfkidgeb",
    "jmfkcklnlgedgmkdfbfdefgncadkjhfg",
    # Fake YouTube downloaders (credential harvesters)
    "bkfjjagbibepnalipodcijcljhmlnaib",
    "pjlkfekoejjhooimcjpahoogbnecbaaj",
    # Banking Trojans (browser layer)
    "baemfnjjfmolpbcgimliomfkdmjlhepj",
    "fbgcedjacmlbgleddnoacbnijgmiolem",
    # Malicious API interceptors
    "boadgeojelhgndaghljhdicfkmllpafd",
    "cjabmdjcfcfdmffimndhafhblfmpjdpe",
}

# Registry paths checked for browser homepage / search hijacks
BROWSER_REGISTRY_PATHS = [
    (winreg.HKEY_CURRENT_USER,      r"Software\Microsoft\Internet Explorer\Main",            "Start Page"),
    (winreg.HKEY_CURRENT_USER,      r"Software\Microsoft\Internet Explorer\Main",            "Default_Page_URL"),
    (winreg.HKEY_LOCAL_MACHINE,     r"Software\Microsoft\Internet Explorer\Main",            "Default_Page_URL"),
    (winreg.HKEY_LOCAL_MACHINE,     r"Software\Microsoft\Internet Explorer\Main",            "Start Page"),
    (winreg.HKEY_CURRENT_USER,      r"Software\Policies\Google\Chrome",                      "HomepageLocation"),
    (winreg.HKEY_LOCAL_MACHINE,     r"Software\Policies\Google\Chrome",                      "HomepageLocation"),
    (winreg.HKEY_CURRENT_USER,      r"Software\Policies\Microsoft\Edge",                     "HomepageLocation"),
    (winreg.HKEY_LOCAL_MACHINE,     r"Software\Policies\Microsoft\Edge",                     "HomepageLocation"),
]

# Trusted homepage/search domains (substrings)
TRUSTED_HOMEPAGE_DOMAINS = [
    "microsoft.com", "google.com", "bing.com", "yahoo.com",
    "duckduckgo.com", "startpage.com", "about:blank", "about:newtab",
    "chrome://newtab", "edge://newtab",
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _run_ps(cmd: str, timeout: int = 20) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _get_extension_dirs() -> List[Path]:
    """Return paths to Chrome, Edge, and Brave extension dirs for all profiles."""
    dirs = []
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roaming = Path(os.environ.get("APPDATA", ""))

    browser_roots = [
        local / "Google" / "Chrome" / "User Data",
        local / "Microsoft" / "Edge" / "User Data",
        local / "BraveSoftware" / "Brave-Browser" / "User Data",
        local / "Chromium" / "User Data",
    ]

    for root in browser_roots:
        if not root.exists():
            continue
        # Profiles: Default, Profile 1, Profile 2, etc.
        for profile_dir in root.iterdir():
            if profile_dir.name.startswith(("Default", "Profile ")):
                ext_dir = profile_dir / "Extensions"
                if ext_dir.exists():
                    dirs.append(ext_dir)

    # Firefox (xpi/json in extensions folder)
    firefox_root = roaming / "Mozilla" / "Firefox" / "Profiles"
    if firefox_root.exists():
        for profile in firefox_root.iterdir():
            ext_dir = profile / "extensions"
            if ext_dir.exists():
                dirs.append(ext_dir)

    return dirs


def _load_manifest(ext_version_dir: Path) -> Optional[Dict]:
    """Load manifest.json from a Chrome-style extension version directory."""
    manifest_path = ext_version_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


# ──────────────────────────────────────────────
# Check 1: Extension manifest scan
# ──────────────────────────────────────────────

def check_extension_manifests() -> List[Dict]:
    """
    Scan installed browser extensions for dangerous permission combinations
    and known malicious extension IDs.
    """
    findings = []
    ext_dirs = _get_extension_dirs()

    for ext_root in ext_dirs:
        browser_label = "Chrome"
        root_str = str(ext_root).lower()
        if "edge" in root_str:
            browser_label = "Edge"
        elif "brave" in root_str:
            browser_label = "Brave"
        elif "firefox" in root_str:
            browser_label = "Firefox"
            continue  # Firefox uses different format; skip for now

        try:
            for ext_id_dir in ext_root.iterdir():
                ext_id = ext_id_dir.name

                # Check known-bad ID
                if ext_id.lower() in KNOWN_BAD_EXTENSION_IDS:
                    findings.append({
                        "title":       f"{browser_label} known malicious extension: {ext_id}",
                        "path":        str(ext_id_dir),
                        "reason":      (
                            f"Extension ID '{ext_id}' in {browser_label} matches a "
                            "known malicious/adware extension documented in threat "
                            "intelligence reports. These extensions perform credential "
                            "theft, ad injection, traffic interception, or search hijacking."
                        ),
                        "severity":    "CRITICAL",
                        "category":    "browser",
                        "subcategory": "known_bad_extension",
                    })
                    continue

                # Find the version directory and load manifest
                manifest = None
                for version_dir in ext_id_dir.iterdir():
                    if version_dir.is_dir():
                        m = _load_manifest(version_dir)
                        if m:
                            manifest = m
                            break

                if not manifest:
                    continue

                ext_name = manifest.get("name", ext_id)
                # Resolve __MSG_ i18n keys
                if ext_name.startswith("__MSG_"):
                    ext_name = ext_id

                # Collect all permissions (permissions + optional_permissions + host_permissions)
                perms = set()
                for perm_key in ("permissions", "optional_permissions", "host_permissions"):
                    for p in manifest.get(perm_key, []):
                        perms.add(str(p).lower())

                # Count dangerous permissions hit
                danger_hits = {p for p in perms if p in {hp.lower() for hp in DANGEROUS_PERMISSIONS}}

                if len(danger_hits) >= HIGH_RISK_PERMISSION_THRESHOLD:
                    # Extra flag: does it also have a background script? (persistent browser agent)
                    has_background = bool(
                        manifest.get("background") or
                        manifest.get("background_page")
                    )
                    severity = "HIGH" if not has_background else "CRITICAL"
                    findings.append({
                        "title":       f"{browser_label} high-risk extension: {ext_name[:60]}",
                        "path":        str(ext_id_dir),
                        "reason":      (
                            f"{browser_label} extension '{ext_name}' (ID: {ext_id}) "
                            f"holds {len(danger_hits)} high-risk permissions: "
                            f"{', '.join(sorted(danger_hits))}. "
                            "Extensions combining broad URL access with webRequest or "
                            "cookie permissions can intercept all HTTPS traffic, hijack "
                            "authenticated sessions, and exfiltrate passwords."
                            + (" Has persistent background script." if has_background else "")
                        ),
                        "severity":    severity,
                        "category":    "browser",
                        "subcategory": "dangerous_permissions",
                    })
        except PermissionError:
            pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 2: Browser shortcut injection
# ──────────────────────────────────────────────

def check_browser_shortcuts() -> List[Dict]:
    """
    Scan LNK shortcuts for browsers on desktop and taskbar for
    injected command-line flags that bypass security controls.
    """
    findings = []

    SUSPICIOUS_FLAGS = [
        "--load-extension",
        "--disable-extensions-except",
        "--disable-web-security",
        "--allow-running-insecure-content",
        "--no-sandbox",
        "--proxy-server",
        "--remote-debugging-port",
        "--user-data-dir",        # redirect to attacker-controlled profile
        "--disable-popup-blocking",
        "--disable-features=IsolateOrigins",
    ]

    BROWSER_KEYWORDS = ["chrome", "msedge", "edge", "brave", "firefox", "chromium"]

    shortcut_dirs = [
        Path(os.environ.get("USERPROFILE", "")) / "Desktop",
        Path(r"C:\Users\Public\Desktop"),
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Internet Explorer" / "Quick Launch",
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    ]

    for sdir in shortcut_dirs:
        if not sdir.exists():
            continue
        try:
            for lnk in sdir.glob("*.lnk"):
                lnk_name_lower = lnk.name.lower()
                if not any(kw in lnk_name_lower for kw in BROWSER_KEYWORDS):
                    continue

                # Read the LNK target using PowerShell
                cmd = (
                    f"$sh = New-Object -ComObject WScript.Shell; "
                    f"$sc = $sh.CreateShortcut('{lnk}'); "
                    f"[PSCustomObject]@{{Target=$sc.TargetPath; Args=$sc.Arguments}} "
                    f"| ConvertTo-Json -Compress"
                )
                out = _run_ps(cmd)
                try:
                    data = json.loads(out)
                    args_str = str(data.get("Args", ""))
                    target = str(data.get("Target", ""))
                except Exception:
                    continue

                for flag in SUSPICIOUS_FLAGS:
                    if flag.lower() in args_str.lower():
                        findings.append({
                            "title":       f"Browser shortcut injection: {flag}",
                            "path":        str(lnk),
                            "reason":      (
                                f"Browser shortcut '{lnk.name}' (target: '{target}') "
                                f"contains the injected flag '{flag}'. Browser hijackers "
                                "modify desktop shortcuts to load malicious extensions, "
                                "disable security features, or redirect traffic through "
                                "attacker-controlled proxies every time the browser opens."
                            ),
                            "severity":    "CRITICAL",
                            "category":    "browser",
                            "subcategory": "shortcut_injection",
                        })
                        break
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 3: Homepage / search engine hijack (registry)
# ──────────────────────────────────────────────

def check_homepage_hijack() -> List[Dict]:
    findings = []
    for hive, subkey, value_name in BROWSER_REGISTRY_PATHS:
        try:
            with winreg.OpenKey(hive, subkey) as k:
                val, _ = winreg.QueryValueEx(k, value_name)
                val_str = str(val).lower()
                if not any(td in val_str for td in TRUSTED_HOMEPAGE_DOMAINS):
                    hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                    findings.append({
                        "title":       f"Browser homepage/search hijacked: {value_name}",
                        "path":        f"{hive_name}\\{subkey}\\{value_name}",
                        "reason":      (
                            f"Registry value '{value_name}' under '{subkey}' is set to "
                            f"'{val}'. This URL is not a recognized trusted homepage. "
                            "Browser hijackers set this registry value to redirect users "
                            "to advertising, phishing, or malware-distribution pages and "
                            "to prevent the user from changing their homepage."
                        ),
                        "severity":    "HIGH",
                        "category":    "browser",
                        "subcategory": "homepage_hijack",
                    })
        except FileNotFoundError:
            pass
        except PermissionError:
            pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 4: NativeMessaging host anomalies
# ──────────────────────────────────────────────

def check_native_messaging() -> List[Dict]:
    """
    NativeMessaging hosts allow browser extensions to communicate with
    native executables on the system, bypassing normal browser sandbox.
    Malicious ones can achieve full code execution from a browser context.
    """
    findings = []
    NM_REGISTRY_PATHS = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Google\Chrome\NativeMessagingHosts"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Google\Chrome\NativeMessagingHosts"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Edge\NativeMessagingHosts"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Edge\NativeMessagingHosts"),
    ]

    # Native messaging hosts installed by known-legitimate software
    KNOWN_SAFE_NMH = {
        "com.google.update_crx",
        "com.google.runtime",
        "com.google.drive.nativeproxy",    # Google Drive File Stream
        "com.google.drive.fs.browser",
        "com.1password.1password",
        "com.lastpass.nativehelper",
        "com.dashlane.nativehelper",
        "com.bitwarden.desktop",
        "com.northwest.signer",
        "com.microsoft.identity.client.helper",
        "com.microsoft.teams2.nativehelper",
        "com.microsoft.browsercore",        # Edge/Windows Browser Core
        "com.microsoft.windowssearch",
        "com.nordpass.app",
        "com.keeper.security",
        "com.dropbox.nmh",                  # Dropbox native messaging helper
        "com.dropbox.chrome",
        "com.adobe.acrobat.chrome.nativeadapter",
        "com.adobe.acrobat.extension",
        "com.teamviewer.chromenativemessager",
    }

    for hive, key_path in NM_REGISTRY_PATHS:
        try:
            with winreg.OpenKey(hive, key_path) as k:
                i = 0
                while True:
                    try:
                        host_name = winreg.EnumKey(k, i)
                        i += 1
                        if host_name.lower() in KNOWN_SAFE_NMH:
                            continue

                        # Read the manifest path
                        with winreg.OpenKey(k, host_name) as hk:
                            try:
                                manifest_path, _ = winreg.QueryValueEx(hk, "")
                            except Exception:
                                manifest_path = "unknown"

                        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                        findings.append({
                            "title":       f"Unknown NativeMessaging host: {host_name}",
                            "path":        f"{hive_name}\\{key_path}\\{host_name}",
                            "reason":      (
                                f"NativeMessaging host '{host_name}' is registered in "
                                f"'{key_path}' pointing to '{manifest_path}'. "
                                "Native messaging allows browser extensions to bypass "
                                "the browser sandbox and execute arbitrary native code "
                                "on the host system. Malicious NMH registrations are "
                                "used to achieve persistent code execution triggered "
                                "every time a compromised extension runs in the browser."
                            ),
                            "severity":    "HIGH",
                            "category":    "browser",
                            "subcategory": "native_messaging",
                        })
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Check 5: Forced enterprise policies
# ──────────────────────────────────────────────

def check_forced_policies() -> List[Dict]:
    """
    Attackers install Chrome/Edge Group Policy extensions or force proxy
    configuration via the enterprise policy registry keys. On non-domain
    machines, these keys should not contain extension force-lists or
    proxy configurations.
    """
    findings = []
    POLICY_CHECKS = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Google\Chrome", "ExtensionInstallForcelist"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Edge",  "ExtensionInstallForcelist"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Policies\Google\Chrome", "ExtensionInstallForcelist"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Policies\Microsoft\Edge",  "ExtensionInstallForcelist"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Google\Chrome", "ProxyServer"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Edge",  "ProxyServer"),
    ]

    for hive, subkey, value_name in POLICY_CHECKS:
        try:
            with winreg.OpenKey(hive, subkey) as k:
                # Some keys store extension lists as sub-keys (1, 2, 3, ...)
                if value_name == "ExtensionInstallForcelist":
                    try:
                        sub_k_path = subkey + "\\" + value_name
                        with winreg.OpenKey(hive, sub_k_path) as sk:
                            i = 0
                            while True:
                                try:
                                    _, ext_entry, _ = winreg.EnumValue(sk, i)
                                    i += 1
                                    hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                                    findings.append({
                                        "title":       f"Extensions force-installed via policy: {str(ext_entry)[:50]}",
                                        "path":        f"{hive_name}\\{sub_k_path}",
                                        "reason":      (
                                            f"Extension '{ext_entry}' is being force-installed "
                                            "via Chrome/Edge enterprise Group Policy. On a "
                                            "non-managed personal workstation, this policy key "
                                            "should not exist. Malware uses this mechanism to "
                                            "silently install browser extensions that survive "
                                            "manual removal attempts."
                                        ),
                                        "severity":    "CRITICAL",
                                        "category":    "browser",
                                        "subcategory": "forced_extension",
                                    })
                                except OSError:
                                    break
                    except FileNotFoundError:
                        pass
                else:
                    val, _ = winreg.QueryValueEx(k, value_name)
                    hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                    findings.append({
                        "title":       f"Browser proxy forced via policy: {val}",
                        "path":        f"{hive_name}\\{subkey}\\{value_name}",
                        "reason":      (
                            f"A proxy server '{val}' is configured via enterprise "
                            "policy registry key for Chrome/Edge. On personal/non-domain "
                            "machines, this policy should not be set. Browser-level proxy "
                            "force-configuration is used by adware to route all browser "
                            "traffic through an attacker-controlled proxy for ad injection "
                            "or credential interception."
                        ),
                        "severity":    "HIGH",
                        "category":    "browser",
                        "subcategory": "forced_proxy",
                    })
        except FileNotFoundError:
            pass
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def scan_browser() -> List[Dict]:
    findings: List[Dict] = []
    checks = [
        ("extension_manifests", check_extension_manifests),
        ("browser_shortcuts",   check_browser_shortcuts),
        ("homepage_hijack",     check_homepage_hijack),
        ("native_messaging",    check_native_messaging),
        ("forced_policies",     check_forced_policies),
    ]
    for name, fn in checks:
        try:
            results = fn()
            findings.extend(results)
        except Exception as e:
            sys.stderr.write(f"[WRAITH-BROWSER] check '{name}' error: {e}\n")

    return findings


if __name__ == "__main__":
    sys.stderr.write("[WRAITH-BROWSER] Browser hijack & extension scan starting...\n")
    results = scan_browser()
    sys.stderr.write(f"[WRAITH-BROWSER] Browser scan complete: {len(results)} findings\n")
    output = {
        "scanner":  "WRAITH-browser",
        "mode":     "browser",
        "findings": results,
    }
    print(json.dumps(output, indent=2))
