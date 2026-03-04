"""
WRAITH — Main Scanner Entry Point
Called by ScanOrchestrator.cs as:
  python scanner.py --mode=<mode> --path=<path> --hours=<n> --rules=<dir>

Modes: persistence | yara | heuristics | events | npm | processes |
       network | winsec | rootkit | ads | browser | defender | credential | kev | all
Output: single JSON blob to stdout.
"""

import argparse
import json
import sys
import os
import traceback
from pathlib import Path
from typing import List, Dict, Any

# ── Output builder ────────────────────────────────────────────────────────
def emit(findings: List[Dict], mode: str, error: str | None = None) -> None:
    findings = assign_anomaly_scores(findings)
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    summary = {
        "total":    len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high":     sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium":   sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low":      sum(1 for f in findings if f.get("severity") == "LOW"),
        "info":     sum(1 for f in findings if f.get("severity") == "INFO"),
    }
    out: Dict[str, Any] = {
        "scanner": f"WRAITH-{mode}",
        "mode": mode,
        "summary": summary,
        "findings": sorted(findings, key=lambda f: sev_rank.get(f.get("severity","INFO"), 0), reverse=True),
    }
    if error:
        out["error"] = error
    print(json.dumps(out, default=str))


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def compute_anomaly_score(f: Dict[str, Any]) -> float:
    severity_base = {
        "CRITICAL": 70.0,
        "HIGH": 52.0,
        "MEDIUM": 34.0,
        "LOW": 18.0,
        "INFO": 8.0,
    }

    category_weight = {
        "network": 12.0,
        "processes": 11.0,
        "persistence": 10.0,
        "heuristics": 10.0,
        "yara": 9.0,
        "rootkit": 9.0,
        "credential": 8.0,
        "events": 6.0,
        "defender": 5.0,
        "winsec": 5.0,
        "npm": 5.0,
        "ads": 4.0,
        "browser": 4.0,
        "kev": 4.0,
    }

    subcategory_weight = {
        "bind_shell": 18.0,
        "suspicious_listener": 16.0,
        "c2_port": 14.0,
        "suspicious_outbound": 14.0,
        "pe_anomaly": 16.0,
        "suspicious_string": 12.0,
        "high_entropy": 10.0,
        "double_extension": 8.0,
        "suspicious_cmdline": 13.0,
        "suspicious_name": 12.0,
        "service": 11.0,
        "scheduled_task": 10.0,
        "registry_run": 8.0,
    }

    sev = str(f.get("severity", "INFO")).upper()
    category = str(f.get("category", "")).lower()
    sub = str(f.get("subcategory", "")).lower()
    reason = str(f.get("reason", "")).lower()
    title = str(f.get("title", "")).lower()

    score = severity_base.get(sev, 8.0)
    score += category_weight.get(category, 0.0)
    score += subcategory_weight.get(sub, 0.0)

    if f.get("rule"):
        score += 6.0
    if f.get("pid"):
        score += 4.0

    entropy = _to_float(f.get("entropy"), 0.0)
    if entropy > 0:
        score += _clamp((entropy - 6.2) * 7.5, 0.0, 16.0)

    if any(k in reason or k in title for k in ("openclaw", "metaquest", "oculus")):
        score += 8.0
    if any(k in reason or k in title for k in ("inject", "shell", "beacon", "backdoor", "c2")):
        score += 8.0

    return round(_clamp(score), 2)


def assign_anomaly_scores(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for f in findings:
        existing = _to_float(f.get("anomaly_score"), -1.0)
        computed = compute_anomaly_score(f)
        f["anomaly_score"] = round(max(existing, computed) if existing >= 0 else computed, 2)
    return findings


def log(msg: str) -> None:
    print(f"[WRAITH] {msg}", file=sys.stderr)


# ── Mode: persistence ─────────────────────────────────────────────────────
def scan_persistence(path: str) -> List[Dict]:
    """Checks registry run keys, startup folders, scheduled tasks, services."""
    findings: List[Dict] = []
    import subprocess, re

    # ── Registry run keys ────────────────────────────────────────────────
    run_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    for key in run_keys:
        try:
            r = subprocess.run(["reg", "query", key], capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("HKEY"): continue
                parts = stripped.split(None, 2)
                if len(parts) < 3: continue
                name, _, value = parts[0], parts[1], parts[2]
                sev = "LOW"
                reason = f"Registry autorun: {key}\\{name}"
                # Elevate suspicious entries
                lower_val = value.lower()
                if any(x in lower_val for x in ["temp\\","tmp\\","appdata\\roaming","downloads\\","powershell -","wscript","mshta","cscript","regsvr32","rundll32 c:\\"]):
                    sev = "HIGH"
                elif any(x in lower_val for x in ["openclaw","metaquest","oculus","ovrservice","airlink"]):
                    sev = "CRITICAL"
                    reason = f"SUSPICIOUS autorun (openclaw/Meta Quest related): {value}"
                findings.append({
                    "title":       f"Autorun: {name}",
                    "path":        value,
                    "reason":      reason,
                    "severity":    sev,
                    "category":    "persistence",
                    "subcategory": "registry_run",
                })
        except Exception as e:
            log(f"Registry key {key} error: {e}")

    # ── Startup folders ───────────────────────────────────────────────────
    startup_dirs = [
        os.path.join(os.environ.get("APPDATA",""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    ]
    for sd in startup_dirs:
        if not os.path.isdir(sd): continue
        for item in Path(sd).iterdir():
            if item.name.lower() == "desktop.ini": continue
            sev = "MEDIUM"
            lower = item.name.lower()
            if any(x in lower for x in ["openclaw","metaquest","oculus","airlink","ovrservice"]):
                sev = "CRITICAL"
            findings.append({
                "title":       f"Startup item: {item.name}",
                "path":        str(item),
                "reason":      f"File in startup folder: {sd}",
                "severity":    sev,
                "category":    "persistence",
                "subcategory": "startup_folder",
            })

    # ── Scheduled tasks ───────────────────────────────────────────────────
    try:
        ps = r"""
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object {
  $info = Get-ScheduledTaskInfo -TaskPath $_.TaskPath -TaskName $_.TaskName -ErrorAction SilentlyContinue
    $lrt = ''
    $lrtSource = ''

    if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -ge 2005) {
        $lrt = $info.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss')
        $lrtSource = 'last_run'
    }

    if (-not $lrt) {
        try {
            [xml]$taskXml = $_.Xml
            $regRaw = $taskXml.Task.RegistrationInfo.Date
            if ($regRaw) {
                $reg = [DateTime]::Parse($regRaw)
                if ($reg.Year -ge 2005) {
                    $lrt = $reg.ToString('yyyy-MM-dd HH:mm:ss')
                    $lrtSource = 'registered'
                }
            }
        } catch {}
    }

  [PSCustomObject]@{
    TaskName    = $_.TaskName
    TaskPath    = $_.TaskPath
    Action      = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | '
    LastRunTime = $lrt
        LastRunSource = $lrtSource
  }
} | ConvertTo-Json -Depth 2
"""
        r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command", ps],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0 and r.stdout.strip():
            tasks = json.loads(r.stdout)
            if isinstance(tasks, dict): tasks = [tasks]
            for t in (tasks or []):
                action = (t.get("Action") or "").lower()
                name   = t.get("TaskName","")
                sev = "INFO"
                reason = f"Scheduled task active: {t.get('TaskPath','')}{name}"
                if any(x in action for x in ["temp\\","tmp\\","appdata\\roaming","powershell -enc","mshta","wscript","cscript","curl","wget","bitsadmin","certutil"]):
                    sev = "HIGH"
                    reason = f"Suspicious scheduled task command: {action[:200]}"
                elif any(x in action+name.lower() for x in ["openclaw","metaquest","oculus","ovrservice","airlink"]):
                    sev = "CRITICAL"
                    reason = f"SUSPICIOUS task (openclaw/Meta Quest related): {action[:200]}"
                elif any(x in action for x in ["powershell","cmd","wscript","cscript"]):
                    sev = "LOW"
                if sev != "INFO":
                    f = {
                        "title":       f"Scheduled Task: {name}",
                        "path":        t.get("TaskPath",""),
                        "reason":      reason,
                        "severity":    sev,
                        "category":    "persistence",
                        "subcategory": "scheduled_task",
                        "cmdline":     t.get("Action","")[:300],
                    }
                    lrt = t.get("LastRunTime","")
                    if lrt:
                        f["last_run"] = lrt
                        if t.get("LastRunSource") == "registered":
                            f["reason"] += " (showing task registration date; scheduler last-run was unavailable/invalid)"
                    findings.append(f)
    except Exception as e:
        log(f"Scheduled task scan error: {e}")

    # ── Services ──────────────────────────────────────────────────────────
    try:
        ps2 = r"""
Get-CimInstance Win32_Service | Where-Object {$_.StartMode -in @('Auto','Manual') -and $_.State -eq 'Running'} |
  Select-Object Name,DisplayName,PathName,StartMode,ProcessId |
  ConvertTo-Json -Depth 2
"""
        r2 = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command", ps2],
                            capture_output=True, text=True, timeout=30)
        if r2.returncode == 0 and r2.stdout.strip():
            svcs = json.loads(r2.stdout)
            if isinstance(svcs, dict): svcs = [svcs]
            for svc in (svcs or []):
                pname = (svc.get("PathName") or "").lower()
                name  = svc.get("Name","")
                svc_pid = svc.get("ProcessId") or None
                sev = "INFO"
                reason = ""
                if any(x in pname+name.lower() for x in ["openclaw","metaquest","oculus","ovrservice","airlink"]):
                    sev = "HIGH"
                    reason = f"Service related to openclaw/Meta Quest: {svc.get('PathName','')}"
                elif any(x in pname for x in ["\\temp\\","\\tmp\\","\\downloads\\","\\appdata\\roaming\\"]):
                    sev = "HIGH"
                    reason = f"Service binary in suspicious path: {svc.get('PathName','')}"
                if sev != "INFO":
                    f = {
                        "title":       f"Service: {svc.get('DisplayName', name)}",
                        "path":        svc.get("PathName",""),
                        "reason":      reason,
                        "severity":    sev,
                        "category":    "persistence",
                        "subcategory": "service",
                    }
                    if svc_pid and int(svc_pid) > 0:
                        f["pid"] = int(svc_pid)
                    findings.append(f)
    except Exception as e:
        log(f"Service scan error: {e}")

    return findings


# ── Mode: yara ────────────────────────────────────────────────────────────
def scan_yara(path: str, rules_dir: str) -> List[Dict]:
    try:
        import yara_scanner
        result = yara_scanner.scan_yara(path, rules_dir)
        return result.get("findings", [])
    except ImportError:
        log("yara_scanner module missing")
        return []
    except Exception as e:
        log(f"YARA scan error: {e}")
        return []


# ── Mode: heuristics ──────────────────────────────────────────────────────
def scan_heuristics(path: str) -> List[Dict]:
    try:
        import heuristics
        result = heuristics.scan_heuristics(path)
        return result.get("findings", [])
    except ImportError:
        log("heuristics module missing")
        return []
    except Exception as e:
        log(f"Heuristic scan error: {e}")
        return []


# ── Mode: events ──────────────────────────────────────────────────────────
def scan_events(hours: int) -> List[Dict]:
    try:
        import event_parser
        result = event_parser.scan_events(hours)
        return result.get("findings", [])
    except ImportError:
        log("event_parser module missing")
        return []
    except Exception as e:
        log(f"Event scan error: {e}")
        return []


# ── Mode: npm ────────────────────────────────────────────────────────────
def scan_npm() -> List[Dict]:
    try:
        import npm_check
        result = npm_check.scan_npm()
        return result.get("findings", [])
    except ImportError:
        log("npm_check module missing")
        return []
    except Exception as e:
        log(f"npm scan error: {e}")
        return []


# ── Mode: processes ───────────────────────────────────────────────────────
def scan_processes() -> List[Dict]:
    try:
        import process_scanner
        result = process_scanner.scan_processes()
        return result.get("findings", [])
    except ImportError:
        log("process_scanner module missing")
        return []
    except Exception as e:
        log(f"Process scan error: {e}")
        return []


# ── Mode: network ─────────────────────────────────────────────────────────
def scan_network_module() -> List[Dict]:
    try:
        import network_scanner
        return network_scanner.scan_network()
    except ImportError:
        log("network_scanner module missing")
        return []
    except Exception as e:
        log(f"Network scan error: {e}")
        return []


# ── Mode: winsec ──────────────────────────────────────────────────────────
def scan_winsec_module() -> List[Dict]:
    try:
        import winsec_scanner
        return winsec_scanner.scan_winsec()
    except ImportError:
        log("winsec_scanner module missing")
        return []
    except Exception as e:
        log(f"Windows security scan error: {e}")
        return []


# ── Mode: rootkit ─────────────────────────────────────────────────────────
def scan_rootkit_module() -> List[Dict]:
    try:
        import rootkit_scanner
        return rootkit_scanner.scan_rootkit()
    except ImportError:
        log("rootkit_scanner module missing")
        return []
    except Exception as e:
        log(f"Rootkit scan error: {e}")
        return []


# ── Mode: ads ────────────────────────────────────────────────────────────
def scan_ads_module() -> List[Dict]:
    try:
        import ads_scanner
        return ads_scanner.scan_ads()
    except ImportError:
        log("ads_scanner module missing")
        return []
    except Exception as e:
        log(f"ADS scan error: {e}")
        return []


# ── Mode: browser ─────────────────────────────────────────────────────────
def scan_browser_module() -> List[Dict]:
    try:
        import browser_scanner
        return browser_scanner.scan_browser()
    except ImportError:
        log("browser_scanner module missing")
        return []
    except Exception as e:
        log(f"Browser scan error: {e}")
        return []


# ── Mode: defender ────────────────────────────────────────────────────────
def scan_defender_module() -> List[Dict]:
    try:
        import wdefender_integration
        return wdefender_integration.scan_defender()
    except ImportError:
        log("wdefender_integration module missing")
        return []
    except Exception as e:
        log(f"Defender scan error: {e}")
        return []


# ── Mode: credential ──────────────────────────────────────────────────────
def scan_credential_module() -> List[Dict]:
    try:
        import credential_scanner
        return credential_scanner.scan_credentials()
    except ImportError:
        log("credential_scanner module missing")
        return []
    except Exception as e:
        log(f"Credential scan error: {e}")
        return []


# ── Mode: kev ─────────────────────────────────────────────────────────────
def scan_kev_module() -> List[Dict]:
    try:
        import cisa_kev_scanner
        return cisa_kev_scanner.scan_cisa_kev()
    except ImportError:
        log("cisa_kev_scanner module missing")
        return []
    except Exception as e:
        log(f"CISA KEV scan error: {e}")
        return []


# ── Entry point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WRAITH Scanner")
    parser.add_argument("--mode",  default="all",  help="Scan mode")
    parser.add_argument("--path",  default=r"C:\\", help="Scan root path")
    parser.add_argument("--hours", type=int, default=72, help="Event log lookback hours")
    parser.add_argument("--rules", default="rules", help="YARA rules directory")
    args = parser.parse_args()

    mode      = args.mode.lower()
    scan_path = args.path
    hours     = args.hours
    rules_dir = args.rules

    log(f"WRAITH scanner starting: mode={mode} path={scan_path} hours={hours}")

    findings: List[Dict] = []
    error: str | None    = None

    try:
        if mode == "persistence":
            findings = scan_persistence(scan_path)
        elif mode == "yara":
            findings = scan_yara(scan_path, rules_dir)
        elif mode == "heuristics":
            findings = scan_heuristics(scan_path)
        elif mode == "events":
            findings = scan_events(hours)
        elif mode == "npm":
            findings = scan_npm()
        elif mode == "processes":
            findings = scan_processes()
        elif mode == "network":
            findings = scan_network_module()
        elif mode == "winsec":
            findings = scan_winsec_module()
        elif mode == "rootkit":
            findings = scan_rootkit_module()
        elif mode == "ads":
            findings = scan_ads_module()
        elif mode == "browser":
            findings = scan_browser_module()
        elif mode == "defender":
            findings = scan_defender_module()
        elif mode == "credential":
            findings = scan_credential_module()
        elif mode == "kev":
            findings = scan_kev_module()
        elif mode == "all":
            findings += scan_persistence(scan_path)
            findings += scan_yara(scan_path, rules_dir)
            findings += scan_heuristics(scan_path)
            findings += scan_events(hours)
            findings += scan_npm()
            findings += scan_processes()
            findings += scan_network_module()
            findings += scan_winsec_module()
            findings += scan_rootkit_module()
            findings += scan_ads_module()
            findings += scan_browser_module()
            findings += scan_defender_module()
            findings += scan_credential_module()
            findings += scan_kev_module()
        else:
            error = f"Unknown mode: {mode}"
    except Exception as e:
        error = f"Unhandled error in mode '{mode}': {e}\n{traceback.format_exc()}"
        log(error)

    emit(findings, mode, error)


if __name__ == "__main__":
    # Ensure scanner/ directory is on the path so sibling modules import cleanly
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
