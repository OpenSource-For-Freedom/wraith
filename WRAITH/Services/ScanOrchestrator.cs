using System.Diagnostics;
using System.Text;
using System.Text.Json;
using WRAITH.Models;

namespace WRAITH.Services;

/// <summary>
/// Orchestrates all scan modules: Python YARA/heuristic scanner and C native file scanner.
/// </summary>
public class ScanOrchestrator
{
    private readonly string _scannerDir;
    private readonly string _nativeDir;
    private readonly string _pythonExe;

    public event Action<string>?        LogMessage        { add => _logMessage        += value; remove => _logMessage        -= value; }
    public event Action<ThreatFinding>? FindingDiscovered { add => _findingDiscovered += value; remove => _findingDiscovered -= value; }

    private Action<string>?        _logMessage;
    private Action<ThreatFinding>? _findingDiscovered;

    // Tracks every child process so we can kill them all on shutdown/cancel
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, Process> _activeProcs = new();

    /// <summary>Kill all running child scanner processes immediately.</summary>
    public void KillAll()
    {
        foreach (var kvp in _activeProcs)
        {
            try { if (!kvp.Value.HasExited) kvp.Value.Kill(entireProcessTree: true); } catch { }
            try { kvp.Value.Dispose(); } catch { }
        }
        _activeProcs.Clear();
    }

    public ScanOrchestrator()
    {
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        _scannerDir = FindDirectory(baseDir, "scanner") ?? System.IO.Path.Combine(baseDir, "scanner");
        _nativeDir  = FindDirectory(baseDir, "native")  ?? System.IO.Path.Combine(baseDir, "native");
        _pythonExe  = ResolveVenvPython(baseDir);
    }

    /// <summary>
    /// Reads wraith.env.json (written by WRAITH.ps1) to get the venv python path.
    /// Falls back to system "python" if not found.
    /// </summary>
    private static string ResolveVenvPython(string baseDir)
    {
        var dir = new System.IO.DirectoryInfo(baseDir);
        while (dir != null)
        {
            var cfg = System.IO.Path.Combine(dir.FullName, "wraith.env.json");
            if (System.IO.File.Exists(cfg))
            {
                try
                {
                    using var doc  = JsonDocument.Parse(System.IO.File.ReadAllText(cfg));
                    if (doc.RootElement.TryGetProperty("python", out var p))
                    {
                        var path = p.GetString();
                        if (!string.IsNullOrWhiteSpace(path) && System.IO.File.Exists(path))
                            return path;
                    }
                }
                catch { /* fall through */ }
            }
            dir = dir.Parent;
        }
        return "python"; // system fallback
    }

    private static string? FindDirectory(string start, string name)
    {
        var dir = new System.IO.DirectoryInfo(start);
        while (dir != null)
        {
            var target = System.IO.Path.Combine(dir.FullName, name);
            if (System.IO.Directory.Exists(target)) return target;
            var local = System.IO.Path.Combine(dir.FullName, "local", name);
            if (System.IO.Directory.Exists(local)) return local;
            dir = dir.Parent;
        }
        return null;
    }

    private static string SystemRoot =>
        System.IO.Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";

    private void Log(string msg) => _logMessage?.Invoke($"[{DateTime.Now:HH:mm:ss}] {msg}");

    // ── Python Scanner ────────────────────────────────────────────────────
    public async Task<ScanResult> RunPythonScanAsync(string mode, string? path = null,
        int eventHours = 72, CancellationToken ct = default)
    {
        path ??= SystemRoot;
        Log($"Starting Python scan: mode={mode}");
        var scriptPath = System.IO.Path.Combine(_scannerDir, "scanner.py");

        if (!System.IO.File.Exists(scriptPath))
        {
            Log($"ERROR: Python scanner not found at {scriptPath}");
            return new ScanResult { Error = $"scanner.py not found at {scriptPath}", Mode = mode };
        }

        var rulesDir = System.IO.Path.Combine(_scannerDir, "rules");
        // Prevent a trailing backslash from escaping the closing quote (e.g. "C:\") 
        var safePath  = path.TrimEnd('\\') + @"\\";
        var safeRules = rulesDir.TrimEnd('\\') + @"\\";
        var args     = $"\"{scriptPath}\" --mode={mode} --path=\"{safePath}\" --hours={eventHours} --rules=\"{safeRules}\"";
        return await RunProcessAsync(_pythonExe, args, mode, ct);
    }

    // ── Native C Scanner ──────────────────────────────────────────────────
    public async Task<ScanResult> RunNativeScanAsync(string? path = null,
        bool startupOnly = false, CancellationToken ct = default)
    {
        path ??= SystemRoot;
        Log("Starting native file system scan...");
        var exePath = System.IO.Path.Combine(_nativeDir, "fast_scan.exe");

        if (!System.IO.File.Exists(exePath))
        {
            Log($"Native scanner not found at {exePath}. Attempting build...");
            await BuildNativeScanner(ct);
        }

        if (!System.IO.File.Exists(exePath))
        {
            Log("Native scanner build failed. Skipping native scan.");
            return new ScanResult { Error = "fast_scan.exe not found", Mode = "native" };
        }

        var args = startupOnly ? "--startup" : $"--path=\"{path}\"";
        return await RunProcessAsync(exePath, args, "native", ct);
    }

    private async Task BuildNativeScanner(CancellationToken ct)
    {
        var buildScript = System.IO.Path.Combine(_nativeDir, "build.bat");
        if (!System.IO.File.Exists(buildScript)) return;

        Log("Building native scanner (build.bat)...");
        using var proc = Process.Start(new ProcessStartInfo("cmd.exe", $"/c \"{buildScript}\"")
        {
            WorkingDirectory       = _nativeDir,
            UseShellExecute        = false,
            CreateNoWindow         = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true
        });
        if (proc == null) return;
        await proc.WaitForExitAsync(ct);
        Log(proc.ExitCode == 0 ? "Native scanner built successfully." : "Native scanner build failed.");
    }

    // ── Generic process runner → ScanResult ──────────────────────────────
    private async Task<ScanResult> RunProcessAsync(string exe, string args,
        string mode, CancellationToken ct)
    {
        var sb     = new StringBuilder();
        var result = new ScanResult { Mode = mode, Timestamp = DateTime.Now };

        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding  = Encoding.UTF8
            };

            var proc = new Process { StartInfo = psi };
            proc.OutputDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
            proc.ErrorDataReceived  += (_, e) => { if (e.Data != null) Log($"[STDERR] {e.Data}"); };

            try
            {
                proc.Start();
                _activeProcs.TryAdd(proc.Id, proc);
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                await proc.WaitForExitAsync(ct);

                var json = sb.ToString().Trim();
                if (string.IsNullOrWhiteSpace(json))
                {
                    result.Error = "No output from scanner process";
                }
                else
                {
                    ParseScanJson(json, result);
                }
            }
            catch (OperationCanceledException)
            {
                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { }
                result.Error = "Scan cancelled";
            }
            finally
            {
                _activeProcs.TryRemove(proc.Id, out _);
                proc.Dispose();
            }
        }
        catch (OperationCanceledException)
        {
            result.Error = "Scan cancelled";
        }
        catch (Exception ex)
        {
            Log($"ERROR running {exe}: {ex.Message}");
            result.Error = ex.Message;
        }

        Log($"Scan '{mode}' complete: {result.Findings.Count} findings, {result.Summary.Critical} critical");
        return result;
    }

    private void ParseScanJson(string json, ScanResult result)
    {
        try
        {
            using var doc  = JsonDocument.Parse(json);
            var root        = doc.RootElement;

            result.Scanner = root.TryGetProperty("scanner", out var s) ? s.GetString() ?? "" : "";
            result.Error   = root.TryGetProperty("error",   out var e) ? e.GetString() : null;

            if (root.TryGetProperty("findings", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in arr.EnumerateArray())
                {
                    var finding = ParseFinding(item);
                    result.Findings.Add(finding);
                    _findingDiscovered?.Invoke(finding);
                }
            }

            if (root.TryGetProperty("summary", out var sum))
            {
                result.Summary.Total    = sum.TryGetProperty("total",    out var t) ? t.GetInt32() : 0;
                result.Summary.Critical = sum.TryGetProperty("critical", out var c) ? c.GetInt32() : 0;
                result.Summary.High     = sum.TryGetProperty("high",     out var h) ? h.GetInt32() : 0;
                result.Summary.Medium   = sum.TryGetProperty("medium",   out var m) ? m.GetInt32() : 0;
                result.Summary.Low      = sum.TryGetProperty("low",      out var l) ? l.GetInt32() : 0;
            }
            else
            {
                result.Summary.Total    = result.Findings.Count;
                result.Summary.Critical = result.Findings.Count(f => f.Severity == Severity.Critical);
                result.Summary.High     = result.Findings.Count(f => f.Severity == Severity.High);
                result.Summary.Medium   = result.Findings.Count(f => f.Severity == Severity.Medium);
                result.Summary.Low      = result.Findings.Count(f => f.Severity == Severity.Low);
            }
        }
        catch (JsonException ex)
        {
            result.Error = $"JSON parse error: {ex.Message}. Snippet: {json[..Math.Min(200, json.Length)]}";
        }
    }

    private static ThreatFinding ParseFinding(JsonElement item)
    {
        string? Get(string key)    => item.TryGetProperty(key, out var v) ? v.GetString() : null;
        int?  GetInt(string key)   => item.TryGetProperty(key, out var v) && v.TryGetInt32(out var n)  ? n : null;
        double? GetDbl(string key) => item.TryGetProperty(key, out var v) && v.TryGetDouble(out var d) ? d : null;

        var finding = new ThreatFinding
        {
            Title          = Get("title")   ?? Get("rule") ?? "Unknown Finding",
            Path           = Get("path")    ?? "",
            Reason         = Get("reason")  ?? Get("detail") ?? "",
            Category       = Get("category")    ?? "",
            Subcategory    = Get("subcategory") ?? "",
            Severity       = ThreatFinding.ParseSeverity(Get("severity")),
            RuleName       = Get("rule"),
            CommandLine    = Get("cmdline")  ?? Get("action"),
            MessagePreview = Get("message_preview"),
            Pid            = GetInt("pid"),
            EventLog       = Get("log"),
            EventId        = GetInt("event_id"),
            Entropy        = GetDbl("entropy"),
            AnomalyScore   = GetDbl("anomaly_score") ?? 0,
            Package        = Get("package"),
            Version        = Get("version"),
        };

        if (finding.AnomalyScore <= 0)
        {
            finding.AnomalyScore = finding.Severity switch
            {
                Severity.Critical => 85,
                Severity.High => 65,
                Severity.Medium => 45,
                Severity.Low => 25,
                _ => 10
            };
            if (finding.Entropy.HasValue)
                finding.AnomalyScore = Math.Min(100, finding.AnomalyScore + Math.Max(0, (finding.Entropy.Value - 6.0) * 5));
        }

        // Populate live-process fields
        var pid = finding.Pid;
        if (pid.HasValue)
        {
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(pid.Value);
                finding.IsLive        = !proc.HasExited;
                finding.ProcessStatus = finding.IsLive ? "LIVE" : "TASK";
                if (finding.IsLive)
                    finding.LastRunTime = proc.StartTime;
            }
            catch
            {
                // Process not found — was live when detected but exited already
                finding.IsLive        = false;
                finding.ProcessStatus = "TASK";
            }
        }

        // Parse last_run from Python output if provided
        if (item.TryGetProperty("last_run", out var lr) && lr.ValueKind == JsonValueKind.String)
        {
            if (DateTime.TryParse(lr.GetString(), out var dt))
            {
                if (dt.Year >= 2005)
                    finding.LastRunTime ??= dt;
            }
        }

        return finding;
    }

    // ── Full scan: runs all modules in sequence ───────────────────────────
    public async Task<ScanResult> RunFullScanAsync(string? scanPath = null,
        int eventHours = 72, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        scanPath ??= SystemRoot;
        var combined = new ScanResult
        {
            Scanner   = "WRAITH Full Scan",
            Mode      = "all",
            Timestamp = DateTime.Now
        };

        var steps = new (string label, Func<Task<ScanResult>> func)[]
        {
            ("Persistence Check",    () => RunPythonScanAsync("persistence", scanPath, eventHours, ct)),
            ("YARA Scan",            () => RunPythonScanAsync("yara",        scanPath, eventHours, ct)),
            ("Heuristic Scan",       () => RunPythonScanAsync("heuristics",  scanPath, eventHours, ct)),
            ("Event Log Scan",       () => RunPythonScanAsync("events",      scanPath, eventHours, ct)),
            ("npm Supply Chain",     () => RunPythonScanAsync("npm",         scanPath, eventHours, ct)),
            ("Process Scan",         () => RunPythonScanAsync("processes",   scanPath, eventHours, ct)),
            ("Network Scan",         () => RunPythonScanAsync("network",     scanPath, eventHours, ct)),
            ("Windows Security",     () => RunPythonScanAsync("winsec",      scanPath, eventHours, ct)),
            ("Rootkit Detection",    () => RunPythonScanAsync("rootkit",     scanPath, eventHours, ct)),
            ("ADS Scanner",          () => RunPythonScanAsync("ads",         scanPath, eventHours, ct)),
            ("Browser Integrity",    () => RunPythonScanAsync("browser",     scanPath, eventHours, ct)),
            ("Defender Integration", () => RunPythonScanAsync("defender",    scanPath, eventHours, ct)),
            ("Credential Audit",     () => RunPythonScanAsync("credential",  scanPath, eventHours, ct)),
            ("CISA KEV Check",       () => RunPythonScanAsync("kev",         scanPath, eventHours, ct)),
            ("Native File Scan",     () => RunNativeScanAsync(scanPath, ct: ct)),
        };

        foreach (var (label, func) in steps)
        {
            if (ct.IsCancellationRequested) break;
            progress?.Report(label);
            Log($"Running: {label}");
            try
            {
                var r = await func();
                combined.Findings.AddRange(r.Findings);
                if (r.Error != null) Log($"Warning: {label} — {r.Error}");
            }
            catch (Exception ex)
            {
                Log($"ERROR in {label}: {ex.Message}");
            }
        }

        combined.Summary.Total    = combined.Findings.Count;
        combined.Summary.Critical = combined.Findings.Count(f => f.Severity == Severity.Critical);
        combined.Summary.High     = combined.Findings.Count(f => f.Severity == Severity.High);
        combined.Summary.Medium   = combined.Findings.Count(f => f.Severity == Severity.Medium);
        combined.Summary.Low      = combined.Findings.Count(f => f.Severity == Severity.Low);
        combined.Summary.Info     = combined.Findings.Count(f => f.Severity == Severity.Info);

        return combined;
    }
}
