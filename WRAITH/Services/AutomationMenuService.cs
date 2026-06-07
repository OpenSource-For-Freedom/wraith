using System.IO;
using System.Diagnostics;
using System.Text.Json;

namespace WRAITH.Services;

public sealed class AutomationMenuService
{
    private readonly string _baseDir;
    private readonly string _automationDir;
    private readonly string _scannerDir;
    private readonly string _envJsonPath;

    public AutomationMenuService()
    {
        // Resolve once and sanitise via Path.GetFullPath so every downstream
        // File.* call sees a value that CodeQL's path-injection rule accepts
        // as cleansed. Computing in properties left the sanitiser invisible
        // to the rule at each leaf site.
        _baseDir       = Path.GetFullPath(BootstrapService.ResolveBaseDir());
        _automationDir = Path.GetFullPath(Path.Combine(_baseDir, "automation"));
        _scannerDir    = Path.GetFullPath(Path.Combine(_baseDir, "scanner"));
        _envJsonPath   = Path.GetFullPath(BootstrapService.GetStableEnvJsonPath());
    }

    private string AutomationDir => _automationDir;
    private string ScannerDir    => _scannerDir;
    private string EnvJsonPath   => _envJsonPath;

    /// <summary>
    /// Resolves the python.exe path baked into wraith.env.json by the bootstrap
    /// step. Scheduled tasks run as SYSTEM (so the user PATH that bootstrap
    /// configured is invisible) and bare `python` resolves to nothing — the
    /// task fires, the scanner never runs, and the menu reports success while
    /// nothing actually happens.
    /// </summary>
    private string ResolvePythonPath()
    {
        var envPath = Path.GetFullPath(EnvJsonPath);
        if (!File.Exists(envPath)) return "python";
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(envPath));
            if (doc.RootElement.TryGetProperty("python", out var p) &&
                p.ValueKind == JsonValueKind.String)
            {
                var raw = p.GetString();
                var normalized = NormalizePathInput(raw);
                if (normalized != null && File.Exists(normalized))
                    return normalized;
            }
        }
        catch { /* fall through to PATH lookup */ }
        return "python";
    }

    /// <summary>
    /// Funnel for paths that come in from outside the binary (env.json on disk,
    /// GUI input). Resolves to an absolute path through Path.GetFullPath, rejects
    /// anything that doesn't end up rooted, and lets CodeQL see that the value
    /// is sanitised before it flows into File.* or ProcessStartInfo.ArgumentList.
    /// </summary>
    private static string? NormalizePathInput(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try
        {
            var full = Path.GetFullPath(raw);
            return Path.IsPathRooted(full) ? full : null;
        }
        catch
        {
            return null;
        }
    }

    // ── User preference persistence ──────────────────────────────────────
    // Tray menu choices are written into the stable env.json so they survive
    // both app restarts and Velopack version bumps. ResyncTasksAsync re-reads
    // them at every launch and re-registers the scheduled tasks against the
    // current install's automation/ + scanner/ paths — that closes the loop
    // where a Velopack update silently invalidates the absolute paths baked
    // into Task Scheduler entries.

    private void MergeEnvJson(Action<Dictionary<string, JsonElement>> mutate)
    {
        try
        {
            var envPath = Path.GetFullPath(EnvJsonPath);
            Directory.CreateDirectory(Path.GetDirectoryName(envPath)!);

            var current = new Dictionary<string, JsonElement>();
            if (File.Exists(envPath))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(envPath));
                    foreach (var p in doc.RootElement.EnumerateObject())
                        current[p.Name] = p.Value.Clone();
                }
                catch { /* tolerate a corrupted file by overwriting */ }
            }

            mutate(current);

            using var ms = new MemoryStream();
            using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
            {
                w.WriteStartObject();
                foreach (var kv in current)
                {
                    w.WritePropertyName(kv.Key);
                    kv.Value.WriteTo(w);
                }
                w.WriteEndObject();
            }
            File.WriteAllBytes(envPath, ms.ToArray());
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[automation] env.json write failed: {ex.Message}");
        }
    }

    private static JsonElement IntElement(int v)
    {
        using var doc = JsonDocument.Parse(v.ToString());
        return doc.RootElement.Clone();
    }
    private static JsonElement BoolElement(bool v)
    {
        using var doc = JsonDocument.Parse(v ? "true" : "false");
        return doc.RootElement.Clone();
    }
    private static JsonElement StringElement(string v)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(v));
        return doc.RootElement.Clone();
    }

    private void WriteAutoScanPreference(int minutes, string scanPath) => MergeEnvJson(d =>
    {
        d["auto_scan_minutes"] = IntElement(minutes);
        d["auto_scan_path"]    = StringElement(scanPath);
    });

    private void ClearAutoScanPreference() => MergeEnvJson(d => d["auto_scan_minutes"] = IntElement(0));

    private void WritePersistencePreference(bool enabled, string scanPath) => MergeEnvJson(d =>
    {
        d["persistence_enabled"]   = BoolElement(enabled);
        d["persistence_scan_path"] = StringElement(scanPath);
    });

    private void ClearPersistencePreference() => MergeEnvJson(d => d["persistence_enabled"] = BoolElement(false));

    /// <summary>
    /// Re-registers any user-enabled scheduled tasks against the current
    /// install's paths. Called once at app launch after BootstrapService
    /// completes, so a Velopack update that moved the install dir doesn't
    /// leave Task Scheduler pointing at a stale app-x.y.z folder.
    /// Idempotent — Register-ScheduledTask -Force overwrites cleanly.
    /// </summary>
    public async Task ResyncTasksAsync()
    {
        var envPath = Path.GetFullPath(EnvJsonPath);
        if (!File.Exists(envPath)) return;

        int autoScanMinutes = 0;
        string autoScanPath = string.Empty;
        bool persistenceEnabled = false;
        string persistenceScanPath = string.Empty;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(envPath));
            var root = doc.RootElement;
            if (root.TryGetProperty("auto_scan_minutes", out var m) && m.ValueKind == JsonValueKind.Number)
                autoScanMinutes = m.GetInt32();
            if (root.TryGetProperty("auto_scan_path", out var ap) && ap.ValueKind == JsonValueKind.String)
                autoScanPath = ap.GetString() ?? string.Empty;
            if (root.TryGetProperty("persistence_enabled", out var pe))
                persistenceEnabled = pe.ValueKind == JsonValueKind.True;
            if (root.TryGetProperty("persistence_scan_path", out var ps) && ps.ValueKind == JsonValueKind.String)
                persistenceScanPath = ps.GetString() ?? string.Empty;
        }
        catch { return; }

        if (autoScanMinutes > 0)
        {
            var path = NormalizePathInput(autoScanPath) ?? "C:\\";
            await SetTimedScanAsync(autoScanMinutes, path);
        }
        if (persistenceEnabled)
        {
            var path = NormalizePathInput(persistenceScanPath) ?? "C:\\";
            await EnablePersistenceListenerAsync(path);
        }
    }

    public async Task<(bool ok, string output)> SetTimedScanAsync(int intervalMinutes, string scanPath)
    {
        var script = Path.Combine(AutomationDir, "Register-WraithTimedScan.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var pythonPath = ResolvePythonPath();
        var result = await RunPowerShellAsync(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
            "-IntervalMinutes", intervalMinutes.ToString(),
            "-ScanPath", scanPath,
            "-Hours", "24",
            "-Mode", "all",
            "-RunAsSystem",
            "-PythonPath", pythonPath,
            "-ScannerDir", ScannerDir);
        if (result.ok) WriteAutoScanPreference(intervalMinutes, scanPath);
        return result;
    }

    public async Task<(bool ok, string output)> DisableTimedScanAsync()
    {
        var script = Path.Combine(AutomationDir, "Unregister-WraithTimedScan.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var result = await RunPowerShellAsync(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script);
        if (result.ok) ClearAutoScanPreference();
        return result;
    }

    public async Task<(bool ok, string output)> EnablePersistenceListenerAsync(string scanPath)
    {
        var script = Path.Combine(AutomationDir, "Register-WraithPersistenceListener.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var pythonPath = ResolvePythonPath();
        var result = await RunPowerShellAsync(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
            "-ScanPath", scanPath,
            "-PollSeconds", "120",
            "-PythonPath", pythonPath,
            "-ScannerDir", ScannerDir);
        if (result.ok) WritePersistencePreference(true, scanPath);
        return result;
    }

    public async Task<(bool ok, string output)> DisablePersistenceListenerAsync()
    {
        var script = Path.Combine(AutomationDir, "Unregister-WraithPersistenceListener.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var result = await RunPowerShellAsync(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script);
        if (result.ok) ClearPersistencePreference();
        return result;
    }

    // Per-argument list rather than a single string so .NET escapes each value
    // independently. The previous string-interpolation form let any quote or
    // shell metacharacter in a path read from env.json (or in scanPath) become
    // an injection point — CodeQL flagged every call site as command injection.
    private static async Task<(bool ok, string output)> RunPowerShellAsync(params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi);
            if (proc == null) return (false, "Failed to start powershell.exe");

            var stdout = await proc.StandardOutput.ReadToEndAsync();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            var output = (stdout + Environment.NewLine + stderr).Trim();
            return (proc.ExitCode == 0, string.IsNullOrWhiteSpace(output) ? "OK" : output);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
