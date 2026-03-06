using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace WRAITH.Services;

/// <summary>
/// Runs on first launch (or whenever wraith.env.json has no valid Python path) to:
///  1. Report the Windows version.
///  2. Locate Python 3.10+ (PATH → common dirs → registry).
///  3. If not found, attempt a silent install via winget; fall back to a help message.
///  4. Create a .venv next to the exe.
///  5. pip-install scanner/requirements.txt into that venv.
///  6. Write wraith.env.json so ScanOrchestrator finds everything automatically.
/// </summary>
public sealed class BootstrapService
{
    private Action<string>? _log;
    private Action<string>? _osDetected;
    public event Action<string>? LogMessage  { add => _log        += value; remove => _log        -= value; }
    public event Action<string>? OsDetected  { add => _osDetected += value; remove => _osDetected -= value; }

    private void Log(string msg) => _log?.Invoke($"[{DateTime.Now:HH:mm:ss}] [Setup] {msg}");

    // ── Entry point ────────────────────────────────────────────────────
    /// <summary>
    /// Returns the resolved Python path on success, null if Python could not be found/installed.
    /// </summary>
    public async Task<string?> EnsureDependenciesAsync(string baseDir, CancellationToken ct = default)
    {
        Log($"OS: {GetWindowsDescription()}");
        _osDetected?.Invoke(GetWindowsDescription());

        // ── Fast path: wraith.env.json already points at a valid Python ──
        var envPath   = System.IO.Path.Combine(baseDir, "wraith.env.json");
        var quickPath = ReadPythonFromEnvJson(envPath);
        if (quickPath != null)
        {
            // Still validate the python binary is reachable
            var ver = await GetPythonVersionAsync(quickPath, ct);
            if (ver != null)
            {
                Log($"Already configured — {ver} ({quickPath})");
                return quickPath;
            }
            Log("Cached Python path no longer valid — reconfiguring...");
        }

        // ── 1. Find Python ───────────────────────────────────────────────
        Log("Searching for Python 3.10+...");
        var pythonExe = await FindPythonAsync(ct);

        if (pythonExe == null)
        {
            Log("Python 3.10+ not found. Attempting installation via winget...");
            pythonExe = await TryInstallPythonViaWingetAsync(ct);
        }

        if (pythonExe == null)
        {
            Log("ERROR: Python could not be located or installed automatically.");
            Log("       Please install Python 3.10+ from https://python.org/downloads/");
            Log("       Enable 'Add Python to PATH', then re-launch WRAITH.");
            return null;
        }

        Log($"Python found: {pythonExe}");

        // ── 2. Create / validate venv ────────────────────────────────────
        var venvDir    = System.IO.Path.Combine(baseDir, ".venv");
        var venvPython = System.IO.Path.Combine(venvDir, "Scripts", "python.exe");

        if (!System.IO.File.Exists(venvPython))
        {
            Log("Creating virtual environment...");
            await RunAsync(pythonExe, $"-m venv \"{venvDir}\"", null, ct);
        }

        if (System.IO.File.Exists(venvPython))
        {
            pythonExe = venvPython;
            Log("Virtual environment ready.");
        }

        // ── 3. Upgrade pip silently ──────────────────────────────────────
        await RunAsync(pythonExe, "-m pip install --upgrade pip --quiet", null, ct);

        // ── 4. Install scanner requirements ─────────────────────────────
        // Walk up from baseDir to find scanner/ — handles debug builds where
        // baseDir is bin\Debug\net8.0-windows\ rather than the repo root.
        var scannerDir = FindDirectoryUp(baseDir, "scanner") ?? System.IO.Path.Combine(baseDir, "scanner");
        var reqFile    = System.IO.Path.Combine(scannerDir, "requirements.txt");
        if (System.IO.File.Exists(reqFile))
        {
            Log("Installing scanner packages (first run may take a moment)...");
            var (code, stderr) = await RunAsync(pythonExe,
                $"-m pip install --quiet -r \"{reqFile}\"", null, ct);
            if (code != 0)
                Log($"Warning: Some packages may have failed. YARA scanning might be unavailable. ({stderr.Trim()})");
            else
                Log("Scanner packages installed.");
        }
        else
        {
            Log($"Notice: requirements.txt not found at {reqFile} — skipping package install.");
        }

        // ── 5. Write / update wraith.env.json ────────────────────────────
        try
        {
            // Preserve any existing keys (e.g. abuse_ch_api_key) while updating python + scanner_dir
            Dictionary<string, string> config = new()
            {
                ["python"]      = pythonExe,
                ["scanner_dir"] = scannerDir,
                ["abuse_ch_api_key"] = ""
            };

            if (System.IO.File.Exists(envPath))
            {
                try
                {
                    using var existing = JsonDocument.Parse(System.IO.File.ReadAllText(envPath));
                    foreach (var prop in existing.RootElement.EnumerateObject())
                        if (!config.ContainsKey(prop.Name) && prop.Value.ValueKind == JsonValueKind.String)
                            config[prop.Name] = prop.Value.GetString() ?? "";
                }
                catch { /* ignore parse errors */ }
            }

            System.IO.File.WriteAllText(envPath,
                JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            Log($"Warning: Could not write wraith.env.json — {ex.Message}");
        }

        Log("Environment setup complete. Ready to scan.");
        return pythonExe;
    }

    // ── OS ─────────────────────────────────────────────────────────────
    private static string GetWindowsDescription()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key != null)
            {
                var name  = key.GetValue("ProductName") as string ?? "Windows";
                var build = key.GetValue("CurrentBuildNumber") as string ?? "";
                var ubr   = key.GetValue("UBR")?.ToString() ?? "";
                var arch  = Environment.Is64BitOperatingSystem ? "x64" : "x86";
                // Microsoft kept "Windows 10" in ProductName even for Windows 11.
                // Build 22000+ is Windows 11.
                if (int.TryParse(build, out var buildNum) && buildNum >= 22000)
                    name = name.Replace("Windows 10", "Windows 11");
                var ver = build.Length > 0 ? $" (Build {build}.{ubr})" : "";
                return $"{name}{ver} {arch}";
            }
        }
        catch { /* fallthrough */ }
        return Environment.OSVersion.ToString();
    }

    // ── Python discovery ───────────────────────────────────────────────
    private static async Task<string?> FindPythonAsync(CancellationToken ct)
    {
        // 1. Well-known exe names on PATH
        foreach (var exe in new[] { "python", "python3", "py" })
        {
            var found = await FindOnPathAsync(exe, ct);
            if (found != null) return found;
        }

        // 2. Common installation directories
        var localAppData  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var programFiles  = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var candidates = new List<string>();
        foreach (var ver in new[] { "313", "312", "311", "310" })
        {
            candidates.Add(System.IO.Path.Combine(localAppData, "Programs", "Python", $"Python{ver}", "python.exe"));
            candidates.Add(System.IO.Path.Combine(programFiles,  $"Python{ver}", "python.exe"));
            candidates.Add(System.IO.Path.Combine(programFilesX, $"Python{ver}", "python.exe"));
        }
        // Windows Store stub location (usually opens Store, but check it anyway)
        candidates.Add(System.IO.Path.Combine(localAppData, "Microsoft", "WindowsApps", "python.exe"));
        candidates.Add(System.IO.Path.Combine(localAppData, "Microsoft", "WindowsApps", "python3.exe"));

        foreach (var path in candidates)
        {
            if (!System.IO.File.Exists(path)) continue;
            var v = await GetPythonVersionAsync(path, ct);
            if (v != null) return path;
        }

        // 3. Registry
        return await FindPythonInRegistryAsync(ct);
    }

    private static async Task<string?> FindOnPathAsync(string exe, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo("where", exe)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return null;
            var output = await proc.StandardOutput.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = line.Trim();
                if (!System.IO.File.Exists(candidate)) continue;
                var v = await GetPythonVersionAsync(candidate, ct);
                if (v != null) return candidate;
            }
        }
        catch { /* not on PATH */ }
        return null;
    }

    private static async Task<string?> FindPythonInRegistryAsync(CancellationToken ct)
    {
        var roots   = new[] { Registry.CurrentUser, Registry.LocalMachine };
        var subkeys = new[] { @"SOFTWARE\Python\PythonCore", @"SOFTWARE\WOW6432Node\Python\PythonCore" };

        foreach (var root in roots)
        {
            foreach (var subkey in subkeys)
            {
                try
                {
                    using var key = root.OpenSubKey(subkey);
                    if (key == null) continue;
                    foreach (var ver in key.GetSubKeyNames().OrderByDescending(x => x))
                    {
                        using var vKey = key.OpenSubKey($@"{ver}\InstallPath");
                        if (vKey == null) continue;
                        var installPath = vKey.GetValue("ExecutablePath") as string
                                       ?? vKey.GetValue("") as string;
                        if (string.IsNullOrWhiteSpace(installPath)) continue;
                        var pyExe = installPath.EndsWith("python.exe", StringComparison.OrdinalIgnoreCase)
                            ? installPath
                            : System.IO.Path.Combine(installPath, "python.exe");
                        if (!System.IO.File.Exists(pyExe)) continue;
                        var v = await GetPythonVersionAsync(pyExe, ct);
                        if (v != null) return pyExe;
                    }
                }
                catch { /* registry read failed */ }
            }
        }
        return null;
    }

    /// <summary>Returns "Python X.Y.Z" string if the exe is Python 3.10+ else null.</summary>
    private static async Task<string?> GetPythonVersionAsync(string pythonPath, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo(pythonPath, "--version")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return null;

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(5));

            var stdout = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            var stderr = await proc.StandardError.ReadToEndAsync(timeoutCts.Token);
            await proc.WaitForExitAsync(timeoutCts.Token);

            var text  = (stdout + stderr).Trim();   // "Python 3.12.0"
            var match = System.Text.RegularExpressions.Regex.Match(text, @"Python (\d+)\.(\d+)");
            if (!match.Success) return null;
            int major = int.Parse(match.Groups[1].Value);
            int minor = int.Parse(match.Groups[2].Value);
            return (major > 3 || (major == 3 && minor >= 10)) ? text : null;
        }
        catch { return null; }
    }

    // ── winget install ─────────────────────────────────────────────────
    private async Task<string?> TryInstallPythonViaWingetAsync(CancellationToken ct)
    {
        if (!await IsWingetAvailableAsync(ct))
        {
            Log("winget not available on this system.");
            return null;
        }

        // Try 3.12 first, fall back to 3.11
        foreach (var id in new[] { "Python.Python.3.12", "Python.Python.3.11", "Python.Python.3.10" })
        {
            Log($"Installing {id} via winget...");
            var (code, _) = await RunAsync("winget",
                $"install --id {id} --silent --scope user " +
                "--accept-package-agreements --accept-source-agreements", null, ct);

            if (code == 0 || code == -1978335189 /* WINGET_ERROR_ALREADY_INSTALLED */)
            {
                Log("Installation complete. Locating Python...");
                await Task.Delay(2000, ct); // let installer finalise PATH
                var found = await FindPythonAsync(ct);
                if (found != null) return found;
            }
            Log($"winget returned exit code {code} for {id}.");
        }

        Log("winget install did not succeed.");
        return null;
    }

    private static async Task<bool> IsWingetAvailableAsync(CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo("winget", "--version")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));
            await proc.WaitForExitAsync(cts.Token);
            return proc.ExitCode == 0;
        }
        catch { return false; }
    }

    // ── Helpers ────────────────────────────────────────────────────────
    private static string? ReadPythonFromEnvJson(string envPath)
    {
        if (!System.IO.File.Exists(envPath)) return null;
        try
        {
            using var doc = JsonDocument.Parse(System.IO.File.ReadAllText(envPath));
            if (doc.RootElement.TryGetProperty("python", out var p))
            {
                var path = p.GetString();
                if (!string.IsNullOrWhiteSpace(path) && System.IO.File.Exists(path))
                    return path;
            }
        }
        catch { /* malformed JSON */ }
        return null;
    }

    /// <summary>Runs a process, captures exit code and stderr.</summary>
    private static async Task<(int code, string stderr)> RunAsync(
        string exe, string args, string? workDir, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                WorkingDirectory       = workDir ?? ""
            };
            using var proc = Process.Start(psi);
            if (proc == null) return (-1, "Process failed to start");

            // Drain stdout to avoid deadlocks even though we don't use it
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);
            return (proc.ExitCode, await stderrTask);
        }
        catch (OperationCanceledException) { return (-2, "Cancelled"); }
        catch (Exception ex)               { return (-1, ex.Message); }
    }

    // ── Resolve base dir (same logic as ScanOrchestrator) ─────────────
    public static string ResolveBaseDir()
    {
        var exePath = Environment.ProcessPath
                   ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
        return exePath != null
            ? (System.IO.Path.GetDirectoryName(exePath) ?? AppDomain.CurrentDomain.BaseDirectory)
            : AppDomain.CurrentDomain.BaseDirectory;
    }

    /// <summary>Walk up the directory tree from <paramref name="start"/> until a
    /// sub-directory named <paramref name="name"/> is found.</summary>
    private static string? FindDirectoryUp(string start, string name)
    {
        var dir = new System.IO.DirectoryInfo(start);
        while (dir != null)
        {
            var target = System.IO.Path.Combine(dir.FullName, name);
            if (System.IO.Directory.Exists(target)) return target;
            dir = dir.Parent;
        }
        return null;
    }
}
