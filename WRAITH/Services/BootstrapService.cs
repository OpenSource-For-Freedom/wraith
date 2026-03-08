using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace WRAITH.Services;

/// <summary>Progress states reported by <see cref="BootstrapService.StepProgress"/>.</summary>
public enum SetupStepStatus { Pending, Running, Done, Skipped, Error }

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

    /// <summary>
    /// Fired when a setup step changes state: (stepIndex 0-4, status, detail).
    /// Subscribers must marshal to the UI thread if needed.
    /// </summary>
    public event Action<int, SetupStepStatus, string>? StepProgress;
    private void ReportStep(int idx, SetupStepStatus status, string detail = "")
        => StepProgress?.Invoke(idx, status, detail);

    /// <summary>
    /// Optional owner window for the PATH confirmation dialog.
    /// Set this before calling EnsureDependenciesAsync so the dialog is
    /// properly parented and cannot appear behind other windows.
    /// </summary>
    public System.Windows.Window? DialogOwner { get; set; }

    /// <summary>
    /// Returns true when setup needs to run: either no valid Python is configured
    /// yet, or the user has not yet confirmed the PATH step.
    /// </summary>
    public static bool IsFirstRun(string baseDir)
    {
        var envPath = System.IO.Path.Combine(baseDir, "wraith.env.json");
        return ReadPythonFromEnvJson(envPath) == null || !IsPathConfirmed(envPath);
    }

    private static readonly string _diagLog = System.IO.Path.Combine(
        System.IO.Path.GetTempPath(), "wraith-setup.log");

    // Secondary log in the exe directory — readable from non-elevated terminals.
    private static string? _localLog;

    private void Log(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] [Setup] {msg}";
        _log?.Invoke(line);
        try { System.IO.File.AppendAllText(_diagLog, line + "\n"); } catch { }
        try { if (_localLog != null) System.IO.File.AppendAllText(_localLog, line + "\n"); } catch { }
    }

    /// <summary>Set a second log path that is always readable (e.g. the exe directory).</summary>
    public static void SetLocalLogPath(string path) => _localLog = path;

    // Static log for methods that don't have a BootstrapService instance (e.g. FindPythonAsync).
    private static void DiagLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] {msg}";
        try { System.IO.File.AppendAllText(_diagLog, line + "\n"); } catch { }
        try { if (_localLog != null) System.IO.File.AppendAllText(_localLog, line + "\n"); } catch { }
    }

    // ── Entry point ────────────────────────────────────────────────────
    /// <summary>
    /// Returns the resolved Python path on success, null if Python could not be found/installed.
    /// </summary>
    public async Task<string?> EnsureDependenciesAsync(string baseDir, CancellationToken ct = default)
    {
        ReportStep(0, SetupStepStatus.Running, "Detecting OS...");
        var osDesc = GetWindowsDescription();
        Log($"OS: {osDesc}");
        _osDetected?.Invoke(osDesc);
        ReportStep(0, SetupStepStatus.Done, osDesc);

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
                // Always confirm PATH before fast-returning.
                // Use base_python (the real install) for the PATH dialog, not the venv.
                if (!IsPathConfirmed(envPath))
                {
                    var basePython = ReadBasePythonFromEnvJson(envPath) ?? quickPath;
                    await EnsurePythonOnPathAsync(basePython, envPath, ct);
                }
                else
                    ReportStep(2, SetupStepStatus.Skipped, "PATH already confirmed");
                ReportStep(3, SetupStepStatus.Skipped, ".venv already configured");
                ReportStep(4, SetupStepStatus.Skipped, "packages already installed");
                return quickPath;
            }
            Log("Cached Python path no longer valid — reconfiguring...");
        }

        // ── 1. Find Python ───────────────────────────────────────────────
        ReportStep(1, SetupStepStatus.Running, "Searching for Python...");
        var isWin11 = IsWindows11OrLater();
        Log(isWin11
            ? "Searching for Python (preferring 3.14/3.13 for Windows 11)..."
            : "Searching for Python (preferring 3.12/3.11 for Windows 10)...");
        var pythonExe = await FindPythonAsync(ct);

        if (pythonExe == null)
        {
            Log("Python not found. Attempting installation via winget...");
            ReportStep(1, SetupStepStatus.Running, "Installing via winget...");
            pythonExe = await TryInstallPythonViaWingetAsync(ct);
        }

        if (pythonExe == null)
        {
            ReportStep(1, SetupStepStatus.Error, "Could not install Python");
            Log("ERROR: Python could not be located or installed automatically.");
            Log("       Please install Python 3.10+ from https://python.org/downloads/");
            Log("       Enable 'Add Python to PATH', then re-launch WRAITH.");
            return null;
        }

        var pyVer = await GetPythonVersionAsync(pythonExe, ct) ?? "Python";
        ReportStep(1, SetupStepStatus.Done, pyVer);
        Log($"Python found: {pythonExe}");
        var pythonExeBase = pythonExe;   // save real python before possible venv replacement
        await EnsurePythonOnPathAsync(pythonExe, envPath, ct);

        // ── 2. Create / validate venv ────────────────────────────────────
        ReportStep(3, SetupStepStatus.Running, "Creating virtual environment...");
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
            ReportStep(3, SetupStepStatus.Done, ".venv ready");
        }
        else
        {
            ReportStep(3, SetupStepStatus.Done, "Using system Python");
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
            ReportStep(4, SetupStepStatus.Running, "Installing scanner packages...");
            Log("Installing scanner packages (first run may take a moment)...");
            // --prefer-binary: use pre-built wheels when available; avoids long
            // source builds (e.g. yara-python) on machines without a C compiler.
            // CancellationTokenSource caps the install at 3 minutes.
            using var pipCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            pipCts.CancelAfter(TimeSpan.FromMinutes(3));
            var (code, stderr) = await RunAsync(pythonExe,
                $"-m pip install --quiet --prefer-binary -r \"{reqFile}\"", null, pipCts.Token);
            if (code != 0)
            {
                ReportStep(4, SetupStepStatus.Error, "Some packages failed — YARA may be unavailable");
                Log($"Warning: Some packages may have failed. YARA scanning might be unavailable. ({stderr.Trim()})");
            }
            else
            {
                ReportStep(4, SetupStepStatus.Done, "All packages installed");
                Log("Scanner packages installed.");
            }
        }
        else
        {
            ReportStep(4, SetupStepStatus.Skipped, "requirements.txt not found");
            Log($"Notice: requirements.txt not found at {reqFile} — skipping package install.");
        }

        // ── 5. Write / update wraith.env.json ────────────────────────────
        try
        {
            // Preserve any existing keys (e.g. abuse_ch_api_key) while updating python + scanner_dir.
            // Store the venv python for scanner use; track the base python separately so the
            // PATH confirmation isn't re-triggered on every launch.
            Dictionary<string, string> config = new()
            {
                ["python"]       = pythonExe,        // venv python (or base if venv failed)
                ["base_python"]  = pythonExeBase,    // real Python install — PATH check target
                ["scanner_dir"]  = scannerDir,
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

            // Re-stamp path_confirmed — the base WriteAllText above uses string dict and
            // drops boolean flags.  WritePathConfirmed merges it back correctly.
            WritePathConfirmed(envPath);
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

    private static bool IsWindows11OrLater()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key != null)
            {
                var build = key.GetValue("CurrentBuildNumber") as string ?? "";
                return int.TryParse(build, out var b) && b >= 22000;
            }
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Returns ordered winget IDs and directory name suffixes for the most
    /// secure Python compatible with this OS.
    /// Windows 11 → 3.14 / 3.13; Windows 10 / Server → 3.12 / 3.11 / 3.10.
    /// </summary>
    private static (string[] wingetIds, string[] dirSuffixes) GetPreferredPythonTargets()
    {
        // For winget install we still prefer the latest stable for each OS.
        // For directory probing (FindPythonAsync) we prefer 3.12 first even on Win11
        // because all scanner packages (yara-python, pywin32, etc.) have pre-built
        // binary wheels for cp312; 3.14 wheels may not exist yet.
        if (IsWindows11OrLater())
            return (new[] { "Python.Python.3.14", "Python.Python.3.13", "Python.Python.3.12" },
                    new[] { "312", "313", "314" });   // probe 3.12 first
        return (new[] { "Python.Python.3.12", "Python.Python.3.11", "Python.Python.3.10" },
                new[] { "312", "311", "310" });
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

        var (_, dirSuffixes) = GetPreferredPythonTargets();
        var programFiles  = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        // 2. Build candidate list:
        //    a) current user's LocalAppData (may differ when running elevated as admin)
        //    b) every profile under C:\Users\  (covers Python installed by non-admin users)
        //    c) system-wide ProgramFiles installs
        var localAppDataDirs = new List<string>();
        var currentLocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        localAppDataDirs.Add(currentLocalAppData);

        // Enumerate all sibling profiles so an elevated admin process can still find
        // Python installed under the invoking user's profile.
        try
        {
            var usersRoot = System.IO.Path.GetDirectoryName(  // C:\Users
                System.IO.Path.GetDirectoryName(currentLocalAppData) // strip \AppData\Local
                ?? "C:\\Users") ?? "C:\\Users";
            // Also try the direct parent of all profiles: C:\Users
            var usersDir = @"C:\Users";
            if (System.IO.Directory.Exists(usersDir))
            {
                foreach (var profile in System.IO.Directory.GetDirectories(usersDir))
                {
                    var lad = System.IO.Path.Combine(profile, "AppData", "Local");
                    if (!string.Equals(lad, currentLocalAppData, StringComparison.OrdinalIgnoreCase)
                        && System.IO.Directory.Exists(lad))
                        localAppDataDirs.Add(lad);
                }
            }
        }
        catch { /* enumerate best-effort */ }

        var candidates = new List<string>();
        foreach (var lad in localAppDataDirs)
        {
            DiagLog($"[FindPython] probing LocalAppData: {lad}");
            foreach (var ver in dirSuffixes)
                candidates.Add(System.IO.Path.Combine(lad, "Programs", "Python", $"Python{ver}", "python.exe"));
            candidates.Add(System.IO.Path.Combine(lad, "Microsoft", "WindowsApps", "python.exe"));
            candidates.Add(System.IO.Path.Combine(lad, "Microsoft", "WindowsApps", "python3.exe"));
        }
        foreach (var ver in dirSuffixes)
        {
            candidates.Add(System.IO.Path.Combine(programFiles,  $"Python{ver}", "python.exe"));
            candidates.Add(System.IO.Path.Combine(programFilesX, $"Python{ver}", "python.exe"));
        }

        foreach (var path in candidates)
        {
            var exists = System.IO.File.Exists(path);
            if (!exists) continue;
            DiagLog($"[FindPython] exists=True {path}");
            var v = await GetPythonVersionAsync(path, ct);
            DiagLog($"[FindPython] version={v ?? "null"} for {path}");
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

        var (wingetIds, _) = GetPreferredPythonTargets();
        foreach (var id in wingetIds)
        {
            Log($"Installing {id} via winget...");
            var (code, _) = await RunAsync("winget",
                $"install --id {id} --silent --scope user " +
                "--accept-package-agreements --accept-source-agreements", null, ct);

            if (code == 0 || code == -1978335189 /* WINGET_ERROR_ALREADY_INSTALLED */)
            {
                Log("Installation complete. Refreshing PATH and locating Python...");
                // Reload the running-process PATH from registry so FindPythonAsync
                // can discover the newly installed Python without a restart.
                var machinePath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
                var userPathNow = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User)  ?? "";
                Environment.SetEnvironmentVariable("PATH", userPathNow + ";" + machinePath);
                await Task.Delay(2000, ct); // let installer finalise file handles
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

    /// <summary>Returns the real Python install (not the venv) stored in wraith.env.json.</summary>
    private static string? ReadBasePythonFromEnvJson(string envPath)
    {
        if (!System.IO.File.Exists(envPath)) return null;
        try
        {
            using var doc = JsonDocument.Parse(System.IO.File.ReadAllText(envPath));
            if (doc.RootElement.TryGetProperty("base_python", out var p))
            {
                var path = p.GetString();
                if (!string.IsNullOrWhiteSpace(path) && System.IO.File.Exists(path))
                    return path;
            }
        }
        catch { }
        return null;
    }

    private static bool IsPathConfirmed(string envPath)
    {
        if (!System.IO.File.Exists(envPath)) return false;
        try
        {
            using var doc = JsonDocument.Parse(System.IO.File.ReadAllText(envPath));
            return doc.RootElement.TryGetProperty("path_confirmed", out var v)
                   && v.ValueKind == JsonValueKind.True;
        }
        catch { return false; }
    }

    private static void WritePathConfirmed(string envPath)
    {
        try
        {
            var config = new Dictionary<string, object> { ["path_confirmed"] = true };
            if (System.IO.File.Exists(envPath))
            {
                try
                {
                    using var existing = JsonDocument.Parse(System.IO.File.ReadAllText(envPath));
                    foreach (var prop in existing.RootElement.EnumerateObject())
                        if (prop.Value.ValueKind == JsonValueKind.String)
                            config[prop.Name] = prop.Value.GetString() ?? "";
                }
                catch { }
            }
            System.IO.File.WriteAllText(envPath,
                JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
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

    /// <summary>
    /// Prepends the Python install directory and its Scripts\ subfolder to the
    /// current user's persistent PATH.  Always shows a WRAITH-styled confirmation
    /// dialog directly on the UI thread — no delegate, no race condition.
    /// </summary>
    private async Task EnsurePythonOnPathAsync(string pythonExe, string envPath, CancellationToken ct)
    {
        ReportStep(2, SetupStepStatus.Running, "Checking PATH...");
        try
        {
            var pythonDir     = System.IO.Path.GetDirectoryName(pythonExe) ?? "";
            var pythonScripts = System.IO.Path.Combine(pythonDir, "Scripts");

            // Read PATH from the invoking user's hive (not the elevated admin account).
            var userPath = ReadUserPathViaInvokingUser()
                        ?? Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User)
                        ?? "";
            var parts = userPath.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList();

            bool alreadyPresent = parts.Any(p => string.Equals(
                p.TrimEnd('\\'), pythonDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));

            var version = await GetPythonVersionAsync(pythonExe, ct) ?? pythonExe;

            // ── Show confirmation dialog on the WPF dispatcher ───────────────
            bool approved = false;
            Application.Current.Dispatcher.Invoke(() =>
            {
                var dlg = new PathConfirmDialog(version, pythonDir, alreadyPresent);
                // Set owner so the dialog is properly parented and always on top
                if (DialogOwner != null)
                    dlg.Owner = DialogOwner;
                dlg.WindowStartupLocation = DialogOwner != null
                    ? System.Windows.WindowStartupLocation.CenterOwner
                    : System.Windows.WindowStartupLocation.CenterScreen;
                dlg.Topmost = (DialogOwner == null);   // only use Topmost if no owner
                Log($"Showing PATH dialog (owner={(DialogOwner?.GetType().Name ?? "none")})");
                approved = dlg.ShowDialog() == true;
            });

            // Record that the user was asked, regardless of answer
            WritePathConfirmed(envPath);

            if (!approved)
            {
                Log("PATH update skipped — user declined.");
                ReportStep(2, SetupStepStatus.Skipped, "Declined by user");
                return;
            }

            if (alreadyPresent)
            {
                Log("Python directory already on PATH — confirmed by user.");
                ReportStep(2, SetupStepStatus.Done, "Already on PATH");
                return;
            }

            foreach (var dir in new[] { pythonDir, pythonScripts })
            {
                if (string.IsNullOrEmpty(dir)) continue;
                if (!parts.Any(p => string.Equals(p.TrimEnd('\\'), dir.TrimEnd('\\'),
                                                   StringComparison.OrdinalIgnoreCase)))
                    parts.Insert(0, dir);
            }

            var newUserPath = string.Join(";", parts);

            // Write to the invoking user's PATH, not the elevated account's.
            // When WRAITH runs elevated (requireAdministrator), the process token is
            // the admin account, so EnvironmentVariableTarget.User would update admin's
            // PATH rather than the user who launched WRAITH.  We use the linked token's
            // SID (the original non-elevated user) to open the correct registry hive.
            WriteUserPathViaInvokingUser(newUserPath, Log);

            // Also update the live process PATH so subsequent child Process.Start calls find python
            var procPath = Environment.GetEnvironmentVariable("PATH") ?? "";
            Environment.SetEnvironmentVariable("PATH", newUserPath + ";" + procPath);
            Log($"Python added to PATH: {pythonDir}");
            ReportStep(2, SetupStepStatus.Done, pythonDir);
        }
        catch (Exception ex)
        {
            Log($"PATH step error: {ex.GetType().Name}: {ex.Message}");
            ReportStep(2, SetupStepStatus.Error, "PATH update failed");
        }
    }

    // ── Invoking-user registry PATH helpers ────────────────────────────
    // When WRAITH runs with requireAdministrator, the process identity is the
    // elevated admin account.  These helpers use the linked (original) token's
    // SID to open the correct HKEY_USERS\<SID>\Environment hive so PATH is
    // written to the user who actually launched WRAITH, not the admin account.

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool ConvertSidToStringSid(IntPtr pSID, out string strSid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint TOKEN_QUERY        = 0x0008;
    private const uint TokenLinkedToken   = 19;
    private const uint TokenUser          = 1;

    /// <summary>
    /// Returns the SID string of the user who invoked this process (before elevation).
    /// Falls back to the current process token's user SID if the linked token is unavailable.
    /// </summary>
    private static string? GetInvokingUserSid()
    {
        try
        {
            // Try to get the linked (non-elevated) token first
            if (OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY, out var token))
            {
                try
                {
                    uint sz = (uint)IntPtr.Size;
                    var buf = Marshal.AllocHGlobal((int)sz);
                    try
                    {
                        if (GetTokenInformation(token, TokenLinkedToken, buf, sz, out _))
                        {
                            var linkedToken = Marshal.ReadIntPtr(buf);
                            var sid = GetSidFromToken(linkedToken);
                            CloseHandle(linkedToken);
                            if (sid != null) return sid;
                        }
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
                finally { CloseHandle(token); }
            }
        }
        catch { }

        // Fallback: current token's SID (works for non-elevated or same-user elevation)
        try
        {
            return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        }
        catch { return null; }
    }

    private static string? GetSidFromToken(IntPtr token)
    {
        try
        {
            GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out uint sz);
            var buf = Marshal.AllocHGlobal((int)sz);
            try
            {
                if (!GetTokenInformation(token, TokenUser, buf, sz, out _)) return null;
                var sidPtr = Marshal.ReadIntPtr(buf); // TOKEN_USER.User.Sid
                ConvertSidToStringSid(sidPtr, out var sidStr);
                return sidStr;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { return null; }
    }

    private static string? ReadUserPathViaInvokingUser()
    {
        try
        {
            var sid = GetInvokingUserSid();
            if (sid == null) return null;
            using var key = Registry.Users.OpenSubKey($@"{sid}\Environment", writable: false);
            return key?.GetValue("Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        }
        catch { return null; }
    }

    private static void WriteUserPathViaInvokingUser(string newPath, Action<string> log)
    {
        try
        {
            var sid = GetInvokingUserSid();
            if (sid == null)
            {
                // Fallback: write via standard API (works if not elevated or same user)
                Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User);
                log("PATH written via standard API (SID lookup failed).");
                return;
            }
            using var key = Registry.Users.OpenSubKey($@"{sid}\Environment", writable: true);
            if (key == null)
            {
                Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User);
                log("PATH written via standard API (registry key not writable).");
                return;
            }
            key.SetValue("Path", newPath, RegistryValueKind.ExpandString);
            log($"PATH written to HKEY_USERS\\{sid}\\Environment.");
        }
        catch (Exception ex)
        {
            // Last resort
            try { Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User); } catch { }
            log($"PATH write fallback used: {ex.Message}");
        }
    }
}
