using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using WRAITH.Models;
using WRAITH.Services;

namespace WRAITH.ViewModels;

public class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;
    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    { _execute = execute; _canExecute = canExecute; }
    public bool CanExecute(object? p) => _canExecute?.Invoke(p) ?? true;
    public void Execute(object? p) => _execute(p);
    public event EventHandler? CanExecuteChanged
    {
        add    => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

public class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _running;
    public AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    { _execute = execute; _canExecute = canExecute; }
    public bool CanExecute(object? _) => !_running && (_canExecute?.Invoke() ?? true);
    public async void Execute(object? _)
    {
        _running = true; CommandManager.InvalidateRequerySuggested();
        try { await _execute(); }
        finally { _running = false; CommandManager.InvalidateRequerySuggested(); }
    }
    public event EventHandler? CanExecuteChanged
    {
        add    => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

/// <summary>Async relay command that accepts a typed parameter (e.g. ThreatFinding from data-bound button).</summary>
public class AsyncRelayCommand<T> : ICommand
{
    private readonly Func<T?, Task> _execute;
    private readonly Func<T?, bool>? _canExecute;
    private bool _running;
    public AsyncRelayCommand(Func<T?, Task> execute, Func<T?, bool>? canExecute = null)
    { _execute = execute; _canExecute = canExecute; }
    public bool CanExecute(object? p) => !_running && (_canExecute?.Invoke(p is T t ? t : default) ?? true);
    public async void Execute(object? p)
    {
        _running = true; CommandManager.InvalidateRequerySuggested();
        try { await _execute(p is T t ? t : default); }
        finally { _running = false; CommandManager.InvalidateRequerySuggested(); }
    }
    public event EventHandler? CanExecuteChanged
    {
        add    => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

/// <summary>Single line in the scan log with a colour tag derived from its [PREFIX].</summary>
public sealed class LogEntry
{
    public string Text { get; }
    public string Tag  { get; }   // "ERROR"|"WARN"|"DONE"|"KILLED"|"STOP"|"CANCELLED"|"TRACE"|"LIVE"|"INFO"|"SEP"|"" 
    public LogEntry(string text, string tag = "") { Text = text; Tag = tag; }

    private static readonly (string prefix, string tag)[] _rules =
    [
        ("[ERROR]",     "ERROR"),
        ("[WARN]",      "WARN"),
        ("[KILLED]",    "KILLED"),
        ("[DONE]",      "DONE"),
        ("[STOP]",      "STOP"),
        ("[CANCELLED]", "CANCELLED"),
        ("[TRACE]",     "TRACE"),
        ("[LIVE]",      "LIVE"),
        ("[PATH]",      "INFO"),
        ("[INFO]",      "INFO"),
    ];

    public static LogEntry From(string msg)
    {
        foreach (var (prefix, tag) in _rules)
            if (msg.Contains(prefix)) return new LogEntry(msg, tag);
        if (msg.TrimStart().StartsWith("---")) return new LogEntry(msg, "SEP");
        return new LogEntry(msg, "");
    }
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    // ── Fields ──────────────────────────────────────────────────────────
    private ScanOrchestrator? _orchestrator;
    private CancellationTokenSource? _cts;

    private bool _isScanning;
    private bool _isReady;
    private string _currentPhase = "Awaiting your command...";
    private string _scanPath = System.IO.Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
    private int _eventHours = 72;
    private string _searchText = "";
    private string _severityFilter = "All";
    private string _categoryFilter = "All";
    private string _threatLevel = "UNKNOWN";
    private double _scanProgress;
    private bool _fullScan = true;
    private string _logOutput = "";
    private ThreatFinding? _selectedFinding;
    // ── Sort state ──────────────────────────────────────────────────────
    private string  _sortColumn    = "SEVERITY";
    private bool    _sortAscending = false;
    // ── Incoming-finding / log queue (batched to avoid UI-thread flood) ────
    private readonly ConcurrentQueue<ThreatFinding> _pendingFindings = new();
    private readonly List<string> _pendingLogs = new();
    private readonly object _logLock = new();
    private readonly DispatcherTimer _flushTimer;
    // ── Observable collections ────────────────────────────────────────
    public ObservableCollection<ThreatFinding> AllFindings      { get; } = new();
    public ObservableCollection<ThreatFinding> FilteredFindings { get; } = new();
    public ObservableCollection<LogEntry>      LogEntries       { get; } = new();

    // ── Summary counts ────────────────────────────────────────────────
    private int _critCount, _highCount, _medCount, _lowCount, _infoCount;
    public int CritCount { get => _critCount; private set { _critCount = value; OnPropertyChanged(); } }
    public int HighCount { get => _highCount; private set { _highCount = value; OnPropertyChanged(); } }
    public int MedCount  { get => _medCount;  private set { _medCount  = value; OnPropertyChanged(); } }
    public int LowCount  { get => _lowCount;  private set { _lowCount  = value; OnPropertyChanged(); } }
    public int InfoCount { get => _infoCount; private set { _infoCount = value; OnPropertyChanged(); } }
    public int TotalCount => AllFindings.Count;

    // ── Properties ───────────────────────────────────────────────────
    public bool IsScanning
    {
        get => _isScanning;
        set { _isScanning = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsNotScanning)); }
    }
    public bool IsNotScanning => !_isScanning;

    public bool IsReady
    {
        get => _isReady;
        set { _isReady = value; OnPropertyChanged(); CommandManager.InvalidateRequerySuggested(); }
    }

    public string CurrentPhase
    {
        get => _currentPhase;
        set { _currentPhase = value; OnPropertyChanged(); }
    }

    public string ScanPath
    {
        get => _scanPath;
        set { _scanPath = value; OnPropertyChanged(); }
    }

    public int EventHours
    {
        get => _eventHours;
        set { _eventHours = value; OnPropertyChanged(); }
    }

    public string SearchText
    {
        get => _searchText;
        set { _searchText = value; OnPropertyChanged(); ApplyFilter(); }
    }

    public string SeverityFilter
    {
        get => _severityFilter;
        set { _severityFilter = value; OnPropertyChanged(); ApplyFilter(); }
    }

    public string CategoryFilter
    {
        get => _categoryFilter;
        set { _categoryFilter = value; OnPropertyChanged(); ApplyFilter(); }
    }

    public string ThreatLevel
    {
        get => _threatLevel;
        set { _threatLevel = value; OnPropertyChanged(); }
    }

    private string _osDescription = "Detecting...";
    public string OsDescription
    {
        get => _osDescription;
        set { _osDescription = value; OnPropertyChanged(); }
    }

    public double ScanProgress
    {
        get => _scanProgress;
        set { _scanProgress = value; OnPropertyChanged(); }
    }

    public bool FullScan
    {
        get => _fullScan;
        set { _fullScan = value; OnPropertyChanged(); }
    }

    public string LogOutput
    {
        get => _logOutput;
        set { _logOutput = value; OnPropertyChanged(); }
    }

    public ThreatFinding? SelectedFinding
    {
        get => _selectedFinding;
        set
        {
            _selectedFinding = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanKillProcess));
            CommandManager.InvalidateRequerySuggested();
        }
    }

    public bool CanKillProcess =>
        _selectedFinding?.Pid != null && _selectedFinding.IsLive && !IsScanning;

    // ── Filter Options ─────────────────────────────────────────────────
    public List<string> SeverityOptions { get; } = new()
        { "All", "Critical", "High", "Medium", "Low", "Info" };

    public List<string> CategoryOptions { get; } = new()
    {
        "All", "Persistence", "Yara", "Heuristics", "Events", "Npm", "Processes",
        "Network", "WinSec", "Rootkit", "ADS", "Browser", "Defender", "Credential", "KEV",
        "NativeScan"
    };

    public List<string> LiveFilterOptions { get; } = new()
        { "All", "Live", "Task", "Dead" };

    private string _liveFilter = "All";
    public string LiveFilter
    {
        get => _liveFilter;
        set { _liveFilter = value; OnPropertyChanged(); ApplyFilter(); }
    }

    // ── Commands ───────────────────────────────────────────────────────
    public ICommand StartScanCommand   { get; }
    public ICommand StopScanCommand    { get; }
    public ICommand ClearCommand       { get; }
    public ICommand ExportHtmlCommand  { get; }
    public ICommand ExportCsvCommand   { get; }
    public ICommand ExportJsonCommand  { get; }
    public ICommand KillProcessCommand { get; }
    public ICommand CopyTitleCommand   { get; }
    public ICommand CopyPathCommand    { get; }
    public ICommand CopyCommandLineCommand { get; }
    public ICommand OpenPathCommand { get; }
    public ICommand InspectFindingCommand { get; }
    public ICommand RefreshStatusCommand { get; }
    public ICommand TraceOriginCommand { get; }

    // ── Constructor ───────────────────────────────────────────────────
    public MainViewModel()
    {
        StartScanCommand  = new AsyncRelayCommand(RunScanAsync,   () => !IsScanning && IsReady);
        StopScanCommand   = new RelayCommand(_ => StopScan(),     _ => IsScanning);
        ClearCommand      = new RelayCommand(_ => Clear(),        _ => !IsScanning);
        ExportHtmlCommand = new AsyncRelayCommand(ExportHtmlAsync, () => AllFindings.Count > 0 && !IsScanning);
        ExportCsvCommand  = new AsyncRelayCommand(ExportCsvAsync,  () => AllFindings.Count > 0 && !IsScanning);
        ExportJsonCommand = new AsyncRelayCommand(ExportJsonAsync, () => AllFindings.Count > 0 && !IsScanning);
        KillProcessCommand = new AsyncRelayCommand<ThreatFinding>(
            f => KillProcessAsync(f ?? _selectedFinding),
            f => (f?.Pid ?? _selectedFinding?.Pid) != null && !IsScanning);
        CopyTitleCommand   = new RelayCommand(_ =>
        {
            if (_selectedFinding?.Title != null)
                System.Windows.Clipboard.SetText(_selectedFinding.Title);
        });
        CopyPathCommand    = new RelayCommand(_ =>
        {
            if (!string.IsNullOrEmpty(_selectedFinding?.Path))
                System.Windows.Clipboard.SetText(_selectedFinding.Path);
        });
        CopyCommandLineCommand = new RelayCommand(_ =>
        {
            if (!string.IsNullOrWhiteSpace(_selectedFinding?.CommandLine))
                System.Windows.Clipboard.SetText(_selectedFinding.CommandLine);
        });
        OpenPathCommand = new RelayCommand(_ => OpenSelectedPath());
        InspectFindingCommand = new AsyncRelayCommand<ThreatFinding>(
            f => InspectFindingAsync(f ?? _selectedFinding));
        RefreshStatusCommand = new RelayCommand(_ =>
        {
            if (_selectedFinding != null)
            {
                RefreshFindingStatus(_selectedFinding);
                AppendLog($"[LIVE] PID {_selectedFinding.Pid}: {_selectedFinding.ProcessStatus}");
            }
        });
        TraceOriginCommand = new AsyncRelayCommand<ThreatFinding>(
            f => TraceOriginAsync(f ?? _selectedFinding));

        // Drain pending findings/logs on the UI thread every 150 ms
        _flushTimer = new DispatcherTimer(DispatcherPriority.Background)
            { Interval = TimeSpan.FromMilliseconds(150) };
        _flushTimer.Tick += (_, _) => FlushPendingBatch();
        _flushTimer.Start();
    }

    // ── First-run dependency bootstrap ───────────────────────────────
    /// <summary>
    /// Called once from MainWindow.OnLoaded.  Runs silently in the background and
    /// writes wraith.env.json so that ScanOrchestrator finds Python automatically.
    /// </summary>
    public async Task InitializeAsync()
    {
        var baseDir      = BootstrapService.ResolveBaseDir();
        var bootstrapper = new BootstrapService();
        bootstrapper.LogMessage += msg => AppendLog(msg);
        bootstrapper.OsDetected  += os  => OsDescription = os;

        CurrentPhase = "Checking environment...";
        ThreatLevel  = "UNKNOWN";

        var pythonPath = await bootstrapper.EnsureDependenciesAsync(baseDir);

        if (pythonPath == null)
        {
            CurrentPhase = "Setup required — see log for instructions";
            ThreatLevel  = "UNKNOWN";
        }
        else
        {
            CurrentPhase = "Awaiting your command...";
        }
        IsReady = true;
    }

    // ── Scan execution ────────────────────────────────────────────────
    private async Task RunScanAsync()
    {
        IsScanning    = true;
        ScanProgress  = 0;
        CurrentPhase  = "Casting Expecto Patronum...";
        AllFindings.Clear();
        FilteredFindings.Clear();
        UpdateSummary();
        ThreatLevel = "SCANNING";
        AppendLog("---------------------------------------------------");
        AppendLog("  WRAITH  Expecto Patronum  Scan Started");
        AppendLog($"  Path: {ScanPath}   EventHours: {EventHours}h");
        AppendLog("---------------------------------------------------");

        _cts = new CancellationTokenSource();
        _orchestrator = new ScanOrchestrator();
        // Enqueue — flushed in batches by _flushTimer (no per-finding Dispatcher.Invoke)
        _orchestrator.LogMessage        += msg => { lock (_logLock) _pendingLogs.Add(msg); };
        _orchestrator.FindingDiscovered += f   => _pendingFindings.Enqueue(f);

        var phases = new[]
        {
            "Persistence Check","YARA Scan","Heuristic Scan",
            "Event Log Scan","npm Supply Chain","Process Scan",
            "Network Scan","Windows Security","Rootkit Detection",
            "ADS Scanner","Browser Integrity","Defender Integration",
            "Credential Audit","CISA KEV Check","Native File Scan"
        };
        int step = 0;

        var progress = new Progress<string>(lbl =>
        {
            CurrentPhase = lbl;
            ScanProgress = Math.Min(100, ++step * 100.0 / phases.Length);
        });

        try
        {
            var result = await _orchestrator.RunFullScanAsync(
                ScanPath, EventHours, progress, _cts.Token);

            // Merge any findings not already captured via event
            foreach (var f in result.Findings)
                if (!AllFindings.Contains(f)) { AllFindings.Add(f); }

            UpdateSummary();
            ApplyFilter();

            var lvl = result.Summary.ThreatLevel;
            ThreatLevel  = lvl;
            CurrentPhase = $"Scan complete — Threat level: {lvl}";
            ScanProgress = 100;
            AppendLog($"[DONE] {AllFindings.Count} finding(s) · Threat level: {lvl}");
        }
        catch (OperationCanceledException)
        {
            CurrentPhase = "Scan cancelled";
            AppendLog("[CANCELLED]");
        }
        catch (Exception ex)
        {
            CurrentPhase = $"Error: {ex.Message}";
            AppendLog($"[ERROR] {ex.Message}");
        }
        finally
        {
            try { _orchestrator?.KillAll(); } catch { }
            try { _cts?.Dispose(); } catch { }
            _cts = null;
            IsScanning = false;
        }
    }

    /// <summary>
    /// Called on app exit — cancels any running scan and kills all child processes.
    /// </summary>
    public void Shutdown()
    {
        _cts?.Cancel();
        _orchestrator?.KillAll();
        try { _cts?.Dispose(); } catch { }
        _cts = null;
    }

    private void StopScan()
    {
        _cts?.Cancel();
        _orchestrator?.KillAll();
        CurrentPhase = "Stopping...";
        AppendLog("[STOP] Cancel signal sent and scanner child processes terminated.");
    }

    // ── Kill Process ──────────────────────────────────────────────────
    private async Task KillProcessAsync(ThreatFinding? finding = null)
    {
        finding ??= _selectedFinding;
        if (finding?.Pid == null) return;

        int pid  = finding.Pid.Value;
        var name = finding.Title;

        RefreshFindingStatus(finding);
        if (!finding.IsLive)
        {
            AppendLog($"[INFO] PID {pid} is not currently running.");
            return;
        }

        var confirm = MessageBox.Show(
            $"Terminate process?\n\nPID:   {pid}\nName:  {name}\n\nThis cannot be undone.",
            "WRAITH — Kill Process",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        await Task.Run(() =>
        {
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(pid);
                proc.Kill(entireProcessTree: true);
                try { proc.WaitForExit(3000); } catch { }
                App.Current.Dispatcher.Invoke(() => FinalizeKillResult(finding, pid, name));
            }
            catch (ArgumentException)
            {
                App.Current.Dispatcher.Invoke(() =>
                    AppendLog($"[WARN] PID {pid} not found — process may have already exited."));
                App.Current.Dispatcher.Invoke(() =>
                {
                    finding.IsLive = false;
                    finding.ProcessStatus = "";
                    TouchFinding(finding);
                });
            }
            catch (Exception ex)
            {
                try
                {
                    var psi = new ProcessStartInfo("taskkill", $"/PID {pid} /T /F")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var fallback = Process.Start(psi);
                    fallback?.WaitForExit(5000);
                }
                catch { }

                App.Current.Dispatcher.Invoke(() =>
                {
                    AppendLog($"[WARN] Primary kill failed for PID {pid}: {ex.Message}");
                    FinalizeKillResult(finding, pid, name);
                });
            }
        });
    }

    private void FinalizeKillResult(ThreatFinding finding, int pid, string name)
    {
        RefreshFindingStatus(finding);

        if (!finding.IsLive)
        {
            AppendLog($"[KILLED] PID {pid} — {name}");
            finding.Reason += "  [TERMINATED by WRAITH]";
            finding.ProcessStatus = "";
        }
        else
        {
            AppendLog($"[ERROR] PID {pid} is still LIVE. Process may be protected, re-spawned by a service, or require SYSTEM context.");
        }

        TouchFinding(finding);
        CommandManager.InvalidateRequerySuggested();
    }

    private void RefreshFindingStatus(ThreatFinding finding)
    {
        if (finding.Pid == null)
        {
            finding.IsLive = false;
            finding.ProcessStatus = "";
            return;
        }

        try
        {
            using var proc = Process.GetProcessById(finding.Pid.Value);
            finding.IsLive = !proc.HasExited;
            finding.ProcessStatus = finding.IsLive ? "LIVE" : "";
        }
        catch
        {
            finding.IsLive = false;
            finding.ProcessStatus = "";
        }
    }

    private void TouchFinding(ThreatFinding finding)
    {
        var allIdx = AllFindings.IndexOf(finding);
        if (allIdx >= 0) AllFindings[allIdx] = finding;

        var filteredIdx = FilteredFindings.IndexOf(finding);
        if (filteredIdx >= 0) FilteredFindings[filteredIdx] = finding;

        if (ReferenceEquals(SelectedFinding, finding))
            OnPropertyChanged(nameof(SelectedFinding));

        OnPropertyChanged(nameof(CanKillProcess));
    }

    private void OpenSelectedPath()
    {
        var finding = _selectedFinding;
        if (finding == null) return;

        var candidate = finding.Path;
        if (string.IsNullOrWhiteSpace(candidate))
            candidate = ExtractExecutablePath(finding.CommandLine);

        if (string.IsNullOrWhiteSpace(candidate))
        {
            AppendLog("[PATH] No path available for selected finding.");
            return;
        }

        try
        {
            if (System.IO.File.Exists(candidate))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{candidate}\"") { UseShellExecute = true });
                return;
            }
            if (System.IO.Directory.Exists(candidate))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{candidate}\"") { UseShellExecute = true });
                return;
            }

            AppendLog($"[PATH] Not found on disk: {candidate}");
        }
        catch (Exception ex)
        {
            AppendLog($"[ERROR] Could not open path: {ex.Message}");
        }
    }

    private static string? ExtractExecutablePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var text = commandLine.Trim();

        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            if (end > 1) return text[1..end];
        }

        var exeIdx = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
            return text[..(exeIdx + 4)].Trim();

        return null;
    }

    private async Task InspectFindingAsync(ThreatFinding? finding)
    {
        if (finding == null) return;

        await Task.Run(async () =>
        {
            var lines = new List<string>
            {
                "[INSPECT] ---------------------------------------------------",
                $"[INSPECT] Title: {finding.Title}",
                $"[INSPECT] Category: {finding.Category}/{finding.Subcategory}",
                $"[INSPECT] Severity: {finding.SeverityLabel}",
                $"[INSPECT] Path: {finding.Path}",
                $"[INSPECT] CommandLine: {finding.CommandLine}",
                $"[INSPECT] PID: {(finding.Pid?.ToString() ?? "(none)")}",
                $"[INSPECT] Status: {finding.ProcessStatus}"
            };

            if (finding.Pid is int pid)
            {
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    lines.Add($"[INSPECT] ProcessName: {proc.ProcessName}");
                    lines.Add($"[INSPECT] Started: {proc.StartTime:yyyy-MM-dd HH:mm:ss}");

                    try
                    {
                        var image = proc.MainModule?.FileName;
                        if (!string.IsNullOrWhiteSpace(image))
                            lines.Add($"[INSPECT] ImagePath: {image}");
                    }
                    catch (Exception ex)
                    {
                        lines.Add($"[INSPECT] ImagePath: <access denied: {ex.Message}>");
                    }

                    var svc = await RunCommandCaptureAsync("cmd.exe", $"/c tasklist /svc /FI \"PID eq {pid}\"");
                    if (!string.IsNullOrWhiteSpace(svc))
                    {
                        lines.Add("[INSPECT] tasklist /svc:");
                        lines.AddRange(svc.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                            .Select(x => $"[INSPECT]   {x}"));
                    }
                }
                catch
                {
                    lines.Add("[INSPECT] PID is not currently running.");
                }
            }

            App.Current.Dispatcher.Invoke(() =>
            {
                foreach (var line in lines) AppendLog(line);
            });
        });
    }

        private async Task TraceOriginAsync(ThreatFinding? finding)
        {
                if (finding == null) return;

                var processHint = ExtractProcessHint(finding);
                var portHint = ExtractPortHint(finding);
                var keyword = !string.IsNullOrWhiteSpace(processHint)
                        ? processHint
                        : ExtractExecutablePath(finding.CommandLine) ?? finding.Path;

                if (string.IsNullOrWhiteSpace(keyword))
                {
                        AppendLog("[TRACE] No usable keyword/path found on selected finding.");
                        return;
                }

                AppendLog("[TRACE] ---------------------------------------------------");
                AppendLog($"[TRACE] Finding: {finding.Title}");
                AppendLog($"[TRACE] Keyword: {keyword}");
                if (portHint.HasValue) AppendLog($"[TRACE] Port hint: {portHint.Value}");

                var rawOutput = await RunCommandCaptureAsync("powershell", BuildTracePowerShellArgs(keyword, portHint));
                var jsonText = ExtractJsonObject(rawOutput);

                if (string.IsNullOrWhiteSpace(jsonText))
                {
                        AppendLog("[TRACE] Could not parse trace output. Raw output excerpt:");
                        foreach (var line in SanitizePowerShellOutput(rawOutput)
                                                 .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                                 .Take(10))
                        {
                                AppendLog($"[TRACE]   {line}");
                        }
                        return;
                }

                try
                {
                        using var doc = JsonDocument.Parse(jsonText);
                        var root = doc.RootElement;

                        LogTraceSection(root, "services", "Services");
                        LogTraceSection(root, "tasks", "Scheduled Tasks");
                        LogTraceSection(root, "runKeys", "Run Keys");
                        LogTraceSection(root, "startup", "Startup Folder");
                        LogTraceSection(root, "listeners", "Port Listeners");
                        LogTraceSection(root, "listenerServices", "Services On Listener PID");
                        LogTraceSection(root, "processes", "Processes");
                }
                catch (Exception ex)
                {
                        AppendLog($"[TRACE] Failed to decode trace JSON: {ex.Message}");
                }
        }

        private void LogTraceSection(JsonElement root, string propertyName, string label)
        {
                if (!root.TryGetProperty(propertyName, out var arr) || arr.ValueKind != JsonValueKind.Array)
                        return;

                var items = arr.EnumerateArray().ToList();
                AppendLog($"[TRACE] {label}: {items.Count}");

                foreach (var item in items.Take(5))
                {
                        var parts = new List<string>();
                        foreach (var p in item.EnumerateObject())
                        {
                                if (p.Value.ValueKind == JsonValueKind.Null) continue;
                                var v = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.ToString();
                                if (string.IsNullOrWhiteSpace(v)) continue;
                                parts.Add($"{p.Name}={v}");
                        }

                        if (parts.Count > 0)
                                AppendLog($"[TRACE]   - {string.Join(" | ", parts)}");
                }
        }

        private static string BuildTracePowerShellArgs(string keyword, int? portHint)
        {
                var kw = EscapePowerShellSingleQuoted(keyword);
                var port = portHint?.ToString() ?? "0";

                var script = $@"
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
$kw='{kw}'
$port={port}

$result = [ordered]@{{
    services=@()
    tasks=@()
    runKeys=@()
    startup=@()
    listeners=@()
    listenerServices=@()
    processes=@()
}}

$svc = Get-CimInstance Win32_Service | Where-Object {{
    $_.Name -match [regex]::Escape($kw) -or
    $_.DisplayName -match [regex]::Escape($kw) -or
    $_.PathName -match [regex]::Escape($kw)
}} | Select-Object Name,DisplayName,State,StartMode,ProcessId,PathName
$result.services = @($svc)

$tasks = Get-ScheduledTask | ForEach-Object {{
    [PSCustomObject]@{{
        TaskPath=$_.TaskPath
        TaskName=$_.TaskName
        State=$_.State
        Actions=(($_.Actions | ForEach-Object {{ ($_.Execute + ' ' + $_.Arguments).Trim() }}) -join ' | ')
    }}
}} | Where-Object {{
    $_.TaskName -match [regex]::Escape($kw) -or
    $_.Actions -match [regex]::Escape($kw)
}}
$result.tasks = @($tasks)

$runKeys=@(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$rkHits=@()
foreach($rk in $runKeys){{
    if(-not (Test-Path $rk)){{ continue }}
    $item = Get-ItemProperty -Path $rk
    foreach($prop in $item.PSObject.Properties){{
        if($prop.Name -like 'PS*'){{ continue }}
        $val=[string]$prop.Value
        if($prop.Name -match [regex]::Escape($kw) -or $val -match [regex]::Escape($kw)){{
            $rkHits += [PSCustomObject]@{{ Key=$rk; Name=$prop.Name; Command=$val }}
        }}
    }}
}}
$result.runKeys=@($rkHits)

$startupDirs=@(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
)
$stHits=@()
$wsh = New-Object -ComObject WScript.Shell
foreach($dir in $startupDirs){{
    if(-not (Test-Path $dir)){{ continue }}
    Get-ChildItem -Path $dir -File | ForEach-Object {{
        $target=''; $args=''
        if($_.Extension -ieq '.lnk'){{
            try {{
                $sc=$wsh.CreateShortcut($_.FullName)
                $target=$sc.TargetPath
                $args=$sc.Arguments
            }} catch {{}}
        }}
        $line=($_.FullName + ' ' + $target + ' ' + $args)
        if($line -match [regex]::Escape($kw)){{
            $stHits += [PSCustomObject]@{{ File=$_.FullName; Target=$target; Arguments=$args }}
        }}
    }}
}}
$result.startup=@($stHits)

$procHits = Get-CimInstance Win32_Process | Where-Object {{
    $_.Name -match [regex]::Escape($kw) -or
    $_.ExecutablePath -match [regex]::Escape($kw) -or
    $_.CommandLine -match [regex]::Escape($kw)
}} | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
$result.processes=@($procHits)

if($port -gt 0){{
    $ls = Get-NetTCPConnection -State Listen -LocalPort $port |
        Select-Object LocalAddress,LocalPort,OwningProcess,State
    $result.listeners=@($ls)

    $pids = @($ls | Select-Object -ExpandProperty OwningProcess -Unique)
    if($pids.Count -gt 0){{
        $lsvc = Get-CimInstance Win32_Service | Where-Object {{ $_.ProcessId -in $pids }} |
            Select-Object Name,DisplayName,State,StartMode,ProcessId,PathName
        $result.listenerServices=@($lsvc)
    }}
}}

$result | ConvertTo-Json -Depth 8 -Compress
";

                var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                return $"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}";
        }

        private static string ExtractJsonObject(string output)
        {
                if (string.IsNullOrWhiteSpace(output)) return string.Empty;
                var cleaned = SanitizePowerShellOutput(output);
                var start = cleaned.IndexOf('{');
                var end = cleaned.LastIndexOf('}');
                if (start < 0 || end <= start) return string.Empty;
                return cleaned.Substring(start, end - start + 1);
        }

        private static string SanitizePowerShellOutput(string output)
        {
                var lines = output.Split('\n');
                var filtered = lines.Where(line =>
                        !line.Contains("#< CLIXML", StringComparison.OrdinalIgnoreCase) &&
                        !line.TrimStart().StartsWith("<Objs", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("S=\"progress\"", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("<PR>", StringComparison.OrdinalIgnoreCase));
                return string.Join("\n", filtered);
        }

        private static string EscapePowerShellSingleQuoted(string input) =>
                input.Replace("'", "''");

        private static string ExtractProcessHint(ThreatFinding finding)
        {
                if (!string.IsNullOrWhiteSpace(finding.Path))
                {
                        var arrow = finding.Path.IndexOf('→');
                        if (arrow >= 0 && arrow < finding.Path.Length - 1)
                        {
                                var fromPath = finding.Path[(arrow + 1)..].Trim();
                                if (!string.IsNullOrWhiteSpace(fromPath)) return fromPath;
                        }
                }

                if (!string.IsNullOrWhiteSpace(finding.Title))
                {
                        var m = Regex.Match(finding.Title, @":\s*(?<name>[^:]+?)\s+listening", RegexOptions.IgnoreCase);
                        if (m.Success)
                        {
                                var fromTitle = m.Groups["name"].Value.Trim();
                                if (!string.IsNullOrWhiteSpace(fromTitle)) return fromTitle;
                        }
                }

                return string.Empty;
        }

        private static int? ExtractPortHint(ThreatFinding finding)
        {
                var source = $"{finding.Title} {finding.Reason}";
                var m = Regex.Match(source, @"(?<!\d)(\d{2,5})(?!\d)");
                if (m.Success && int.TryParse(m.Groups[1].Value, out var port) && port is >= 1 and <= 65535)
                        return port;
                return null;
        }

    private static async Task<string> RunCommandCaptureAsync(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        using var proc = Process.Start(psi);
        if (proc == null) return string.Empty;

        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        return string.IsNullOrWhiteSpace(stderr)
            ? stdout
            : $"{stdout}\n{stderr}";
    }

    private void Clear()
    {
        AllFindings.Clear();
        FilteredFindings.Clear();
        LogEntries.Clear();
        LogOutput  = "";
        ThreatLevel = "UNKNOWN";
        CurrentPhase = "Awaiting your command...";
        ScanProgress = 0;
        // Reset backing fields directly so notifications fire once each
        _critCount = _highCount = _medCount = _lowCount = _infoCount = 0;
        OnPropertyChanged(nameof(CritCount));
        OnPropertyChanged(nameof(HighCount));
        OnPropertyChanged(nameof(MedCount));
        OnPropertyChanged(nameof(LowCount));
        OnPropertyChanged(nameof(InfoCount));
        OnPropertyChanged(nameof(TotalCount));
    }

    // ── Batch flush (called by _flushTimer on the UI thread) ──────────────
    private void FlushPendingBatch()
    {
        // Flush log messages first
        string[]? logs = null;
        lock (_logLock)
        {
            if (_pendingLogs.Count > 0)
            {
                logs = _pendingLogs.ToArray();
                _pendingLogs.Clear();
            }
        }
        if (logs != null)
        {
            LogOutput += string.Join(string.Empty, logs.Select(m => m + "\n"));
            foreach (var m in logs) LogEntries.Add(LogEntry.From(m));
        }

        // Flush findings — add directly, check filter incrementally
        if (_pendingFindings.IsEmpty) return;
        bool any = false;
        while (_pendingFindings.TryDequeue(out var f))
        {
            AllFindings.Add(f);
            if (PassesFilter(f)) FilteredFindings.Add(f);
            // Increment backing fields only (no PropertyChanged per finding)
            switch (f.Severity)
            {
                case Severity.Critical: _critCount++; break;
                case Severity.High:     _highCount++; break;
                case Severity.Medium:   _medCount++;  break;
                case Severity.Low:      _lowCount++;  break;
                default:                _infoCount++; break;
            }
            any = true;
        }
        if (any)
        {
            // Fire summary notifications once for the whole batch
            OnPropertyChanged(nameof(CritCount));
            OnPropertyChanged(nameof(HighCount));
            OnPropertyChanged(nameof(MedCount));
            OnPropertyChanged(nameof(LowCount));
            OnPropertyChanged(nameof(InfoCount));
            OnPropertyChanged(nameof(TotalCount));
        }
    }

    /// <summary>Returns true if <paramref name="f"/> passes all active filters.</summary>
    private bool PassesFilter(ThreatFinding f)
    {
        if (_severityFilter != "All" &&
            !f.Severity.ToString().Equals(_severityFilter, StringComparison.OrdinalIgnoreCase))
            return false;
        if (_categoryFilter != "All" &&
            !f.Category.Equals(_categoryFilter, StringComparison.OrdinalIgnoreCase))
            return false;
        if (_liveFilter != "All")
        {
            switch (_liveFilter)
            {
                case "Live" when f.ProcessStatus != "LIVE": return false;
                case "Task" when f.ProcessStatus != "TASK": return false;
                case "Dead" when !string.IsNullOrEmpty(f.ProcessStatus): return false;
            }
        }
        if (!string.IsNullOrWhiteSpace(_searchText))
        {
            var q = _searchText.ToLowerInvariant();
            if (!f.Title.ToLowerInvariant().Contains(q) &&
                !f.Path.ToLowerInvariant().Contains(q) &&
                !f.Reason.ToLowerInvariant().Contains(q))
                return false;
        }
        return true;
    }

    // ── Filtering ─────────────────────────────────────────────────────
    private void ApplyFilter()
    {
        FilteredFindings.Clear();
        foreach (var f in AllFindings)
        {
            if (_severityFilter != "All" &&
                !f.Severity.ToString().Equals(_severityFilter, StringComparison.OrdinalIgnoreCase))
                continue;
            if (_categoryFilter != "All" &&
                !f.Category.Equals(_categoryFilter, StringComparison.OrdinalIgnoreCase))
                continue;
            if (_liveFilter != "All")
            {
                switch (_liveFilter)
                {
                    case "Live" when f.ProcessStatus != "LIVE": continue;
                    case "Task" when f.ProcessStatus != "TASK": continue;
                    case "Dead" when !string.IsNullOrEmpty(f.ProcessStatus): continue;
                }
            }
            if (!string.IsNullOrWhiteSpace(_searchText))
            {
                var q = _searchText.ToLowerInvariant();
                if (!f.Title.ToLowerInvariant().Contains(q) &&
                    !f.Path.ToLowerInvariant().Contains(q) &&
                    !f.Reason.ToLowerInvariant().Contains(q))
                    continue;
            }
            FilteredFindings.Add(f);
        }
        OnPropertyChanged(nameof(TotalCount));
    }

    // ── Sort column ───────────────────────────────────────────────────

    /// <summary>Called by the XAML column header click handler.</summary>
    public void SortBy(string column)
    {
        if (_sortColumn == column)
            _sortAscending = !_sortAscending;
        else
        {
            _sortColumn    = column;
            _sortAscending = column switch
            {
                "Category" => true,
                "Title" => true,
                "Path" => true,
                "Reason" => true,
                "RuleName" => true,
                _ => false
            };
        }

        var sorted = _sortAscending
            ? FilteredFindings.OrderBy(f => GetSortKey(f, column)).ToList()
            : FilteredFindings.OrderByDescending(f => GetSortKey(f, column)).ToList();

        FilteredFindings.Clear();
        foreach (var f in sorted) FilteredFindings.Add(f);
    }

    private static object GetSortKey(ThreatFinding f, string col) => col switch
    {
        "LiveSortKey" => f.LiveSortKey,
        "Severity"    => (int)f.Severity,
        "Pid"         => f.Pid ?? -1,
        "Entropy"     => f.Entropy ?? -1,
        "AnomalyScore"=> f.AnomalyScore,
        "LastRunTime" => f.LastRunTime ?? DateTime.MinValue,
        "Category"    => f.Category,
        "Title"       => f.Title,
        "Path"        => f.Path,
        "Reason"      => f.Reason,
        "RuleName"    => f.RuleName ?? string.Empty,
        _             => f.LiveSortKey
    };

    // ── Summary ───────────────────────────────────────────────────────
    private void UpdateSummary()
    {
        CritCount = AllFindings.Count(f => f.Severity == Severity.Critical);
        HighCount = AllFindings.Count(f => f.Severity == Severity.High);
        MedCount  = AllFindings.Count(f => f.Severity == Severity.Medium);
        LowCount  = AllFindings.Count(f => f.Severity == Severity.Low);
        InfoCount = AllFindings.Count(f => f.Severity == Severity.Info);
        OnPropertyChanged(nameof(TotalCount));
    }

    // ── Logging ───────────────────────────────────────────────────────
    private void AppendLog(string msg)
    {
        LogOutput += msg + "\n";
        LogEntries.Add(LogEntry.From(msg));
    }

    // ── Export ───────────────────────────────────────────────────────
    private ScanResult BuildResult() => new()
    {
        Scanner   = "WRAITH",
        Mode      = "full",
        Timestamp = DateTime.Now,
        Findings  = AllFindings.ToList(),
        Summary   = new ScanSummary
        {
            Total = AllFindings.Count,
            Critical = CritCount, High = HighCount,
            Medium = MedCount,    Low  = LowCount,
            Info   = InfoCount
        }
    };

    private async Task ExportHtmlAsync()
    {
        var path = GetSavePath("html");
        if (path == null) return;
        await Task.Run(() => new ReportExporter().ExportHtml(BuildResult(), path));
        AppendLog($"[EXPORT] HTML saved: {path}");
        RevealInExplorer(path);
    }

    private async Task ExportCsvAsync()
    {
        var path = GetSavePath("csv");
        if (path == null) return;
        await Task.Run(() => new ReportExporter().ExportCsv(BuildResult(), path));
        AppendLog($"[EXPORT] CSV saved: {path}");
        RevealInExplorer(path);
    }

    private async Task ExportJsonAsync()
    {
        var path = GetSavePath("json");
        if (path == null) return;
        await Task.Run(() => new ReportExporter().ExportJson(BuildResult(), path));
        AppendLog($"[EXPORT] JSON saved: {path}");
        RevealInExplorer(path);
    }

    private static string? GetSavePath(string ext)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName         = $"WRAITH_Report_{DateTime.Now:yyyyMMdd_HHmmss}",
            DefaultExt       = $".{ext}",
            Filter           = $"{ext.ToUpperInvariant()} files|*.{ext}|All files|*.*",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            AddExtension     = true
        };
        return dlg.ShowDialog() == true ? dlg.FileName : null;
    }

    private static void RevealInExplorer(string filePath)
    {
        try
        {
            System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{filePath}\"");
        }
        catch { /* non-critical */ }
    }

    // ── INotifyPropertyChanged ────────────────────────────────────────
    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
