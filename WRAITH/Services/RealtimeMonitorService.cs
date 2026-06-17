using System.IO;

namespace WRAITH.Services;

/// <summary>A real-time autostart-location change worth surfacing to the user.</summary>
public sealed record RealtimeEvent(string Path, string Reason, DateTime DetectedUtc);

/// <summary>
/// Lightweight always-on watcher for the highest-signal persistence locations —
/// the per-user and all-users Startup folders, where dropped executables and
/// scripts auto-run at logon. New or modified files there fire <see cref="Detected"/>
/// in near real time, so WRAITH can alert (and optionally trigger a targeted scan)
/// the moment something installs itself, instead of only at the next full scan.
///
/// This is deliberately narrow: Startup folders are flat, low-churn, and almost
/// never written by anything benign at runtime, so the false-positive/noise cost
/// is tiny compared with watching, say, %TEMP% or the whole disk.
/// </summary>
public sealed class RealtimeMonitorService : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly Dictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private readonly TimeSpan _debounce;

    /// <summary>Raised (off the UI thread) when a watched location changes.</summary>
    public event Action<RealtimeEvent>? Detected;

    public bool IsRunning { get; private set; }

    public RealtimeMonitorService(TimeSpan? debounce = null)
    {
        // FileSystemWatcher commonly fires several events for one logical write
        // (Created + Changed + Changed). Collapse them per-path.
        _debounce = debounce ?? TimeSpan.FromSeconds(2);
    }

    /// <summary>
    /// The autostart folders to watch — current user's Startup and the all-users
    /// Startup. Only paths that exist are returned, de-duplicated.
    /// </summary>
    public static IReadOnlyList<string> DefaultWatchPaths()
    {
        var candidates = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };

        return candidates
            .Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Starts watching. Pass explicit paths (tests use a temp dir); defaults to
    /// the autostart folders. Safe to call when already running (no-op).
    /// </summary>
    public void Start(IEnumerable<string>? paths = null)
    {
        lock (_sync)
        {
            if (IsRunning) return;

            var watchList = (paths ?? DefaultWatchPaths())
                .Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p))
                .ToList();

            foreach (var dir in watchList)
            {
                var w = new FileSystemWatcher(dir)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true,
                };
                w.Created += OnChanged;
                w.Changed += OnChanged;
                w.Renamed += OnRenamed;
                _watchers.Add(w);
            }

            IsRunning = _watchers.Count > 0;
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            foreach (var w in _watchers)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch { /* best-effort */ }
            }
            _watchers.Clear();
            _recent.Clear();
            IsRunning = false;
        }
    }

    private void OnChanged(object sender, FileSystemEventArgs e) =>
        Report(e.FullPath, "New or modified file in an autostart location");

    private void OnRenamed(object sender, RenamedEventArgs e) =>
        Report(e.FullPath, "File renamed into an autostart location");

    private void Report(string path, string reason)
    {
        if (!ShouldReport(path, DateTime.UtcNow)) return;

        // Directory entries and our own transient temp files aren't interesting.
        try { if (Directory.Exists(path)) return; } catch { /* fall through */ }

        Detected?.Invoke(new RealtimeEvent(path, reason, DateTime.UtcNow));
    }

    /// <summary>
    /// Debounce gate: returns true only when this path hasn't already been
    /// reported within the debounce window. Pure and deterministic (caller
    /// supplies the clock) so the collapsing behaviour is unit-testable.
    /// </summary>
    public bool ShouldReport(string path, DateTime nowUtc)
    {
        lock (_sync)
        {
            if (_recent.TryGetValue(path, out var last) && nowUtc - last < _debounce)
                return false;

            _recent[path] = nowUtc;

            // Opportunistic cleanup so the map can't grow without bound.
            if (_recent.Count > 512)
            {
                var cutoff = nowUtc - _debounce;
                foreach (var stale in _recent.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    _recent.Remove(stale);
            }

            return true;
        }
    }

    public void Dispose() => Stop();
}
