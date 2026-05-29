using System.Windows;
using System.Reflection;
using System.Threading;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using Velopack;
using Velopack.Sources;

namespace WRAITH.Services;

/// <summary>
/// Silently checks GitHub Releases for a newer version of WRAITH, downloads it in the
/// background, and fires <see cref="UpdateDownloaded"/> on the UI thread when ready.
/// Call <see cref="ApplyAndRestart"/> to apply the downloaded update.
/// </summary>
public static class UpdateService
{
    private const string RepoUrl = "https://github.com/OpenSource-For-Freedom/wraith";

    /// <summary>Public link to the latest release — surfaced when auto-apply is unavailable.</summary>
    public const string ReleasesUrl = RepoUrl + "/releases/latest";
    private static readonly SemaphoreSlim _checkGate = new(1, 1);
    private static readonly string _logDir = Path.GetFullPath(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WRAITH", "Logs"));
    private static readonly string _logFile = Path.Combine(_logDir, "wraith-update.log");

    /// <summary>
    /// Fired on the UI thread when an update has been fully downloaded.
    /// Parameters: (currentVersion, newVersion, changelog, isInstalled)
    /// </summary>
    public static event Action<string, string, string, bool>? UpdateDownloaded;

    /// <summary>True when running as a Velopack-installed build (not from source).</summary>
    public static bool IsInstalled => _mgr?.IsInstalled ?? false;

    private static UpdateManager? _mgr;
    private static UpdateInfo?    _pendingUpdate;
    /// <summary>
    /// Version we've already fired <see cref="UpdateDownloaded"/> for in this session.
    /// Prevents duplicate auto-popups when the check runs more than once per launch.
    /// </summary>
    private static string? _lastNotifiedVersion;

    private static void Trace(string msg)
    {
        try
        {
            Directory.CreateDirectory(_logDir);
            File.AppendAllText(_logFile, $"[{DateTime.Now:HH:mm:ss.fff}] {msg}\n");
        }
        catch
        {
            // Never throw from logging.
        }
    }

    public static async Task CheckForUpdatesAsync()
    {
        await _checkGate.WaitAsync();
        try
        {
            Trace("CheckForUpdatesAsync: begin");
            _mgr = new UpdateManager(new GithubSource(RepoUrl, null, false));
            var installed = _mgr.IsInstalled;
            Trace($"CheckForUpdatesAsync: IsInstalled={installed}");

            _pendingUpdate = await WithRetryAsync(
                () => _mgr.CheckForUpdatesAsync(),
                "CheckForUpdatesAsync");

            if (_pendingUpdate == null)
            {
                Trace("CheckForUpdatesAsync: no update");
                return;
            }

            var newVersion = _pendingUpdate.TargetFullRelease.Version.ToString();

            // Skip if we already surfaced this version earlier in the session — the
            // title-bar "UPDATE READY" button stays visible from the first prompt,
            // so the user already has a path back into the dialog if they dismissed it.
            if (string.Equals(_lastNotifiedVersion, newVersion, StringComparison.Ordinal))
            {
                Trace($"CheckForUpdatesAsync: version {newVersion} already notified, skipping");
                return;
            }

            // Only download the payload when we can actually apply it.
            // Portable (zip + START.bat) builds report IsInstalled=false; downloading
            // the nupkg would waste 50+ MB for an apply that can never run.
            if (installed)
            {
                await WithRetryAsync(
                    () => _mgr.DownloadUpdatesAsync(_pendingUpdate),
                    "DownloadUpdatesAsync");
                Trace("CheckForUpdatesAsync: payload downloaded");
            }
            else
            {
                Trace("CheckForUpdatesAsync: portable build — skipping download, prompting for manual update");
            }

            var changelog      = _pendingUpdate.TargetFullRelease.NotesMarkdown ?? string.Empty;
            var currentVersion = Assembly.GetExecutingAssembly()
                                         .GetName().Version?.ToString(3) ?? "unknown";

            Trace($"CheckForUpdatesAsync: update ready current={currentVersion} new={newVersion} installed={installed}");
            _lastNotifiedVersion = newVersion;

            Application.Current.Dispatcher.Invoke(() =>
                UpdateDownloaded?.Invoke(currentVersion, newVersion, changelog, installed));
        }
        catch (Exception ex)
        {
            // Never block the app over a failed update check
            Trace($"CheckForUpdatesAsync: failed {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            _checkGate.Release();
        }
    }

    /// <summary>Applies the downloaded update and restarts the app.</summary>
    public static void ApplyAndRestart()
    {
        if (_mgr == null || _pendingUpdate == null) return;
        _mgr.ApplyUpdatesAndRestart(_pendingUpdate);
    }

    // ── Transient-failure retry ──────────────────────────────────────────────
    // Three tries, 2s/4s backoff. We only retry network-shaped failures —
    // anything else (auth, parse error, disk full) is not going to fix itself.
    private static async Task<T> WithRetryAsync<T>(Func<Task<T>> op, string label)
    {
        var delaysMs = new[] { 2000, 4000 };
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await op();
            }
            catch (Exception ex) when (attempt < delaysMs.Length && IsTransient(ex))
            {
                Trace($"{label}: transient {ex.GetType().Name} on attempt {attempt + 1}, retrying in {delaysMs[attempt]}ms");
                await Task.Delay(delaysMs[attempt]);
            }
        }
    }

    private static async Task WithRetryAsync(Func<Task> op, string label) =>
        await WithRetryAsync<object?>(async () => { await op(); return null; }, label);

    private static bool IsTransient(Exception ex) =>
        ex is HttpRequestException
           or SocketException
           or TaskCanceledException
           or IOException;
}
