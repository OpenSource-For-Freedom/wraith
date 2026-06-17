using System.Windows;
using System.Reflection;
using System.Threading;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
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

    /// <summary>Outcome of an update check, for the manual "Check for updates now" UX.</summary>
    public enum UpdateCheckResult
    {
        UpToDate,
        UpdateReady,               // installed build — downloaded, ready to apply
        PortableUpdateAvailable,   // portable build — must download manually
        Failed,
    }

    public static async Task<UpdateCheckResult> CheckForUpdatesAsync()
    {
        await _checkGate.WaitAsync();
        try
        {
            Trace("CheckForUpdatesAsync: begin");
            _mgr = new UpdateManager(new GithubSource(RepoUrl, null, false));
            var installed = _mgr.IsInstalled;
            Trace($"CheckForUpdatesAsync: IsInstalled={installed}");

            // Velopack's CheckForUpdatesAsync throws NotInstalledException for
            // portable/dev builds (no install context). Rather than report a
            // scary "couldn't check" error, query GitHub Releases directly so
            // the user still learns whether a newer version exists and gets
            // pointed at the download page.
            if (!installed)
                return await CheckPortableAsync();

            _pendingUpdate = await WithRetryAsync(
                () => _mgr.CheckForUpdatesAsync(),
                "CheckForUpdatesAsync");

            if (_pendingUpdate == null)
            {
                Trace("CheckForUpdatesAsync: no update");
                return UpdateCheckResult.UpToDate;
            }

            var newVersion = _pendingUpdate.TargetFullRelease.Version.ToString();

            // Skip the popup if we already surfaced this version earlier in the
            // session — the title-bar "UPDATE READY" button stays visible — but
            // still report that an update is waiting so a manual check gives feedback.
            if (string.Equals(_lastNotifiedVersion, newVersion, StringComparison.Ordinal))
            {
                Trace($"CheckForUpdatesAsync: version {newVersion} already notified, skipping");
                return installed ? UpdateCheckResult.UpdateReady : UpdateCheckResult.PortableUpdateAvailable;
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

            return installed ? UpdateCheckResult.UpdateReady : UpdateCheckResult.PortableUpdateAvailable;
        }
        catch (Exception ex)
        {
            // Never block the app over a failed update check
            Trace($"CheckForUpdatesAsync: failed {ex.GetType().Name}: {ex.Message}");
            return UpdateCheckResult.Failed;
        }
        finally
        {
            _checkGate.Release();
        }
    }

    /// <summary>
    /// Update check for portable / dev builds (Velopack not installed). Reads the
    /// latest GitHub release directly and, if it's newer than the running version,
    /// fires <see cref="UpdateDownloaded"/> with isInstalled=false so the dialog
    /// offers the release page rather than an in-place apply.
    /// </summary>
    private static async Task<UpdateCheckResult> CheckPortableAsync()
    {
        var latest = await WithRetryAsync(FetchLatestGithubReleaseAsync, "FetchLatestGithubRelease");
        if (latest == null)
        {
            Trace("CheckPortableAsync: could not read latest release");
            return UpdateCheckResult.Failed;
        }

        var (latestVersion, notes) = latest.Value;
        var current        = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);
        var currentTriplet = new Version(current.Major, current.Minor, current.Build);
        var currentVersion = currentTriplet.ToString();

        if (latestVersion <= currentTriplet)
        {
            Trace($"CheckPortableAsync: up to date (current={currentVersion} latest={latestVersion})");
            return UpdateCheckResult.UpToDate;
        }

        var newVersion = latestVersion.ToString();
        Trace($"CheckPortableAsync: newer release available current={currentVersion} latest={newVersion}");

        if (!string.Equals(_lastNotifiedVersion, newVersion, StringComparison.Ordinal))
        {
            _lastNotifiedVersion = newVersion;
            Application.Current.Dispatcher.Invoke(() =>
                UpdateDownloaded?.Invoke(currentVersion, newVersion, notes, false));
        }
        return UpdateCheckResult.PortableUpdateAvailable;
    }

    /// <summary>Returns (version, releaseNotes) of the latest GitHub release, or null.</summary>
    private static async Task<(Version Version, string Notes)?> FetchLatestGithubReleaseAsync()
    {
        // RepoUrl is https://github.com/<owner>/<repo>; the API host differs.
        var apiUrl = RepoUrl.Replace("https://github.com/", "https://api.github.com/repos/")
                            .TrimEnd('/') + "/releases/latest";

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("WRAITH-Updater/1.0");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

        using var resp = await http.GetAsync(apiUrl);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        var tag  = root.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
        var body = root.TryGetProperty("body", out var b) ? b.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(tag)) return null;

        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var ver)) return null;
        return (ver, body);
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
