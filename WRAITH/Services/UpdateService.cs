using System.Windows;
using System.Reflection;
using System.Threading;
using System.IO;
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

            _pendingUpdate = await _mgr.CheckForUpdatesAsync();
            if (_pendingUpdate == null)
            {
                Trace("CheckForUpdatesAsync: no update");
                return;
            }

            // Only download the payload when we can actually apply it.
            // Portable (zip + START.bat) builds report IsInstalled=false; downloading
            // the nupkg would waste 50+ MB for an apply that can never run.
            if (installed)
            {
                await _mgr.DownloadUpdatesAsync(_pendingUpdate);
                Trace("CheckForUpdatesAsync: payload downloaded");
            }
            else
            {
                Trace("CheckForUpdatesAsync: portable build — skipping download, prompting for manual update");
            }

            var newVersion     = _pendingUpdate.TargetFullRelease.Version.ToString();
            var changelog      = _pendingUpdate.TargetFullRelease.NotesMarkdown ?? string.Empty;
            var currentVersion = Assembly.GetExecutingAssembly()
                                         .GetName().Version?.ToString(3) ?? "unknown";

            Trace($"CheckForUpdatesAsync: update ready current={currentVersion} new={newVersion} installed={installed}");

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
}
