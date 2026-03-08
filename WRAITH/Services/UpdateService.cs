using System.Windows;
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

    /// <summary>Fired on the UI thread when an update has been fully downloaded.</summary>
    /// <remarks>Parameter is the new version string, e.g. "1.2.0".</remarks>
    public static event Action<string>? UpdateDownloaded;

    private static UpdateManager? _mgr;
    private static UpdateInfo?    _pendingUpdate;

    public static async Task CheckForUpdatesAsync()
    {
        try
        {
            _mgr = new UpdateManager(new GithubSource(RepoUrl, null, false));

            // Skip when running from source / dev environment (not installed via Velopack)
            if (!_mgr.IsInstalled)
                return;

            _pendingUpdate = await _mgr.CheckForUpdatesAsync();
            if (_pendingUpdate == null)
                return;

            await _mgr.DownloadUpdatesAsync(_pendingUpdate);

            var version = _pendingUpdate.TargetFullRelease.Version.ToString();
            Application.Current.Dispatcher.Invoke(() => UpdateDownloaded?.Invoke(version));
        }
        catch
        {
            // Never block the app over a failed update check
        }
    }

    /// <summary>Applies the downloaded update and restarts the app.</summary>
    public static void ApplyAndRestart()
    {
        if (_mgr == null || _pendingUpdate == null) return;
        _mgr.ApplyUpdatesAndRestart(_pendingUpdate);
    }
}
