using System;
using System.IO;
using System.Threading;
using WRAITH.Services;
using Xunit;

namespace WRAITH.Tests;

/// <summary>
/// Tests the real-time autostart watcher: the deterministic debounce gate
/// (pure, clock-injected) and one real FileSystemWatcher round-trip against a
/// temp directory to prove the wiring actually fires.
/// </summary>
public sealed class RealtimeMonitorServiceTests : IDisposable
{
    private readonly string _dir;

    public RealtimeMonitorServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "wraith-rt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void ShouldReport_collapses_duplicates_within_debounce_window()
    {
        using var svc = new RealtimeMonitorService(debounce: TimeSpan.FromSeconds(2));
        var t0 = new DateTime(2026, 6, 16, 12, 0, 0, DateTimeKind.Utc);
        var path = @"C:\Users\x\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe";

        Assert.True(svc.ShouldReport(path, t0));                       // first wins
        Assert.False(svc.ShouldReport(path, t0.AddSeconds(1)));        // within window → suppressed
        Assert.True(svc.ShouldReport(path, t0.AddSeconds(3)));         // window elapsed → reports again
    }

    [Fact]
    public void ShouldReport_tracks_paths_independently()
    {
        using var svc = new RealtimeMonitorService(debounce: TimeSpan.FromSeconds(5));
        var t0 = new DateTime(2026, 6, 16, 12, 0, 0, DateTimeKind.Utc);

        Assert.True(svc.ShouldReport(@"C:\a.exe", t0));
        Assert.True(svc.ShouldReport(@"C:\b.exe", t0));   // different path, not debounced by a.exe
    }

    [Fact]
    public void DefaultWatchPaths_only_returns_existing_directories()
    {
        foreach (var p in RealtimeMonitorService.DefaultWatchPaths())
            Assert.True(Directory.Exists(p), $"watch path should exist: {p}");
    }

    [Fact]
    public void Watcher_fires_Detected_when_file_dropped_in_watched_dir()
    {
        using var svc = new RealtimeMonitorService(debounce: TimeSpan.FromMilliseconds(100));
        using var fired = new ManualResetEventSlim(false);
        string? seen = null;

        svc.Detected += ev => { seen = ev.Path; fired.Set(); };
        svc.Start(new[] { _dir });
        Assert.True(svc.IsRunning);

        var dropped = Path.Combine(_dir, "payload.exe");
        File.WriteAllText(dropped, "MZ...");

        // FileSystemWatcher delivery is asynchronous; allow generous slack.
        Assert.True(fired.Wait(TimeSpan.FromSeconds(10)),
            "expected a real-time Detected event for the dropped file");
        Assert.Equal(Path.GetFullPath(dropped), Path.GetFullPath(seen!));
    }
}
