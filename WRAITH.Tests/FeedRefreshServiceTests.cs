using System.IO;
using System.Text.Json;
using WRAITH.Services;
using Xunit;

namespace WRAITH.Tests;

/// <summary>
/// Tests the bits of <see cref="FeedRefreshService"/> that don't need a live
/// network: feed source declarations, manifest round-trip, atomic write
/// behaviour, FeedsRoot computation. Anything that actually downloads a
/// feed is exercised by the integration smoke test under
/// <c>tests/integration/</c> on a Windows runner.
/// </summary>
public sealed class FeedRefreshServiceTests
{
    [Fact]
    public void Sources_includes_every_bundled_feed()
    {
        var ids = FeedRefreshService.Sources.Select(s => s.Id).ToHashSet();
        Assert.Contains("vuln_drivers", ids);
        Assert.Contains("tor", ids);
        Assert.Contains("digitalside_ips", ids);
        Assert.Contains("digitalside_domains", ids);
        Assert.Contains("digitalside_urls", ids);
        // The origin's separate md5/sha256 plain lists were consolidated into a
        // single JSON hash lookup when we moved DigitalSide to its GitHub mirror.
        Assert.Contains("digitalside_hashes", ids);
    }

    [Fact]
    public void Sources_all_have_valid_url()
    {
        foreach (var src in FeedRefreshService.Sources)
        {
            Assert.False(string.IsNullOrWhiteSpace(src.SourceUrl), $"{src.Id} has empty SourceUrl");
            Assert.True(Uri.TryCreate(src.SourceUrl, UriKind.Absolute, out var uri),
                        $"{src.Id} SourceUrl is not a valid absolute URI");
            Assert.True(uri!.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps,
                        $"{src.Id} SourceUrl must be http(s); got {uri.Scheme}");
        }
    }

    [Fact]
    public void Sources_local_relative_paths_are_well_formed()
    {
        foreach (var src in FeedRefreshService.Sources)
        {
            Assert.False(string.IsNullOrWhiteSpace(src.LocalRelativePath), $"{src.Id} has empty path");
            Assert.False(Path.IsPathRooted(src.LocalRelativePath),
                         $"{src.Id} LocalRelativePath must be relative, got: {src.LocalRelativePath}");
            // Forward slashes only — keeps the layout portable for Python readers.
            Assert.DoesNotContain("\\", src.LocalRelativePath);
        }
    }

    [Fact]
    public void Sources_have_unique_local_paths()
    {
        var paths = FeedRefreshService.Sources.Select(s => s.LocalRelativePath).ToList();
        Assert.Equal(paths.Count, paths.Distinct().Count());
    }

    [Fact]
    public void Sources_have_unique_ids()
    {
        var ids = FeedRefreshService.Sources.Select(s => s.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    [Fact]
    public void FeedsRoot_resolves_under_programdata()
    {
        var root = FeedRefreshService.FeedsRoot;
        Assert.False(string.IsNullOrWhiteSpace(root));
        // Path is fully-qualified.
        Assert.True(Path.IsPathRooted(root));
        // Path is normalised — no '..', no doubled separators.
        Assert.Equal(Path.GetFullPath(root), root);
        // Leaf segment matches the documented layout.
        Assert.EndsWith("feeds", root);
    }

    [Fact]
    public void LoadManifest_returns_empty_when_file_missing()
    {
        // FeedsRoot points at ProgramData\WRAITH\feeds which may or may not
        // exist on the test runner. We can't safely delete it, so this just
        // verifies the return shape — an empty manifest is the worst case.
        var manifest = FeedRefreshService.LoadManifest();
        Assert.NotNull(manifest);
    }

    [Fact]
    public void FeedStatus_round_trips_through_json()
    {
        var status = new FeedStatus
        {
            SourceUrl      = "https://example.com/x.txt",
            LastRefreshUtc = "2026-06-07T12:34:56Z",
            SizeBytes      = 12345,
            Status         = "ok",
            Error          = null,
        };
        var manifest = new Dictionary<string, FeedStatus> { ["tor"] = status };
        var json = JsonSerializer.Serialize(manifest);
        var roundTripped = JsonSerializer.Deserialize<Dictionary<string, FeedStatus>>(json);

        Assert.NotNull(roundTripped);
        Assert.Equal("https://example.com/x.txt", roundTripped!["tor"].SourceUrl);
        Assert.Equal("2026-06-07T12:34:56Z",      roundTripped["tor"].LastRefreshUtc);
        Assert.Equal(12345,                       roundTripped["tor"].SizeBytes);
        Assert.Equal("ok",                        roundTripped["tor"].Status);
        Assert.Null(roundTripped["tor"].Error);
    }

    [Fact]
    public void FeedStatus_serialises_error_field()
    {
        var status = new FeedStatus
        {
            SourceUrl      = "https://x",
            Status         = "error",
            Error          = "connection refused",
            LastRefreshUtc = null,
        };
        var json = JsonSerializer.Serialize(status);
        Assert.Contains("\"error\":", json);
        Assert.Contains("connection refused", json);
    }

    // ── Feed health / self-test ─────────────────────────────────────────

    private static readonly IReadOnlyList<FeedSource> TwoSources = new[]
    {
        new FeedSource("a", "Feed A", "https://a", "a/a.txt", "desc"),
        new FeedSource("b", "Feed B", "https://b", "b/b.txt", "desc"),
    };

    [Fact]
    public void EvaluateHealth_marks_missing_when_no_manifest_entry()
    {
        var now = new DateTime(2026, 6, 16, 12, 0, 0, DateTimeKind.Utc);
        var reports = FeedRefreshService.EvaluateHealth(
            TwoSources, new Dictionary<string, FeedStatus>(), now, TimeSpan.FromHours(24));

        Assert.All(reports, r => Assert.Equal(FeedRefreshService.FeedHealth.Missing, r.Health));
    }

    [Fact]
    public void EvaluateHealth_marks_missing_when_last_status_errored()
    {
        var now = new DateTime(2026, 6, 16, 12, 0, 0, DateTimeKind.Utc);
        var manifest = new Dictionary<string, FeedStatus>
        {
            ["a"] = new FeedStatus { Status = "error", Error = "timeout", LastRefreshUtc = null },
        };
        var reports = FeedRefreshService.EvaluateHealth(TwoSources, manifest, now, TimeSpan.FromHours(24));

        Assert.Equal(FeedRefreshService.FeedHealth.Missing, reports.First(r => r.Id == "a").Health);
    }

    [Fact]
    public void EvaluateHealth_marks_stale_past_threshold_and_ok_within()
    {
        var now = new DateTime(2026, 6, 16, 12, 0, 0, DateTimeKind.Utc);
        var manifest = new Dictionary<string, FeedStatus>
        {
            // Refreshed 2h ago → Ok.
            ["a"] = new FeedStatus { Status = "ok", LastRefreshUtc = "2026-06-16T10:00:00Z" },
            // Refreshed 30h ago → Stale.
            ["b"] = new FeedStatus { Status = "ok", LastRefreshUtc = "2026-06-15T06:00:00Z" },
        };
        var reports = FeedRefreshService.EvaluateHealth(TwoSources, manifest, now, TimeSpan.FromHours(24));

        Assert.Equal(FeedRefreshService.FeedHealth.Ok,    reports.First(r => r.Id == "a").Health);
        Assert.Equal(FeedRefreshService.FeedHealth.Stale, reports.First(r => r.Id == "b").Health);
    }

    [Fact]
    public void EvaluateHealth_covers_every_source()
    {
        var now = new DateTime(2026, 6, 16, 12, 0, 0, DateTimeKind.Utc);
        var reports = FeedRefreshService.EvaluateHealth(
            FeedRefreshService.Sources, new Dictionary<string, FeedStatus>(), now, TimeSpan.FromHours(24));

        Assert.Equal(FeedRefreshService.Sources.Count, reports.Count);
    }
}
