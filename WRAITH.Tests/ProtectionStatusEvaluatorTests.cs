using System;
using WRAITH.Services;
using Xunit;

namespace WRAITH.Tests;

/// <summary>
/// Tests the pure posture-collapsing logic behind the one-line protection
/// banner. Severity precedence (critical &gt; high &gt; hygiene), the
/// never-scanned and scanning short-circuits, and the "clean but stale/feeds/
/// realtime-off" recommendation path are all covered.
/// </summary>
public sealed class ProtectionStatusEvaluatorTests
{
    private static readonly DateTime Now = new(2026, 6, 16, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Scanning_short_circuits_everything()
    {
        var s = ProtectionStatusEvaluator.Evaluate(
            isScanning: true, lastScanUtc: null, criticalCount: 9, highCount: 9,
            realtimeEnabled: false, staleOrMissingFeeds: 5, nowUtc: Now);
        Assert.Equal(ProtectionLevel.Scanning, s.Level);
    }

    [Fact]
    public void Never_scanned_is_unknown()
    {
        var s = ProtectionStatusEvaluator.Evaluate(
            false, null, 0, 0, realtimeEnabled: true, staleOrMissingFeeds: 0, Now);
        Assert.Equal(ProtectionLevel.Unknown, s.Level);
    }

    [Fact]
    public void Critical_findings_are_at_risk_and_outrank_high()
    {
        var s = ProtectionStatusEvaluator.Evaluate(
            false, Now.AddMinutes(-5), criticalCount: 2, highCount: 4,
            realtimeEnabled: true, staleOrMissingFeeds: 0, Now);
        Assert.Equal(ProtectionLevel.AtRisk, s.Level);
        Assert.Contains("2 critical threats", s.Headline);
    }

    [Fact]
    public void High_only_is_needs_attention()
    {
        var s = ProtectionStatusEvaluator.Evaluate(
            false, Now.AddMinutes(-5), criticalCount: 0, highCount: 1,
            realtimeEnabled: true, staleOrMissingFeeds: 0, Now);
        Assert.Equal(ProtectionLevel.NeedsAttention, s.Level);
        Assert.Contains("1 high-severity finding", s.Headline);   // singular
    }

    [Fact]
    public void Clean_fresh_realtime_on_feeds_ok_is_protected()
    {
        var s = ProtectionStatusEvaluator.Evaluate(
            false, Now.AddHours(-1), 0, 0,
            realtimeEnabled: true, staleOrMissingFeeds: 0, Now);
        Assert.Equal(ProtectionLevel.Protected, s.Level);
        Assert.Equal("You're protected", s.Headline);
    }

    [Fact]
    public void Clean_but_realtime_off_recommends_attention()
    {
        var s = ProtectionStatusEvaluator.Evaluate(
            false, Now.AddHours(-1), 0, 0,
            realtimeEnabled: false, staleOrMissingFeeds: 0, Now);
        Assert.Equal(ProtectionLevel.NeedsAttention, s.Level);
        Assert.Contains("real-time monitoring is off", s.Detail);
    }

    [Fact]
    public void Clean_but_stale_scan_and_feeds_lists_both_notes()
    {
        var s = ProtectionStatusEvaluator.Evaluate(
            false, Now.AddDays(-10), 0, 0,
            realtimeEnabled: true, staleOrMissingFeeds: 3, Now);
        Assert.Equal(ProtectionLevel.NeedsAttention, s.Level);
        Assert.Contains("10 days ago", s.Detail);
        Assert.Contains("3 intel feeds need refreshing", s.Detail);
    }
}
