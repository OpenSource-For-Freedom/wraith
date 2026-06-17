namespace WRAITH.Services;

/// <summary>Overall, at-a-glance protection state for the one-line status banner.</summary>
public enum ProtectionLevel
{
    Scanning,
    AtRisk,          // critical threats present — red
    NeedsAttention,  // high findings, stale scan/feeds, or realtime off — amber
    Protected,       // clean, fresh, realtime on — green
    Unknown,         // never scanned
}

public sealed record ProtectionStatus(ProtectionLevel Level, string Headline, string Detail);

/// <summary>
/// Collapses the system's security posture into a single Malwarebytes-style
/// verdict the user reads in one glance. Pure function — no I/O, no clock of its
/// own (caller passes <paramref name="nowUtc"/>) — so it's fully unit-testable
/// and the UI just binds to the result.
/// </summary>
public static class ProtectionStatusEvaluator
{
    /// <summary>A scan older than this nudges the user to re-run, even when clean.</summary>
    public static readonly TimeSpan ScanFreshnessWindow = TimeSpan.FromDays(7);

    public static ProtectionStatus Evaluate(
        bool isScanning,
        DateTime? lastScanUtc,
        int criticalCount,
        int highCount,
        bool realtimeEnabled,
        int staleOrMissingFeeds,
        DateTime nowUtc)
    {
        if (isScanning)
            return new(ProtectionLevel.Scanning, "Scanning…",
                "WRAITH is analysing your system.");

        if (lastScanUtc == null)
            return new(ProtectionLevel.Unknown, "Not scanned yet",
                "Run your first scan to check this system.");

        // Active threats dominate everything else.
        if (criticalCount > 0)
            return new(ProtectionLevel.AtRisk,
                $"{criticalCount} critical threat{Plural(criticalCount)} found",
                "Contain the critical findings now — kill the process or delete the file.");

        if (highCount > 0)
            return new(ProtectionLevel.NeedsAttention,
                $"{highCount} high-severity finding{Plural(highCount)}",
                "Review the high-severity findings.");

        // Clean — but is the system actually well-covered?
        var notes = new List<string>();
        var age = nowUtc - lastScanUtc.Value;
        if (age > ScanFreshnessWindow)
            notes.Add($"last scan was {(int)age.TotalDays} day{Plural((int)age.TotalDays)} ago");
        if (staleOrMissingFeeds > 0)
            notes.Add($"{staleOrMissingFeeds} intel feed{Plural(staleOrMissingFeeds)} need refreshing");
        if (!realtimeEnabled)
            notes.Add("real-time monitoring is off");

        if (notes.Count == 0)
            return new(ProtectionLevel.Protected, "You're protected",
                "No threats found, intel is current, and real-time monitoring is on.");

        return new(ProtectionLevel.NeedsAttention, "Protected — with recommendations",
            "No active threats, but " + JoinNotes(notes) + ".");
    }

    private static string Plural(int n) => n == 1 ? "" : "s";

    private static string JoinNotes(List<string> notes) =>
        notes.Count switch
        {
            1 => notes[0],
            2 => $"{notes[0]} and {notes[1]}",
            _ => string.Join(", ", notes.Take(notes.Count - 1)) + ", and " + notes[^1],
        };
}
