namespace WRAITH.Models;

public enum Severity
{
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4
}

public enum FindingCategory
{
    Persistence,
    Yara,
    Heuristics,
    Events,
    Npm,
    Processes,
    NativeScan,
    Unknown
}

public class ThreatFinding
{
    public Guid   Id          { get; set; } = Guid.NewGuid();
    public string Title       { get; set; } = string.Empty;
    public string Path        { get; set; } = string.Empty;
    public string Reason      { get; set; } = string.Empty;
    public string Category    { get; set; } = string.Empty;
    public string Subcategory { get; set; } = string.Empty;
    public Severity Severity  { get; set; } = Severity.Medium;
    public DateTime Timestamp { get; set; } = DateTime.Now;

    // Extended fields
    public string? RuleName       { get; set; }
    public string? CommandLine    { get; set; }
    public string? MessagePreview { get; set; }
    public int?    Pid            { get; set; }
    public string? EventLog       { get; set; }
    public int?    EventId        { get; set; }
    public double? Entropy        { get; set; }
    public double  AnomalyScore   { get; set; }
    public string? Package        { get; set; }
    public string? Version        { get; set; }
    /// Set by ParseFinding: true if process is still running at scan time.
    public bool    IsLive         { get; set; }
    /// "LIVE", "TASK", or "" — derived from Pid + process liveness check.
    public string  ProcessStatus  { get; set; } = "";
    /// Process start time (live processes) or last scheduled-task run time.
    public DateTime? LastRunTime  { get; set; }

    // Display helpers
    public string SeverityLabel => Severity.ToString().ToUpper();
    public string CategoryLabel => Category.Replace("_", " ").ToUpperInvariant();
    public bool   IsLiveProcess => IsLive;
    /// LIVE/TASK badge or last-run string for the STATUS column.
    public string LiveStatus    => IsLive                  ? $"LIVE · {Pid}"
                                 : ProcessStatus == "TASK" ? "TASK"
                                 : LastRunTime.HasValue    ? LastRunTime.Value.ToString("yyyy-MM-dd HH:mm")
                                 : "";

    /// <summary>Formatted last-run label shown in the LAST RUN column (empty for live processes).</summary>
    public string LastRunLabel =>
        IsLive ? ""
        : LastRunTime.HasValue ? LastRunTime.Value.ToString("yyyy-MM-dd HH:mm") : "";

    /// <summary>Sort key for the LIVE column: 2 = LIVE, 1 = TASK, 0 = dead/unknown.</summary>
    public int LiveSortKey => ProcessStatus switch
    {
        "LIVE" => 2,
        "TASK" => 1,
        _      => 0
    };

    public string AnomalyLabel => AnomalyScore.ToString("F1");

    public static Severity ParseSeverity(string? s) => s?.ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical,
        "HIGH"     => Severity.High,
        "MEDIUM"   => Severity.Medium,
        "LOW"      => Severity.Low,
        _          => Severity.Info
    };

    public static FindingCategory ParseCategory(string? s) => s?.ToLowerInvariant() switch
    {
        "persistence" => FindingCategory.Persistence,
        "yara"        => FindingCategory.Yara,
        "heuristics"  => FindingCategory.Heuristics,
        "events"      => FindingCategory.Events,
        "npm"         => FindingCategory.Npm,
        "processes"   => FindingCategory.Processes,
        _             => FindingCategory.Unknown
    };
}

public class ScanResult
{
    public string Scanner      { get; set; } = string.Empty;
    public string Mode         { get; set; } = string.Empty;
    public DateTime Timestamp  { get; set; } = DateTime.Now;
    public List<ThreatFinding> Findings { get; set; } = new();
    public ScanSummary Summary { get; set; } = new();
    public string? Error       { get; set; }
}

public class ScanSummary
{
    public int Total    { get; set; }
    public int Critical { get; set; }
    public int High     { get; set; }
    public int Medium   { get; set; }
    public int Low      { get; set; }
    public int Info     { get; set; }

    public string ThreatLevel =>
        Critical > 0 ? "CRITICAL" :
        High     > 0 ? "HIGH"     :
        Medium   > 0 ? "MEDIUM"   :
        Low      > 0 ? "LOW"      : "CLEAN";
}
