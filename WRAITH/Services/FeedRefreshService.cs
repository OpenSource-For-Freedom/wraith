using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WRAITH.Services;

/// <summary>
/// One feed-source entry. Kept verbatim in code (not config) so the
/// no-API-key intel bundle is the *same* on every install — operators
/// don't have to discover or assemble feed lists themselves.
/// </summary>
public sealed record FeedSource(
    string Id,
    string DisplayName,
    string SourceUrl,
    string LocalRelativePath,
    string Description,
    bool IsBinary = false);

/// <summary>Per-feed status persisted to feeds/manifest.json.</summary>
public sealed class FeedStatus
{
    [JsonPropertyName("source_url")]      public string SourceUrl       { get; set; } = string.Empty;
    [JsonPropertyName("last_refresh_utc")] public string? LastRefreshUtc { get; set; }
    [JsonPropertyName("size_bytes")]      public long SizeBytes         { get; set; }
    [JsonPropertyName("status")]          public string Status          { get; set; } = "unknown";  // ok | error | downloading
    [JsonPropertyName("error")]           public string? Error          { get; set; }
}

/// <summary>
/// Downloads the bundled no-API-key threat-intel feeds into
/// %ProgramData%\WRAITH\feeds\. Read by the Python scanners
/// (feed_store.py / vuln_driver_scanner.py / tor_check.py /
/// digitalside_intel.py) at scan time.
///
/// Lives outside the Velopack-managed install dir so version bumps
/// don't strand the downloaded feeds.
/// </summary>
public sealed class FeedRefreshService
{
    public static readonly IReadOnlyList<FeedSource> Sources = new[]
    {
        new FeedSource(
            Id:                "vuln_drivers",
            DisplayName:       "LOLDrivers vulnerable driver list",
            // The MicrosoftDocs/windows-itpro-docs repo was archived in 2024
            // and the markdown source page returns 404 — that's why the
            // previous URL silently failed since the feed pane was added.
            // LOLDrivers (loldrivers.io) is a community-maintained superset
            // of Microsoft's recommended blocklist plus community-submitted
            // BYOVD samples, published as machine-readable JSON. The vuln-
            // driver scanner now consumes this format directly.
            SourceUrl:         "https://www.loldrivers.io/api/drivers.json",
            LocalRelativePath: "vuln_drivers/loldrivers.json",
            Description:       "LOLDrivers community-maintained vulnerable driver catalog (BYOVD detection)."),

        new FeedSource(
            Id:                "tor",
            DisplayName:       "Tor exit node list",
            SourceUrl:         "https://check.torproject.org/torbulkexitlist",
            LocalRelativePath: "tor/exit_nodes.txt",
            Description:       "Active Tor exit relays (network reputation)."),

        new FeedSource(
            Id:                "digitalside_ips",
            DisplayName:       "DigitalSide malicious IPs",
            SourceUrl:         "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
            LocalRelativePath: "digitalside/ips.txt",
            Description:       "DigitalSide OSINT malicious IP feed."),

        new FeedSource(
            Id:                "digitalside_domains",
            DisplayName:       "DigitalSide malicious domains",
            SourceUrl:         "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
            LocalRelativePath: "digitalside/domains.txt",
            Description:       "DigitalSide OSINT malicious domain feed."),

        new FeedSource(
            Id:                "digitalside_urls",
            DisplayName:       "DigitalSide malicious URLs",
            SourceUrl:         "https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt",
            LocalRelativePath: "digitalside/urls.txt",
            Description:       "DigitalSide OSINT malicious URL feed."),

        new FeedSource(
            Id:                "digitalside_sha256",
            DisplayName:       "DigitalSide malware SHA256",
            SourceUrl:         "https://osint.digitalside.it/Threat-Intel/lists/latestsha256.txt",
            LocalRelativePath: "digitalside/hashes_sha256.txt",
            Description:       "DigitalSide OSINT malware SHA256 hashes."),

        new FeedSource(
            Id:                "digitalside_md5",
            DisplayName:       "DigitalSide malware MD5",
            SourceUrl:         "https://osint.digitalside.it/Threat-Intel/lists/latestmd5.txt",
            LocalRelativePath: "digitalside/hashes_md5.txt",
            Description:       "DigitalSide OSINT malware MD5 hashes."),

        // ── abuse.ch feeds ──────────────────────────────────────────────────
        new FeedSource(
            Id:                "urlhaus",
            DisplayName:       "URLhaus malicious URLs",
            SourceUrl:         "https://urlhaus.abuse.ch/downloads/text/",
            LocalRelativePath: "urlhaus/urls.txt",
            Description:       "abuse.ch URLhaus — active malicious URLs (no API key)."),

        new FeedSource(
            Id:                "feodo",
            DisplayName:       "Feodo botnet C2 IPs",
            SourceUrl:         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            LocalRelativePath: "feodo/c2_ips.txt",
            Description:       "abuse.ch Feodo Tracker — active botnet C2 IPs (no API key)."),

        // ── Community aggregated IPs ─────────────────────────────────────────
        new FeedSource(
            Id:                "ipsum",
            DisplayName:       "IPsum aggregated bad IPs",
            SourceUrl:         "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            LocalRelativePath: "ipsum/ips.txt",
            Description:       "IPsum — IPs seen across 30+ block lists (score ≥ 3 threshold applied at scan time)."),

        new FeedSource(
            Id:                "et_compromised",
            DisplayName:       "EmergingThreats compromised hosts",
            SourceUrl:         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            LocalRelativePath: "et/compromised_ips.txt",
            Description:       "EmergingThreats — compromised/rooted hosts (no API key)."),

        // ── Phishing ─────────────────────────────────────────────────────────
        new FeedSource(
            Id:                "openphish",
            DisplayName:       "OpenPhish phishing URLs",
            SourceUrl:         "https://openphish.com/feed.txt",
            LocalRelativePath: "openphish/urls.txt",
            Description:       "OpenPhish — active phishing URLs (no API key, free tier)."),

        // ── Malicious domains ─────────────────────────────────────────────────
        new FeedSource(
            Id:                "botvrij_domains",
            DisplayName:       "Botvrij.eu malicious domains",
            SourceUrl:         "https://www.botvrij.eu/data/ioclist.domain.raw",
            LocalRelativePath: "botvrij/domains.txt",
            Description:       "Botvrij.eu — community-curated malicious domain IOCs (no API key)."),
    };

    // DigitalSide + LOLDrivers (and most CDN-fronted feeds) return 403 to
    // requests with an empty or default .NET User-Agent — this was the cause
    // of every "Error" status in the feed pane except Tor (whose endpoint
    // doesn't gate UA). The string is honest and identifies the project so
    // feed operators can contact us if a feed needs throttling.
    private static readonly HttpClient _http = BuildHttpClient();

    private static HttpClient BuildHttpClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd(
            "WRAITH-ThreatHunter/1.0 (+https://github.com/OpenSource-For-Freedom/wraith)");
        c.DefaultRequestHeaders.Accept.ParseAdd("*/*");
        return c;
    }

    /// <summary>Path to the feeds directory, stable across Velopack updates.</summary>
    public static string FeedsRoot => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WRAITH",
        "feeds"));

    private static string ManifestPath => Path.Combine(FeedsRoot, "manifest.json");

    /// <summary>
    /// Fired once per individual feed completion (success or failure)
    /// so the UI can update a progress list as downloads stream in.
    /// </summary>
    public event Action<FeedSource, FeedStatus>? FeedRefreshed;

    /// <summary>
    /// Downloads every feed in <see cref="Sources"/> sequentially. Failures
    /// don't abort the rest — a flaky Tor mirror shouldn't block the
    /// DigitalSide pulls.
    /// </summary>
    /// <summary>
    /// Normalises a path and validates it sits under the feeds root.
    /// The StartsWith containment check is what CodeQL's cs/path-injection
    /// rule recognises as a sanitiser; Path.GetFullPath alone normalises but
    /// doesn't gate. Throws if the resolved path escapes the root — at every
    /// call this only happens for a logic bug, not for user input.
    /// </summary>
    private static string GatedFeedPath(string candidate)
    {
        var root = Path.GetFullPath(FeedsRoot);
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            ? root
            : root + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(candidate);
        if (!full.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Resolved path '{full}' escapes feeds root '{root}'.");
        }
        return full;
    }

    public async Task<Dictionary<string, FeedStatus>> RefreshAllAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(GatedFeedPath(FeedsRoot));
        var manifest = LoadManifest();

        foreach (var source in Sources)
        {
            if (ct.IsCancellationRequested) break;
            var status = await RefreshOneAsync(source, ct);
            manifest[source.Id] = status;
            FeedRefreshed?.Invoke(source, status);
            SaveManifest(manifest);   // persist after each so a crash mid-run doesn't lose state
        }
        return manifest;
    }

    /// <summary>
    /// Refreshes a single feed. Public so the UI can offer per-feed retries.
    /// </summary>
    public async Task<FeedStatus> RefreshOneAsync(FeedSource source, CancellationToken ct = default)
    {
        var status = new FeedStatus
        {
            SourceUrl = source.SourceUrl,
            Status    = "downloading",
        };

        string destPath;
        try
        {
            // GatedFeedPath: Path.GetFullPath + StartsWith(FeedsRoot) check.
            // CodeQL recognises the containment check as a cs/path-injection
            // sanitiser, so every leaf below is now considered cleansed.
            destPath = GatedFeedPath(Path.Combine(FeedsRoot, source.LocalRelativePath));
        }
        catch (InvalidOperationException ex)
        {
            status.Status = "error";
            status.Error  = ex.Message;
            return status;
        }

        try
        {
            Directory.CreateDirectory(GatedFeedPath(Path.GetDirectoryName(destPath)!));

            // Stream into a sibling .tmp file, then atomically swap so a crash
            // mid-download doesn't leave a half-written feed that the Python
            // scanners would happily read.
            var tmp = GatedFeedPath(destPath + ".tmp");

            using (var resp = await _http.GetAsync(source.SourceUrl,
                                                   HttpCompletionOption.ResponseHeadersRead, ct))
            {
                resp.EnsureSuccessStatusCode();
                await using var src = await resp.Content.ReadAsStreamAsync(ct);
                await using var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None);
                await src.CopyToAsync(dst, ct);
            }

            if (File.Exists(destPath))
                File.Replace(tmp, destPath, destinationBackupFileName: null);
            else
                File.Move(tmp, destPath);

            var info = new FileInfo(destPath);
            status.SizeBytes      = info.Length;
            status.LastRefreshUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            status.Status         = "ok";
            status.Error          = null;
        }
        catch (Exception ex)
        {
            status.Status = "error";
            status.Error  = $"{ex.GetType().Name}: {ex.Message}";
        }

        return status;
    }

    /// <summary>Reads manifest.json, returning an empty dict if missing or corrupt.</summary>
    public static Dictionary<string, FeedStatus> LoadManifest()
    {
        string path;
        try { path = GatedFeedPath(ManifestPath); }
        catch { return new(); }
        if (!File.Exists(path)) return new();

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, FeedStatus>>(File.ReadAllText(path))
                   ?? new();
        }
        catch
        {
            return new();
        }
    }

    private static void SaveManifest(Dictionary<string, FeedStatus> manifest)
    {
        string path;
        try { path = GatedFeedPath(ManifestPath); }
        catch { return; }
        try
        {
            Directory.CreateDirectory(GatedFeedPath(Path.GetDirectoryName(path)!));
            var tmp = GatedFeedPath(path + ".tmp");
            var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            });
            File.WriteAllText(tmp, json);
            if (File.Exists(path))
                File.Replace(tmp, path, null);
            else
                File.Move(tmp, path);
        }
        catch
        {
            // best-effort — losing the manifest only costs status reporting,
            // the actual feed files are still on disk.
        }
    }
}
