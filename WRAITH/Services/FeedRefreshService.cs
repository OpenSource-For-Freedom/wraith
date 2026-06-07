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
            DisplayName:       "Microsoft vulnerable driver blocklist",
            SourceUrl:         "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md",
            LocalRelativePath: "vuln_drivers/driver_blocklist.xml",
            Description:       "Microsoft's recommended driver blocklist (BYOVD detection)."),

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
    };

    private static readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(60),
    };

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
    public async Task<Dictionary<string, FeedStatus>> RefreshAllAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(FeedsRoot);
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

        var destPath = Path.GetFullPath(Path.Combine(FeedsRoot, source.LocalRelativePath));
        if (!destPath.StartsWith(FeedsRoot, StringComparison.OrdinalIgnoreCase))
        {
            status.Status = "error";
            status.Error  = "destination outside feeds root";
            return status;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);

            // Stream into a sibling .tmp file, then atomically swap so a crash
            // mid-download doesn't leave a half-written feed that the Python
            // scanners would happily read.
            var tmp = destPath + ".tmp";

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
        var path = Path.GetFullPath(ManifestPath);
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
        var path = Path.GetFullPath(ManifestPath);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
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
