using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using WRAITH.Models;

namespace WRAITH.Services;

// ── Discord payload DTOs ────────────────────────────────────────────────────────────────
// Concrete types so System.Text.Json serializes the full structure correctly.
// Anonymous types inside object[] lose their type at runtime and serialize as {}.

internal sealed record DiscordField(
    [property: JsonPropertyName("name")]   string Name,
    [property: JsonPropertyName("value")]  string Value,
    [property: JsonPropertyName("inline")] bool   Inline
);

internal sealed record DiscordFooter(
    [property: JsonPropertyName("text")]     string Text,
    [property: JsonPropertyName("icon_url")] string IconUrl
);

internal sealed record DiscordEmbed(
    [property: JsonPropertyName("title")]       string        Title,
    [property: JsonPropertyName("color")]       int           Color,
    [property: JsonPropertyName("description")] string        Description,
    [property: JsonPropertyName("fields")]      DiscordField[] Fields,
    [property: JsonPropertyName("footer")]      DiscordFooter  Footer,
    [property: JsonPropertyName("timestamp")]   string        Timestamp
);

internal sealed record DiscordPayload(
    [property: JsonPropertyName("username")]   string        Username,
    [property: JsonPropertyName("avatar_url")] string        AvatarUrl,
    [property: JsonPropertyName("embeds")]     DiscordEmbed[] Embeds
);
// ─────────────────────────────────────────────────────────────────────────────────────────

public sealed class AlertingService
{
    // WRAITH palette — matches PatronusTheme.xaml and UI converters
    private const int DiscordColorCritical = 0xFF2D55; // #FF2D55
    private const int DiscordColorHigh     = 0xFF6B35; // #FF6B35
    private const int DiscordColorMedium   = 0xFFD700; // #FFD700
    private const int DiscordColorLow      = 0x4FC3F7; // #4FC3F7
    private const int DiscordColorInfo     = 0x9E9E9E; // #9E9E9E

    private const string SlackColorCritical = "#FF2D55";
    private const string SlackColorHigh     = "#FF6B35";
    private const string SlackColorMedium   = "#FFD700";
    private const string SlackColorLow      = "#4FC3F7";
    private const string SlackColorInfo     = "#9E9E9E";

    private const string AvatarUrl = "https://raw.githubusercontent.com/OpenSource-For-Freedom/wraith/main/WRAITH/Assets/wraith.png";
    private const string Footer    = "WRAITH · Windows Runtime Analysis & Intrusion Threat Hunter";

    // Do not reuse a static HttpClient for webhook POSTs — a fresh instance
    // per call avoids stale connection state that can cause silent 400s.
    private static HttpClient MakeWebhookClient() =>
        new() { Timeout = TimeSpan.FromSeconds(15) };

    // ── Public API ─────────────────────────────────────────────────────────────

    public async Task<(bool sent, string message)> SendSlackAlertAsync(
        ScanResult result, AutomatedResponseReport soar, string scanPath,
        ResponsePolicy policy, CancellationToken ct = default)
    {
        if (!policy.EnableSlackWebhook)         return (false, "Slack webhook is disabled in policy");
        if (string.IsNullOrWhiteSpace(policy.SlackWebhookUrl)) return (false, "Slack webhook URL is empty");
        if (!policy.SlackWebhookUrl.StartsWith("https://hooks.slack.com/", StringComparison.OrdinalIgnoreCase))
            return (false, "Invalid Slack webhook URL. It should start with https://hooks.slack.com/");

        var payload = BuildSlackPayload(result, soar, scanPath);
        return await PostWebhookAsync(policy.SlackWebhookUrl, payload, "Slack", ct);
    }

    public async Task<(bool sent, string message)> SendDiscordAlertAsync(
        ScanResult result, AutomatedResponseReport soar, string scanPath,
        ResponsePolicy policy, CancellationToken ct = default)
    {
        // Diagnostics: always surface the exact gate that blocks the send.
        if (!policy.EnableDiscordWebhook)
            return (false, $"Discord webhook is disabled in policy (URL={policy.DiscordWebhookUrl?.Length > 0})");
        if (string.IsNullOrWhiteSpace(policy.DiscordWebhookUrl))
            return (false, "Discord webhook URL is empty in policy");
        if (!policy.DiscordWebhookUrl.StartsWith("https://discord.com/api/webhooks/", StringComparison.OrdinalIgnoreCase) &&
            !policy.DiscordWebhookUrl.StartsWith("https://discordapp.com/api/webhooks/", StringComparison.OrdinalIgnoreCase))
            return (false, $"Invalid Discord webhook URL (got: {policy.DiscordWebhookUrl[..Math.Min(60, policy.DiscordWebhookUrl.Length)]}…). Must start with https://discord.com/api/webhooks/");

        var payload = BuildDiscordPayload(result, soar, scanPath);
        return await PostWebhookAsync(policy.DiscordWebhookUrl, payload, "Discord", ct);
    }

    // ── Discord — Rich Embed ────────────────────────────────────────────────────

    private static string BuildDiscordPayload(ScanResult result, AutomatedResponseReport soar, string scanPath)
    {
        var level  = result.Summary.ThreatLevel?.ToUpperInvariant() ?? "UNKNOWN";
        var color  = LevelToDiscordColor(level);
        var ts     = result.Timestamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        var impact = BuildImpactAnalysis(result, soar, scanPath);

        var topFindings  = TopFindings(result);
        var summaryTable = BuildDiscordSummaryTable(result, soar);
        var findingsList = BuildDiscordFindingsList(topFindings, result.Findings.Count);

        var soarLine = soar.ActionsTaken > 0
            ? $"**{soar.ActionsTaken}** action(s)  ·  **{soar.ProcessesKilled}** killed  ·  **{soar.FilesQuarantined}** quarantined"
            : "_No automated actions taken._";

        var responseSummary =
            $"**SOAR:** {soarLine}\n" +
            $"**Quarantine:** {Trim(BuildQuarantineOutcome(soar), 180)}\n\n" +
            $"**Impact:** {impact.EstimatedImpact}\n" +
            $"**Risk Index:** {impact.RiskIndex}/100  ·  **Confidence:** {impact.ConfidencePercent}%\n\n" +
            Trim(impact.RecommendedActions, 350);

        // All fields must share IDENTICAL anonymous-type shape so C# infers a
        // typed array (new[]) rather than object[] — object[] causes STJ to
        // serialize every element as {} at runtime.
        var fields = new[]
        {
            new { name = "Critical", value = $"**{result.Summary.Critical}**",         inline = true  },
            new { name = "High",     value = $"**{result.Summary.High}**",             inline = true  },
            new { name = "Medium",   value = $"**{result.Summary.Medium}**",           inline = true  },
            new { name = "Low",      value = $"**{result.Summary.Low}**",              inline = true  },
            new { name = "Info",     value = $"**{result.Summary.Info}**",             inline = true  },
            new { name = "\u200b",   value = "\u200b",                                 inline = true  },
            new { name = "Alert Matrix",                   value = SafeField(summaryTable,    1024), inline = false },
            new { name = "Top Findings (Critical / High)", value = SafeField(findingsList,    1024), inline = false },
            new { name = "Response Summary",               value = SafeField(responseSummary, 1024), inline = false },
        };

        // Use JsonSerializer.Serialize with fully-typed anonymous types —
        // the same pattern the working test webhook uses.
        // No avatar_url or icon_url — those point to GitHub raw which Discord
        // validates at POST time and rejects if unreachable.
        return JsonSerializer.Serialize(new
        {
            username = "WRAITH",
            embeds   = new[]
            {
                new
                {
                    title       = $"THREAT LEVEL: {level}",
                    color,
                    description = $"Threat hunt completed on **{Trim(scanPath, 80)}** at **{result.Timestamp:yyyy-MM-dd HH:mm}**",
                    fields,
                    footer      = new { text = Footer },
                    timestamp   = ts,
                }
            }
        });
    }

    // ── Slack — Block Kit ───────────────────────────────────────────────────────

    private static string BuildSlackPayload(ScanResult result, AutomatedResponseReport soar, string scanPath)
    {
        var level = result.Summary.ThreatLevel?.ToUpperInvariant() ?? "UNKNOWN";
        var color = LevelToSlackColor(level);
        var impact = BuildImpactAnalysis(result, soar, scanPath);

        var topFindings = TopFindings(result);
        var findingsText = topFindings.Count > 0
            ? string.Join("\n", topFindings.Select(f =>
                $"• `{f.SeverityLabel}` *{Trim(f.Title, 55)}*  —  _{Trim(f.Path ?? f.Category, 70)}_"))
            : "_No critical/high findings._";

        var soarText = soar.ActionsTaken > 0
            ? $"*{soar.ActionsTaken}* action(s) taken  |  *{soar.ProcessesKilled}* process(es) killed  |  *{soar.FilesQuarantined}* file(s) quarantined"
            : "_No automated actions taken._";
        var quarantineOutcome = BuildQuarantineOutcome(soar);

        var impactText =
            $"*Estimated Impact:* {impact.EstimatedImpact}\n" +
            $"*Confidence:* {impact.ConfidencePercent}%\n" +
            $"*Primary Assets:* {impact.PrimaryAssets}\n" +
            $"*Risk Index:* {impact.RiskIndex}/100\n\n" +
            $"*Evidence:*\n{impact.EvidenceLines}";

        var blocks = new List<object>
        {
            new { type = "header", text = new { type = "plain_text", text = $"WRAITH  —  THREAT LEVEL: {level}", emoji = false } },
            new { type = "section", text = new { type = "mrkdwn",
                text = $"*Scan Target:*  `{Trim(scanPath, 90)}`\n*Scan Time:*  {result.Timestamp:yyyy-MM-dd HH:mm}\n*Scanner:*  WRAITH" } },
            new { type = "divider" },
            new
            {
                type   = "section",
                fields = new[]
                {
                    new { type = "mrkdwn", text = $"*Critical*\n{result.Summary.Critical}" },
                    new { type = "mrkdwn", text = $"*High*\n{result.Summary.High}"     },
                    new { type = "mrkdwn", text = $"*Medium*\n{result.Summary.Medium}" },
                    new { type = "mrkdwn", text = $"*Low*\n{result.Summary.Low}"       },
                    new { type = "mrkdwn", text = $"*Info*\n{result.Summary.Info}"     },
                }
            },
            new { type = "divider" },
            new { type = "section", text = new { type = "mrkdwn", text = $"*SOAR Response*\n{soarText}" } },
            new { type = "section", text = new { type = "mrkdwn", text = $"*Quarantine Outcome*\n{Trim(quarantineOutcome, 2500)}" } },
            new { type = "divider" },
            new { type = "section", text = new { type = "mrkdwn", text = $"*Impact Analysis*\n{Trim(impactText, 2500)}" } },
            new { type = "section", text = new { type = "mrkdwn", text = $"*Recommended Response*\n{Trim(impact.RecommendedActions, 2500)}" } },
            new { type = "divider" },
            new { type = "section", text = new { type = "mrkdwn", text = $"*Top Findings (Critical / High)*\n{findingsText}" } },
            new { type = "context", elements = new[] { new { type = "mrkdwn", text = Footer } } },
        };

        return JsonSerializer.Serialize(new
        {
            attachments = new[]
            {
                new { color, blocks }
            }
        });
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private static List<ThreatFinding> TopFindings(ScanResult result) =>
        result.Findings
              .Where(f => f.Severity is Severity.Critical or Severity.High)
              .OrderByDescending(f => f.Severity)
              .ThenByDescending(f => f.AnomalyScore)
              .Take(8)
              .ToList();

    private static string BuildDiscordSummaryTable(ScanResult result, AutomatedResponseReport soar)
    {
        var rows = new[]
        {
            ("THREAT", result.Summary.ThreatLevel),
            ("TOTAL", result.Summary.Total.ToString()),
            ("CRITICAL", result.Summary.Critical.ToString()),
            ("HIGH", result.Summary.High.ToString()),
            ("MEDIUM", result.Summary.Medium.ToString()),
            ("LOW", result.Summary.Low.ToString()),
            ("INFO", result.Summary.Info.ToString()),
            ("SOAR_ACTIONS", soar.ActionsTaken.ToString()),
            ("QUARANTINED", soar.FilesQuarantined.ToString()),
            ("KILLED", soar.ProcessesKilled.ToString())
        };

        var leftWidth = Math.Max("METRIC".Length, rows.Max(r => r.Item1.Length));
        var rightWidth = Math.Max("VALUE".Length, rows.Max(r => r.Item2.Length));

        // Use \n not AppendLine (\r\n) — Discord rejects \r\n in embed field values.
        var sb = new StringBuilder();
        sb.Append("```text\n");
        sb.Append($"+{new string('-', leftWidth + 2)}+{new string('-', rightWidth + 2)}+\n");
        sb.Append($"| {PadRight("METRIC", leftWidth)} | {PadRight("VALUE", rightWidth)} |\n");
        sb.Append($"+{new string('=', leftWidth + 2)}+{new string('=', rightWidth + 2)}+\n");
        foreach (var row in rows)
            sb.Append($"| {PadRight(row.Item1, leftWidth)} | {PadRight(row.Item2, rightWidth)} |\n");
        sb.Append($"+{new string('-', leftWidth + 2)}+{new string('-', rightWidth + 2)}+\n");
        sb.Append("```");
        return sb.ToString();
    }

    private static string BuildDiscordFindingsTable(List<ThreatFinding> findings)
    {
        if (findings.Count == 0)
            return "_No critical/high findings._";

        const int sevWidth = 8;
        const int catWidth = 14;
        const int titleWidth = 34;
        const int targetWidth = 42;

        var sb = new StringBuilder();
        sb.AppendLine("```text");
        sb.AppendLine($"+{new string('-', sevWidth + 2)}+{new string('-', catWidth + 2)}+{new string('-', titleWidth + 2)}+{new string('-', targetWidth + 2)}+");
        sb.AppendLine($"| {PadRight("SEV", sevWidth)} | {PadRight("CATEGORY", catWidth)} | {PadRight("TITLE", titleWidth)} | {PadRight("TARGET", targetWidth)} |");
        sb.AppendLine($"+{new string('=', sevWidth + 2)}+{new string('=', catWidth + 2)}+{new string('=', titleWidth + 2)}+{new string('=', targetWidth + 2)}+");

        foreach (var f in findings)
        {
            var category = string.IsNullOrWhiteSpace(f.Category)
                ? "unknown"
                : f.Category;
            var target = !string.IsNullOrWhiteSpace(f.Path)
                ? f.Path
                : string.IsNullOrWhiteSpace(f.Package) ? "n/a" : f.Package;

            sb.AppendLine(
                $"| {PadRight(Trim(f.SeverityLabel, sevWidth), sevWidth)} | " +
                $"{PadRight(Trim(category, catWidth), catWidth)} | " +
                $"{PadRight(Trim(f.Title, titleWidth), titleWidth)} | " +
                $"{PadRight(Trim(target, targetWidth), targetWidth)} |");
        }

        sb.Append($"+{new string('-', sevWidth + 2)}+{new string('-', catWidth + 2)}+{new string('-', titleWidth + 2)}+{new string('-', targetWidth + 2)}+\n");
        sb.Append("```");
        return sb.ToString();
    }

    private static string BuildDiscordFindingsList(List<ThreatFinding> findings, int totalCount = 0)
    {
        if (findings.Count == 0)
            return "_No critical/high findings._";

        var sb = new StringBuilder();
        foreach (var f in findings)
        {
            var target = !string.IsNullOrWhiteSpace(f.Path)
                ? f.Path
                : string.IsNullOrWhiteSpace(f.Package) ? "n/a" : f.Package;
            var category = string.IsNullOrWhiteSpace(f.Category) ? "unknown" : f.Category;
            sb.Append($"**[{f.SeverityLabel}]** {Trim(f.Title, 50)}  ·  `{Trim(category, 14)}`\n");
            sb.Append($"> `{Trim(target, 70)}`\n");
        }
        if (totalCount > findings.Count)
            sb.Append($"_… and {totalCount - findings.Count} more. Export full report for complete listing._");
        return sb.ToString().TrimEnd();
    }

    private static string PadRight(string value, int width)
    {
        if (value.Length >= width)
            return value;
        return value + new string(' ', width - value.Length);
    }

    private static string BuildQuarantineOutcome(AutomatedResponseReport soar)
    {
        var quarantined = soar.Messages
            .Where(m => m.StartsWith("File quarantined:", StringComparison.OrdinalIgnoreCase))
            .Take(4)
            .Select(m => $"- {Trim(m.Replace("File quarantined:", "", StringComparison.OrdinalIgnoreCase).Trim(), 140)}")
            .ToList();

        if (quarantined.Count > 0)
        {
            return $"Quarantined files: {soar.FilesQuarantined}\n" + string.Join("\n", quarantined);
        }

        var skips = soar.Messages
            .Where(m => m.StartsWith("Quarantine ", StringComparison.OrdinalIgnoreCase)
                     || m.StartsWith("Skip ", StringComparison.OrdinalIgnoreCase))
            .Take(4)
            .Select(m => $"- {Trim(m, 160)}")
            .ToList();

        if (skips.Count > 0)
        {
            return "No files were quarantined in this run. Top reasons:\n" + string.Join("\n", skips);
        }

        return "No quarantine actions were attempted for this run.";
    }

    private sealed class ImpactModel
    {
        public string EstimatedImpact { get; init; } = "Undetermined";
        public int ConfidencePercent { get; init; }
        public int RiskIndex { get; init; }
        public string PrimaryAssets { get; init; } = "N/A";
        public string EvidenceLines { get; init; } = "- Limited evidence available";
        public string RecommendedActions { get; init; } = "- Continue monitoring and validate suspicious indicators.";
    }

    private static ImpactModel BuildImpactAnalysis(ScanResult result, AutomatedResponseReport soar, string scanPath)
    {
        var findings = result.Findings ?? new List<ThreatFinding>();

        var persistenceHits = findings.Count(f => MatchesAny(f, "persistence", "autorun", "scheduled", "startup", "run key", "registry", "wmi", "service"));
        var executionHits = findings.Count(f =>
            f.IsLive || f.Pid.HasValue || !string.IsNullOrWhiteSpace(f.CommandLine) ||
            MatchesAny(f, "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "execution"));
        var defenseEvasionHits = findings.Count(f => MatchesAny(f, "defender", "tamper", "exclude", "disable", "bypass", "amsi"));
        var credentialHits = findings.Count(f => MatchesAny(f, "credential", "lsass", "sam", "token", "cookie", "browser", "vault", "dpapi"));
        var c2Hits = findings.Count(f => MatchesAny(f, "c2", "beacon", "dns", "network", "callback", "remote", "exfil"));

        var topAssets = findings
            .Select(GetAssetTag)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .GroupBy(s => s, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Take(3)
            .Select(g => g.Key)
            .ToList();

        var primaryAssets = topAssets.Count > 0 ? string.Join(", ", topAssets) : Trim(scanPath, 80);

        // Base score: Critical findings floor at 45 so a single critical always
        // reaches "Suspicious activity" — avoids the contradiction of a CRITICAL
        // threat level paired with a "low-confidence / continue validation" label.
        var risk = (result.Summary.Critical * 45)
                 + (result.Summary.High * 15)
                 + (result.Summary.Medium * 5)
                 + (result.Summary.Low * 2)
                 + (executionHits * 4)
                 + (persistenceHits * 6)
                 + (credentialHits * 7)
                 + (c2Hits * 7)
                 + (defenseEvasionHits * 5);
        risk = Math.Clamp(risk, 0, 100);

        var corroborating = executionHits + persistenceHits + credentialHits + c2Hits + defenseEvasionHits;
        var confidence = Math.Clamp(35
            + (result.Summary.Critical > 0 ? 25 : 0)
            + (result.Summary.High > 0 ? 10 : 0)
            + Math.Min(28, corroborating * 4), 0, 98);

        var impact = risk >= 85 ? "Potential host compromise with active persistence/execution indicators"
                 : risk >= 65 ? "Likely malicious activity with elevated operational risk"
                 : risk >= 45 ? "Suspicious activity detected — validate findings and prepare containment"
                 : "Low-severity anomalies — continue monitoring and run a full deep scan";

        var evidenceLines = new List<string>
        {
            $"- Critical/High findings: {result.Summary.Critical + result.Summary.High}",
            $"- Persistence indicators: {persistenceHits}",
            $"- Execution indicators: {executionHits}",
            $"- Defense evasion indicators: {defenseEvasionHits}",
            $"- Credential-access indicators: {credentialHits}",
            $"- C2/network indicators: {c2Hits}",
            $"- SOAR actions applied: {soar.ActionsTaken} (killed={soar.ProcessesKilled}, quarantined={soar.FilesQuarantined})"
        };

        var actions = new List<string>();
        // Only recommend network isolation when there is real corroborating evidence
        // alongside critical findings — avoids a false "isolate immediately" on a
        // single unconfirmed critical hit with no execution/C2/persistence context.
        if (result.Summary.Critical > 0 && (corroborating > 0 || result.Summary.Critical >= 2))
            actions.Add("- Isolate the endpoint from the network immediately.");
        else if (result.Summary.Critical > 0)
            actions.Add("- Treat as high-priority: validate the critical finding and monitor for further indicators before isolating.");
        if (executionHits > 0)
            actions.Add("- Triage live processes and collect volatile memory for forensic review.");
        if (persistenceHits > 0)
            actions.Add("- Audit and remove scheduled tasks, startup entries, and autoruns created recently.");
        if (credentialHits > 0)
            actions.Add("- Rotate impacted credentials, tokens, and browser/session secrets.");
        if (defenseEvasionHits > 0)
            actions.Add("- Verify Defender tamper protection and restore disabled protections.");
        if (c2Hits > 0)
            actions.Add("- Block suspected external destinations and review DNS/network telemetry.");
        if (actions.Count == 0)
            actions.Add("- Continue monitoring and run a full deep scan to validate indicators.");

        return new ImpactModel
        {
            EstimatedImpact = impact,
            ConfidencePercent = confidence,
            RiskIndex = risk,
            PrimaryAssets = primaryAssets,
            EvidenceLines = string.Join("\n", evidenceLines),
            RecommendedActions = string.Join("\n", actions.Take(5)),
        };
    }

    private static bool MatchesAny(ThreatFinding f, params string[] tokens)
    {
        var blob = string.Join(" ",
            f.Category ?? string.Empty,
            f.Subcategory ?? string.Empty,
            f.Title ?? string.Empty,
            f.Reason ?? string.Empty,
            f.Path ?? string.Empty,
            f.CommandLine ?? string.Empty,
            f.RuleName ?? string.Empty).ToLowerInvariant();

        foreach (var token in tokens)
        {
            if (blob.Contains(token, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string GetAssetTag(ThreatFinding f)
    {
        var path = (f.Path ?? string.Empty).Trim();
        if (path.Length >= 3 && path[1] == ':' && path[2] == '\\')
        {
            var rest = path[3..];
            var firstSlash = rest.IndexOf('\\');
            if (firstSlash > 0)
            {
                var top = rest[..firstSlash];
                return $"{char.ToUpperInvariant(path[0])}:\\{top}";
            }
            return $"{char.ToUpperInvariant(path[0])}:\\";
        }

        var category = string.IsNullOrWhiteSpace(f.Category) ? "unknown" : f.Category;
        var sub = string.IsNullOrWhiteSpace(f.Subcategory) ? "general" : f.Subcategory;
        return $"{category}/{sub}";
    }

    private static int LevelToDiscordColor(string level) => level switch
    {
        "CRITICAL" => DiscordColorCritical,
        "HIGH"     => DiscordColorHigh,
        "MEDIUM"   => DiscordColorMedium,
        "LOW"      => DiscordColorLow,
        _          => DiscordColorInfo,
    };

    private static string LevelToSlackColor(string level) => level switch
    {
        "CRITICAL" => SlackColorCritical,
        "HIGH"     => SlackColorHigh,
        "MEDIUM"   => SlackColorMedium,
        "LOW"      => SlackColorLow,
        _          => SlackColorInfo,
    };

    private static string Trim(string? value, int max)
    {
        var v = value ?? string.Empty;
        return v.Length <= max ? v : v[..max] + "…";
    }

    /// Discord hard-limits field values to 1024 chars.
    /// Truncate at 1023 so the appended ellipsis keeps total ≤ 1024.
    /// Also strip \r to avoid Discord rejecting \r\n line endings.
    private static string SafeField(string? value, int max)
    {
        var v = (value ?? string.Empty).Replace("\r\n", "\n").Replace("\r", "\n");
        if (v.Length <= max - 1) return v.Length > 0 ? v : "\u200b";
        return v[..(max - 1)] + "…";
    }

    // Debug log path — written next to the exe so it's always easy to find.
    private static readonly string _debugLog = System.IO.Path.Combine(
        AppContext.BaseDirectory, "wraith_webhook_debug.log");

    private static void WebhookLog(string line)
    {
        try
        {
            var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {line}{Environment.NewLine}";
            System.IO.File.AppendAllText(_debugLog, entry);
        }
        catch { /* never crash the app over logging */ }
    }

    private static async Task<(bool sent, string message)> PostWebhookAsync(
        string url, string payload, string channelName, CancellationToken ct)
    {
        // Append ?wait=true so Discord returns the full error body
        var postUrl = url.Contains('?') ? url + "&wait=true" : url + "?wait=true";

        WebhookLog($"=== {channelName} POST ===");
        WebhookLog($"URL  : {url[..Math.Min(80, url.Length)]}");
        WebhookLog($"LEN  : {payload.Length} bytes");
        WebhookLog($"BODY : {payload}");

        try
        {
            using var http = MakeWebhookClient();
            using var req  = new HttpRequestMessage(HttpMethod.Post, postUrl)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };

            using var res = await http.SendAsync(req, ct);
            var body = await res.Content.ReadAsStringAsync(CancellationToken.None);

            WebhookLog($"HTTP : {(int)res.StatusCode} {res.ReasonPhrase}");
            WebhookLog($"RESP : {body}");

            if (!res.IsSuccessStatusCode)
            {
                var detail = string.IsNullOrWhiteSpace(body) ? string.Empty : $" — {body[..Math.Min(400, body.Length)]}";
                return (false, $"{channelName} HTTP {(int)res.StatusCode}{detail}");
            }

            WebhookLog("OK");
            return (true, $"{channelName} alert sent");
        }
        catch (OperationCanceledException)
        {
            WebhookLog("CANCELLED");
            return (false, $"{channelName} POST timed out or cancelled");
        }
        catch (Exception ex)
        {
            WebhookLog($"EXCEPTION: {ex}");
            return (false, $"{channelName} POST failed: {ex.Message}");
        }
    }
}
