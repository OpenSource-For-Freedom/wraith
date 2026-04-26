using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using WRAITH.Models;

namespace WRAITH.Services;

public sealed class ResponsePolicy
{
    public bool AutoContainmentEnabled { get; set; } = true;
    public bool AutoKillLiveProcess { get; set; } = true;
    public bool AutoQuarantineFile { get; set; }
    public bool AutoQuarantineCritical { get; set; } = true;
    public int MaxActionsPerScan { get; set; } = 3;
    public double MinAnomalyScoreForAction { get; set; } = 85.0;

    public string[] TrustedPathPrefixes { get; set; } =
    [
        @"C:\Windows\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
    ];

    public string[] TrustedSignerKeywords { get; set; } =
    [
        "Microsoft Corporation",
        "Google LLC",
        "Apple Inc.",
        "Lenovo",
        "NVIDIA",
        "Intel",
    ];

    // Alerting controls
    public bool EnableSlackWebhook { get; set; }
    public string SlackWebhookUrl { get; set; } = string.Empty;
    public bool SlackNotifyOnHigh { get; set; } = true;
    public bool EnableDiscordWebhook { get; set; }
    public string DiscordWebhookUrl { get; set; } = string.Empty;
    public bool DiscordNotifyOnHigh { get; set; } = true;
}

public sealed class AutomatedResponseReport
{
    public int ActionsTaken { get; set; }
    public int ProcessesKilled { get; set; }
    public int FilesQuarantined { get; set; }
    public List<string> Messages { get; } = new();
}

public sealed class AutomatedResponseService
{
    private readonly QuarantineService _quarantine;
    private readonly string _policyFile;

    public AutomatedResponseService(QuarantineService quarantine)
    {
        _quarantine = quarantine;
        var baseDir = BootstrapService.ResolveBaseDir();
        _policyFile = Path.Combine(baseDir, "wraith.policy.json");
    }

    public ResponsePolicy LoadPolicy()
    {
        try
        {
            if (!File.Exists(_policyFile))
            {
                var def = new ResponsePolicy();
                SavePolicy(def);
                return def;
            }

            var json = File.ReadAllText(_policyFile);
            var loaded = JsonSerializer.Deserialize<ResponsePolicy>(json);
            return loaded ?? new ResponsePolicy();
        }
        catch
        {
            return new ResponsePolicy();
        }
    }

    public void SavePolicy(ResponsePolicy policy)
    {
        var json = JsonSerializer.Serialize(policy, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_policyFile, json);
    }

    public async Task<AutomatedResponseReport> ApplyAsync(IEnumerable<ThreatFinding> findings, CancellationToken ct = default)
    {
        var report = new AutomatedResponseReport();
        var policy = LoadPolicy();

        if (!policy.AutoContainmentEnabled)
        {
            report.Messages.Add("Auto containment is disabled in wraith.policy.json");
            return report;
        }

        var ordered = findings
            .Where(f => f.Severity is Severity.Critical or Severity.High)
            .OrderByDescending(f => f.Severity)
            .ThenByDescending(f => f.AnomalyScore)
            .ToList();

        foreach (var finding in ordered)
        {
            if (ct.IsCancellationRequested)
                break;

            var isCritical = finding.Severity == Severity.Critical;
            var forceCriticalContainment = isCritical && policy.AutoQuarantineCritical;

            // Critical containment is not capped by MaxActionsPerScan.
            if (!forceCriticalContainment && report.ActionsTaken >= policy.MaxActionsPerScan)
                break;

            var containmentPath = ResolveContainmentPath(finding);
            var shouldAutoQuarantine =
                forceCriticalContainment ||
                (finding.Severity == Severity.High && policy.AutoQuarantineFile);

            if (!forceCriticalContainment && finding.AnomalyScore < policy.MinAnomalyScoreForAction)
            {
                report.Messages.Add($"Skip (low confidence): {finding.Title} score={finding.AnomalyScore:F1}");
                continue;
            }

            // Trusted path/signer gates apply to ALL severities including Critical.
            // Without this, legitimate Microsoft-signed binaries in system paths
            // get quarantined as false positives (e.g. CognitiveServices Speech SDK,
            // Windows SDIAG audio diagnostics DLLs).
            if (!string.IsNullOrWhiteSpace(containmentPath) && IsTrustedPath(containmentPath, policy))
            {
                report.Messages.Add($"Skip (trusted path): {containmentPath}");
                continue;
            }

            var signer = GetSignerSubject(containmentPath);
            if (!string.IsNullOrWhiteSpace(signer) && IsTrustedSigner(signer, policy))
            {
                report.Messages.Add($"Skip (trusted signer): {signer} :: {containmentPath}");
                continue;
            }

            if (policy.AutoKillLiveProcess && finding.Pid.HasValue)
            {
                if (TryKillProcess(finding.Pid.Value))
                {
                    report.ActionsTaken++;
                    report.ProcessesKilled++;
                    report.Messages.Add($"Process killed: PID {finding.Pid.Value} :: {finding.Title}");
                }
                else if (forceCriticalContainment)
                {
                    report.Messages.Add($"Critical process kill failed: PID {finding.Pid.Value} :: {finding.Title}");
                }
            }

            if (!shouldAutoQuarantine)
                continue;

            if (string.IsNullOrWhiteSpace(containmentPath))
            {
                report.Messages.Add($"Quarantine skipped (no file path): {finding.Title}");
                continue;
            }

            if (!File.Exists(containmentPath))
            {
                report.Messages.Add($"Quarantine skipped (file missing): {containmentPath}");
                continue;
            }

            try
            {
                var rec = _quarantine.QuarantineFile(containmentPath, finding.Reason, finding.Severity.ToString());
                report.ActionsTaken++;
                report.FilesQuarantined++;
                report.Messages.Add($"File quarantined: {rec.OriginalPath} -> {Path.GetFileName(rec.QuarantinedPath)}");
            }
            catch (Exception ex)
            {
                report.Messages.Add($"Quarantine failed: {containmentPath} :: {ex.Message}");
            }
        }

        await Task.CompletedTask;
        return report;
    }

    private static bool TryKillProcess(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.HasExited) return false;
            p.Kill(entireProcessTree: true);
            p.WaitForExit(3000);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveContainmentPath(ThreatFinding finding)
    {
        var fromPath = NormalizePotentialPath(finding.Path);
        if (!string.IsNullOrWhiteSpace(fromPath))
            return fromPath;

        var fromCmd = NormalizePotentialPath(ExtractExecutablePath(finding.CommandLine));
        if (!string.IsNullOrWhiteSpace(fromCmd))
            return fromCmd;

        return string.Empty;
    }

    private static string NormalizePotentialPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var path = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));

        if (path.StartsWith(@"\\??\"))
            path = path[4..];
        else if (path.StartsWith(@"\??\"))
            path = path[4..];

        if (path.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) > 0)
        {
            var idx = path.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            path = path[..(idx + 4)].Trim().Trim('"');
        }

        return path;
    }

    private static string ExtractExecutablePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return string.Empty;
        var text = commandLine.Trim();

        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            if (end > 1) return text[1..end];
        }

        var exeIdx = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
            return text[..(exeIdx + 4)].Trim();

        return string.Empty;
    }

    private static string GetSignerSubject(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return string.Empty;
            var cert = X509Certificate.CreateFromSignedFile(path);
            return cert?.Subject ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static bool IsTrustedPath(string path, ResponsePolicy policy)
    {
        var p = path.Replace('/', '\\').ToLowerInvariant();
        return policy.TrustedPathPrefixes.Any(prefix =>
        {
            if (string.IsNullOrWhiteSpace(prefix)) return false;
            // Expand environment variables so entries like %USERPROFILE% work
            var expanded = Environment.ExpandEnvironmentVariables(prefix)
                                      .Replace('/', '\\')
                                      .ToLowerInvariant();
            return p.StartsWith(expanded);
        });
    }

    private static bool IsTrustedSigner(string signerSubject, ResponsePolicy policy)
    {
        return policy.TrustedSignerKeywords.Any(k => !string.IsNullOrWhiteSpace(k) && signerSubject.Contains(k, StringComparison.OrdinalIgnoreCase));
    }
}
