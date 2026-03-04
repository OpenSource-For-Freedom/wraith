using System.Net;
using System.Text;
using System.Text.Json;
using WRAITH.Models;

namespace WRAITH.Services;

public class ReportExporter
{
    public void ExportJson(ScanResult result, string filePath)
    {
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        System.IO.File.WriteAllText(filePath, json, Encoding.UTF8);
    }

    public void ExportCsv(ScanResult result, string filePath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Severity,Category,Subcategory,Title,Path,Reason,RuleName,Package,EventId,Pid,Entropy,ProcessStatus,LastRunTime");
        foreach (var f in result.Findings.OrderByDescending(x => x.Severity))
        {
            sb.AppendLine(string.Join(",",
                Q(f.SeverityLabel),
                Q(f.Category),
                Q(f.Subcategory),
                Q(f.Title),
                Q(f.Path),
                Q(f.Reason),
                Q(f.RuleName  ?? ""),
                Q(f.Package   ?? ""),
                Q(f.EventId?.ToString() ?? ""),
                Q(f.Pid?.ToString()     ?? ""),
                Q(f.Entropy?.ToString("F3") ?? ""),
                Q(f.ProcessStatus ?? ""),
                Q(f.LastRunTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "")
            ));
        }
        System.IO.File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
    }

    public void ExportHtml(ScanResult result, string filePath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        sb.AppendLine("<title>WRAITH Scan Report</title>");
        sb.AppendLine(HtmlStyle());
        sb.AppendLine("</head><body>");
        sb.AppendLine($"<div class='header'><h1>⚡ WRAITH — Expecto Patronum Threat Report</h1>");
        sb.AppendLine($"<p>Generated: {result.Timestamp:yyyy-MM-dd HH:mm:ss} &nbsp;|&nbsp; Mode: {result.Mode}</p>");
        sb.AppendLine($"<div class='summary'>");
        sb.AppendLine($"  <span class='badge critical'>CRITICAL: {result.Summary.Critical}</span>");
        sb.AppendLine($"  <span class='badge high'>HIGH: {result.Summary.High}</span>");
        sb.AppendLine($"  <span class='badge medium'>MEDIUM: {result.Summary.Medium}</span>");
        sb.AppendLine($"  <span class='badge low'>LOW: {result.Summary.Low}</span>");
        sb.AppendLine($"  <span class='badge info'>TOTAL: {result.Summary.Total}</span>");
        sb.AppendLine("</div></div>");
        sb.AppendLine("<table><thead><tr>");
        sb.AppendLine("<th>Severity</th><th>Category</th><th>Title</th><th>Status</th><th>Last Run</th><th>Path</th><th>Reason</th>");
        sb.AppendLine("</tr></thead><tbody>");
        foreach (var f in result.Findings.OrderByDescending(x => x.Severity))
        {
            var cls    = f.Severity.ToString().ToLower();
            var status = f.ProcessStatus ?? "";
            var statCls = status == "LIVE" ? "live" : status == "TASK" ? "task" : "";
            sb.AppendLine($"<tr class='{cls}'>");
            sb.AppendLine($"<td><span class='badge {cls}'>{f.SeverityLabel}</span></td>");
            sb.AppendLine($"<td>{H(f.Category)}/{H(f.Subcategory)}</td>");
            sb.AppendLine($"<td>{H(f.Title)}</td>");
            sb.AppendLine($"<td>{(string.IsNullOrEmpty(status) ? "" : $"<span class='badge {statCls}'>{H(status)}</span>")}</td>");
            sb.AppendLine($"<td class='mono'>{H(f.LastRunTime?.ToString("yyyy-MM-dd HH:mm") ?? "")}</td>");
            sb.AppendLine($"<td class='path'>{H(f.Path)}</td>");
            sb.AppendLine($"<td>{H(f.Reason)}</td>");
            sb.AppendLine("</tr>");
        }
        sb.AppendLine("</tbody></table></body></html>");
        System.IO.File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
    }

    private static string Q(string? s) => $"\"{s?.Replace("\"", "\"\"") ?? ""}\"";
    private static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

    private static string HtmlStyle() => @"<style>
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e5e7eb;margin:0;padding:20px}
.header{background:#1e293b;padding:20px;border-radius:8px;margin-bottom:20px}
h1{color:#a8c8e8;margin:0 0 8px}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.badge.live{background:#00c853;color:#002;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:bold}
.badge.task{background:#ffc107;color:#120;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:bold}
.mono{font-family:Consolas,monospace;font-size:11px;color:#b8a040}
table{width:100%;border-collapse:collapse;background:#111827;border-radius:8px;overflow:hidden}
th{background:#0f172a;color:#9ca3af;padding:10px;text-align:left;font-size:12px}
td{padding:8px 10px;border-bottom:1px solid #374151;font-size:13px;vertical-align:top}
td.path{font-family:monospace;font-size:11px;color:#93c5fd;word-break:break-all}
tr:hover{background:#1e293b}
.badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}
.badge.critical,.critical td{color:#fff;background:#dc2626}
.badge.high{background:#ea580c;color:#fff}
.badge.medium{background:#d97706;color:#1a1400}
.badge.low{background:#2563eb;color:#fff}
.badge.info{background:#374151;color:#9ca3af}
</style>";
}
