using System.Security.Cryptography;
using System.Security.Principal;
using System.IO;
using System.Text.Json;

namespace WRAITH.Services;

public sealed class QuarantineRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinedPath { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public DateTime QuarantinedAtUtc { get; set; } = DateTime.UtcNow;
    public string Reason { get; set; } = string.Empty;
    public bool Deleted { get; set; }
    public string Severity { get; set; } = "Info";  // Critical, High, Medium, Low, Info
}

public sealed class QuarantineService
{
    private readonly string _vaultDir;
    private readonly string _indexFile;
    private readonly object _sync = new();

    public QuarantineService()
    {
        _vaultDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WRAITH", "Quarantine");
        _indexFile = Path.Combine(_vaultDir, "quarantine-index.json");
        Directory.CreateDirectory(_vaultDir);
    }

    public string VaultDirectory => _vaultDir;

    public IReadOnlyList<QuarantineRecord> GetRecords()
    {
        lock (_sync)
        {
            return LoadIndex().OrderByDescending(x => x.QuarantinedAtUtc).ToList();
        }
    }

    public QuarantineRecord QuarantineFile(string filePath, string reason, string severity = "Info")
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("file path is required", nameof(filePath));
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found", filePath);

        lock (_sync)
        {
            var id = Guid.NewGuid().ToString("N");
            var fileName = Path.GetFileName(filePath);
            var safeName = $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{id}_{fileName}";
            var dest = Path.Combine(_vaultDir, safeName);

            File.Move(filePath, dest);

            var rec = new QuarantineRecord
            {
                Id = id,
                OriginalPath = filePath,
                QuarantinedPath = dest,
                Sha256 = ComputeSha256(dest),
                QuarantinedAtUtc = DateTime.UtcNow,
                Reason = reason,
                Deleted = false,
                Severity = severity,
            };

            var index = LoadIndex();
            index.Add(rec);
            SaveIndex(index);
            return rec;
        }
    }

    public bool Restore(string id, out string restoredPath)
    {
        restoredPath = string.Empty;
        if (string.IsNullOrWhiteSpace(id)) return false;

        lock (_sync)
        {
            var index = LoadIndex();
            var rec = index.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (rec == null || rec.Deleted || !File.Exists(rec.QuarantinedPath)) return false;

            var targetDir = Path.GetDirectoryName(rec.OriginalPath);
            if (string.IsNullOrWhiteSpace(targetDir)) return false;
            Directory.CreateDirectory(targetDir);

            var target = rec.OriginalPath;
            if (File.Exists(target))
            {
                var baseName = Path.GetFileNameWithoutExtension(target);
                var ext = Path.GetExtension(target);
                target = Path.Combine(targetDir, $"{baseName}_restored_{DateTime.Now:yyyyMMdd_HHmmss}{ext}");
            }

            File.Move(rec.QuarantinedPath, target);
            restoredPath = target;
            rec.QuarantinedPath = string.Empty;
            SaveIndex(index);
            return true;
        }
    }

    public bool DeleteFromVault(string id, bool requireAdmin = true)
    {
        if (string.IsNullOrWhiteSpace(id)) return false;
        if (requireAdmin && !IsAdministrator())
            throw new UnauthorizedAccessException("Administrator privileges are required to permanently delete quarantined items.");

        lock (_sync)
        {
            var index = LoadIndex();
            var rec = index.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (rec == null) return false;

            if (!string.IsNullOrWhiteSpace(rec.QuarantinedPath) && File.Exists(rec.QuarantinedPath))
                File.Delete(rec.QuarantinedPath);

            rec.Deleted = true;
            rec.QuarantinedPath = string.Empty;
            SaveIndex(index);
            return true;
        }
    }

    public static bool IsAdministrator()
    {
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private List<QuarantineRecord> LoadIndex()
    {
        try
        {
            if (!File.Exists(_indexFile)) return new List<QuarantineRecord>();
            var json = File.ReadAllText(_indexFile);
            var data = JsonSerializer.Deserialize<List<QuarantineRecord>>(json);
            return data ?? new List<QuarantineRecord>();
        }
        catch
        {
            return new List<QuarantineRecord>();
        }
    }

    private void SaveIndex(List<QuarantineRecord> records)
    {
        var json = JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_indexFile, json);
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }
}
