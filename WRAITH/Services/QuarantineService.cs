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

    private static string NormalizeFullPath(string path)
    {
        return Path.GetFullPath(path);
    }

    private static bool IsUnderRoot(string fullPath, string rootPath)
    {
        var full = NormalizeFullPath(fullPath);
        var root = NormalizeFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                   + Path.DirectorySeparatorChar;
        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

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
        var sourcePath = NormalizeFullPath(filePath);
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("File not found", sourcePath);

        lock (_sync)
        {
            var id = Guid.NewGuid().ToString("N");
            var fileName = Path.GetFileName(sourcePath);
            var safeName = $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{id}_{fileName}";
            var dest = NormalizeFullPath(Path.Combine(_vaultDir, safeName));

            if (!IsUnderRoot(dest, _vaultDir))
                throw new InvalidOperationException("Resolved quarantine destination is outside the vault directory.");

            File.Move(sourcePath, dest);

            var rec = new QuarantineRecord
            {
                Id = id,
                OriginalPath = sourcePath,
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
            if (rec == null || rec.Deleted) return false;

            var quarantinedPath = string.IsNullOrWhiteSpace(rec.QuarantinedPath)
                ? string.Empty
                : NormalizeFullPath(rec.QuarantinedPath);
            if (string.IsNullOrWhiteSpace(quarantinedPath) || !IsUnderRoot(quarantinedPath, _vaultDir) || !File.Exists(quarantinedPath))
                return false;

            var originalPath = string.IsNullOrWhiteSpace(rec.OriginalPath)
                ? string.Empty
                : NormalizeFullPath(rec.OriginalPath);
            if (string.IsNullOrWhiteSpace(originalPath))
                return false;

            var targetDir = Path.GetDirectoryName(originalPath);
            if (string.IsNullOrWhiteSpace(targetDir)) return false;
            Directory.CreateDirectory(targetDir);

            var target = originalPath;
            if (File.Exists(target))
            {
                var baseName = Path.GetFileNameWithoutExtension(target);
                var ext = Path.GetExtension(target);
                target = Path.Combine(targetDir, $"{baseName}_restored_{DateTime.Now:yyyyMMdd_HHmmss}{ext}");
            }

            target = NormalizeFullPath(target);

            File.Move(quarantinedPath, target);
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

            var quarantinedPath = string.IsNullOrWhiteSpace(rec.QuarantinedPath)
                ? string.Empty
                : NormalizeFullPath(rec.QuarantinedPath);
            if (!string.IsNullOrWhiteSpace(quarantinedPath) && IsUnderRoot(quarantinedPath, _vaultDir) && File.Exists(quarantinedPath))
                File.Delete(quarantinedPath);

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
