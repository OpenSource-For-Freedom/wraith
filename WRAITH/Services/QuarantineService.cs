using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

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
    public bool Restored { get; set; }
    /// <summary>True when the original file was locked and is scheduled for deletion at next boot.</summary>
    public bool PendingRebootDelete { get; set; }
    public string Severity { get; set; } = "Info";  // Critical, High, Medium, Low, Info

    /// <summary>Computed lifecycle state for the UI — never serialised.</summary>
    [JsonIgnore]
    public string State =>
        Deleted             ? "Deleted"
        : Restored          ? "Restored"
        : PendingRebootDelete ? "Pending Reboot"
                              : "Quarantined";
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

            bool pendingReboot = false;
            try
            {
                File.Move(sourcePath, dest);
            }
            catch (IOException)
            {
                // Source is locked (mapped into a running process, AV scanner open handle, etc.).
                // Copy the bytes into the vault so we can still hash/contain them, then schedule
                // the original for deletion at next reboot. Without this fallback the most
                // important case (active malware) just fails outright.
                CopyWithSharedAccess(sourcePath, dest);

                if (!TryDeleteFile(sourcePath))
                {
                    if (!MoveFileEx(sourcePath, null, MOVEFILE_DELAY_UNTIL_REBOOT))
                    {
                        var err = Marshal.GetLastWin32Error();
                        // Vault copy succeeded but we couldn't even schedule the delete.
                        // Roll back the vault copy so we don't leak duplicates.
                        TryDeleteFile(dest);
                        throw new IOException(
                            $"File is locked and could not be scheduled for reboot deletion (Win32 error {err}).");
                    }
                    pendingReboot = true;
                }
            }

            var rec = new QuarantineRecord
            {
                Id = id,
                OriginalPath = sourcePath,
                QuarantinedPath = dest,
                Sha256 = ComputeSha256(dest),
                QuarantinedAtUtc = DateTime.UtcNow,
                Reason = reason,
                Deleted = false,
                Restored = false,
                PendingRebootDelete = pendingReboot,
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
            rec.Restored = true;
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

            // No-op deletes (already restored/deleted) should report false so the
            // UI counter reflects what actually happened on disk.
            if (rec.Deleted || rec.Restored || string.IsNullOrWhiteSpace(rec.QuarantinedPath))
                return false;

            var quarantinedPath = NormalizeFullPath(rec.QuarantinedPath);
            if (!IsUnderRoot(quarantinedPath, _vaultDir) || !File.Exists(quarantinedPath))
                return false;

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
        // Write to a sibling temp file and atomically swap. A crash during the
        // write must never leave the live index truncated — that would make the
        // whole vault appear empty even though the files still exist on disk.
        var tmp = _indexFile + ".tmp";
        File.WriteAllText(tmp, json);

        if (File.Exists(_indexFile))
            File.Replace(tmp, _indexFile, destinationBackupFileName: null);
        else
            File.Move(tmp, _indexFile);
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }

    private static void CopyWithSharedAccess(string source, string dest)
    {
        // Permissive share flags so we can read a file that's currently mapped
        // into a running process. The destination is a fresh file in the vault,
        // so CreateNew + FileShare.None is correct there.
        using var src = new FileStream(source, FileMode.Open, FileAccess.Read,
                                       FileShare.ReadWrite | FileShare.Delete);
        using var dst = new FileStream(dest, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        src.CopyTo(dst);
    }

    private static bool TryDeleteFile(string path)
    {
        try { File.Delete(path); return true; }
        catch { return false; }
    }

    // ── Win32 fallback for locked sources ────────────────────────────────────
    // Passing null for lpNewFileName with MOVEFILE_DELAY_UNTIL_REBOOT instructs
    // the Session Manager (smss.exe) to delete the file on next boot before any
    // user process can re-open it. Requires admin — the app manifest guarantees
    // that here.
    private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);
}
