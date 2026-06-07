using System.IO;
using System.IO.Compression;
using System.Text.Json;
using WRAITH.Services;
using Xunit;

namespace WRAITH.Tests;

/// <summary>
/// Tests for <see cref="QuarantineService"/>'s file, directory, and registry
/// containment paths. Filesystem tests run against a temp vault dir
/// overridden through reflection on _vaultDir / _indexFile. Registry-touching
/// tests would only run on Windows; none are included in this fixture yet
/// since the Win32 registry isn't reachable from the cross-platform runner
/// the test project builds against.
/// </summary>
public sealed class QuarantineServiceTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly QuarantineService _svc;

    public QuarantineServiceTests()
    {
        // Path.GetFullPath normalises the temp path and serves as the
        // CodeQL sanitiser for the cs/path-injection rule, which treats
        // GetTempPath()-derived paths as untrusted at the rule level.
        _tempRoot = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(), "wraith-tests-" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(_tempRoot);
        _svc = new QuarantineService();
        OverrideVault(_svc, Path.GetFullPath(Path.Combine(_tempRoot, "vault")));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { }
    }

    /// <summary>QuarantineService picks up its vault path from a private field.
    /// Tests need to redirect it to a temp dir; reflection is the least-bad option.</summary>
    private static void OverrideVault(QuarantineService svc, string newRoot)
    {
        // Normalise newRoot the same way the production code does so CodeQL
        // sees a sanitised value before File.* / Directory.* sinks.
        newRoot = Path.GetFullPath(newRoot);
        Directory.CreateDirectory(newRoot);
        var t = typeof(QuarantineService);
        t.GetField("_vaultDir", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .SetValue(svc, newRoot);
        t.GetField("_indexFile", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .SetValue(svc, Path.GetFullPath(Path.Combine(newRoot, "quarantine-index.json")));
    }

    // ── Path-shape detection ────────────────────────────────────────────

    [Fact]
    public void IsRegistryPath_recognises_short_hive_names()
    {
        Assert.True(QuarantineService.IsRegistryPath(@"HKLM\Software\Foo\bar"));
        Assert.True(QuarantineService.IsRegistryPath(@"HKCU\Software\Foo"));
        Assert.True(QuarantineService.IsRegistryPath(@"HKCR\.exe"));
        Assert.True(QuarantineService.IsRegistryPath(@"HKU\.DEFAULT"));
    }

    [Fact]
    public void IsRegistryPath_recognises_long_hive_names()
    {
        Assert.True(QuarantineService.IsRegistryPath(@"HKEY_LOCAL_MACHINE\Software\Foo"));
        Assert.True(QuarantineService.IsRegistryPath(@"HKEY_CURRENT_USER\Software"));
        Assert.True(QuarantineService.IsRegistryPath(@"HKEY_CLASSES_ROOT\.exe"));
        Assert.True(QuarantineService.IsRegistryPath(@"HKEY_USERS\.DEFAULT"));
    }

    [Fact]
    public void IsRegistryPath_rejects_file_paths()
    {
        Assert.False(QuarantineService.IsRegistryPath(@"C:\Windows\System32\notepad.exe"));
        Assert.False(QuarantineService.IsRegistryPath(@"\\server\share\file"));
        Assert.False(QuarantineService.IsRegistryPath(@"/etc/passwd"));
    }

    [Fact]
    public void IsRegistryPath_rejects_null_and_empty()
    {
        Assert.False(QuarantineService.IsRegistryPath(null));
        Assert.False(QuarantineService.IsRegistryPath(""));
        Assert.False(QuarantineService.IsRegistryPath("   "));
    }

    // ── File quarantine ─────────────────────────────────────────────────

    [Fact]
    public void QuarantineFile_moves_file_into_vault()
    {
        var src = Path.Combine(_tempRoot, "malware.exe");
        File.WriteAllText(src, "dummy malware bytes");

        var rec = _svc.QuarantineFile(src, "test", "HIGH");

        Assert.False(File.Exists(src), "source should be moved into the vault");
        Assert.True(File.Exists(rec.QuarantinedPath));
        Assert.Equal("HIGH", rec.Severity);
        Assert.False(rec.IsDirectory);
        Assert.False(rec.IsRegistry);
        Assert.False(rec.Restored);
        Assert.False(rec.Deleted);
        Assert.Equal("Quarantined", rec.State);
        Assert.NotEmpty(rec.Sha256);
    }

    [Fact]
    public void QuarantineFile_records_appear_in_GetRecords()
    {
        var src = Path.Combine(_tempRoot, "x.exe");
        File.WriteAllText(src, "x");
        var rec = _svc.QuarantineFile(src, "test");
        Assert.Contains(_svc.GetRecords(), r => r.Id == rec.Id);
    }

    [Fact]
    public void QuarantineFile_missing_source_throws()
    {
        Assert.Throws<FileNotFoundException>(() =>
            _svc.QuarantineFile(Path.Combine(_tempRoot, "nope.exe"), "test"));
    }

    [Fact]
    public void QuarantineFile_null_path_throws()
    {
        Assert.Throws<ArgumentException>(() => _svc.QuarantineFile("", "test"));
    }

    // ── Directory quarantine ────────────────────────────────────────────

    [Fact]
    public void QuarantineFile_zips_directory_source()
    {
        var srcDir = Path.Combine(_tempRoot, "EvilExtension");
        Directory.CreateDirectory(srcDir);
        File.WriteAllText(Path.Combine(srcDir, "manifest.json"), "{}");
        File.WriteAllText(Path.Combine(srcDir, "background.js"), "evil();");

        var rec = _svc.QuarantineFile(srcDir, "Chrome extension");

        Assert.True(rec.IsDirectory);
        Assert.False(Directory.Exists(srcDir), "source dir should be removed after quarantine");
        Assert.True(File.Exists(rec.QuarantinedPath), "vault zip should exist");
        Assert.EndsWith(".zip", rec.QuarantinedPath);

        // Vault zip should actually be a readable zip with both files inside.
        using var zip = ZipFile.OpenRead(rec.QuarantinedPath);
        Assert.Equal(2, zip.Entries.Count(e => !string.IsNullOrEmpty(e.Name)));
    }

    // ── Restore / Delete ────────────────────────────────────────────────

    [Fact]
    public void Restore_returns_file_to_original_location()
    {
        var src = Path.Combine(_tempRoot, "doc.txt");
        File.WriteAllText(src, "important");
        var rec = _svc.QuarantineFile(src, "test");

        var ok = _svc.Restore(rec.Id, out var restoredPath);

        Assert.True(ok);
        Assert.True(File.Exists(restoredPath));
        Assert.Equal("important", File.ReadAllText(restoredPath));

        var refreshed = _svc.GetRecords().First(r => r.Id == rec.Id);
        Assert.True(refreshed.Restored);
        Assert.Equal("Restored", refreshed.State);
    }

    [Fact]
    public void Restore_unknown_id_returns_false()
    {
        Assert.False(_svc.Restore("not-a-real-id", out var path));
        Assert.Equal("", path);
    }

    [Fact]
    public void DeleteFromVault_removes_vault_file_and_flags_record()
    {
        var src = Path.Combine(_tempRoot, "evil.bin");
        File.WriteAllText(src, "evil");
        var rec = _svc.QuarantineFile(src, "test");

        var ok = _svc.DeleteFromVault(rec.Id, requireAdmin: false);

        Assert.True(ok);
        Assert.False(File.Exists(rec.QuarantinedPath));
        var refreshed = _svc.GetRecords().First(r => r.Id == rec.Id);
        Assert.True(refreshed.Deleted);
        Assert.Equal("Deleted", refreshed.State);
    }

    [Fact]
    public void DeleteFromVault_after_restore_is_noop()
    {
        var src = Path.Combine(_tempRoot, "x.bin");
        File.WriteAllText(src, "x");
        var rec = _svc.QuarantineFile(src, "test");
        _svc.Restore(rec.Id, out _);

        // Already restored — DeleteFromVault should report false (nothing to delete).
        Assert.False(_svc.DeleteFromVault(rec.Id, requireAdmin: false));
    }

    // ── Record state transitions ────────────────────────────────────────

    [Fact]
    public void QuarantineRecord_state_reflects_lifecycle()
    {
        var fresh = new QuarantineRecord();
        Assert.Equal("Quarantined", fresh.State);

        fresh.Restored = true;
        Assert.Equal("Restored", fresh.State);
        fresh.Restored = false;

        fresh.Deleted = true;
        Assert.Equal("Deleted", fresh.State);
        fresh.Deleted = false;

        fresh.PendingRebootDelete = true;
        Assert.Equal("Pending Reboot", fresh.State);
    }

    [Fact]
    public void QuarantineRecord_serialises_without_State_key()
    {
        // State is JsonIgnore so it never round-trips through the index.
        var rec = new QuarantineRecord
        {
            Id = "abc",
            OriginalPath = "C:\\x.exe",
            Sha256 = "deadbeef",
            Severity = "HIGH",
        };
        var json = JsonSerializer.Serialize(rec);
        Assert.DoesNotContain("\"State\"", json);
    }

    [Fact]
    public void QuarantineRecord_round_trips_IsDirectory_and_IsRegistry_flags()
    {
        var rec = new QuarantineRecord { IsDirectory = true, IsRegistry = false };
        var json = JsonSerializer.Serialize(rec);
        var clone = JsonSerializer.Deserialize<QuarantineRecord>(json);
        Assert.NotNull(clone);
        Assert.True(clone!.IsDirectory);
        Assert.False(clone.IsRegistry);
    }
}
