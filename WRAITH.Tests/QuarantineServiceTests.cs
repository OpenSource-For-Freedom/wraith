using System.IO;
using System.IO.Compression;
using System.Text.Json;
using WRAITH.Services;
using Xunit;

namespace WRAITH.Tests;

/// <summary>
/// Tests for <see cref="QuarantineService"/>'s file, directory, and registry
/// path-shape detection plus the vault lifecycle (move / restore / delete /
/// state transitions). The test project targets <c>net8.0-windows</c> so the
/// fixture is Windows-only at build/run time; registry-touching scenarios
/// aren't covered here yet but the registry-path **detection** is.
/// </summary>
public sealed class QuarantineServiceTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly QuarantineService _svc;

    public QuarantineServiceTests()
    {
        _tempRoot = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(), "wraith-tests-" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(_tempRoot);
        _svc = new QuarantineService();
        OverrideVault(_svc, TempChild("vault"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { }
    }

    /// <summary>
    /// Constructs a normalised child path under <see cref="_tempRoot"/>.
    /// Path.GetFullPath at every test-side leaf serves as the CodeQL
    /// sanitiser for cs/path-injection — without it the rule re-evaluates
    /// _tempRoot at every File.* / Directory.* call site.
    /// </summary>
    private string TempChild(params string[] segments)
    {
        var combined = _tempRoot;
        foreach (var s in segments) combined = Path.Combine(combined, s);
        return Path.GetFullPath(combined);
    }

    private static void OverrideVault(QuarantineService svc, string newRoot)
    {
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
        var src = TempChild("malware.exe");
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
        var src = TempChild("x.exe");
        File.WriteAllText(src, "x");
        var rec = _svc.QuarantineFile(src, "test");
        Assert.Contains(_svc.GetRecords(), r => r.Id == rec.Id);
    }

    [Fact]
    public void QuarantineFile_missing_source_throws()
    {
        Assert.Throws<FileNotFoundException>(() =>
            _svc.QuarantineFile(TempChild("nope.exe"), "test"));
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
        var srcDir = TempChild("EvilExtension");
        Directory.CreateDirectory(srcDir);
        File.WriteAllText(Path.GetFullPath(Path.Combine(srcDir, "manifest.json")), "{}");
        File.WriteAllText(Path.GetFullPath(Path.Combine(srcDir, "background.js")), "evil();");

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
        var src = TempChild("doc.txt");
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
        var src = TempChild("evil.bin");
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
        var src = TempChild("x.bin");
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

    // ── Vault lockdown ──────────────────────────────────────────────────

    [Fact]
    public void QuarantineFile_marks_vault_entry_readonly()
    {
        var src = TempChild("locked.exe");
        File.WriteAllText(src, "payload");
        var rec = _svc.QuarantineFile(src, "test", "CRITICAL");

        var attrs = File.GetAttributes(rec.QuarantinedPath);
        Assert.True(attrs.HasFlag(FileAttributes.ReadOnly),
            "vaulted payload should be hardened read-only so it can't be casually run/altered");
    }

    [Fact]
    public void DeleteFromVault_succeeds_even_though_entry_is_readonly()
    {
        var src = TempChild("ro.bin");
        File.WriteAllText(src, "x");
        var rec = _svc.QuarantineFile(src, "test");
        Assert.True(File.GetAttributes(rec.QuarantinedPath).HasFlag(FileAttributes.ReadOnly));

        // DeleteFromVault must clear ReadOnly before File.Delete or this throws.
        Assert.True(_svc.DeleteFromVault(rec.Id, requireAdmin: false));
        Assert.False(File.Exists(rec.QuarantinedPath));
    }

    // ── Force delete ────────────────────────────────────────────────────

    [Fact]
    public void ForceDeleteOriginal_deletes_unlocked_file()
    {
        var src = TempChild("evil.exe");
        File.WriteAllText(src, "evil");

        var result = QuarantineService.ForceDeleteOriginal(src, killHolders: true);

        Assert.Equal(ForceDeleteOutcome.Deleted, result.Outcome);
        Assert.False(File.Exists(src));
        Assert.Empty(result.KilledProcesses);
    }

    [Fact]
    public void ForceDeleteOriginal_reports_NotFound_for_missing_file()
    {
        var result = QuarantineService.ForceDeleteOriginal(TempChild("ghost.exe"));
        Assert.Equal(ForceDeleteOutcome.NotFound, result.Outcome);
    }

    [Fact]
    public void ForceDeleteOriginal_deletes_readonly_file()
    {
        var src = TempChild("readonly.exe");
        File.WriteAllText(src, "x");
        File.SetAttributes(src, File.GetAttributes(src) | FileAttributes.ReadOnly);

        var result = QuarantineService.ForceDeleteOriginal(src);

        Assert.Equal(ForceDeleteOutcome.Deleted, result.Outcome);
        Assert.False(File.Exists(src));
    }
}
