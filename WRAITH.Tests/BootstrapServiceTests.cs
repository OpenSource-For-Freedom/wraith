using System.IO;
using System.Text.Json;
using WRAITH.Services;
using Xunit;

namespace WRAITH.Tests;

/// <summary>
/// Tests the static helpers on <see cref="BootstrapService"/> — path
/// resolution and env.json shape. The interactive bootstrap flow
/// (Python install, PATH dialog) needs an integration harness on Windows
/// and isn't covered here.
/// </summary>
public sealed class BootstrapServiceTests
{
    [Fact]
    public void GetStableEnvJsonPath_returns_normalised_absolute_path()
    {
        var p = BootstrapService.GetStableEnvJsonPath();
        Assert.True(Path.IsPathRooted(p));
        Assert.Equal(Path.GetFullPath(p), p);
        Assert.EndsWith("wraith.env.json", p);
    }

    [Fact]
    public void GetStableEnvJsonPath_is_under_programdata()
    {
        var p = BootstrapService.GetStableEnvJsonPath();
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        Assert.StartsWith(programData, p, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ResolveBaseDir_returns_a_rooted_path()
    {
        var dir = BootstrapService.ResolveBaseDir();
        Assert.False(string.IsNullOrWhiteSpace(dir));
        Assert.True(Path.IsPathRooted(dir));
    }

    [Fact]
    public void IsFirstRun_returns_a_bool_without_throwing()
    {
        // We don't control %ProgramData% on the runner, so we just assert
        // it doesn't blow up — actual True/False depends on env state.
        var _ = BootstrapService.IsFirstRun(Path.GetTempPath());
    }
}
