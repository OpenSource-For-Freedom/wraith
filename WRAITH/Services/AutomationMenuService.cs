using System.IO;
using System.Diagnostics;

namespace WRAITH.Services;

public sealed class AutomationMenuService
{
    private readonly string _baseDir;

    public AutomationMenuService()
    {
        _baseDir = BootstrapService.ResolveBaseDir();
    }

    private string AutomationDir => Path.Combine(_baseDir, "automation");

    public async Task<(bool ok, string output)> SetTimedScanAsync(int intervalMinutes, string scanPath)
    {
        var script = Path.Combine(AutomationDir, "Register-WraithTimedScan.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -IntervalMinutes {intervalMinutes} -ScanPath \"{scanPath}\" -Hours 24 -Mode all -RunAsSystem";
        return await RunPowerShellAsync(args);
    }

    public async Task<(bool ok, string output)> DisableTimedScanAsync()
    {
        var script = Path.Combine(AutomationDir, "Unregister-WraithTimedScan.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\"";
        return await RunPowerShellAsync(args);
    }

    public async Task<(bool ok, string output)> EnablePersistenceListenerAsync(string scanPath)
    {
        var script = Path.Combine(AutomationDir, "Register-WraithPersistenceListener.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -ScanPath \"{scanPath}\" -PollSeconds 120";
        return await RunPowerShellAsync(args);
    }

    public async Task<(bool ok, string output)> DisablePersistenceListenerAsync()
    {
        var script = Path.Combine(AutomationDir, "Unregister-WraithPersistenceListener.ps1");
        if (!File.Exists(script))
            return (false, $"Missing script: {script}");

        var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\"";
        return await RunPowerShellAsync(args);
    }

    private static async Task<(bool ok, string output)> RunPowerShellAsync(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null) return (false, "Failed to start powershell.exe");

            var stdout = await proc.StandardOutput.ReadToEndAsync();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            var output = (stdout + Environment.NewLine + stderr).Trim();
            return (proc.ExitCode == 0, string.IsNullOrWhiteSpace(output) ? "OK" : output);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
