using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace WRAITH.Services;

/// <summary>
/// Outcome of a force-delete attempt, surfaced to the UI so the user knows
/// whether the file is gone now or only after the next reboot.
/// </summary>
public enum ForceDeleteOutcome
{
    /// <summary>File did not exist (already gone).</summary>
    NotFound,
    /// <summary>File was deleted immediately.</summary>
    Deleted,
    /// <summary>File was locked; holders were killed and then it was deleted.</summary>
    DeletedAfterKill,
    /// <summary>File could not be unlocked; scheduled for deletion at next reboot.</summary>
    ScheduledForReboot,
    /// <summary>Deletion failed and could not even be scheduled.</summary>
    Failed,
}

public sealed record ForceDeleteResult(
    ForceDeleteOutcome Outcome,
    string Detail,
    IReadOnlyList<string> KilledProcesses);

/// <summary>
/// Force-deletes a file even when another process holds it open. Uses the
/// Windows Restart Manager (the same API the Windows "file in use" dialog uses)
/// to enumerate the exact processes locking the file, terminates them — except
/// a hard denylist of OS-critical processes whose death would crash the machine —
/// then deletes. If the file still can't be removed (e.g. a denylisted holder),
/// it is scheduled for deletion on next boot via MoveFileEx.
///
/// Requires Administrator. The app manifest already guarantees that.
/// </summary>
public static class LockedFileDeleter
{
    // Killing any of these blue-screens or wedges the session. The user asserting
    // a file is malicious must never be able to turn "delete" into a forced crash,
    // so holders with these names are skipped (the file then falls through to
    // reboot-scheduled deletion instead).
    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "smss", "csrss", "wininit", "winlogon",
        "services", "lsass", "lsaiso", "fontdrvhost", "dwm",
        "registry", "memory compression", "idle",
    };

    /// <summary>
    /// Attempts to delete <paramref name="path"/>. When <paramref name="killHolders"/>
    /// is true, terminates non-critical processes locking the file first.
    /// </summary>
    public static ForceDeleteResult ForceDelete(string path, bool killHolders = true)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) { return new(ForceDeleteOutcome.Failed, $"Invalid path: {ex.Message}", Array.Empty<string>()); }

        if (!File.Exists(full))
            return new(ForceDeleteOutcome.NotFound, "File does not exist.", Array.Empty<string>());

        // Vaulted / hardened files are ReadOnly — clear it or Delete throws.
        ClearReadOnly(full);

        // 1) Plain delete — works when nothing holds the file.
        if (TryDelete(full))
            return new(ForceDeleteOutcome.Deleted, "Deleted.", Array.Empty<string>());

        var killed = new List<string>();

        // 2) Find and kill the processes locking it, then retry.
        if (killHolders)
        {
            foreach (var pid in FindLockingProcessIds(full))
            {
                if (TryKill(pid, out var name))
                    killed.Add($"{name} (PID {pid})");
            }

            if (killed.Count > 0)
            {
                // Give the OS a moment to release the image section after the
                // holders exit, then retry a few times.
                for (var attempt = 0; attempt < 5; attempt++)
                {
                    if (TryDelete(full))
                        return new(ForceDeleteOutcome.DeletedAfterKill,
                            $"Deleted after terminating: {string.Join(", ", killed)}.", killed);
                    Thread.Sleep(150);
                }
            }
        }

        // 3) Still locked (denylisted holder, kernel-mapped image, etc.).
        //    Schedule for deletion at next boot before any process can re-open it.
        if (MoveFileEx(full, null, MOVEFILE_DELAY_UNTIL_REBOOT))
        {
            var note = killed.Count > 0
                ? $"Locked after terminating {string.Join(", ", killed)} — scheduled for deletion on next reboot."
                : "File is locked by a protected process — scheduled for deletion on next reboot.";
            return new(ForceDeleteOutcome.ScheduledForReboot, note, killed);
        }

        var err = Marshal.GetLastWin32Error();
        return new(ForceDeleteOutcome.Failed,
            $"Could not delete or schedule deletion (Win32 error {err}).", killed);
    }

    private static void ClearReadOnly(string path)
    {
        try
        {
            var attrs = File.GetAttributes(path);
            if (attrs.HasFlag(FileAttributes.ReadOnly))
                File.SetAttributes(path, attrs & ~FileAttributes.ReadOnly);
        }
        catch { /* best-effort */ }
    }

    private static bool TryDelete(string path)
    {
        try { File.Delete(path); return true; }
        catch { return false; }
    }

    private static bool TryKill(int pid, out string name)
    {
        name = $"PID {pid}";
        try
        {
            if (pid == Environment.ProcessId)
                return false;           // never terminate WRAITH itself
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName;
            if (CriticalProcesses.Contains(p.ProcessName))
                return false;           // never terminate an OS-critical holder
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

    // ── Windows Restart Manager: find the PIDs locking a file ────────────────
    private static List<int> FindLockingProcessIds(string path)
    {
        var pids = new List<int>();
        var sessionKey = Guid.NewGuid().ToString("N");

        if (RmStartSession(out var handle, 0, sessionKey) != 0)
            return pids;

        try
        {
            string[] resources = { path };
            if (RmRegisterResources(handle, (uint)resources.Length, resources,
                                    0, null, 0, null) != 0)
                return pids;

            uint pnProcInfoNeeded = 0;
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = RmRebootReasonNone;

            // First call with a zero-sized array discovers how many entries we need.
            var rc = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

            if (rc == ERROR_MORE_DATA && pnProcInfoNeeded > 0)
            {
                var info = new RM_PROCESS_INFO[pnProcInfoNeeded];
                pnProcInfo = pnProcInfoNeeded;
                if (RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, info, ref lpdwRebootReasons) == 0)
                {
                    for (var i = 0; i < pnProcInfo; i++)
                        pids.Add(info[i].Process.dwProcessId);
                }
            }
        }
        finally
        {
            RmEndSession(handle);
        }

        return pids;
    }

    // ── P/Invoke: Restart Manager (rstrtmgr.dll) ─────────────────────────────
    private const int RmRebootReasonNone = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    private enum RM_APP_TYPE
    {
        RmUnknownApp = 0, RmMainWindow = 1, RmOtherWindow = 2,
        RmService = 3, RmExplorer = 4, RmConsole = 5, RmCritical = 1000,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out IntPtr pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(IntPtr pSessionHandle,
        uint nFiles, string[] rgsFilenames,
        uint nApplications, [In] RM_UNIQUE_PROCESS[]? rgApplications,
        uint nServices, string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(IntPtr dwSessionHandle,
        out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[]? rgAffectedApps, ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(IntPtr pSessionHandle);

    // ── P/Invoke: delete-on-reboot fallback ──────────────────────────────────
    private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);
}
