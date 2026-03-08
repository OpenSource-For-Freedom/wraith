using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Velopack;
using WRAITH.Services;

namespace WRAITH;

public partial class App : Application
{
    private DispatcherTimer? _windowWatchdog;
    private Mutex? _singleInstanceMutex;

    private static void Trace(string msg)
    {
        try
        {
            var f = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "wraith-setup.log");
            System.IO.File.AppendAllText(f, $"[{DateTime.Now:HH:mm:ss.fff}] {msg}\n");
        }
        catch { }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        Trace("OnStartup: begin");

        // ── Velopack bootstrap — must be called before anything else ─────────
        VelopackApp.Build().Run();
        Trace("OnStartup: past Velopack");

        // ── Single-instance enforcement ──────────────────────────────────────
        _singleInstanceMutex = new Mutex(initiallyOwned: true,
            name: "Global\\WRAITH_SingleInstance_4A2F9C1B",
            out bool createdNew);

        if (!createdNew)
        {
            Trace("OnStartup: duplicate instance — exiting");
            BringExistingInstanceToFront();
            _singleInstanceMutex.Dispose();
            Environment.Exit(0);
            return;
        }
        Trace("OnStartup: single-instance mutex acquired");

        base.OnStartup(e);

        DispatcherUnhandledException += (_, ex) =>
        {
            MessageBox.Show($"Unhandled error:\n{ex.Exception.Message}",
                "WRAITH — Unhandled Exception", MessageBoxButton.OK, MessageBoxImage.Error);
            ex.Handled = true;
            try { Current.Shutdown(-1); } catch { }
            Environment.Exit(-1);
        };

        var baseDir = BootstrapService.ResolveBaseDir();
        Trace($"OnStartup: baseDir={baseDir}, IsFirstRun={BootstrapService.IsFirstRun(baseDir)}");

        if (BootstrapService.IsFirstRun(baseDir))
        {
            // ── First run: show ONLY the setup window ──────────────────────────
            // MainWindow is not created until setup completes and WRAITH restarts.
            Trace("OnStartup: first-run — showing setup window");
            ShutdownMode = ShutdownMode.OnLastWindowClose;
            RunSetupThenLaunch(baseDir);
        }
        else
        {
            // ── Normal launch: show the main window directly ───────────────────
            Trace("OnStartup: showing main window");
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            var main = new MainWindow();
            main.Show();

            Dispatcher.BeginInvoke(async () => await UpdateService.CheckForUpdatesAsync(),
                DispatcherPriority.ApplicationIdle);

            _windowWatchdog = new DispatcherTimer(
                TimeSpan.FromSeconds(3),
                DispatcherPriority.Background,
                (_, _) =>
                {
                    if (Current.Windows.Count == 0)
                    {
                        try { Current.Shutdown(-1); } catch { }
                        Environment.Exit(-1);
                    }
                },
                Dispatcher);
            _windowWatchdog.Start();
        }
    }

    /// <summary>
    /// Shows the setup window, runs bootstrap, then restarts WRAITH so the main
    /// window opens in a fresh process that inherits the updated PATH.
    /// </summary>
    private void RunSetupThenLaunch(string baseDir)
    {
        var setupWin = new SetupProgressWindow();
        setupWin.Show();

        // Write a second diagnostic log next to the exe so it's readable from
        // a non-elevated terminal (no need to search %TEMP% as admin).
        var localLog = System.IO.Path.Combine(baseDir, "wraith-setup.log");
        BootstrapService.SetLocalLogPath(localLog);

        var bs = new BootstrapService();
        bs.DialogOwner  = setupWin;   // ensures dialog is owned & properly modal
        bs.StepProgress += (idx, status, detail) => setupWin.UpdateStep(idx, status, detail);
        bs.LogMessage   += msg => Trace(msg);

        _ = Task.Run(async () =>
        {
            var result = await bs.EnsureDependenciesAsync(baseDir);

            Dispatcher.Invoke(() =>
            {
                if (result == null)
                {
                    // Leave window open and show the exit button so the user can read the error
                    setupWin.StatusLine = "Setup failed — see log for details.";
                    setupWin.ShowCancel();
                    return;
                }

                Trace("Setup complete — launching WRAITH");
                setupWin.StatusLine = "Setup complete! Launching WRAITH...";

                // Brief pause so the user sees the completed state, then restart
                var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
                t.Tick += (_, _) =>
                {
                    t.Stop();
                    // Release mutex first so the new instance can acquire it
                    try { _singleInstanceMutex?.ReleaseMutex(); _singleInstanceMutex?.Dispose(); } catch { }
                    _singleInstanceMutex = null;

                    var exe = Environment.ProcessPath ??
                              System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                    if (exe != null)
                    {
                        Trace($"Restarting: {exe}");
                        System.Diagnostics.Process.Start(exe);
                    }
                    Current.Shutdown(0);
                };
                t.Start();
            });
        });
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _windowWatchdog?.Stop(); } catch { }
        try { _singleInstanceMutex?.ReleaseMutex(); } catch { }
        try { _singleInstanceMutex?.Dispose(); } catch { }
        base.OnExit(e);
    }

    private static void BringExistingInstanceToFront()
    {
        try
        {
            var current = System.Diagnostics.Process.GetCurrentProcess();
            foreach (var proc in System.Diagnostics.Process.GetProcessesByName(current.ProcessName))
            {
                if (proc.Id == current.Id) continue;
                var hwnd = proc.MainWindowHandle;
                if (hwnd == IntPtr.Zero) continue;
                // Restore if minimised, then bring to front
                NativeMethods.ShowWindow(hwnd, NativeMethods.SW_RESTORE);
                NativeMethods.SetForegroundWindow(hwnd);
                break;
            }
        }
        catch { /* best-effort */ }
    }

    private static class NativeMethods
    {
        internal const int SW_RESTORE = 9;
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        internal static extern bool SetForegroundWindow(IntPtr hWnd);
    }
}
