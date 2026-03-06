using System.Windows;
using System.Windows.Threading;
using System.Threading;

namespace WRAITH;

public partial class App : Application
{
    private DispatcherTimer? _windowWatchdog;
    private Mutex? _singleInstanceMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        // ── Single-instance enforcement ──────────────────────────────────
        _singleInstanceMutex = new Mutex(initiallyOwned: true,
            name: "Global\\WRAITH_SingleInstance_4A2F9C1B",
            out bool createdNew);

        if (!createdNew)
        {
            // Another instance is already running — bring it to the foreground
            BringExistingInstanceToFront();
            _singleInstanceMutex.Dispose();
            Environment.Exit(0);
            return;
        }

        ShutdownMode = ShutdownMode.OnMainWindowClose;
        base.OnStartup(e);

        DispatcherUnhandledException += (_, ex) =>
        {
            MessageBox.Show($"Unhandled error:\n{ex.Exception.Message}",
                "WRAITH — Unhandled Exception", MessageBoxButton.OK, MessageBoxImage.Error);
            ex.Handled = true;

            try { Current.Shutdown(-1); } catch { }
            Environment.Exit(-1);
        };

        Dispatcher.BeginInvoke(() =>
        {
            if (MainWindow == null)
            {
                try
                {
                    MessageBox.Show(
                        "WRAITH failed to initialize a main window and will now exit to avoid a background zombie process.",
                        "WRAITH Startup Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                catch { }

                try { Current.Shutdown(-1); } catch { }
                Environment.Exit(-1);
            }
        }, DispatcherPriority.ApplicationIdle);

        _windowWatchdog = new DispatcherTimer(
            TimeSpan.FromSeconds(3),
            DispatcherPriority.Background,
            (_, _) =>
            {
                // If the app is alive but has no windows, force exit to avoid zombie background process.
                if (Current.Windows.Count == 0)
                {
                    try { Current.Shutdown(-1); } catch { }
                    Environment.Exit(-1);
                }
            },
            Dispatcher);
        _windowWatchdog.Start();
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
