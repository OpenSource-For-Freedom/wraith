using System.Windows;
using System.Windows.Threading;

namespace WRAITH;

public partial class App : Application
{
    private DispatcherTimer? _windowWatchdog;

    protected override void OnStartup(StartupEventArgs e)
    {
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
        base.OnExit(e);
    }
}
