using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using WRAITH.Models;
using WRAITH.ViewModels;

namespace WRAITH;

public partial class MainWindow : Window
{
    private readonly List<Storyboard> _patronusBoards = new();

    // ── Ghost wraith ambient sweep ─────────────────────────────────────
    private readonly DispatcherTimer _ghostTimer = new();
    private readonly Random          _ghostRng   = new();
    private          int             _ghostActive = 0;   // active pass count
    // ── Header scan animation ───────────────────────────────────────────
    private readonly DispatcherTimer _headerDataTimer  = new();
    private readonly Random          _headerRng        = new();
    private          int             _headerDataTick   = 0;
    // ── GIF sprite frame cache (loaded once, shared across all passes) ──
    private static BitmapFrame[]? _gifFrames;
    private static int[]?         _gifDelayMs;
    // ── Win32 for window chrome ──────────────────────────────────────────
    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    // ── WM_NCHITTEST resize hook ─────────────────────────────────────────
    private const int WM_NCHITTEST    = 0x0084;
    private const int HTLEFT          = 10;
    private const int HTRIGHT         = 11;
    private const int HTTOP           = 12;
    private const int HTTOPLEFT       = 13;
    private const int HTTOPRIGHT      = 14;
    private const int HTBOTTOM        = 15;
    private const int HTBOTTOMLEFT    = 16;
    private const int HTBOTTOMRIGHT   = 17;
    private const int GripPx          = 8;   // physical pixels from edge

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var source = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
        source?.AddHook(ResizeHook);
    }

    private IntPtr ResizeHook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam,
                              ref bool handled)
    {
        if (msg == WM_NCHITTEST && WindowState == WindowState.Normal)
        {
            // lParam is screen coords in physical pixels
            int sx = unchecked((short)(lParam.ToInt32() & 0xFFFF));
            int sy = unchecked((short)(lParam.ToInt32() >> 16));

            var ps    = PresentationSource.FromVisual(this);
            double dx = ps?.CompositionTarget.TransformToDevice.M11 ?? 1.0;
            double dy = ps?.CompositionTarget.TransformToDevice.M22 ?? 1.0;

            double wL = Left            * dx;
            double wT = Top             * dy;
            double wR = (Left + Width)  * dx;
            double wB = (Top  + Height) * dy;

            bool onL = sx <= wL + GripPx;
            bool onR = sx >= wR - GripPx;
            bool onT = sy <= wT + GripPx;
            bool onB = sy >= wB - GripPx;

            if (onT && onL) { handled = true; return new IntPtr(HTTOPLEFT);     }
            if (onT && onR) { handled = true; return new IntPtr(HTTOPRIGHT);    }
            if (onB && onL) { handled = true; return new IntPtr(HTBOTTOMLEFT);  }
            if (onB && onR) { handled = true; return new IntPtr(HTBOTTOMRIGHT); }
            if (onL)        { handled = true; return new IntPtr(HTLEFT);        }
            if (onR)        { handled = true; return new IntPtr(HTRIGHT);       }
            if (onT)        { handled = true; return new IntPtr(HTTOP);         }
            if (onB)        { handled = true; return new IntPtr(HTBOTTOM);      }
        }
        return IntPtr.Zero;
    }

    public MainWindow()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Loaded += OnLoaded;
        Closing += (_, _) =>
        {
            if (DataContext is MainViewModel vm)
                vm.Shutdown();
            Environment.Exit(0);
        };

        // DataContext was already set by XAML inside InitializeComponent before we
        // subscribed to DataContextChanged, so wire up the existing ViewModel now.
        if (DataContext is MainViewModel existingVm)
            existingVm.PropertyChanged += VmPropertyChanged;
    }

    // ── Hook into ViewModel events ─────────────────────────────────────
    private void OnDataContextChanged(object s, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is MainViewModel old)
            old.PropertyChanged -= VmPropertyChanged;
        if (e.NewValue is MainViewModel vm)
            vm.PropertyChanged += VmPropertyChanged;
    }

    private void VmPropertyChanged(object? s, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.IsScanning))
        {
            var vm = (MainViewModel)DataContext;
            Dispatcher.Invoke(() =>
            {
                if (vm.IsScanning)
                {
                    TriggerWooshAnimation();
                    StartPatronusAnimation();
                }
                else StopPatronusAnimation();
            });
        }
        else if (e.PropertyName == nameof(MainViewModel.CurrentPhase))
        {
            var vm = (MainViewModel)DataContext;
            if (vm.IsScanning)
                Dispatcher.Invoke(() => UpdateHeaderPhase(vm.CurrentPhase));
        }
    }

    private void OnLoaded(object s, RoutedEventArgs e)
    {
        // Pulse the status dot once
        PulseSpinnerDot();

        // Wire auto-scroll when new log entries arrive
        if (DataContext is MainViewModel vm)
        {
            vm.LogEntries.CollectionChanged += (_, _) =>
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                    () => LogScroller.ScrollToBottom());

            // Kick off first-run dependency check / install in the background.
            // Progress and errors are streamed to the log panel automatically.
            _ = vm.InitializeAsync();
        }
    }

    // ── Custom chrome ──────────────────────────────────────────────────
    private void TitleBar_MouseDown(object s, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.LeftButton == System.Windows.Input.MouseButtonState.Pressed)
        {
            if (e.ClickCount == 2) { ToggleMaximize(); return; }
            ReleaseCapture();
            SendMessage(new System.Windows.Interop.WindowInteropHelper(this).Handle,
                0xA1, new IntPtr(2), IntPtr.Zero);
        }
    }

    private void BtnClose_Click(object s, RoutedEventArgs e) => Close();
    private void BtnMinimize_Click(object s, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void BtnMaximize_Click(object s, RoutedEventArgs e) => ToggleMaximize();

    private void ToggleMaximize()
        => WindowState = WindowState == WindowState.Maximized
               ? WindowState.Normal : WindowState.Maximized;

    // ── Folder browse ─────────────────────────────────────────────────
    private void BtnBrowse_Click(object s, RoutedEventArgs e)
    {
        var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select scan root folder",
            SelectedPath = System.IO.Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\"
        };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            if (DataContext is MainViewModel vm)
                vm.ScanPath = dlg.SelectedPath;
    }

    // ─────────────────────────────────────────────────────────────────
    //  Patronus Spell Animation
    //  Three expanding glowing rings spray outward from centre while scan runs.
    // ══════════════════════════════════════════════════════════════════
    private void StartPatronusAnimation()
    {
        _patronusBoards.Clear();

        var rings = new[] { Ring1, Ring2, Ring3 };
        var colours = new[] { "#60A8C8E8", "#50D4AF37", "#40A8C8E8" };
        var delays  = new[] { 0.0, 0.6, 1.2 };
        var durations = new[] { 2.8, 3.4, 4.0 };

        // Place rings at canvas centre
        PatronusCanvas.SizeChanged += RepositionRings;
        RepositionRings(null, null);

        for (int i = 0; i < rings.Length; i++)
        {
            var ring = rings[i];
            var sb   = BuildRingStoryboard(ring, colours[i], delays[i], durations[i]);
            sb.RepeatBehavior = RepeatBehavior.Forever;
            _patronusBoards.Add(sb);
            sb.Begin(this, true);
        }

        // Pulse spinner dot green
        AnimateSpinnerDot(Color.FromRgb(0xA8, 0xC8, 0xE8), true);

        // Start ambient ghost wraith sweeps
        StartGhostAnimation();

        // Start header scan cutscene
        StartHeaderScanAnimation();
    }

    private void StopPatronusAnimation()
    {
        foreach (var sb in _patronusBoards) sb.Stop(this);
        _patronusBoards.Clear();
        PatronusCanvas.SizeChanged -= RepositionRings;

        // Reset rings
        foreach (var r in new[] { Ring1, Ring2, Ring3 })
        { r.Width = 0; r.Height = 0; }

        AnimateSpinnerDot(Color.FromRgb(0x3D, 0x3D, 0x5A), false);

        // Stop ghost sweeps
        StopGhostAnimation();

        // Stop header scan cutscene
        StopHeaderScanAnimation();
    }

    private void RepositionRings(object? s, SizeChangedEventArgs? e)
    {
        double cx = PatronusCanvas.ActualWidth  > 0 ? PatronusCanvas.ActualWidth  / 2 : 500;
        double cy = PatronusCanvas.ActualHeight > 0 ? PatronusCanvas.ActualHeight / 2 : 80;
        foreach (var r in new[] { Ring1, Ring2, Ring3 })
        {
            Canvas.SetLeft(r, cx);
            Canvas.SetTop(r,  cy);
        }
    }

    private static Storyboard BuildRingStoryboard(Ellipse ring, string colorHex,
        double delaySeconds, double durationSeconds)
    {
        var sb   = new Storyboard();
        var delay = TimeSpan.FromSeconds(delaySeconds);
        var dur   = new Duration(TimeSpan.FromSeconds(durationSeconds));

        // Width 0 → 400
        var wAnim = new DoubleAnimation(0, 400, dur) { BeginTime = delay, EasingFunction = new QuadraticEase() };
        Storyboard.SetTarget(wAnim, ring);
        Storyboard.SetTargetProperty(wAnim, new PropertyPath(WidthProperty));
        sb.Children.Add(wAnim);

        // Height 0 → 400
        var hAnim = new DoubleAnimation(0, 400, dur) { BeginTime = delay, EasingFunction = new QuadraticEase() };
        Storyboard.SetTarget(hAnim, ring);
        Storyboard.SetTargetProperty(hAnim, new PropertyPath(HeightProperty));
        sb.Children.Add(hAnim);

        // X offset so ring expands from centre: Canvas.Left -= width/2
        var xAnim = new DoubleAnimation(0, -200, dur) { BeginTime = delay };
        Storyboard.SetTarget(xAnim, ring);
        Storyboard.SetTargetProperty(xAnim, new PropertyPath(Canvas.LeftProperty));
        sb.Children.Add(xAnim);

        var yAnim = new DoubleAnimation(0, -200, dur) { BeginTime = delay };
        Storyboard.SetTarget(yAnim, ring);
        Storyboard.SetTargetProperty(yAnim, new PropertyPath(Canvas.TopProperty));
        sb.Children.Add(yAnim);

        // Opacity: 0.7 → 0 (fade out as it expands)
        var oAnim = new DoubleAnimation(0.7, 0, dur) { BeginTime = delay };
        Storyboard.SetTarget(oAnim, ring);
        Storyboard.SetTargetProperty(oAnim, new PropertyPath(OpacityProperty));
        sb.Children.Add(oAnim);

        return sb;
    }

    // ══════════════════════════════════════════════════════════════════
    //  Woosh: Purge-rush particle burst on scan launch (one-shot)
    // ══════════════════════════════════════════════════════════════════
    private void TriggerWooshAnimation()
    {
        WooshCanvas.Children.Clear();
        WooshCanvas.Visibility = Visibility.Visible;

        var rng = new Random();
        double W = Math.Max(ActualWidth,  1300);
        double H = Math.Max(ActualHeight,  820);

        var sb     = new Storyboard();
        double maxEnd = 0.0;

        // ── Flash: brief purple-white bloom at the moment of launch ──────
        var flash = new System.Windows.Shapes.Rectangle
        {
            Width   = W,
            Height  = H,
            Opacity = 0,
            Fill    = new LinearGradientBrush(
                Color.FromArgb(0,   80,  0, 160),
                Color.FromArgb(110, 80,  0, 160), 0)
            {
                StartPoint = new System.Windows.Point(0, 0.5),
                EndPoint   = new System.Windows.Point(1, 0.5)
            }
        };
        Canvas.SetLeft(flash, 0);
        Canvas.SetTop(flash,  0);
        WooshCanvas.Children.Add(flash);

        var flashIn  = new DoubleAnimation(0, 0.35, new Duration(TimeSpan.FromSeconds(0.07)));
        var flashOut = new DoubleAnimation(0.35, 0, new Duration(TimeSpan.FromSeconds(0.28)))
                       { BeginTime = TimeSpan.FromSeconds(0.07) };
        Storyboard.SetTarget(flashIn,  flash);
        Storyboard.SetTarget(flashOut, flash);
        Storyboard.SetTargetProperty(flashIn,  new PropertyPath(OpacityProperty));
        Storyboard.SetTargetProperty(flashOut, new PropertyPath(OpacityProperty));
        sb.Children.Add(flashIn);
        sb.Children.Add(flashOut);

        // ── Speed streaks ────────────────────────────────────────────────
        //   Thin horizontal rectangles with a transparent-left → vivid-right gradient
        //   so they have a sharp leading edge and a fading tail (reversed since they
        //   fly left-to-right the gradient should be vivid leading, fade trailing —
        //   we set StartPoint right→left so the bright end is at the front)
        (Color tail, Color head)[] streakPalette =
        [
            (Color.FromArgb(  0, 168, 200, 232), Color.FromArgb(180, 168, 200, 232)), // ice blue
            (Color.FromArgb(  0,  79, 195, 247), Color.FromArgb(160,  79, 195, 247)), // cyan
            (Color.FromArgb(  0, 212, 175,  55), Color.FromArgb(140, 212, 175,  55)), // gold
            (Color.FromArgb(  0, 176, 140, 240), Color.FromArgb(150, 176, 140, 240)), // violet
            (Color.FromArgb(  0, 255, 255, 255), Color.FromArgb(120, 255, 255, 255)), // white
            (Color.FromArgb(  0, 140, 100, 255), Color.FromArgb(130, 140, 100, 255)), // purple
        ];

        for (int i = 0; i < 24; i++)
        {
            double length = rng.Next(60, 620);
            double thick  = rng.NextDouble() * 3.5 + 0.5;
            double yPos   = rng.NextDouble() * H;
            double delay  = rng.NextDouble() * 0.42;
            double dur    = rng.NextDouble() * 0.38 + 0.22;
            var (tail, head) = streakPalette[rng.Next(streakPalette.Length)];

            // Gradient: head (bright) on the right end, tail (transparent) on the left
            var grad = new LinearGradientBrush { StartPoint = new System.Windows.Point(0, 0.5), EndPoint = new System.Windows.Point(1, 0.5) };
            grad.GradientStops.Add(new GradientStop(tail, 0.0));
            grad.GradientStops.Add(new GradientStop(head, 1.0));

            var streak = new System.Windows.Shapes.Rectangle
            {
                Width  = length,
                Height = thick,
                Fill   = grad,
            };
            Canvas.SetLeft(streak, -length - 30);
            Canvas.SetTop(streak, yPos);
            WooshCanvas.Children.Add(streak);

            var move = new DoubleAnimation(-length - 30, W + 60,
                new Duration(TimeSpan.FromSeconds(dur)))
            {
                BeginTime      = TimeSpan.FromSeconds(delay),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn }
            };
            Storyboard.SetTarget(move, streak);
            Storyboard.SetTargetProperty(move, new PropertyPath(Canvas.LeftProperty));
            sb.Children.Add(move);

            maxEnd = Math.Max(maxEnd, delay + dur);
        }

        // ── Dust motes ───────────────────────────────────────────────────
        //   Small squished ellipses that shoot out, drift slightly in Y, and fade
        for (int i = 0; i < 45; i++)
        {
            double w      = rng.NextDouble() * 7  + 2.0;
            double h      = w * (rng.NextDouble() * 0.45 + 0.12);  // squish to look like flying debris
            double xStart = -(w + rng.NextDouble() * 180);
            double yPos   = rng.NextDouble() * H;
            double delay  = rng.NextDouble() * 0.55;
            double dur    = rng.NextDouble() * 0.45 + 0.18;
            double travelX = W * (0.55 + rng.NextDouble() * 0.7);
            double driftY  = (rng.NextDouble() - 0.5) * 90;
            double opStart = rng.NextDouble() * 0.75 + 0.15;

            // Colour: ghostly white-blue-violet range
            byte br = (byte)rng.Next(140, 256);
            byte bg = (byte)rng.Next(155, 245);
            byte bb = (byte)rng.Next(200, 256);

            var dot = new Ellipse
            {
                Width   = w,
                Height  = h,
                Fill    = new SolidColorBrush(Color.FromRgb(br, bg, bb)),
                Opacity = opStart,
            };
            Canvas.SetLeft(dot, xStart);
            Canvas.SetTop(dot,  yPos);
            WooshCanvas.Children.Add(dot);

            var mx = new DoubleAnimation(xStart, xStart + travelX,
                new Duration(TimeSpan.FromSeconds(dur)))
            {
                BeginTime      = TimeSpan.FromSeconds(delay),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn }
            };
            Storyboard.SetTarget(mx, dot);
            Storyboard.SetTargetProperty(mx, new PropertyPath(Canvas.LeftProperty));
            sb.Children.Add(mx);

            var my = new DoubleAnimation(yPos, yPos + driftY,
                new Duration(TimeSpan.FromSeconds(dur)))
            { BeginTime = TimeSpan.FromSeconds(delay) };
            Storyboard.SetTarget(my, dot);
            Storyboard.SetTargetProperty(my, new PropertyPath(Canvas.TopProperty));
            sb.Children.Add(my);

            var fade = new DoubleAnimation(opStart, 0,
                new Duration(TimeSpan.FromSeconds(dur * 0.5)))
            { BeginTime = TimeSpan.FromSeconds(delay + dur * 0.5) };
            Storyboard.SetTarget(fade, dot);
            Storyboard.SetTargetProperty(fade, new PropertyPath(OpacityProperty));
            sb.Children.Add(fade);

            maxEnd = Math.Max(maxEnd, delay + dur);
        }

        // ── Shockwave ring: a single fast-expanding ellipse from screen centre ──
        var shock = new Ellipse
        {
            Width   = 0,
            Height  = 0,
            Stroke  = new SolidColorBrush(Color.FromArgb(200, 130, 80, 255)),
            StrokeThickness = 3,
            Opacity = 1,
        };
        double cx = W / 2;
        double cy = H / 2;
        Canvas.SetLeft(shock, cx);
        Canvas.SetTop(shock,  cy);
        WooshCanvas.Children.Add(shock);

        double shockFinal = Math.Max(W, H) * 1.2;
        var shW = new DoubleAnimation(0, shockFinal,
            new Duration(TimeSpan.FromSeconds(0.55)))
        { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } };
        var shH = new DoubleAnimation(0, shockFinal,
            new Duration(TimeSpan.FromSeconds(0.55)))
        { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } };
        var shX = new DoubleAnimation(cx, cx - shockFinal / 2,
            new Duration(TimeSpan.FromSeconds(0.55)));
        var shY = new DoubleAnimation(cy, cy - shockFinal / 2,
            new Duration(TimeSpan.FromSeconds(0.55)));
        var shO = new DoubleAnimation(1, 0,
            new Duration(TimeSpan.FromSeconds(0.55)));
        foreach (var a in new Timeline[] { shW, shH, shX, shY, shO })
            Storyboard.SetTarget(a, shock);
        Storyboard.SetTargetProperty(shW, new PropertyPath(WidthProperty));
        Storyboard.SetTargetProperty(shH, new PropertyPath(HeightProperty));
        Storyboard.SetTargetProperty(shX, new PropertyPath(Canvas.LeftProperty));
        Storyboard.SetTargetProperty(shY, new PropertyPath(Canvas.TopProperty));
        Storyboard.SetTargetProperty(shO, new PropertyPath(OpacityProperty));
        sb.Children.Add(shW); sb.Children.Add(shH);
        sb.Children.Add(shX); sb.Children.Add(shY);
        sb.Children.Add(shO);

        maxEnd = Math.Max(maxEnd, 0.55);

        sb.Duration = new Duration(TimeSpan.FromSeconds(maxEnd + 0.15));
        sb.Completed += (_, _) =>
        {
            WooshCanvas.Children.Clear();
            WooshCanvas.Visibility = Visibility.Collapsed;
        };
        sb.Begin(this, false);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Ghost Wraith Ambient Sweeps
    //  While scanning: a DispatcherTimer fires every 4-11s and spawns a
    //  spectral form that glides across the whole window — varying Y,
    //  direction, speed, opacity — like something hunting through the UI.
    // ══════════════════════════════════════════════════════════════════
    private void StartGhostAnimation()
    {
        GhostCanvas.Visibility = Visibility.Visible;
        _ghostTimer.Interval   = RandomGhostInterval();
        _ghostTimer.Tick       += GhostTimer_Tick;
        _ghostTimer.Start();
        // Spawn one immediately so it doesn't feel empty
        SpawnWraithPass();
    }

    private void StopGhostAnimation()
    {
        _ghostTimer.Stop();
        _ghostTimer.Tick -= GhostTimer_Tick;
        GhostCanvas.Children.Clear();
        GhostCanvas.Visibility = Visibility.Collapsed;
        _ghostActive = 0;
    }

    private void GhostTimer_Tick(object? s, EventArgs e)
    {
        _ghostTimer.Interval = RandomGhostInterval();
        // Cap concurrent passes to avoid stacking too many on slow machines
        if (_ghostActive < 3) SpawnWraithPass();
    }

    private TimeSpan RandomGhostInterval()
        => TimeSpan.FromSeconds(_ghostRng.NextDouble() * 7.0 + 4.0);  // 4 – 11 s

    private static void EnsureGifFrames()
    {
        if (_gifFrames != null) return;
        try
        {
            var uri     = new Uri("pack://application:,,,/Assets/wraith.gif");
            var decoder = BitmapDecoder.Create(
                uri, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            _gifFrames  = [.. decoder.Frames];
            _gifDelayMs = _gifFrames.Select(f =>
            {
                int delay = 80;
                try
                {
                    if (f.Metadata is BitmapMetadata meta)
                    {
                        var raw = meta.GetQuery("/grctlext/Delay");
                        if (raw is ushort cs) delay = Math.Max((int)cs * 10, 30);
                    }
                }
                catch { /* use default */ }
                return delay;
            }).ToArray();
        }
        catch
        {
            _gifFrames  = [];
            _gifDelayMs = [];
        }
    }

    private void SpawnWraithPass()
    {
        double W = Math.Max(ActualWidth,  1300);
        double H = Math.Max(ActualHeight,  820);

        bool   ltr   = _ghostRng.NextDouble() > 0.28;              // 72% left-to-right
        double scale = _ghostRng.NextDouble() * 0.65 + 0.45;       // 0.45 – 1.10
        double bW    = 110 * scale;                                 // wraith bounding W
        double bH    = 155 * scale;                                 // wraith bounding H

        double peakOpacity = _ghostRng.NextDouble() * 0.35 + 0.50; // 0.50 – 0.85
        double totalDur    = _ghostRng.NextDouble() * 3.0 + 3.0;   // 3.0 – 6.0 s

        double startX = ltr ? -(bW + 20)  : W + 20;
        double endX   = ltr ?  W  + 20    : -(bW + 20);
        double travel = endX - startX;

        double entryY = _ghostRng.NextDouble() * (H * 0.14);  // top 14% of window

        // Ghost colour palette
        Color[] palette =
        [
            Color.FromRgb(168, 200, 232),   // ice blue
            Color.FromRgb(176, 140, 240),   // violet
            Color.FromRgb(140, 180, 255),   // deep blue
            Color.FromRgb(200, 230, 255),   // pale white-blue
            Color.FromRgb(212, 175,  55),   // gold (rare)
        ];
        Color gc = _ghostRng.NextDouble() > 0.12
            ? palette[_ghostRng.Next(4)]
            : palette[4];

        // ── Container: all elements travel together via Canvas.Left/Top ──────
        var container = new Canvas { Opacity = 0 };
        Canvas.SetLeft(container, startX);
        Canvas.SetTop(container,  entryY);

        // ── Stringy ghost trails (drawn first so they sit behind the sprite) ───
        // Thin elongated strands fading away behind the direction of travel
        int trailCount = _ghostRng.Next(6, 14);
        for (int i = 0; i < trailCount; i++)
        {
            double tLen = (_ghostRng.NextDouble() * 80 + 30) * scale;
            double tThk = (_ghostRng.NextDouble() * 3.5 + 0.8) * scale;
            byte   ta   = (byte)(_ghostRng.NextDouble() * 110 + 40);

            // Spread strands vertically across the sprite height with slight wave offset
            double ty = bH * 0.15 + _ghostRng.NextDouble() * bH * 0.78;
            // Horizontal: behind the direction of travel
            double tx = ltr ? -tLen - _ghostRng.NextDouble() * 12 * scale
                             :  bW   + _ghostRng.NextDouble() * 12 * scale;

            // Gradient fades from visible (near sprite) to transparent (tip of trail)
            var trailBrush = new LinearGradientBrush
            {
                StartPoint = ltr ? new System.Windows.Point(1, 0.5) : new System.Windows.Point(0, 0.5),
                EndPoint   = ltr ? new System.Windows.Point(0, 0.5) : new System.Windows.Point(1, 0.5),
            };
            trailBrush.GradientStops.Add(new GradientStop(Color.FromArgb(ta,  gc.R, gc.G, gc.B), 0.0));
            trailBrush.GradientStops.Add(new GradientStop(Color.FromArgb(0,   gc.R, gc.G, gc.B), 1.0));

            var strand = new System.Windows.Shapes.Rectangle
            {
                Width   = tLen,
                Height  = tThk,
                Fill    = trailBrush,
                RadiusX = tThk / 2,
                RadiusY = tThk / 2,
            };
            Canvas.SetLeft(strand, tx);
            Canvas.SetTop(strand,  ty - tThk / 2);
            container.Children.Add(strand);

            // Give each strand a slow undulating drift on Y so they ripple like smoke
            double driftAmp  = (_ghostRng.NextDouble() * 6 + 3) * scale;
            double driftSpeed = _ghostRng.NextDouble() * 1.2 + 0.6;
            strand.BeginAnimation(Canvas.TopProperty,
                new DoubleAnimation(ty - tThk / 2 - driftAmp, ty - tThk / 2 + driftAmp,
                    new Duration(TimeSpan.FromSeconds(driftSpeed)))
                {
                    AutoReverse    = true,
                    RepeatBehavior = RepeatBehavior.Forever,
                    BeginTime      = TimeSpan.FromSeconds(_ghostRng.NextDouble() * driftSpeed),
                    EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
                });
        }

        // ── GIF sprite body ────────────────────────────────────────────────
        EnsureGifFrames();
        DispatcherTimer? frameTimer = null;

        if (_gifFrames?.Length > 0)
        {
            // Flip horizontally for RTL passes
            System.Windows.Media.Transform imgXform = ltr
                ? Transform.Identity
                : new ScaleTransform(-1, 1, bW / 2, 0);

            var img = new System.Windows.Controls.Image
            {
                Width               = bW,
                Height              = bH,
                Source              = _gifFrames[0],
                Stretch             = Stretch.Uniform,
                RenderTransform     = imgXform,
                Effect              = new DropShadowEffect
                {
                    Color       = gc,
                    BlurRadius  = 18 * scale,
                    ShadowDepth = 0,
                    Opacity     = 0.85,
                }
            };
            Canvas.SetLeft(img, 0);
            Canvas.SetTop(img,  0);
            container.Children.Add(img);

            // Cycle frames if the GIF has more than one
            if (_gifFrames.Length > 1)
            {
                int frameIdx = 0;
                frameTimer = new DispatcherTimer
                    { Interval = TimeSpan.FromMilliseconds(_gifDelayMs![0]) };
                frameTimer.Tick += (_, _) =>
                {
                    frameIdx = (frameIdx + 1) % _gifFrames.Length;
                    img.Source = _gifFrames[frameIdx];
                    frameTimer.Interval = TimeSpan.FromMilliseconds(_gifDelayMs[frameIdx]);
                };
                frameTimer.Start();
            }
        }
        else
        {
            // Fallback vector silhouette if GIF failed to load
            System.Windows.Point P(double x, double y) => new(x * scale, y * scale);
            var geo = new StreamGeometry();
            using (var ctx = geo.Open())
            {
                ctx.BeginFigure(P(55, 0), isFilled: true, isClosed: true);
                ctx.BezierTo(P(38, 4), P(20, 14), P(20, 32), isStroked: true, isSmoothJoin: true);
                ctx.LineTo(P( 4, 54), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(14, 92), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P( 1, 114), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(16, 98),  isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P( 4, 134), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(22, 114), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(12, 152), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(32, 130), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(55, 148), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(78, 130), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(98, 152), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(88, 114), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(106, 134), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P( 94,  98), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(109, 114), isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(96, 92),  isStroked: true, isSmoothJoin: false);
                ctx.LineTo(P(106, 54), isStroked: true, isSmoothJoin: false);
                ctx.BezierTo(P(90, 14), P(72, 4), P(55, 0), isStroked: true, isSmoothJoin: true);
            }
            geo.Freeze();
            var fill = new RadialGradientBrush
            {
                Center = new System.Windows.Point(0.50, 0.18), GradientOrigin = new System.Windows.Point(0.50, 0.14),
                RadiusX = 0.62, RadiusY = 0.58,
            };
            fill.GradientStops.Add(new GradientStop(Color.FromArgb(240, gc.R, gc.G, gc.B), 0.00));
            fill.GradientStops.Add(new GradientStop(Color.FromArgb(160, gc.R, gc.G, gc.B), 0.35));
            fill.GradientStops.Add(new GradientStop(Color.FromArgb(  0, gc.R, gc.G, gc.B), 1.00));
            container.Children.Add(new Path
            {
                Data = geo, Fill = fill,
                RenderTransform = ltr ? Transform.Identity : new ScaleTransform(-1, 1, 55 * scale, 0),
                Effect = new DropShadowEffect { Color = gc, BlurRadius = 16 * scale, ShadowDepth = 0, Opacity = 0.80 }
            });
        }

        GhostCanvas.Children.Add(container);
        _ghostActive++;

        // ── X movement: fast burst in → slow hunt → fast burst out ───────────
        var xAnim = new DoubleAnimationUsingKeyFrames();
        xAnim.Duration = new Duration(TimeSpan.FromSeconds(totalDur));
        // t=0%  : enter from off-screen
        // t=12% : cover 30% of distance fast (burst entry)
        // t=35% : slow to hunting crawl across main content
        // t=55% : still hunting / slightly paused
        // t=74% : beginning to accelerate out
        // t=88% : rapid exit starts
        // t=100%: fully off-screen
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX,              KeyTime.FromPercent(0.00)));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel*0.30, KeyTime.FromPercent(0.12),
            new QuarticEase { EasingMode = EasingMode.EaseOut }));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel*0.48, KeyTime.FromPercent(0.35)));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel*0.60, KeyTime.FromPercent(0.55)));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel*0.72, KeyTime.FromPercent(0.74)));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel*0.82, KeyTime.FromPercent(0.88),
            new QuarticEase { EasingMode = EasingMode.EaseIn }));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(endX,                 KeyTime.FromPercent(1.00)));
        Storyboard.SetTarget(xAnim, container);
        Storyboard.SetTargetProperty(xAnim, new PropertyPath(Canvas.LeftProperty));

        // ── Y movement: gentle swoops — wraith stays in the top band ──
        double amp   = _ghostRng.NextDouble() * 40 + 25;   // 25–65 px swing, stays near top
        double exitY = entryY + (_ghostRng.NextDouble() - 0.5) * amp * 0.6;
        double[] yPts =
        [
            entryY,
            entryY - amp * (_ghostRng.NextDouble() * 0.55 + 0.28),    // rise on entry
            entryY + amp * (_ghostRng.NextDouble() * 0.45 + 0.22),    // dive down
            entryY - amp * (_ghostRng.NextDouble() * 0.60 + 0.15),    // swoop back up (hunting)
            entryY + amp * (_ghostRng.NextDouble() * 0.35 + 0.12),    // another dip
            entryY - amp * (_ghostRng.NextDouble() * 0.20 + 0.05),    // slight rise toward exit
            exitY,                                                      // off-screen
        ];
        double[] yTimes = [ 0.00, 0.15, 0.30, 0.50, 0.65, 0.82, 1.00 ];

        var yAnim = new DoubleAnimationUsingKeyFrames();
        yAnim.Duration = new Duration(TimeSpan.FromSeconds(totalDur));
        for (int i = 0; i < yPts.Length; i++)
            yAnim.KeyFrames.Add(new EasingDoubleKeyFrame(yPts[i], KeyTime.FromPercent(yTimes[i]),
                new SineEase { EasingMode = EasingMode.EaseInOut }));
        Storyboard.SetTarget(yAnim, container);
        Storyboard.SetTargetProperty(yAnim, new PropertyPath(Canvas.TopProperty));

        // ── Opacity: materialise → hold → dematerialise ────────────────────
        var opAnim = new DoubleAnimationUsingKeyFrames();
        opAnim.Duration = new Duration(TimeSpan.FromSeconds(totalDur));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0,            KeyTime.FromPercent(0.00)));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(peakOpacity,  KeyTime.FromPercent(0.12)));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(peakOpacity,  KeyTime.FromPercent(0.78)));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0,            KeyTime.FromPercent(1.00)));
        Storyboard.SetTarget(opAnim, container);
        Storyboard.SetTargetProperty(opAnim, new PropertyPath(OpacityProperty));

        // ── Fire directly on the element — reliable for dynamically created objects ──
        opAnim.Completed += (_, _) =>
        {
            frameTimer?.Stop();
            GhostCanvas.Children.Remove(container);
            _ghostActive = Math.Max(0, _ghostActive - 1);
        };

        container.BeginAnimation(Canvas.LeftProperty,    xAnim);
        container.BeginAnimation(Canvas.TopProperty,     yAnim);
        container.BeginAnimation(UIElement.OpacityProperty, opAnim);
    }

    // ── Spinner dot pulse ─────────────────────────────────────────────
    private void PulseSpinnerDot()
    {
        var anim = new ColorAnimation(
            Color.FromRgb(0x3D, 0x3D, 0x5A),
            Color.FromRgb(0xA8, 0xC8, 0xE8),
            new Duration(TimeSpan.FromSeconds(1.5)))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever
        };
        SpinnerBrush.BeginAnimation(SolidColorBrush.ColorProperty, anim);
    }

    private void AnimateSpinnerDot(Color target, bool pulse)
    {
        if (pulse)
        {
            var anim = new ColorAnimation(
                Color.FromRgb(0x3D, 0x3D, 0x5A), target,
                new Duration(TimeSpan.FromSeconds(0.5)))
            {
                AutoReverse = true,
                RepeatBehavior = RepeatBehavior.Forever
            };
            SpinnerBrush.BeginAnimation(SolidColorBrush.ColorProperty, anim);
        }
        else
        {
            var anim = new ColorAnimation(target,
                new Duration(TimeSpan.FromSeconds(0.3)));
            SpinnerBrush.BeginAnimation(SolidColorBrush.ColorProperty, anim);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Header Scan Cutscene
    //  Beam sweeps left→right repeatedly while scanning.
    //  Hex/binary data fragments scroll right→left in the header.
    //  Mini wraith silhouettes glide across at header scale.
    //  Phase label cross-fades on each CurrentPhase change.
    //  Progress bar fills in sync with ScanProgress.
    // ══════════════════════════════════════════════════════════════════
    private void StartHeaderScanAnimation()
    {
        HeaderScanOverlay.Opacity    = 1;
        HeaderScanOverlay.Visibility = Visibility.Visible;

        double w = Math.Max(PatronusCanvas.ActualWidth,  800);
        double h = Math.Max(PatronusCanvas.ActualHeight, 160);
        ScanBeam.Height = h;

        // Sweep beam left → right, repeating forever — direct BeginAnimation (no Storyboard)
        var beamMove = new DoubleAnimation(-10, w + 10,
            new Duration(TimeSpan.FromSeconds(2.4)))
        { RepeatBehavior = RepeatBehavior.Forever };
        ScanBeam.BeginAnimation(Canvas.LeftProperty, beamMove);

        var opKf = new DoubleAnimationUsingKeyFrames { RepeatBehavior = RepeatBehavior.Forever };
        opKf.Duration = new Duration(TimeSpan.FromSeconds(2.4));
        opKf.KeyFrames.Add(new LinearDoubleKeyFrame(0,    KeyTime.FromPercent(0.00)));
        opKf.KeyFrames.Add(new LinearDoubleKeyFrame(0.90, KeyTime.FromPercent(0.05)));
        opKf.KeyFrames.Add(new LinearDoubleKeyFrame(0.90, KeyTime.FromPercent(0.90)));
        opKf.KeyFrames.Add(new LinearDoubleKeyFrame(0,    KeyTime.FromPercent(1.00)));
        ScanBeam.BeginAnimation(OpacityProperty, opKf);

        _headerDataTick = 0;
        _headerDataTimer.Interval = TimeSpan.FromMilliseconds(280);
        _headerDataTimer.Tick    += HeaderDataTimer_Tick;
        _headerDataTimer.Start();

        if (DataContext is WRAITH.ViewModels.MainViewModel vm)
            UpdateHeaderPhase(vm.CurrentPhase);
    }

    private void StopHeaderScanAnimation()
    {
        _headerDataTimer.Stop();
        _headerDataTimer.Tick -= HeaderDataTimer_Tick;

        // Cancel beam animations by passing null (restores local/default values)
        ScanBeam.BeginAnimation(Canvas.LeftProperty, null);
        ScanBeam.BeginAnimation(OpacityProperty, null);

        var fadeOut = new DoubleAnimation(1, 0, new Duration(TimeSpan.FromSeconds(0.45)));
        fadeOut.Completed += (_, _) =>
        {
            HeaderScanOverlay.Visibility = Visibility.Collapsed;
            // Remove dynamically-added fragments/wraithlets but keep named XAML elements
            var toRemove = HeaderScanOverlay.Children
                .OfType<UIElement>()
                .Where(c => c != ScanBeam && c != HeaderPhaseLabel && c != HeaderProgressBar)
                .ToList();
            foreach (var el in toRemove) HeaderScanOverlay.Children.Remove(el);
            ScanBeam.Opacity         = 0;
            HeaderPhaseLabel.Opacity  = 0;
            HeaderProgressBar.Width   = 0;
        };
        HeaderScanOverlay.BeginAnimation(OpacityProperty, fadeOut);
    }

    private void HeaderDataTimer_Tick(object? sender, EventArgs e)
    {
        _headerDataTick++;
        SpawnDataFragment();
        if (_headerDataTick % 6 == 0) SpawnHeaderWraithlet();

        if (DataContext is WRAITH.ViewModels.MainViewModel vm)
        {
            double totalW = Math.Max(PatronusCanvas.ActualWidth, 800);
            HeaderProgressBar.Width = totalW * (vm.ScanProgress / 100.0);
        }
    }

    private void SpawnDataFragment()
    {
        double hH = Math.Max(PatronusCanvas.ActualHeight, 160);
        double hW = Math.Max(PatronusCanvas.ActualWidth,  800);

        double y = _headerRng.NextDouble() > 0.4
            ? _headerRng.NextDouble() * (hH - 18)
            : _headerRng.Next(88, (int)(hH - 10));

        string[] fragments =
        [
            "FF D8 FF", "4D 5A 90", "0xCA FE", "PE32+",  "YARA",
            "0xFF",     "SUB EAX",  "JMP 0x",  "CALL",   "MOV EDX",
            "SHA256:",  "HKLM\\",   "\\RUN",   "cmd.exe","regsvr32",
            "0x4C",     "SIG!!",    "HOOK",    "INJECT",  "DLL"
        ];

        bool isGold = _headerRng.NextDouble() > 0.72;
        var frag = new TextBlock
        {
            Text       = fragments[_headerRng.Next(fragments.Length)],
            FontSize   = _headerRng.NextDouble() * 7 + 8,
            FontFamily = new System.Windows.Media.FontFamily("Consolas"),
            Foreground = isGold
                ? new SolidColorBrush(Color.FromArgb(150, 212, 175,  55))
                : new SolidColorBrush(Color.FromArgb(160, 168, 200, 232)),
            Opacity = 0
        };
        Canvas.SetLeft(frag, hW + 10);
        Canvas.SetTop(frag,  y);
        HeaderScanOverlay.Children.Add(frag);

        double dur   = _headerRng.NextDouble() * 1.6 + 0.9;
        double delay = _headerRng.NextDouble() * 0.25;

        var fadeIn  = new DoubleAnimation(0, 0.85, new Duration(TimeSpan.FromSeconds(0.18)))
                      { BeginTime = TimeSpan.FromSeconds(delay) };
        var move    = new DoubleAnimation(hW + 10, -130, new Duration(TimeSpan.FromSeconds(dur)))
                      { BeginTime = TimeSpan.FromSeconds(delay),
                        EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn } };
        var fadeOut2 = new DoubleAnimation(0.85, 0, new Duration(TimeSpan.FromSeconds(0.25)))
                      { BeginTime = TimeSpan.FromSeconds(delay + dur * 0.72) };

        // Sequence opacity: fade in, hold, then fade out
        var opSeq = new DoubleAnimationUsingKeyFrames();
        opSeq.Duration = new Duration(TimeSpan.FromSeconds(delay + dur + 0.05));
        opSeq.KeyFrames.Add(new LinearDoubleKeyFrame(0,    KeyTime.FromTimeSpan(TimeSpan.FromSeconds(delay))));
        opSeq.KeyFrames.Add(new LinearDoubleKeyFrame(0.85, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(delay + 0.18))));
        opSeq.KeyFrames.Add(new LinearDoubleKeyFrame(0.85, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(delay + dur * 0.72))));
        opSeq.KeyFrames.Add(new LinearDoubleKeyFrame(0,    KeyTime.FromTimeSpan(TimeSpan.FromSeconds(delay + dur))));
        opSeq.Completed += (_, _) => { try { HeaderScanOverlay.Children.Remove(frag); } catch { } };

        frag.BeginAnimation(Canvas.LeftProperty, move);
        frag.BeginAnimation(OpacityProperty,     opSeq);
    }

    private void SpawnHeaderWraithlet()
    {
        double hH    = Math.Max(PatronusCanvas.ActualHeight, 160);
        double hW    = Math.Max(PatronusCanvas.ActualWidth,  800);
        double scale = (hH * 0.70) / 155.0;
        double bW    = 110 * scale;
        bool   ltr   = _headerRng.NextDouble() > 0.35;
        double startX = ltr ? -(bW + 10) : hW + 10;
        double endX   = ltr ?  hW + 10   : -(bW + 10);
        double yPos   = _headerRng.NextDouble() * (hH * 0.6) - 5;
        double dur    = _headerRng.NextDouble() * 2.2 + 2.0;

        Color[] palette =
        [
            Color.FromRgb(168, 200, 232), Color.FromRgb(176, 140, 240),
            Color.FromRgb(140, 180, 255), Color.FromRgb(212, 175,  55)
        ];
        Color gc = palette[_headerRng.Next(palette.Length)];

        System.Windows.Point P(double x, double y) => new(x * scale, y * scale);

        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(P(55, 0), true, true);
            ctx.BezierTo(P(38, 4), P(20, 14), P(20, 32), true, true);
            ctx.LineTo(P(  4,  54), true, false); ctx.LineTo(P( 14,  92), true, false);
            ctx.LineTo(P(  1, 114), true, false); ctx.LineTo(P( 16,  98), true, false);
            ctx.LineTo(P(  4, 134), true, false); ctx.LineTo(P( 22, 114), true, false);
            ctx.LineTo(P( 12, 152), true, false); ctx.LineTo(P( 32, 130), true, false);
            ctx.LineTo(P( 55, 148), true, false);
            ctx.LineTo(P( 78, 130), true, false); ctx.LineTo(P( 98, 152), true, false);
            ctx.LineTo(P( 88, 114), true, false); ctx.LineTo(P(106, 134), true, false);
            ctx.LineTo(P( 94,  98), true, false); ctx.LineTo(P(109, 114), true, false);
            ctx.LineTo(P( 96,  92), true, false); ctx.LineTo(P(106,  54), true, false);
            ctx.BezierTo(P(90, 14), P(72, 4), P(55, 0), true, true);
        }
        geo.Freeze();

        var fill = new RadialGradientBrush
        {
            Center = new System.Windows.Point(0.50, 0.18),
            GradientOrigin = new System.Windows.Point(0.50, 0.14),
            RadiusX = 0.62, RadiusY = 0.58
        };
        fill.GradientStops.Add(new GradientStop(Color.FromArgb(210, gc.R, gc.G, gc.B), 0.00));
        fill.GradientStops.Add(new GradientStop(Color.FromArgb(110, gc.R, gc.G, gc.B), 0.45));
        fill.GradientStops.Add(new GradientStop(Color.FromArgb(  0, gc.R, gc.G, gc.B), 1.00));

        System.Windows.Media.Transform bodyTx =
            ltr ? Transform.Identity : new ScaleTransform(-1, 1, 55 * scale, 0);

        var body = new Path
        {
            Data = geo, Fill = fill,
            Stroke = new SolidColorBrush(Color.FromArgb(35, gc.R, gc.G, gc.B)),
            StrokeThickness = 0.6, RenderTransform = bodyTx,
            Effect = new DropShadowEffect { Color = gc, BlurRadius = 12 * scale, ShadowDepth = 0, Opacity = 0.70 }
        };

        var container = new Canvas { Width = bW * 2, Height = hH, Opacity = 0 };
        container.Children.Add(body);

        foreach (double eyeNX in new[] { 36.0, 74.0 })
        {
            double ex = ltr ? eyeNX * scale : (110.0 - eyeNX) * scale;
            double ey = 22.0 * scale;
            double er = 6.2 * scale;   // much larger

            // ── Outer iris — blood-red radial glow ──
            var ef = new RadialGradientBrush();
            ef.GradientStops.Add(new GradientStop(Color.FromArgb(255, 255, 40,  20), 0.00));  // hot red core
            ef.GradientStops.Add(new GradientStop(Color.FromArgb(200, 180,  0,   0), 0.40));  // deep crimson
            ef.GradientStops.Add(new GradientStop(Color.FromArgb(  0,  80,  0,   0), 1.00));  // fade out
            var eye = new Ellipse
            {
                Width  = er * 2,
                Height = er * 2.2,   // taller than wide — menacing vertical oval
                Fill   = ef,
                Effect = new DropShadowEffect
                {
                    Color       = Color.FromArgb(255, 255, 30, 0),
                    BlurRadius  = 18 * scale,
                    ShadowDepth = 0,
                    Opacity     = 1.0
                }
            };
            Canvas.SetLeft(eye, ex - er);
            Canvas.SetTop(eye,  ey - er * 1.1);

            // ── Vertical slit pupil on top ──
            double pr = er * 0.28;
            var slitBrush = new SolidColorBrush(Color.FromArgb(230, 5, 0, 0));
            var slit = new Ellipse
            {
                Width  = pr * 2,
                Height = er * 1.8,      // tall thin slit
                Fill   = slitBrush
            };
            Canvas.SetLeft(slit, ex - pr);
            Canvas.SetTop(slit,  ey - er * 0.9);

            // ── Blink: long stare, then snap shut ──
            var blinkAnim = new DoubleAnimationUsingKeyFrames
            {
                Duration       = new Duration(TimeSpan.FromSeconds(3.5 + _headerRng.NextDouble() * 2.0)),
                RepeatBehavior = RepeatBehavior.Forever,
                BeginTime      = TimeSpan.FromSeconds(_headerRng.NextDouble() * 1.5)
            };
            blinkAnim.KeyFrames.Add(new LinearDoubleKeyFrame(1.0, KeyTime.FromPercent(0.00)));  // staring open
            blinkAnim.KeyFrames.Add(new LinearDoubleKeyFrame(1.0, KeyTime.FromPercent(0.82)));  // still staring
            blinkAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0.0, KeyTime.FromPercent(0.88)));  // snap shut
            blinkAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0.0, KeyTime.FromPercent(0.91)));  // hold closed
            blinkAnim.KeyFrames.Add(new LinearDoubleKeyFrame(1.0, KeyTime.FromPercent(0.96)));  // snap back open

            eye.BeginAnimation(OpacityProperty, blinkAnim);
            slit.BeginAnimation(OpacityProperty, blinkAnim);

            container.Children.Add(eye);
            container.Children.Add(slit);
        }

        Canvas.SetLeft(container, startX);
        Canvas.SetTop(container, yPos);
        HeaderScanOverlay.Children.Add(container);

        double travel = endX - startX;
        var xAnim = new DoubleAnimationUsingKeyFrames();
        xAnim.Duration = new Duration(TimeSpan.FromSeconds(dur));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX,                 KeyTime.FromPercent(0.00)));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel * 0.38, KeyTime.FromPercent(0.14),
            new QuarticEase { EasingMode = EasingMode.EaseOut }));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel * 0.58, KeyTime.FromPercent(0.42)));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel * 0.72, KeyTime.FromPercent(0.65)));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(startX + travel * 0.85, KeyTime.FromPercent(0.84),
            new QuarticEase { EasingMode = EasingMode.EaseIn }));
        xAnim.KeyFrames.Add(new EasingDoubleKeyFrame(endX,                   KeyTime.FromPercent(1.00)));

        var opAnim = new DoubleAnimationUsingKeyFrames();
        opAnim.Duration = new Duration(TimeSpan.FromSeconds(dur));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0,    KeyTime.FromPercent(0.00)));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0.78, KeyTime.FromPercent(0.12)));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0.78, KeyTime.FromPercent(0.82)));
        opAnim.KeyFrames.Add(new LinearDoubleKeyFrame(0,    KeyTime.FromPercent(1.00)));
        opAnim.Completed += (_, _) => { try { HeaderScanOverlay.Children.Remove(container); } catch { } };

        container.BeginAnimation(Canvas.LeftProperty,       xAnim);
        container.BeginAnimation(UIElement.OpacityProperty, opAnim);
    }

    /// <summary>Cross-fades the header phase label to the new phase name.</summary>
    private void UpdateHeaderPhase(string phase)
    {
        if (string.IsNullOrWhiteSpace(phase)) return;
        var outAnim = new DoubleAnimation(HeaderPhaseLabel.Opacity, 0,
            new Duration(TimeSpan.FromSeconds(0.16)));
        outAnim.Completed += (_, _) =>
        {
            HeaderPhaseLabel.Text = $"[ {phase.ToUpperInvariant()} ]";
            double h = Math.Max(PatronusCanvas.ActualHeight, 160);
            Canvas.SetTop(HeaderPhaseLabel, h - 34);
            HeaderPhaseLabel.BeginAnimation(OpacityProperty,
                new DoubleAnimation(0, 0.88, new Duration(TimeSpan.FromSeconds(0.28))));
        };
        HeaderPhaseLabel.BeginAnimation(OpacityProperty, outAnim);
    }

    // ── Context menu copy actions ─────────────────────────────────────────
    private void CopyTitle_Click(object s, RoutedEventArgs e)
    {
        if (LvFindings.SelectedItem is ThreatFinding f)
            System.Windows.Clipboard.SetText(f.Title);
    }

    private void CopyPath_Click(object s, RoutedEventArgs e)
    {
        if (LvFindings.SelectedItem is ThreatFinding f && !string.IsNullOrEmpty(f.Path))
            System.Windows.Clipboard.SetText(f.Path);
    }

    // ── Column header click → sort ─────────────────────────────────────
    private void LvFindings_ColumnHeaderClick(object s, RoutedEventArgs e)
    {
        if (e.OriginalSource is GridViewColumnHeader header && header.Tag is string column)
        {
            if (DataContext is MainViewModel vm)
                vm.SortBy(column);
        }
    }
}
