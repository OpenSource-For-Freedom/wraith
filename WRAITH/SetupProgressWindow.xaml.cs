using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using SolidColorBrush = System.Windows.Media.SolidColorBrush;
using WRAITH.Services;

namespace WRAITH;

// ── Step view-model ────────────────────────────────────────────────────
public sealed class SetupStepVm : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? n = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

    // Frozen brushes — reused across all instances (thread-safe reads)
    static readonly Brush BrPending  = Make(0x32, 0x32, 0x52);
    static readonly Brush BrRunning  = Make(0xE8, 0xF4, 0xFF);
    static readonly Brush BrDone     = Make(0xD4, 0xAF, 0x37);
    static readonly Brush BrError    = Make(0xFF, 0x2D, 0x55);
    static readonly Brush BrDimText  = Make(0x40, 0x40, 0x62);
    static readonly Brush BrFullText = Make(0xC8, 0xD8, 0xE8);
    static Brush Make(byte r, byte g, byte b)
    {
        var br = new SolidColorBrush(Color.FromRgb(r, g, b));
        br.Freeze();
        return br;
    }

    private string     _bullet     = "*";
    private string     _name;
    private string     _detail     = "";
    private Brush      _bulletColor;
    private Brush      _nameColor;
    private Visibility _detailVis  = Visibility.Collapsed;

    public string     Bullet      { get => _bullet;      set { _bullet      = value; Notify(); } }
    public string     Name        { get => _name;        set { _name        = value; Notify(); } }
    public string     Detail      { get => _detail;      set { _detail      = value; Notify(); } }
    public Brush      BulletColor { get => _bulletColor; set { _bulletColor = value; Notify(); } }
    public Brush      NameColor   { get => _nameColor;   set { _nameColor   = value; Notify(); } }
    public Visibility DetailVis   { get => _detailVis;   set { _detailVis   = value; Notify(); } }

    public SetupStepVm(string name)
    {
        _name        = name;
        _bulletColor = BrPending;
        _nameColor   = BrDimText;
    }

    public void Apply(SetupStepStatus status, string detail)
    {
        (Bullet, BulletColor, NameColor) = status switch
        {
            SetupStepStatus.Running => (">", BrRunning,  BrFullText),
            SetupStepStatus.Done    => ("+", BrDone,     BrFullText),
            SetupStepStatus.Skipped => ("-", BrPending,  BrDimText),
            SetupStepStatus.Error   => ("x", BrError,    BrError),
            _                       => ("*", BrPending,  BrDimText),
        };
        Detail    = detail;
        DetailVis = string.IsNullOrWhiteSpace(detail) ? Visibility.Collapsed : Visibility.Visible;
    }
}

// ── Window ─────────────────────────────────────────────────────────────
public partial class SetupProgressWindow : Window, INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? n = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

    public List<SetupStepVm> Steps { get; } = new()
    {
        new("Detecting system & Python version"),
        new("Installing Python"),
        new("Adding Python to PATH"),
        new("Creating virtual environment"),
        new("Installing scan packages"),
    };

    private string _statusLine = "Preparing...";
    public string StatusLine
    {
        get => _statusLine;
        set { _statusLine = value; Notify(); }
    }

    public SetupProgressWindow()
    {
        InitializeComponent();
        DataContext = this;
        if (RenderQuality.IsLowTier)
            Loaded += (_, _) => RenderQuality.NullAllEffects(this);
    }

    // ── PATH confirmation dialog ────────────────────────────────────────
    /// <summary>
    /// Opens the WRAITH-styled PATH confirmation dialog (modal, checkbox-gated).
    /// Blocks the calling thread via Dispatcher.Invoke; the UI remains responsive.
    /// Safe to call from any thread.
    /// </summary>
    /// <summary>Thread-safe — can be called from any thread.</summary>
    public void UpdateStep(int index, SetupStepStatus status, string detail = "")
    {
        if (index < 0 || index >= Steps.Count) return;
        Dispatcher.Invoke(() =>
        {
            Steps[index].Apply(status, detail);
            StatusLine = status switch
            {
                SetupStepStatus.Running => Steps[index].Name + "...",
                SetupStepStatus.Done    => Steps[index].Name + " - done.",
                SetupStepStatus.Error   => "[!] " + Steps[index].Name + " failed.",
                _                       => StatusLine,
            };
        });
    }

    /// <summary>Makes the Exit Setup button visible. Call when bootstrap fails.</summary>
    public void ShowCancel()
    {
        Dispatcher.Invoke(() => CancelBtn.Visibility = Visibility.Visible);
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e)
    {
        Application.Current.Shutdown(0);
    }

    private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
