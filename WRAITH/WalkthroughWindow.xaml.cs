using System.IO;
using System.Windows;
using System.Windows.Input;
using WRAITH.Services;

namespace WRAITH;

public partial class WalkthroughWindow : Window
{
    // -- Step data ------------------------------------------------------------
    // TargetY = Y from the top of the owner window to the centre of the element
    // the arrow should point at. 0 = centre the popup instead (no arrow).
    //
    // MainWindow layout used for these values:
    //   Row 0 title bar      32 px
    //   Row 1 header        160 px
    //   Row 2 top margin      6 px  -> content base = 198
    //   SpellPanel padding   12 px  -> stack starts at Y = 210
    private record Step(string Title, string Body, string Note, int TargetY);

    private static readonly Step[] Steps =
    [
        new(
            "Welcome to WRAITH",
            "WRAITH checks your PC for threats - things like malware hiding in running programs, dodgy startup entries, suspicious files, and unusual network activity.",
            "Everything runs locally. Nothing is sent anywhere. A full scan takes about 2-5 minutes.",
            0
        ),
        new(
            "Where to scan",
            "This box shows the folder WRAITH will scan. It defaults to C:\\ which covers your whole main drive.",
            "You can type a different path or click Browse to pick a specific folder.",
            241
        ),
        new(
            "Start the scan",
            "Click this button to run a full scan. WRAITH checks processes, files, the registry, Windows events, network connections, and more.",
            "The button below it (Finite Incantatem) stops the scan early if you need to.",
            473
        ),
        new(
            "If something is found",
            "When WRAITH finds a serious threat it can stop the program and lock the file away automatically - no action needed from you.",
            "Click \"Quarantine Vault\" here to see anything it has locked away. You can restore or delete items from there.",
            590
        ),
        new(
            "You are good to go",
            "That is the tour. Close this and hit EXPECTO PATRONUM to run your first scan.",
            "This will not show again. Bring it back any time by launching WRAITH with the --tour flag.",
            0
        ),
    ];

    private const double LeftPanelRightX = 238.0;
    private const double ArrowTipInPopup = 44.0;

    private readonly string _tourFile;
    private int _step;

    public WalkthroughWindow(string tourFile)
    {
        InitializeComponent();
        if (RenderQuality.IsLowTier)
            Loaded += (_, _) => RenderQuality.NullAllEffects(this);
        _tourFile = tourFile;
    }

    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        ShowStep();
    }

    private void ShowStep()
    {
        var s = Steps[_step];

        StepLabel.Text = $"Step {_step + 1} of {Steps.Length}";
        TitleText.Text = s.Title;
        BodyText.Text  = s.Body;

        NoteText.Text       = s.Note;
        NoteText.Visibility = string.IsNullOrEmpty(s.Note)
            ? Visibility.Collapsed
            : Visibility.Visible;

        BackBtn.IsEnabled  = _step > 0;
        NextBtn.Content    = _step == Steps.Length - 1 ? "Done" : "Next";
        SkipBtn.Visibility = _step == Steps.Length - 1
            ? Visibility.Collapsed
            : Visibility.Visible;

        UpdateLayout();
        PositionNearOwner(s.TargetY);
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_step > 0) { _step--; ShowStep(); }
    }

    private void Next_Click(object sender, RoutedEventArgs e)
    {
        if (_step < Steps.Length - 1) { _step++; ShowStep(); }
        else { MarkDone(); Close(); }
    }

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        MarkDone();
        Close();
    }

    private void PositionNearOwner(int targetY)
    {
        if (Owner is not Window owner) return;

        double ow = owner.ActualWidth;
        double oh = owner.ActualHeight;
        double ox = owner.Left;
        double oy = owner.Top;
        double w  = ActualWidth  > 0 ? ActualWidth  : Width;
        double h  = ActualHeight > 0 ? ActualHeight : 260;

        double x, y;

        if (targetY > 0)
        {
            ArrowLeft.Visibility = Visibility.Visible;
            x = ox + LeftPanelRightX + 2;
            y = oy + targetY - ArrowTipInPopup;
        }
        else
        {
            ArrowLeft.Visibility = Visibility.Collapsed;
            x = ox + (ow - w) / 2;
            y = oy + (oh - h) / 2;
        }

        var screen = SystemParameters.WorkArea;
        Left = Math.Clamp(x, screen.Left, screen.Right  - w);
        Top  = Math.Clamp(y, screen.Top,  screen.Bottom - h);
    }

    private void MarkDone()
    {
        try { File.WriteAllText(_tourFile, DateTime.UtcNow.ToString("O")); } catch { }
    }

    private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }
}
