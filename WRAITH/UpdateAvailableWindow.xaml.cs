using System.Windows;
using System.Windows.Input;
using WRAITH.Services;

namespace WRAITH;

/// <summary>
/// Styled update-available dialog. Shown automatically when Velopack finishes
/// downloading a new release in the background.
/// </summary>
public partial class UpdateAvailableWindow : Window
{
    private readonly bool _canApply;

    /// <summary>
    /// Creates the window.
    /// </summary>
    /// <param name="currentVersion">Installed version string, e.g. "1.0.0".</param>
    /// <param name="newVersion">Incoming version string, e.g. "1.2.0".</param>
    /// <param name="changelog">Release notes / changelog text from GitHub release body.</param>
    /// <param name="canApply">False when Velopack is not installed (dev mode) — disables apply button.</param>
    public UpdateAvailableWindow(string currentVersion, string newVersion,
                                 string changelog, bool canApply = true)
    {
        InitializeComponent();

        if (RenderQuality.IsLowTier)
            Loaded += (_, _) => RenderQuality.NullAllEffects(this);

        _canApply = canApply;

        CurrentVersionText.Text = string.IsNullOrWhiteSpace(currentVersion) ? "unknown" : currentVersion;
        NewVersionText.Text     = newVersion;
        ChangelogText.Text      = FormatChangelog(changelog);

        if (!canApply)
        {
            UpdateBtn.IsEnabled = false;
            UpdateBtn.ToolTip   = "Update can only be applied when running an installed build.";
        }
    }

    private static string FormatChangelog(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "No release notes were provided for this version.";

        // Strip markdown headers/bullets for plain-text display in WPF TextBlock
        return raw
            .Replace("\r\n", "\n")
            .Replace("## ", "\n")
            .Replace("### ", "\n")
            .Replace("**", "")
            .Replace("__", "")
            .Replace("- [ ] ", "  • ")
            .Replace("- [x] ", "  ✓ ")
            .Replace("- [X] ", "  ✓ ")
            .Replace("- ", "  • ")
            .Trim();
    }

    private void UpdateBtn_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void LaterBtn_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }
}
