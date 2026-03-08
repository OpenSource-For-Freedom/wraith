using System.IO;
using System.Windows;
using System.Windows.Input;
using WRAITH.Services;

namespace WRAITH;

public partial class PathConfirmDialog : Window
{
    public PathConfirmDialog(string version, string dir, bool alreadyOnPath = false)
    {
        InitializeComponent();
        if (RenderQuality.IsLowTier)
            Loaded += (_, _) => RenderQuality.NullAllEffects(this);
        VersionText.Text    = version;
        DirText.Text        = dir;
        ScriptsDirText.Text = Path.Combine(dir, "Scripts");

        if (alreadyOnPath)
        {
            HeadingText.Text    = "Python is already on your PATH";
            SubtitleText.Text   = "The directories below are already registered. Tick the box to confirm and continue setup.";
            ExplainText.Text    = "No changes will be made to your PATH. This is a confirmation step so you can verify the Python installation WRAITH will use.";
            ConfirmCheckText.Text = "I confirm the Python installation above looks correct.";
            ConfirmBtn.Content  = "Confirm & Continue";
            SkipBtn.Content     = "Skip Step";
        }
    }

    // Enable the confirm button only when the checkbox is ticked
    private void ConfirmCheck_Changed(object sender, RoutedEventArgs e)
        => ConfirmBtn.IsEnabled = ConfirmCheck.IsChecked == true;

    private void AddBtn_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void SkipBtn_Click(object sender, RoutedEventArgs e)
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
