using System.Diagnostics;
using System.Windows;
using WRAITH.Services;

namespace WRAITH;

public partial class QuarantineWindow : Window
{
    private readonly QuarantineService _quarantine = new();

    public QuarantineWindow()
    {
        InitializeComponent();
        LoadData();
    }

    private void LoadData()
    {
        VaultGrid.ItemsSource = _quarantine.GetRecords();
    }

    private QuarantineRecord? Selected => VaultGrid.SelectedItem as QuarantineRecord;

    private List<QuarantineRecord> GetSelectedRecords()
    {
        var selected = VaultGrid.SelectedItems
            .OfType<QuarantineRecord>()
            .ToList();

        if (selected.Count > 0)
            return selected;

        if (VaultGrid.CurrentItem is QuarantineRecord current)
            selected.Add(current);

        return selected;
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => LoadData();

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = _quarantine.VaultDirectory,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to open vault folder: {ex.Message}", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Restore_Click(object sender, RoutedEventArgs e)
    {
        var rec = GetSelectedRecords().FirstOrDefault() ?? Selected;
        if (rec == null)
        {
            MessageBox.Show("Select a quarantined item first.", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (string.IsNullOrWhiteSpace(rec.QuarantinedPath))
        {
            MessageBox.Show("This item has already been restored or deleted.", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            $"Restore file back to disk?\n\nOriginal: {rec.OriginalPath}",
            "Restore quarantined file",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes) return;

        if (_quarantine.Restore(rec.Id, out var restoredPath))
            MessageBox.Show($"File restored to:\n{restoredPath}", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Information);
        else
            MessageBox.Show("Restore failed. The vault file may be missing.", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Warning);

        LoadData();
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        var records = GetSelectedRecords();
        if (records.Count == 0)
        {
            MessageBox.Show("Select one or more quarantined items first.", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            records.Count == 1
                ? "Permanently delete selected vault file? This action cannot be undone."
                : $"Permanently delete {records.Count} selected vault files? This action cannot be undone.",
            "Delete quarantined file",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            int deleted = 0;
            int failed = 0;

            foreach (var rec in records)
            {
                if (_quarantine.DeleteFromVault(rec.Id, requireAdmin: false))
                    deleted++;
                else
                    failed++;
            }

            if (failed == 0)
                MessageBox.Show($"Deleted {deleted} quarantined item(s).", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Information);
            else
                MessageBox.Show($"Deleted {deleted} item(s), failed {failed} item(s).", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Delete failed: {ex.Message}", "WRAITH", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        LoadData();
    }

    private void ImportFiles_Click(object sender, RoutedEventArgs e)
    {
        var picker = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Import file(s) into Quarantine Vault",
            Multiselect = true,
            CheckFileExists = true,
            CheckPathExists = true,
        };

        if (picker.ShowDialog(this) != true)
            return;

        ImportFiles(picker.FileNames);
    }

    private void DropZone_DragOver(object sender, System.Windows.DragEventArgs e)
    {
        if (e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
        {
            e.Effects = System.Windows.DragDropEffects.Copy;
            e.Handled = true;
            return;
        }

        e.Effects = System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_Drop(object sender, System.Windows.DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
            return;

        var dropped = e.Data.GetData(System.Windows.DataFormats.FileDrop) as string[];
        if (dropped == null || dropped.Length == 0)
            return;

        ImportFiles(dropped);
    }

    private void ImportFiles(IEnumerable<string> paths)
    {
        int imported = 0;
        int failed = 0;

        foreach (var path in paths)
        {
            try
            {
                if (!System.IO.File.Exists(path))
                {
                    failed++;
                    continue;
                }

                _quarantine.QuarantineFile(path, "Manual import from Quarantine Vault");
                imported++;
            }
            catch
            {
                failed++;
            }
        }

        LoadData();

        MessageBox.Show(
            $"Imported: {imported}\nFailed: {failed}",
            "WRAITH",
            MessageBoxButton.OK,
            failed == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
