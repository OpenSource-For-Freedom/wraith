using System.Collections.ObjectModel;
using System.Windows;
using WRAITH.Services;

namespace WRAITH;

public partial class FeedsWindow : Window
{
    private readonly FeedRefreshService _service = new();
    public ObservableCollection<FeedRow> Rows { get; } = new();

    public FeedsWindow()
    {
        InitializeComponent();
        FeedsGrid.ItemsSource = Rows;
        _service.FeedRefreshed += OnFeedRefreshed;
        LoadInitial();
    }

    private void LoadInitial()
    {
        Rows.Clear();
        var manifest = FeedRefreshService.LoadManifest();
        foreach (var src in FeedRefreshService.Sources)
        {
            manifest.TryGetValue(src.Id, out var status);
            Rows.Add(new FeedRow(src, status));
        }
        StatusLine.Text = $"{Rows.Count} feeds tracked. Refresh to update.";
    }

    private async void RefreshAll_Click(object sender, RoutedEventArgs e)
    {
        // Disable the button + status line so the user sees we're working,
        // and the click handler is guarded so a download blow-up doesn't
        // crash the window (the global DispatcherUnhandledException would
        // otherwise turn it into a process exit).
        RefreshAllBtn.IsEnabled = false;
        StatusLine.Text = "Refreshing feeds...";
        try
        {
            await _service.RefreshAllAsync();
            StatusLine.Text = "Refresh complete.";
        }
        catch (System.Exception ex)
        {
            StatusLine.Text = $"Refresh failed: {ex.Message}";
        }
        finally
        {
            RefreshAllBtn.IsEnabled = true;
        }
    }

    private void OnFeedRefreshed(FeedSource src, FeedStatus status)
    {
        Dispatcher.Invoke(() =>
        {
            var row = Rows.FirstOrDefault(r => r.Id == src.Id);
            if (row != null)
                row.Update(status);
            StatusLine.Text = $"{src.DisplayName}: {status.Status}";
        });
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}

/// <summary>Row binding for the feeds DataGrid — bridges FeedSource + FeedStatus.</summary>
public sealed class FeedRow : System.ComponentModel.INotifyPropertyChanged
{
    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    private void Notify(string name) =>
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));

    public string Id { get; }
    public string DisplayName { get; }

    private string _statusLabel = "Unknown";
    public string StatusLabel { get => _statusLabel; private set { _statusLabel = value; Notify(nameof(StatusLabel)); } }

    private string _lastRefreshLabel = "Never";
    public string LastRefreshLabel { get => _lastRefreshLabel; private set { _lastRefreshLabel = value; Notify(nameof(LastRefreshLabel)); } }

    private string _sizeLabel = "—";
    public string SizeLabel { get => _sizeLabel; private set { _sizeLabel = value; Notify(nameof(SizeLabel)); } }

    public FeedRow(FeedSource src, FeedStatus? status)
    {
        Id          = src.Id;
        DisplayName = src.DisplayName;
        if (status != null) Update(status);
    }

    public void Update(FeedStatus status)
    {
        StatusLabel = status.Status switch
        {
            "ok"          => "OK",
            "downloading" => "Downloading…",
            "error"       => "Error",
            _             => status.Status,
        };
        LastRefreshLabel = string.IsNullOrWhiteSpace(status.LastRefreshUtc)
            ? "Never"
            : status.LastRefreshUtc!.Replace("T", " ").TrimEnd('Z');
        SizeLabel = status.SizeBytes <= 0 ? "—" : FormatSize(status.SizeBytes);
    }

    private static string FormatSize(long bytes)
    {
        const long KB = 1024;
        const long MB = KB * 1024;
        if (bytes >= MB) return $"{bytes / (double)MB:F1} MB";
        if (bytes >= KB) return $"{bytes / (double)KB:F1} KB";
        return $"{bytes} B";
    }
}
