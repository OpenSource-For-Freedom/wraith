using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using WRAITH.Models;

namespace WRAITH.Converters;

/// <summary>Maps Severity → background SolidColorBrush for list rows and badges.</summary>
public class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not Severity sev) return Brushes.Transparent;
        return sev switch
        {
            Severity.Critical => new SolidColorBrush(Color.FromRgb(0xFF, 0x2D, 0x55)),
            Severity.High     => new SolidColorBrush(Color.FromRgb(0xFF, 0x6B, 0x35)),
            Severity.Medium   => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x00)),
            Severity.Low      => new SolidColorBrush(Color.FromRgb(0x4F, 0xC3, 0xF7)),
            _                 => new SolidColorBrush(Color.FromRgb(0x9E, 0x9E, 0x9E))
        };
    }
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>Maps Severity → foreground colour (dark for yellow/light badges).</summary>
public class SeverityToForegroundConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not Severity sev) return Brushes.White;
        return sev switch
        {
            Severity.Medium => new SolidColorBrush(Color.FromRgb(0x1A, 0x14, 0x00)),
            Severity.Low    => new SolidColorBrush(Color.FromRgb(0x00, 0x1A, 0x2E)),
            _               => Brushes.White
        };
    }
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>Maps ThreatLevel string → glow brush for the headline badge.</summary>
public class ThreatLevelToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value?.ToString()?.ToUpperInvariant() switch
        {
            "CRITICAL" => new SolidColorBrush(Color.FromRgb(0xFF, 0x2D, 0x55)),
            "HIGH"     => new SolidColorBrush(Color.FromRgb(0xFF, 0x6B, 0x35)),
            "MEDIUM"   => new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x00)),
            "LOW"      => new SolidColorBrush(Color.FromRgb(0x4F, 0xC3, 0xF7)),
            "CLEAN"    => new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0x76)),
            "SCANNING" => new SolidColorBrush(Color.FromRgb(0xA8, 0xC8, 0xE8)),
            _          => new SolidColorBrush(Color.FromRgb(0x60, 0x50, 0x90))
        };
    }
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>bool → Visibility (true = Visible).</summary>
public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___) =>
        val is true ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object v, Type t, object p, CultureInfo c)
        => v is Visibility.Visible;
}

/// <summary>Inverted bool → Visibility.</summary>
public class InvertedBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___) =>
        val is true ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object v, Type t, object p, CultureInfo c)
        => v is not Visibility.Visible;
}

/// <summary>Maps Severity row to row background with alternating shade.</summary>
public class SeverityToRowBgConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not Severity sev) return Brushes.Transparent;
        return sev switch
        {
            Severity.Critical => new SolidColorBrush(Color.FromArgb(0x22, 0xFF, 0x2D, 0x55)),
            Severity.High     => new SolidColorBrush(Color.FromArgb(0x20, 0xFF, 0x6B, 0x35)),
            Severity.Medium   => new SolidColorBrush(Color.FromArgb(0x18, 0xFF, 0xD7, 0x00)),
            Severity.Low      => new SolidColorBrush(Color.FromArgb(0x14, 0x4F, 0xC3, 0xF7)),
            _                 => Brushes.Transparent
        };
    }
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>Null or empty → Collapsed.</summary>
public class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___) =>
        val == null || string.IsNullOrWhiteSpace(val.ToString())
            ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>Null → false, non-null → true. Used for IsEnabled bindings.</summary>
public class NullToBoolConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___) => val != null;
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>
/// Maps ProcessStatus string ("LIVE","TASK","") → badge background colour.
/// "LIVE" → green glow, "TASK" → amber, anything else → transparent.
/// </summary>
public class ProcessStatusToBrushConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___)
    {
        return val?.ToString() switch
        {
            "LIVE" => new SolidColorBrush(Color.FromArgb(0xFF, 0x00, 0xE5, 0x76)),  // green
            "TASK" => new SolidColorBrush(Color.FromArgb(0xFF, 0xFF, 0xC1, 0x07)),  // amber
            _      => Brushes.Transparent
        };
    }
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>
/// Maps ProcessStatus string → foreground: dark text on LIVE/TASK, invisible otherwise.
/// </summary>
public class ProcessStatusToFgConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___)
    {
        return val?.ToString() switch
        {
            "LIVE" => new SolidColorBrush(Color.FromRgb(0x00, 0x1A, 0x0C)), // dark on green
            "TASK" => new SolidColorBrush(Color.FromRgb(0x1A, 0x11, 0x00)), // dark on amber
            _      => Brushes.Transparent
        };
    }
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>Empty / null string → Collapsed, non-empty → Visible.</summary>
public class EmptyStringToCollapsedConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___) =>
        string.IsNullOrWhiteSpace(val?.ToString())
            ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>bool IsLive → Visible when true (for kill button column).</summary>
public class IsLiveToVisibilityConverter : IValueConverter
{
    public object Convert(object val, Type _, object __, CultureInfo ___) =>
        val is true ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}

/// <summary>Maps a LogEntry.Tag string to the appropriate foreground brush for the log panel.</summary>
public class LogTagToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush BrError     = new(Color.FromRgb(0xFF, 0x2D, 0x55)); // red
    private static readonly SolidColorBrush BrWarn      = new(Color.FromRgb(0xFF, 0x8C, 0x35)); // orange
    private static readonly SolidColorBrush BrDone      = new(Color.FromRgb(0x69, 0xFF, 0x47)); // green
    private static readonly SolidColorBrush BrKilled    = new(Color.FromRgb(0x00, 0xFF, 0xB2)); // teal
    private static readonly SolidColorBrush BrCancelled = new(Color.FromRgb(0xFF, 0xD7, 0x00)); // yellow
    private static readonly SolidColorBrush BrLive      = new(Color.FromRgb(0x4F, 0xC3, 0xF7)); // sky blue
    private static readonly SolidColorBrush BrTrace     = new(Color.FromRgb(0x50, 0x44, 0x70)); // muted purple
    private static readonly SolidColorBrush BrSep       = new(Color.FromRgb(0x3D, 0x2D, 0x60)); // very dim
    private static readonly SolidColorBrush BrDefault   = new(Color.FromRgb(0xAA, 0x96, 0xCC)); // lavender

    static LogTagToBrushConverter()
    {
        BrError.Freeze(); BrWarn.Freeze(); BrDone.Freeze(); BrKilled.Freeze();
        BrCancelled.Freeze(); BrLive.Freeze(); BrTrace.Freeze(); BrSep.Freeze(); BrDefault.Freeze();
    }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        (value as string) switch
        {
            "ERROR"     => BrError,
            "WARN"      => BrWarn,
            "DONE"      => BrDone,
            "KILLED"    => BrKilled,
            "STOP"      => BrWarn,
            "CANCELLED" => BrCancelled,
            "LIVE"      => BrLive,
            "TRACE"     => BrTrace,
            "SEP"       => BrSep,
            _           => BrDefault,
        };

    public object ConvertBack(object v, Type t, object p, CultureInfo c) => DependencyProperty.UnsetValue;
}
