using System.Windows;
using System.Windows.Media;

namespace WRAITH.Services;

/// <summary>
/// Detects the WPF hardware rendering tier once at startup and exposes flags
/// used to dial back expensive visual effects on CPU-only or low-GPU machines.
///
/// Tier 0 — software rendering only (Intel HD/old VM/no driver).
/// Tier 1 — partial GPU (DX9-capable but limited).
/// Tier 2 — full DirectX 9+ hardware acceleration.
///
/// On Tier 0/1 we skip DropShadowEffects, limit animations, and run
/// the Patronus animation at a lower frame rate with fewer rings so we
/// do not spike the CPU or make the machine unresponsive.
/// </summary>
public static class RenderQuality
{
    public static readonly int  Tier;
    public static readonly bool IsLowTier;     // Tier 0 or 1
    public static readonly bool IsSoftware;    // Tier 0 only

    static RenderQuality()
    {
        // RenderCapability.Tier encodes the tier in the high 16 bits.
        Tier       = RenderCapability.Tier >> 16;
        IsSoftware = Tier == 0;
        IsLowTier  = Tier <= 1;
    }

    /// <summary>
    /// Walks the visual tree rooted at <paramref name="root"/> and sets
    /// <see cref="UIElement.Effect"/> to <c>null</c> on every element.
    /// Call once after a window's Loaded event fires on low-tier hardware
    /// to strip every DropShadowEffect / BlurEffect from the rendering pipeline.
    /// </summary>
    public static void NullAllEffects(DependencyObject root)
    {
        if (root is UIElement el) el.Effect = null;
        int n = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < n; i++) NullAllEffects(VisualTreeHelper.GetChild(root, i));
    }
}
