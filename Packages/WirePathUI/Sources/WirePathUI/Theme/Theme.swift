import SwiftUI

/// Platform colour tokens from design/*.dc.html (`.wp` = dark, `.wp.light` = light).
/// Used directly by the AppKit/UIKit-drawn packet list; SwiftUI views use `Theme`.
public enum ThemeColors {
    private static func white(_ a: CGFloat) -> PlatformColor { PlatformColor(red: 1, green: 1, blue: 1, alpha: a) }
    private static func black(_ a: CGFloat) -> PlatformColor { PlatformColor(red: 0, green: 0, blue: 0, alpha: a) }
    private static func d(_ dark: PlatformColor, _ light: PlatformColor) -> PlatformColor { .dynamic(dark: dark, light: light) }

    static let win = d(.srgb(0x1D1D20), .srgb(0xFFFFFF))
    static let side = d(.srgb(0x252528), .srgb(0xEDEDF0))
    static let bar = d(.srgb(0x1D1D20), .srgb(0xFFFFFF))
    static let surf = d(.srgb(0x232326), .srgb(0xFFFFFF))
    static let surf2 = d(.srgb(0x2A2A2E), .srgb(0xF5F5F7))
    static let line = d(white(0.075), black(0.085))
    static let line2 = d(white(0.14), black(0.15))
    static let fg = d(.srgb(0xECECEF), .srgb(0x1D1D1F))
    static let fg2 = d(.srgb(0xA9A9B0), .srgb(0x5E5E65))
    static let fg3 = d(.srgb(0x8B8B93), .srgb(0x6C6C73))
    static let sel = d(.srgb(0x1D63D6), .srgb(0x0A64D8))
    static let selSoft = d(.srgb(77, 148, 255, 0.16), .srgb(10, 100, 216, 0.10))
    static let acc = d(.srgb(0x5AA2FF), .srgb(0x0A64D8))
    static let stripe = d(white(0.028), black(0.025))
    static let ok = d(.srgb(0x52C58F), .srgb(0x1C8A4E))
    static let warn = d(.srgb(0xE8A33D), .srgb(0xA86400))
    static let err = d(.srgb(0xF26C5F), .srgb(0xC63A2F))
    static let okBg = d(.srgb(82, 197, 143, 0.13), .srgb(28, 138, 78, 0.10))
    static let warnBg = d(.srgb(232, 163, 61, 0.13), .srgb(200, 120, 0, 0.11))
    static let errBg = d(.srgb(242, 108, 95, 0.14), .srgb(198, 58, 47, 0.10))
    static let ctrl = d(white(0.08), black(0.055))
    static let ctrl2 = d(white(0.13), black(0.09))
    static let grid = d(white(0.07), black(0.07))
    static let m1 = d(.srgb(0x4CC4CB), .srgb(0x0E8F97))
    static let m2 = d(.srgb(0xA594F5), .srgb(0x6A52D9))
    static let m1Bg = d(.srgb(76, 196, 203, 0.13), .srgb(14, 143, 151, 0.10))
    static let highlight = d(.srgb(77, 148, 255, 0.30), .srgb(10, 100, 216, 0.18))
}

/// SwiftUI colour tokens (same names as the CSS variables in the design).
public enum Theme {
    public static let win = Color(platform: ThemeColors.win)
    public static let side = Color(platform: ThemeColors.side)
    public static let bar = Color(platform: ThemeColors.bar)
    public static let surf = Color(platform: ThemeColors.surf)
    public static let surf2 = Color(platform: ThemeColors.surf2)
    public static let line = Color(platform: ThemeColors.line)
    public static let line2 = Color(platform: ThemeColors.line2)
    public static let fg = Color(platform: ThemeColors.fg)
    public static let fg2 = Color(platform: ThemeColors.fg2)
    public static let fg3 = Color(platform: ThemeColors.fg3)
    public static let sel = Color(platform: ThemeColors.sel)
    public static let selSoft = Color(platform: ThemeColors.selSoft)
    public static let acc = Color(platform: ThemeColors.acc)
    public static let stripe = Color(platform: ThemeColors.stripe)
    public static let ok = Color(platform: ThemeColors.ok)
    public static let warn = Color(platform: ThemeColors.warn)
    public static let err = Color(platform: ThemeColors.err)
    public static let okBg = Color(platform: ThemeColors.okBg)
    public static let warnBg = Color(platform: ThemeColors.warnBg)
    public static let errBg = Color(platform: ThemeColors.errBg)
    public static let ctrl = Color(platform: ThemeColors.ctrl)
    public static let ctrl2 = Color(platform: ThemeColors.ctrl2)
    public static let grid = Color(platform: ThemeColors.grid)
    public static let m1 = Color(platform: ThemeColors.m1)
    public static let m2 = Color(platform: ThemeColors.m2)
    public static let m1Bg = Color(platform: ThemeColors.m1Bg)
    public static let highlight = Color(platform: ThemeColors.highlight)
    /// Text on the selection colour.
    public static let onSel = Color.white
    public static let onSelSub = Color.white.opacity(0.75)
    /// Segmented-control thumb shadow.
    public static let thumbShadow = Color.black.opacity(0.18)
}

extension Font {
    /// SF Pro Text at the design's px size. Scales with Dynamic Type relative to the body style.
    static func wp(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight)
    }

    /// SF Mono at the design's px size.
    static func wpMono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}
