import SwiftUI

/// Width class of the detail area, derived from the space actually available (never from the device
/// model), so iPad mini portrait, Split View, Stage Manager windows and large Mac windows all adapt.
public enum LayoutWidth: Int, Comparable, Sendable {
    /// < 760 pt: one column, sheets for details, essential columns only.
    case compact
    /// 760–1180 pt: stacked cards, two-column where it fits.
    case regular
    /// ≥ 1180 pt: the full desktop layout from the design.
    case wide

    public init(width: CGFloat) {
        switch width {
        case ..<760: self = .compact
        case ..<1180: self = .regular
        default: self = .wide
        }
    }

    public static func < (lhs: LayoutWidth, rhs: LayoutWidth) -> Bool { lhs.rawValue < rhs.rawValue }
}

private struct LayoutWidthKey: EnvironmentKey {
    static let defaultValue = LayoutWidth.wide
}

extension EnvironmentValues {
    public var layoutWidth: LayoutWidth {
        get { self[LayoutWidthKey.self] }
        set { self[LayoutWidthKey.self] = newValue }
    }
}

extension View {
    /// Measures this view's width and publishes the matching `LayoutWidth` to its descendants.
    public func adaptiveLayoutWidth() -> some View { modifier(AdaptiveWidthModifier()) }
}

private struct AdaptiveWidthModifier: ViewModifier {
    @State private var width = LayoutWidth.wide

    func body(content: Content) -> some View {
        content
            .environment(\.layoutWidth, width)
            .onGeometryChange(for: LayoutWidth.self) { LayoutWidth(width: $0.size.width) } action: { width = $0 }
    }
}

/// Lays children out horizontally when wide enough, otherwise stacks them vertically.
struct AdaptiveStack<Content: View>: View {
    @Environment(\.layoutWidth) private var layoutWidth
    var threshold: LayoutWidth = .wide
    var spacing: CGFloat = 12
    @ViewBuilder var content: () -> Content

    var body: some View {
        if layoutWidth >= threshold {
            HStack(alignment: .top, spacing: spacing, content: content)
        } else {
            VStack(alignment: .leading, spacing: spacing, content: content)
        }
    }
}

private struct NavigationCollapsedKey: EnvironmentKey {
    static let defaultValue = false
}

extension EnvironmentValues {
    /// True when the split view has collapsed into a single stack (iPad compact width / narrow window):
    /// the header then offers a way back to the analyses list instead of a sidebar toggle.
    public var navigationCollapsed: Bool {
        get { self[NavigationCollapsedKey.self] }
        set { self[NavigationCollapsedKey.self] = newValue }
    }
}
