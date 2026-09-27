import WirePathCore
import SwiftUI

/// The 52 pt bar at the top of the main area: back/forward, title + subtitle, screen-specific controls.
struct HeaderBar<Trailing: View>: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.navigationCollapsed) private var collapsed
    @Environment(\.layoutWidth) private var layoutWidth
    var title: String
    var subtitle: String
    var backHelp = String(localized: "Back (⌘[)")
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack(spacing: 12) {
            if collapsed {
                // Collapsed split view (iPad compact): back to the analyses list.
                Button {
                    window.showSidebar()
                } label: {
                    HStack(spacing: 3) {
                        Icon(Icons.back, size: 14)
                        Text("Analyses").font(.wp(13))
                    }
                    .foregroundStyle(Theme.acc)
                    .frame(height: 28)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Back to Analyses")
            } else if !window.sidebarVisible {
                if Platform.isMac {
                    // Room for the traffic lights, then the sidebar toggle.
                    Color.clear.frame(width: 64, height: 1)
                }
                IconButton(icon: Icons.sidebar, iconSize: 18, width: 30, height: 28, help: String(localized: "Show Sidebar (⌃⌘S)")) {
                    window.showSidebar()
                }
            }
            HStack(spacing: 2) {
                if !collapsed || window.canGoBack {
                IconButton(icon: Icons.back, iconSize: 14, width: 28, height: 28, tint: Theme.fg2, help: backHelp,
                           isEnabled: window.canGoBack) { window.goBack() }
                IconButton(icon: Icons.forward, iconSize: 14, width: 28, height: 28,
                           tint: window.canGoForward ? Theme.fg2 : Theme.fg3, help: String(localized: "Forward (⌘])"),
                           isEnabled: window.canGoForward) { window.goForward() }
                }
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.wp(13, .semibold)).foregroundStyle(Theme.fg).lineLimit(1)
                    .accessibilityIdentifier("header.title")
                    .accessibilityAddTraits(.isHeader)
                Text(subtitle).font(.wp(11)).foregroundStyle(Theme.fg2).lineLimit(1)
            }
            .layoutPriority(1)
            Spacer(minLength: 8)
            trailing()
        }
        .padding(.leading, 12)
        .padding(.trailing, 14)
        .frame(height: 52)
        .background(Theme.bar)
        .background(WindowDragArea())
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
    }
}

/// Screen title block used at the top of scrollable content (h1 + subtitle).
struct ScreenTitle: View {
    var title: String
    var subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.wp(22, .bold)).tracking(-0.2).foregroundStyle(Theme.fg)
            Text(subtitle).font(.wp(12)).foregroundStyle(Theme.fg2).lineLimit(1)
        }
    }
}

/// Good / Warning / Error legend.
struct SeverityLegend: View {
    var body: some View {
        HStack(spacing: 14) {
            item(.ok, "Good")
            item(.warning, "Warning")
            item(.error, "Error")
        }
        .font(.wp(11))
        .foregroundStyle(Theme.fg2)
    }

    private func item(_ severity: Severity, _ label: LocalizedStringKey) -> some View {
        HStack(spacing: 5) {
            StatusIcon(severity: severity, size: 11, plain: true)
            Text(label)
        }
    }
}
