import AppKit
import SwiftUI

/// Configures the hosting NSWindow to match the design: no visible title, content extending under a
/// transparent title bar, and the traffic lights centred in the 52 pt sidebar band at x = 18.
struct WindowConfigurator: NSViewRepresentable {
    static let bandHeight: CGFloat = 52

    func makeNSView(context: Context) -> ConfiguratorView { ConfiguratorView() }
    func updateNSView(_ nsView: ConfiguratorView, context: Context) {}

    final class ConfiguratorView: NSView {
        private var observers: [NSObjectProtocol] = []

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            observers.forEach(NotificationCenter.default.removeObserver)
            observers.removeAll()
            guard let window else { return }
            window.titleVisibility = .hidden
            window.titlebarAppearsTransparent = true
            window.styleMask.insert(.fullSizeContentView)
            window.isMovableByWindowBackground = false
            window.titlebarSeparatorStyle = .none
            window.collectionBehavior.insert(.fullScreenPrimary)
            if window.frame.width < 1100 {
                window.setContentSize(NSSize(width: 1440, height: 900))
                window.center()
            }
            layoutTrafficLights()
            if DebugSnapshot.debugChrome, let frameView = window.contentView?.superview {
                func dump(_ view: NSView, _ depth: Int) {
                    print(String(repeating: "  ", count: depth) + "\(type(of: view)) \(view.frame) hidden=\(view.isHidden) alpha=\(view.alphaValue)")
                    for sub in view.subviews { dump(sub, depth + 1) }
                }
                for sub in frameView.subviews where !(sub === window.contentView) { dump(sub, 0) }
            }
            let names: [Notification.Name] = [NSWindow.didResizeNotification, NSWindow.didEndLiveResizeNotification,
                                              NSWindow.didExitFullScreenNotification, NSWindow.didBecomeKeyNotification,
                                              NSWindow.didResignKeyNotification]
            for name in names {
                observers.append(NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in
                    MainActor.assumeIsolated { self?.layoutTrafficLights() }
                })
            }
            DispatchQueue.main.async { [weak self] in self?.layoutTrafficLights() }
        }

        /// AppKit rebuilds the title bar when the appearance changes (Light ↔ Dark, or the app's own setting),
        /// restoring the system layout; apply ours again once it has done so.
        override func viewDidChangeEffectiveAppearance() {
            super.viewDidChangeEffectiveAppearance()
            layoutTrafficLights()
            DispatchQueue.main.async { [weak self] in self?.layoutTrafficLights() }
        }

        func layoutTrafficLights() {
            guard let window, !window.styleMask.contains(.fullScreen),
                  let close = window.standardWindowButton(.closeButton),
                  let miniaturize = window.standardWindowButton(.miniaturizeButton),
                  let zoom = window.standardWindowButton(.zoomButton),
                  let titlebar = close.superview, let container = titlebar.superview else { return }
            let height = WindowConfigurator.bandHeight
            // Shrink the system title bar to the traffic-light area so the rest of the band (sidebar toggle,
            // header buttons, search) receives clicks; WindowDragArea provides dragging elsewhere.
            let frame = NSRect(x: 0, y: window.frame.height - height, width: 80, height: height)
            if container.frame != frame { container.frame = frame }
            titlebar.frame = container.bounds
            // The system title-bar decoration (edge effect/tint) would dim the design's 52 pt band.
            func hideDecorations(in view: NSView) {
                for sub in view.subviews {
                    let name = String(describing: type(of: sub))
                    if name.contains("TitlebarDecoration") || name.contains("TitlebarBackground") {
                        sub.isHidden = true
                    } else if !(sub is NSButton) {
                        hideDecorations(in: sub)
                    }
                }
            }
            hideDecorations(in: container)
            // Design: 12 pt circles at x = 18, 38, 58 (8 pt gaps), vertically centred in the band.
            for (index, button) in [close, miniaturize, zoom].enumerated() {
                let size = button.frame.size
                let circleInset = (size.width - 12) / 2
                button.setFrameOrigin(NSPoint(x: 18 - circleInset + CGFloat(index) * 20,
                                              y: (height - size.height) / 2))
            }
        }
    }
}
