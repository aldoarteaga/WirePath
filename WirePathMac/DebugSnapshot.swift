import AppKit
import SwiftUI
import WirePathUI

/// Developer-only visual check, driven by environment variables. Compiled into Debug builds only: Release (what
/// ships) has the no-op stub below, so none of these hooks or their names exist in it.
///
/// Environment:
///
///   WIREPATH_LIBRARY_ROOT=<dir>        use an isolated analysis library
///   WIREPATH_IMPORT=<a.pcap:b.pcap>    import captures at launch
///   WIREPATH_APPEARANCE=dark|light     force the appearance
///   WIREPATH_SNAPSHOT_DIR=<dir>        render the window to PNGs, then quit
///   WIREPATH_SNAPSHOT_ROUTES=overview,calls,call:6,packets:6,sip,rtp,timeline
///   WIREPATH_SNAPSHOT_SIZE=1440x900
#if DEBUG
@MainActor
enum DebugSnapshot {
    static var environment: [String: String] { ProcessInfo.processInfo.environment }

    /// Prints the title-bar view hierarchy (WIREPATH_DEBUG_CHROME).
    static var debugChrome: Bool { environment["WIREPATH_DEBUG_CHROME"] != nil }

    static func applyAppearance() {
        switch environment["WIREPATH_APPEARANCE"] {
        case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
        case "light": NSApp.appearance = NSAppearance(named: .aqua)
        default: break
        }
    }

    static func run(window model: WindowModel, library: LibraryModel) {
        LaunchOptions.applyImports(window: model, library: library)
        guard let directory = environment["WIREPATH_SNAPSHOT_DIR"] else { return }
        let routes = (environment["WIREPATH_SNAPSHOT_ROUTES"] ?? "overview").split(separator: ",").map(String.init)
        let size = (environment["WIREPATH_SNAPSHOT_SIZE"] ?? "1440x900").split(separator: "x").compactMap { Double($0) }
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(600))
            if let window = NSApp.windows.first(where: { $0.isVisible }), size.count == 2 {
                window.setContentSize(NSSize(width: size[0], height: size[1]))
            }
            // Wait for analyses to finish and results to load.
            let wait = environment["WIREPATH_SNAPSHOT_NOWAIT"] == nil ? 600 : 3
            for _ in 0..<wait {
                if library.items.allSatisfy({ !$0.isAnalyzing }) && model.document != nil { break }
                model.ensureLoaded()
                try? await Task.sleep(for: .milliseconds(100))
            }
            for route in routes {
                apply(route, to: model)
                try? await Task.sleep(for: .milliseconds(1200))
                capture(to: URL(fileURLWithPath: directory).appendingPathComponent("\(route.replacingOccurrences(of: ":", with: "-")).png"))
            }
            NSApp.terminate(nil)
        }
    }

    private static func apply(_ route: String, to model: WindowModel) {
        if route.hasPrefix("analysis:"), let index = Int(route.dropFirst(9)), index < model.library.items.count {
            model.select(model.library.items[index])
        } else {
            LaunchOptions.apply(route, to: model)
        }
    }

    /// Renders the window's frame view (including the title-bar band and traffic lights) to a PNG.
    private static func capture(to url: URL) {
        guard let window = NSApp.windows.first(where: { $0.isVisible }),
              let view = window.contentView?.superview ?? window.contentView else { return }
        let bounds = view.bounds
        guard let rep = view.bitmapImageRepForCachingDisplay(in: bounds) else { return }
        view.cacheDisplay(in: bounds, to: rep)
        if let data = rep.representation(using: .png, properties: [:]) {
            try? data.write(to: url)
        }
        if debugChrome, let content = window.contentView,
           let contentRep = content.bitmapImageRepForCachingDisplay(in: content.bounds) {
            content.cacheDisplay(in: content.bounds, to: contentRep)
            try? contentRep.representation(using: .png, properties: [:])?.write(to: url.deletingPathExtension().appendingPathExtension("content.png"))
            func dump(_ view: NSView, _ depth: Int) {
                print(String(repeating: "  ", count: depth) + "\(type(of: view)) \(view.frame) hidden=\(view.isHidden) alpha=\(view.alphaValue)")
                for sub in view.subviews where depth < 3 { dump(sub, depth + 1) }
            }
            if let frameView = content.superview { for sub in frameView.subviews where sub !== content { dump(sub, 0) } }
            print("key=\(window.isKeyWindow) main=\(window.isMainWindow) active=\(NSApp.isActive)")
            if let frameView = content.superview {
                for point in [NSPoint(x: 240, y: frameView.bounds.height - 26), NSPoint(x: 540, y: frameView.bounds.height - 26),
                              NSPoint(x: 1300, y: frameView.bounds.height - 26), NSPoint(x: 24, y: frameView.bounds.height - 26)] {
                    let hit = frameView.hitTest(point)
                    var chain: [String] = []
                    var v = hit
                    while let current = v, chain.count < 4 { chain.append(String(describing: type(of: current))); v = current.superview }
                    print("hit \(point): \(chain.joined(separator: " < "))")
                }
            }
        }
    }
}
#else
@MainActor
enum DebugSnapshot {
    static let debugChrome = false
    static func applyAppearance() {}
    static func run(window model: WindowModel, library: LibraryModel) {}
}
#endif
