import Foundation

/// Launch-time options used by UI tests and screenshots, honoured by Debug builds only:
///   WIREPATH_LIBRARY_ROOT=<dir>      isolated analysis library (read by LibraryModel)
///   WIREPATH_IMPORT=<a.pcap:b.pcap>  captures to import at launch
///   WIREPATH_ROUTE=<route>           screen to open once the analysis is ready
///                                    (overview, calls, call:N, packets[:N], frame:N, sip, rtp, timeline, inspector)
@MainActor
public enum LaunchOptions {
    private static var applied = false

    static var environment: [String: String] {
        #if DEBUG
        ProcessInfo.processInfo.environment
        #else
        [:]
        #endif
    }

    /// An isolated analysis library for tests (Debug only; the hook's name is not even in Release builds).
    static var libraryRoot: URL? {
        #if DEBUG
        environment["WIREPATH_LIBRARY_ROOT"].map { URL(fileURLWithPath: $0, isDirectory: true) }
        #else
        nil
        #endif
    }

    public static func applyImports(window: WindowModel, library: LibraryModel) {
        #if DEBUG
        guard !applied, let paths = environment["WIREPATH_IMPORT"], !paths.isEmpty else { return }
        applied = true
        let urls = paths.split(separator: ":").map { URL(fileURLWithPath: String($0)) }
        let items = library.importCaptures(urls)
        if let first = items.first { window.select(first) }
        if let route = environment["WIREPATH_ROUTE"] {
            Task { @MainActor in
                for _ in 0..<600 where window.document == nil {
                    window.ensureLoaded()
                    try? await Task.sleep(for: .milliseconds(100))
                }
                apply(route, to: window)
            }
        }
        #endif
    }

    /// Navigates to a route string (also used by the macOS snapshot tool).
    public static func apply(_ route: String, to window: WindowModel) {
        let parts = route.split(separator: ":").map(String.init)
        let argument = parts.count > 1 ? Int(parts[1]) : nil
        switch parts.first ?? "" {
        case "overview": window.navigate(to: .section(.overview))
        case "inspector": window.inspectorVisible = true; window.navigate(to: .section(.overview))
        case "calls": window.navigate(to: .section(.calls))
        case "call": window.investigate(argument ?? 0)
        case "packets": window.showPackets(forCall: argument)
        case "frame": window.showPacket(frame: argument ?? 1)
        case "sip": window.navigate(to: .section(.sipDialogs))
        case "rtp": window.navigate(to: .section(.rtpStreams))
        case "webrtc": window.showWebRTCSession(argument ?? 0)
        case "timeline": window.navigate(to: .section(.timeline))
        case "flows": window.navigate(to: .section(.flows))
        case "statistics": window.navigate(to: .section(.statistics))
        case "diagnostics": window.navigate(to: .section(.diagnostics))
        case "nosidebar": window.sidebarVisible = false
        case "sidebar": window.sidebarVisible = true
        default: break
        }
    }
}
