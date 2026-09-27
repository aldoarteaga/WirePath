import AppKit
import SwiftUI
import WirePathCore
import WirePathUI

@main
struct WirePathMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var library = LibraryModel()

    var body: some Scene {
        WindowGroup("WirePath", id: "main", for: UUID.self) { $analysisID in
            MacRootView(library: library, initialAnalysis: analysisID)
                .environment(library)
                .onAppear { appDelegate.library = library }
        }
        .defaultSize(width: 1440, height: 900)
        .windowResizability(.contentMinSize)
        .commands { WirePathCommands(library: library) }
    }
}

/// Opens captures double-clicked in Finder, dropped on the Dock icon or chosen from Open Recent.
final class AppDelegate: NSObject, NSApplicationDelegate {
    @MainActor var library: LibraryModel? {
        didSet { flushPending() }
    }
    @MainActor private var pending: [URL] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSWindow.allowsAutomaticWindowTabbing = false
        MainActor.assumeIsolated { DebugSnapshot.applyAppearance() }
        Log.ui.info("WirePath for macOS launched")
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        Log.ui.notice("Open request for \(urls.count) file(s)")
        MainActor.assumeIsolated {
            pending += urls
            flushPending()
        }
    }

    @MainActor private func flushPending() {
        guard let library, !pending.isEmpty else { return }
        // Take the URLs before importing: importing can make a window appear, which sets `library` again.
        let urls = pending
        pending.removeAll()
        library.openExternally(urls)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
