import SwiftUI
import WirePathUI

/// macOS window: the design's flush 256 pt sidebar next to the detail area, content extending under a
/// transparent title bar with the traffic lights in the sidebar band.
struct MacRootView: View {
    @Environment(LibraryModel.self) private var library
    @State private var window: WindowModel

    init(library: LibraryModel, initialAnalysis: UUID?) {
        _window = State(initialValue: WindowModel(library: library, initialAnalysis: initialAnalysis))
    }

    var body: some View {
        HStack(spacing: 0) {
            if window.sidebarVisible {
                SidebarView().transition(.move(edge: .leading))
            }
            DetailView()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Theme.win)
        .background(WindowConfigurator())
        .ignoresSafeArea()
        .frame(minWidth: 1100, minHeight: 680)
        .environment(window)
        .focusedSceneValue(\.windowModel, window)
        .wirePathWindowServices(window: window, library: library)
        .onAppear {
            window.ensureLoaded()
            DebugSnapshot.run(window: window, library: library)
        }
    }
}
