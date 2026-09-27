import SwiftUI
import WirePathCore
import WirePathUI

/// iPad window: a native NavigationSplitView carrying WirePath's sidebar and screens.
///
/// - Regular width (iPad Air/Pro landscape, large Stage Manager windows): sidebar + detail, with the
///   Packet Inspector showing list and details side by side when there is room.
/// - Compact width (Split View, Slide Over, narrow windows): the split view collapses into a stack —
///   analyses list first, then the selected screen, whose header offers the way back.
struct IPadRootView: View {
    @Environment(LibraryModel.self) private var library
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var window: WindowModel
    @State private var columns: NavigationSplitViewVisibility = .all
    @State private var compactColumn: NavigationSplitViewColumn = .detail

    init(library: LibraryModel, initialAnalysis: UUID?) {
        _window = State(initialValue: WindowModel(library: library, initialAnalysis: initialAnalysis))
    }

    private var collapsed: Bool { sizeClass == .compact }

    var body: some View {
        NavigationSplitView(columnVisibility: $columns, preferredCompactColumn: $compactColumn) {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 340)
                .toolbar(.hidden, for: .navigationBar)
        } detail: {
            DetailView()
                .background(Theme.win)
                .toolbar(.hidden, for: .navigationBar)
        }
        .navigationSplitViewStyle(.balanced)
        .environment(\.navigationCollapsed, collapsed)
        .environment(window)
        .focusedSceneValue(\.windowModel, window)
        .wirePathWindowServices(window: window, library: library)
        .onOpenURL { url in
            // Files, AirDrop, Share Sheet / Open In, iCloud Drive and USB storage all arrive here.
            let items = library.importCaptures([url])
            if let first = items.first { window.select(first) }
        }
        .onChange(of: window.sidebarVisible) { _, visible in
            withAnimation { columns = visible ? .all : .detailOnly }
        }
        .onChange(of: columns) { _, value in
            if window.sidebarVisible != (value != .detailOnly) { window.sidebarVisible = value != .detailOnly }
        }
        .onChange(of: window.sidebarRequest) { compactColumn = .sidebar }
        .onChange(of: window.location) { compactColumn = .detail }
        .onAppear {
            window.ensureLoaded()
            LaunchOptions.applyImports(window: window, library: library)
            if window.location == nil { compactColumn = .sidebar }
        }
    }
}
