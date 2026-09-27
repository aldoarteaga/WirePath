import WirePathCore
import Foundation
import Observation
import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Animates unless the user asked to reduce motion.
@MainActor func withAnimationIfAllowed(_ animation: Animation = .easeInOut(duration: 0.2), _ body: () -> Void) {
    #if os(macOS)
    let reduce = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
    #else
    let reduce = UIAccessibility.isReduceMotionEnabled
    #endif
    if reduce { body() } else { withAnimation(animation, body) }
}

/// Per-window navigation state (each window keeps its own selection and back/forward history).
@Observable @MainActor
public final class WindowModel {
    public let library: LibraryModel
    public private(set) var location: Location?
    public private(set) var backStack: [Location] = []
    public private(set) var forwardStack: [Location] = []

    public var sidebarVisible = true
    public var inspectorVisible = false
    public var sidebarFilter = ""
    public var renamingID: UUID?
    public var pendingDeletion: AnalysisItem?
    public var showImporter = false
    public var importFolders = false
    public var dropCount = 0
    public var dropNames: [String] = []
    public var searchFocusRequest = 0
    public var displayFilterFocusRequest = 0
    /// File waiting to be saved through the system save panel.
    public var pendingExport: ExportFile?

    public init(library: LibraryModel, initialAnalysis: UUID? = nil) {
        self.library = library
        if let id = initialAnalysis ?? library.items.first(where: { !$0.isAnalyzing })?.id ?? library.items.first?.id {
            location = Location(analysisID: id, route: .section(.overview))
            library.item(id)?.isExpanded = true
        }
    }

    public var selectedItem: AnalysisItem? { location.flatMap { library.item($0.analysisID) } }
    public var document: AnalysisDocument? { selectedItem?.document }
    public var canGoBack: Bool { !backStack.isEmpty }
    public var canGoForward: Bool { !forwardStack.isEmpty }

    public func navigate(_ destination: Location) {
        guard destination != location else { return }
        if let location { backStack.append(location) }
        forwardStack.removeAll()
        location = destination
        library.item(destination.analysisID)?.isExpanded = true
        ensureLoaded()
    }

    public func navigate(to route: Route) {
        guard let id = location?.analysisID else { return }
        navigate(Location(analysisID: id, route: route))
    }

    public func select(_ item: AnalysisItem, section: AnalysisSection = .overview) {
        navigate(Location(analysisID: item.id, route: .section(section)))
    }

    /// Incremented when the sidebar should be revealed (the iPad split view uses it in compact width).
    public private(set) var sidebarRequest = 0

    public func showSidebar() {
        withAnimationIfAllowed { sidebarVisible = true }
        sidebarRequest += 1
    }

    public func goBack() {
        guard let previous = backStack.popLast() else { return }
        if let location { forwardStack.append(location) }
        location = previous
        ensureLoaded()
    }

    public func goForward() {
        guard let next = forwardStack.popLast() else { return }
        if let location { backStack.append(location) }
        location = next
        ensureLoaded()
    }

    public func ensureLoaded() {
        if let item = selectedItem { library.loadDocument(item) }
    }

    /// Removes history entries that point at a deleted analysis.
    public func forget(_ id: UUID) {
        backStack.removeAll { $0.analysisID == id }
        forwardStack.removeAll { $0.analysisID == id }
        if location?.analysisID == id {
            location = library.items.first.map { Location(analysisID: $0.id, route: .section(.overview)) }
            ensureLoaded()
        }
    }

    // MARK: Call navigation

    public func investigate(_ callIndex: Int) {
        document?.selectedCall = callIndex
        navigate(to: .call(callIndex))
    }

    /// ⌘↑ / ⌘↓ between calls (in the order of the current filter).
    public func stepCall(_ delta: Int) {
        guard let document else { return }
        let order = document.visibleCalls.isEmpty ? Array(document.result.calls.indices) : document.visibleCalls
        guard !order.isEmpty else { return }
        let current: Int? = {
            if case .call(let index)? = location?.route { return index }
            return document.selectedCall
        }()
        let position = current.flatMap { order.firstIndex(of: $0) } ?? -1
        let next = order[max(0, min(order.count - 1, position + delta))]
        document.selectedCall = next
        if case .call? = location?.route {
            // Replace the current investigation instead of stacking history for every step.
            if let id = location?.analysisID { location = Location(analysisID: id, route: .call(next)) }
        }
    }

    public func showPackets(forCall callIndex: Int?) {
        navigate(to: .packets(callIndex: callIndex))
    }

    /// Opens the Packet Inspector filtered to one flow (`flow == N`).
    public func showPackets(forFlow flow: Int) {
        document?.selectedFlow = flow
        showPackets(matching: "flow == \(flow + 1)")
    }

    /// Opens the whole-capture Packet Inspector with a display filter applied (e.g. a diagnostic's packets).
    public func showPackets(matching filter: String) {
        guard let document else { return }
        navigate(to: .packets(callIndex: nil))
        let model = document.packetModel(callIndex: nil)
        model.callIndex = nil
        model.scope = .all
        model.filterText = filter
        model.applyFilter()
    }

    /// Opens the WebRTC screen on one ICE session.
    public func showWebRTCSession(_ index: Int) {
        document?.selectedWebRTCSession = index
        navigate(to: .section(.webrtc))
    }

    /// Opens the Diagnostics screen on one finding.
    public func showDiagnostic(_ id: Int) {
        document?.selectedFinding = id
        navigate(to: .section(.diagnostics))
    }

    /// Opens the Packet Inspector on one packet (frame numbers are 1-based, as shown in the list).
    public func showPacket(frame: Int) {
        guard let document else { return }
        navigate(to: .packets(callIndex: nil))
        document.packetModel(callIndex: nil).reveal(frame: frame)
    }

    // MARK: Export

    /// Prepares the HTML report of the current analysis for saving.
    public func exportReport() {
        guard let item = selectedItem else { return }
        let library = self.library
        let name = item.name
        let id = item.id
        let loaded = item.document?.result
        Task {
            do {
                let result: AnalysisResult
                if let loaded {
                    result = loaded
                } else {
                    result = try await Task.detached { try library.library.loadResult(for: id) }.value
                }
                let file = try await Task.detached { try ReportExporter.exportFile(result: result, name: name) }.value
                pendingExport = file
            } catch {
                library.lastError = String(localized: "The report could not be created: \(error.localizedDescription)")
            }
        }
    }
}
