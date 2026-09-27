import WirePathCore
import Foundation
import Observation

enum CallFilter: Hashable, CaseIterable {
    case all, answered, failed, withIssues

    var title: String {
        switch self {
        // Keyed: the Spanish words agree with "llamadas" (plural, feminine).
        case .all: return String(localized: "callFilter.all", defaultValue: "All")
        case .answered: return String(localized: "callFilter.answered", defaultValue: "Answered")
        case .failed: return String(localized: "callFilter.failed", defaultValue: "Failed")
        case .withIssues: return String(localized: "callFilter.withIssues", defaultValue: "With Issues")
        }
    }
}

/// Loaded results of one analysis plus presentation state shared by its views.
@Observable @MainActor
public final class AnalysisDocument {
    let id: UUID
    let result: AnalysisResult
    let library: AnalysisLibrary
    var manifest: AnalysisManifest

    var callFilter: CallFilter = .all
    var selectedCall: Int?
    var searchText = ""
    var sortAscending = true
    var selectedSession: Int?
    var selectedSessionMessage: Int?
    var selectedStream: Int?
    var selectedFlow: Int?
    var selectedFinding: Int?
    var selectedWebRTCSession: Int?

    /// Flows (and their TCP analysis), read from the analysis folder when first shown.
    enum FlowState { case notLoaded, loading, loaded([FlowRecord]), failed(String) }
    private(set) var flowState: FlowState = .notLoaded

    func loadFlows() {
        guard case .notLoaded = flowState else { return }
        flowState = .loading
        let library = self.library, id = self.id
        Task {
            do {
                let flows = try await Self.readFlows(library: library, id: id)
                flowState = .loaded(flows)
                if selectedFlow == nil { selectedFlow = flows.indices.first }
            } catch {
                flowState = .failed(error.localizedDescription)
            }
        }
    }

    nonisolated private static func readFlows(library: AnalysisLibrary, id: UUID) async throws -> [FlowRecord] {
        try library.loadFlows(for: id)
    }

    var flows: [FlowRecord] {
        if case .loaded(let flows) = flowState { return flows }
        return []
    }

    /// Calls that have quality problems (the "With Issues" filter).
    let issueCalls: Set<Int>

    @ObservationIgnored private var cachedSIPTexts: [String]?
    @ObservationIgnored private var packetModels: [Int?: PacketInspectorModel] = [:]
    @ObservationIgnored private lazy var commentsByFrame: [Int: [String]] =
        Dictionary(grouping: result.capture.packetComments, by: \.frameNumber).mapValues { $0.map(\.text) }

    init(id: UUID, result: AnalysisResult, library: AnalysisLibrary, manifest: AnalysisManifest) {
        self.id = id
        self.result = result
        self.library = library
        self.manifest = manifest
        let kinds: Set<FindingKind> = [.poorQuality, .oneWayAudio, .noMedia]
        issueCalls = Set(result.findings.filter { kinds.contains($0.kind) }.compactMap(\.callIndex))
        // Start on the first call that needs attention (or the first failure), like the design.
        selectedCall = issueCalls.min() ?? result.calls.firstIndex { $0.severity >= .warning }
    }

    // MARK: Calls

    func count(for filter: CallFilter) -> Int {
        result.calls.indices.filter { matches($0, filter: filter) }.count
    }

    func matches(_ index: Int, filter: CallFilter) -> Bool {
        let call = result.calls[index]
        switch filter {
        case .all: return true
        case .answered: return call.state.wasAnswered
        case .failed: return call.state.isFailure
        case .withIssues: return issueCalls.contains(index)
        }
    }

    func matchesSearch(_ index: Int) -> Bool {
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        guard !query.isEmpty else { return true }
        let call = result.calls[index]
        let haystack = [call.caller.user, call.caller.displayName ?? "", call.callee.user, call.callee.displayName ?? "",
                        call.caller.signalling.address.description, call.callee.signalling.address.description,
                        call.statusLabel, call.codec?.displayName ?? ""] + call.callIDs
        return haystack.contains { $0.lowercased().contains(query) }
    }

    /// Calls shown in the current filter/search, in start-time order.
    var visibleCalls: [Int] {
        let indices = result.calls.indices.filter { matches($0, filter: callFilter) && matchesSearch($0) }
        return sortAscending ? indices : indices.reversed()
    }

    func callTitle(_ index: Int) -> String {
        guard result.calls.indices.contains(index) else { return String(localized: "Call") }
        return String(localized: "Call \(result.calls[index].startTime.date.formatted(Formatters.clockTime))")
    }

    // MARK: SIP texts

    func sipText(_ messageIndex: Int) -> String {
        if cachedSIPTexts == nil {
            cachedSIPTexts = PacketStore.loadSIPTexts(from: library.url(.sipTexts, for: id))
        }
        guard let texts = cachedSIPTexts, messageIndex < texts.count else { return "" }
        return texts[messageIndex]
    }

    // MARK: Packets

    /// Comments stored with a packet in the capture file (pcapng).
    func packetComments(frame: Int) -> [String] { commentsByFrame[frame] ?? [] }

    /// Packet inspector state, one per call scope (nil = whole capture).
    func packetModel(callIndex: Int?) -> PacketInspectorModel {
        if let existing = packetModels[callIndex] { return existing }
        let model = PacketInspectorModel(document: self, callIndex: callIndex)
        packetModels[callIndex] = model
        return model
    }

    func openPacketStore() throws -> PacketStore {
        guard let captureURL = library.captureURL(for: manifest) else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSLocalizedDescriptionKey:
                String(localized: "The original capture “\(manifest.originalFileName)” is not available, so packet details cannot be shown. Move it back or re-import it.")])
        }
        return try PacketStore(indexURL: library.url(.packetIndex, for: id),
                               addressTableURL: library.url(.addressTable, for: id), captureURL: captureURL,
                               result: result, flowsURL: library.url(.flows, for: id))
    }
}
