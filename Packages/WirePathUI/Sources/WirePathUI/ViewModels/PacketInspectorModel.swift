import WirePathCore
import Foundation
import Observation

/// State of the Packet Inspector: filtering runs off the main thread over the memory-mapped index.
@Observable @MainActor
public final class PacketInspectorModel {
    unowned let document: AnalysisDocument
    private(set) var store: PacketStore?
    private(set) var openError: String?

    /// Call token in the filter field (removable).
    var callIndex: Int?
    var scope: PacketScope
    var filterText = ""
    private(set) var filterError: DisplayFilterError?
    private(set) var appliedFilterIsValid = true

    /// Positions shown in the list (nil = every packet).
    private(set) var positions: [UInt32]?
    private(set) var isFiltering = false
    var selectedPosition: Int? { didSet { if selectedPosition != oldValue { updateDissection() } } }
    private(set) var dissection: DissectedPacket?
    var selectedFieldID: Int?
    var expandedLayers: Set<Int> = []
    var showDetails = true
    /// Compact layouts: the user picked a packet and wants its details (presented as a sheet).
    var detailRequested = false
    var showBits = false
    /// Bumped whenever `positions` changes so the table reloads.
    private(set) var generation = 0

    @ObservationIgnored private var filterTask: Task<Void, Never>?

    // Search (IP, port, packet number, Call-ID, SIP URI, SSRC, protocol, payload text).
    var searchText = ""
    private(set) var searchResults: SearchResults?
    private(set) var isSearching = false
    private(set) var searchProgress = 0.0
    /// Index into `searchResults.hits` of the match shown.
    private(set) var searchIndex = 0
    @ObservationIgnored private var searchTask: Task<Void, Never>?

    init(document: AnalysisDocument, callIndex: Int?) {
        self.document = document
        self.callIndex = callIndex
        scope = callIndex == nil ? .all : .sipRTP
        do {
            store = try document.openPacketStore()
        } catch {
            openError = error.localizedDescription
        }
        applyFilter()
    }

    /// Searches every packet off the main actor; the first match is selected when results arrive.
    func runSearch() {
        searchTask?.cancel()
        let text = searchText.trimmingCharacters(in: .whitespaces)
        guard let store, !text.isEmpty else {
            searchResults = nil
            isSearching = false
            return
        }
        let result = document.result
        isSearching = true
        searchProgress = 0
        searchTask = Task {
            let results = await PacketSearch.run(text, in: store, result: result) { fraction in
                Task { @MainActor in self.searchProgress = fraction }
            }
            guard !Task.isCancelled else { return }
            searchResults = results
            isSearching = false
            searchIndex = 0
            if let first = results.hits.first { reveal(frame: first.position + 1) }
        }
    }

    /// Moves to the next (or previous) search match, wrapping around.
    func showMatch(offset: Int) {
        guard let hits = searchResults?.hits, !hits.isEmpty else { return }
        searchIndex = ((searchIndex + offset) % hits.count + hits.count) % hits.count
        reveal(frame: hits[searchIndex].position + 1)
    }

    func clearSearch() {
        searchTask?.cancel()
        searchText = ""
        searchResults = nil
        isSearching = false
    }

    /// "3 of 42 · Port", or why nothing was found.
    var searchSummary: String? {
        if isSearching { return String(localized: "Searching… \(Int(searchProgress * 100))%") }
        guard let results = searchResults else { return nil }
        guard !results.hits.isEmpty else { return String(localized: "No matches") }
        let hit = results.hits[min(searchIndex, results.hits.count - 1)]
        let total = Formatters.count(results.hits.count) + (results.truncated ? "+" : "")
        return String(localized: "\(searchIndex + 1) of \(total) · \(hit.reason)")
    }

    /// Selects a packet by frame number, clearing filters that hide it. Returns false for an unknown frame.
    @discardableResult
    func reveal(frame number: Int) -> Bool {
        guard number >= 1, number <= totalCount else { return false }
        if row(forPosition: number - 1) == nil {
            filterText = ""
            callIndex = nil
            scope = .all
            applyFilter()
        }
        selectedPosition = number - 1
        return true
    }

    var totalCount: Int { store?.count ?? 0 }
    var displayedCount: Int { positions?.count ?? totalCount }

    func position(forRow row: Int) -> Int? {
        guard row >= 0 else { return nil }
        if let positions { return row < positions.count ? Int(positions[row]) : nil }
        return row < totalCount ? row : nil
    }

    func row(forPosition position: Int) -> Int? {
        guard let positions else { return position < totalCount ? position : nil }
        // positions are sorted ascending
        var low = 0, high = positions.count - 1
        while low <= high {
            let mid = (low + high) / 2
            let value = Int(positions[mid])
            if value == position { return mid }
            if value < position { low = mid + 1 } else { high = mid - 1 }
        }
        return nil
    }

    /// Time reference for the Time column: the call's INVITE when scoped to a call, else the capture start.
    var referenceNanos: Int64 {
        if let callIndex, callIndex < document.result.calls.count {
            return document.result.calls[callIndex].startTime.nanoseconds
        }
        return store?.captureStartNanos ?? 0
    }

    func applyFilter() {
        guard let store else { return }
        filterTask?.cancel()
        let text = filterText
        let compiled: DisplayFilter?
        do {
            compiled = try DisplayFilter(text, context: store.filterContext)
            filterError = nil
            appliedFilterIsValid = true
        } catch {
            filterError = error
            appliedFilterIsValid = false
            return
        }
        let scope = self.scope
        let call = callIndex
        isFiltering = true
        filterTask = Task {
            let result = await store.filter(text.trimmingCharacters(in: .whitespaces).isEmpty ? nil : compiled,
                                            scope: scope, callIndex: call)
            guard !Task.isCancelled else { return }
            positions = result
            isFiltering = false
            generation += 1
            if let selected = selectedPosition, row(forPosition: selected) == nil { selectedPosition = nil }
            if selectedPosition == nil, let first = position(forRow: 0) { selectedPosition = first }
        }
    }

    /// Validates without applying (for the live "Valid filter" indicator).
    func validate(_ text: String) -> DisplayFilterError? {
        guard let store else { return nil }
        do {
            _ = try DisplayFilter(text, context: store.filterContext)
            return nil
        } catch {
            return error
        }
    }

    func removeCallToken() {
        callIndex = nil
        applyFilter()
    }

    func setScope(_ newScope: PacketScope) {
        scope = newScope
        applyFilter()
    }

    private func updateDissection() {
        guard let store, let position = selectedPosition else {
            dissection = nil
            return
        }
        let packet = store.dissect(at: position)
        dissection = packet
        // Expand the network layer and the application layers by default, like the design (IP, SIP, SDP open).
        let collapsed: Set<String> = ["frame", "eth", "vlan", "mpls", "pppoe", "sll", "null", "llc", "udp", "tcp", "data"]
        expandedLayers = Set(packet.layers.filter { !collapsed.contains($0.protocolName) }.map(\.id))
        selectedFieldID = packet.layers.flatMap(\.fields).first { $0.name == "Call-ID" }?.id
            ?? packet.layers.last?.fields.first?.id
    }

    var selectedField: ProtocolField? {
        guard let dissection, let id = selectedFieldID else { return nil }
        return dissection.layers.flatMap(\.fields).first { $0.id == id }
    }

    func expandAll() {
        expandedLayers = Set(dissection?.layers.map(\.id) ?? [])
    }
}
