import Foundation
import Testing
@testable import WirePathCore
@testable import WirePathUI
import WirePathFixtures

/// View-model tests: navigation, call filters and packet filtering driven by a real (synthetic) analysis.
@MainActor
@Suite("View models")
struct ViewModelTests {
    static func freshDefaults() -> UserDefaults {
        let name = "wirepath-ui-tests-\(UUID().uuidString)"
        return UserDefaults(suiteName: name) ?? .standard
    }

    static func makeLibrary() async throws -> (LibraryModel, AnalysisItem) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-ui-tests-\(UUID().uuidString)")
        let captureURL = root.appendingPathComponent("calls.pcap")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let server = SimHost("10.20.0.5")
        let a = SimParty("1003", "Soporte N1", host: SimHost("10.20.1.23"))
        let b = SimParty("1008", "Soporte N2", host: SimHost("10.20.1.28"))
        var lossy = SimImpairment.perfect
        lossy.dropIndices = Set(100..<120)
        let calls = [
            SimCall(start: 1, caller: a, callee: b, topology: .proxy(server), outcome: .answered(talk: 8, hangupByCaller: true),
                    forward: lossy, reverse: .perfect, seed: 1),
            SimCall(start: 12, caller: b, callee: a, topology: .proxy(server),
                    outcome: .rejected(code: 486, reason: "Busy Here", fromServer: false), seed: 2),
            SimCall(start: 20, caller: a, callee: b, topology: .proxy(server), outcome: .answered(talk: 4, hangupByCaller: false),
                    forward: .perfect, reverse: .perfect, seed: 3),
        ]
        try SimCapture(baseTime: 1_790_415_735, calls: calls).write(to: captureURL)
        let library = LibraryModel(library: AnalysisLibrary(rootURL: root.appendingPathComponent("Library")), defaults: freshDefaults())
        let item = try #require(library.importCaptures([captureURL]).first)
        for _ in 0..<300 where item.document == nil { try await Task.sleep(for: .milliseconds(20)) }
        return (library, item)
    }

    @Test func importAnalysesAndLoadsDocument() async throws {
        let (library, item) = try await Self.makeLibrary()
        #expect(library.items.count == 1)
        #expect(item.manifest.state == .ready)
        let document = try #require(item.document)
        #expect(document.result.calls.count == 3)
        #expect(item.manifest.summary?.callCount == 3)
    }

    @Test func callFiltersMatchCallStates() async throws {
        let (_, item) = try await Self.makeLibrary()
        let document = try #require(item.document)
        #expect(document.count(for: .all) == 3)
        #expect(document.count(for: .answered) == 2)
        #expect(document.count(for: .failed) == 1)
        #expect(document.count(for: .withIssues) == 1)   // 20 lost packets → poor quality
        document.callFilter = .failed
        #expect(document.visibleCalls == [1])
        document.callFilter = .all
        document.searchText = "10.20.1.28"
        #expect(document.visibleCalls.count == 3)
        document.searchText = "busy"
        #expect(document.visibleCalls == [1])
    }

    @Test func navigationHistory() async throws {
        let (library, item) = try await Self.makeLibrary()
        let window = WindowModel(library: library, initialAnalysis: item.id)
        #expect(window.location?.route == .section(.overview))
        window.navigate(to: .section(.calls))
        window.investigate(0)
        #expect(window.location?.route == .call(0))
        window.stepCall(1)
        #expect(window.location?.route == .call(1))   // stepping replaces the investigation
        window.goBack()
        #expect(window.location?.route == .section(.calls))
        window.goForward()
        #expect(window.location?.route == .call(1))
        #expect(!window.canGoForward)
    }

    @Test func packetInspectorFiltersOffTheMainThread() async throws {
        let (_, item) = try await Self.makeLibrary()
        let document = try #require(item.document)
        let model = document.packetModel(callIndex: 0)
        #expect(model.openError == nil)
        for _ in 0..<200 where model.isFiltering { try await Task.sleep(for: .milliseconds(10)) }
        let callPackets = model.displayedCount
        #expect(callPackets > 0 && callPackets < model.totalCount)
        model.filterText = "rtp.seq_gap"
        model.applyFilter()
        for _ in 0..<200 where model.isFiltering { try await Task.sleep(for: .milliseconds(10)) }
        #expect(model.displayedCount == 1)
        model.filterText = "sip.status >="
        model.applyFilter()
        #expect(model.filterError != nil)
    }

    @Test func recentCapturesPersistAsBookmarks() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-ui-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let capture = root.appendingPathComponent("office.pcap")
        try SimCapture(baseTime: 1_790_415_735, calls: []).write(to: capture)
        let defaults = Self.freshDefaults()
        let library = LibraryModel(library: AnalysisLibrary(rootURL: root.appendingPathComponent("Library")), defaults: defaults)
        library.importCaptures([capture])
        library.importCaptures([capture])
        #expect(library.recentCaptures.map(\.lastPathComponent) == ["office.pcap"])

        // Relaunch after the capture was renamed: the bookmark still finds it.
        try FileManager.default.moveItem(at: capture, to: root.appendingPathComponent("renamed.pcap"))
        let relaunched = LibraryModel(library: AnalysisLibrary(rootURL: root.appendingPathComponent("Library")), defaults: defaults)
        #expect(relaunched.recentCaptures.map(\.lastPathComponent) == ["renamed.pcap"])
        relaunched.clearRecentCaptures()
        #expect(LibraryModel(library: relaunched.library, defaults: defaults).recentCaptures.isEmpty)
    }

    @Test func folderImportKeepsOnlyCaptures() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-ui-tests-\(UUID().uuidString)")
        let folder = root.appendingPathComponent("captures/nested", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try SimCapture(baseTime: 1_790_415_735, calls: []).write(to: root.appendingPathComponent("captures/a.pcap"))
        try SimCapture(baseTime: 1_790_415_735, calls: []).write(to: folder.appendingPathComponent("b.pcapng"))
        try Data("notes".utf8).write(to: folder.appendingPathComponent("notes.txt"))
        let library = LibraryModel(library: AnalysisLibrary(rootURL: root.appendingPathComponent("Library")), defaults: Self.freshDefaults())
        let items = library.importCaptures([root.appendingPathComponent("captures")])
        #expect(Set(items.map(\.name)) == ["a.pcap", "b.pcapng"])
        for item in items { library.cancelAnalysis(item) }
    }

    @Test func analysesFromAnOlderEngineAreReanalyzed() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-ui-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let capture = root.appendingPathComponent("old.pcap")
        try SimCapture(baseTime: 1_790_415_735, calls: []).write(to: capture)
        let storage = AnalysisLibrary(rootURL: root.appendingPathComponent("Library"))
        let stale = AnalysisManifest(displayName: "old.pcap", originalFileName: "old.pcap", originalPath: capture.path,
                                     bookmark: nil, fileSize: 1, state: .ready, engineVersion: AnalysisEngine.version - 1)
        try storage.save(stale)
        let library = LibraryModel(library: storage, defaults: Self.freshDefaults())
        let item = try #require(library.items.first)
        library.loadDocument(item)
        for _ in 0..<300 where item.document == nil { try await Task.sleep(for: .milliseconds(20)) }
        #expect(item.manifest.engineVersion == AnalysisEngine.version)
        #expect(item.document != nil)

        // Without the capture, the analysis explains why it cannot be shown.
        var orphan = stale
        orphan.id = UUID()
        orphan.originalPath = root.appendingPathComponent("gone.pcap").path
        try storage.save(orphan)
        let reloaded = LibraryModel(library: storage, defaults: Self.freshDefaults())
        let orphanItem = try #require(reloaded.item(orphan.id))
        reloaded.loadDocument(orphanItem)
        guard case .failed(let message) = orphanItem.loadState else {
            Issue.record("expected a failed load state")
            return
        }
        #expect(message.contains("older version"))
    }

    @Test func analysesMadeInAnotherLanguageAreReanalyzed() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-ui-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let capture = root.appendingPathComponent("other.pcap")
        try SimCapture(baseTime: 1_790_415_735, calls: []).write(to: capture)
        let storage = AnalysisLibrary(rootURL: root.appendingPathComponent("Library"))
        let foreign = AnalysisManifest(displayName: "other.pcap", originalFileName: "other.pcap", originalPath: capture.path,
                                       bookmark: nil, fileSize: 1, state: .ready, engineVersion: AnalysisEngine.version,
                                       language: "xx")
        try storage.save(foreign)
        let library = LibraryModel(library: storage, defaults: Self.freshDefaults())
        let item = try #require(library.items.first)
        library.loadDocument(item)
        for _ in 0..<300 where item.document == nil { try await Task.sleep(for: .milliseconds(20)) }
        #expect(item.document != nil)
        #expect(item.manifest.language == AnalysisEngine.resultLanguage)
        let saved = try #require(storage.loadManifests().first { $0.id == foreign.id })
        #expect(saved.language == AnalysisEngine.resultLanguage)
    }

    @Test func flowsLoadAndFollowFlowFiltersPackets() async throws {
        let (library, item) = try await Self.makeLibrary()
        let document = try #require(item.document)
        document.loadFlows()
        for _ in 0..<200 where document.flows.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        #expect(document.flows.count == document.result.capture.flowCount)
        let window = WindowModel(library: library, initialAnalysis: item.id)
        let sipFlow = try #require(document.flows.first { $0.application.isSIP })
        window.showPackets(forFlow: sipFlow.id)
        #expect(window.location?.route == .packets(callIndex: nil))
        let model = document.packetModel(callIndex: nil)
        for _ in 0..<200 where model.isFiltering { try await Task.sleep(for: .milliseconds(10)) }
        #expect(model.filterText == "flow == \(sipFlow.id + 1)")
        #expect(model.displayedCount == sipFlow.packets)
    }

    @Test func packetSearchSelectsMatches() async throws {
        let (_, item) = try await Self.makeLibrary()
        let document = try #require(item.document)
        let model = document.packetModel(callIndex: nil)
        let callID = try #require(document.result.sipMessages.first?.callID)
        model.searchText = callID
        model.runSearch()
        for _ in 0..<300 where model.isSearching { try await Task.sleep(for: .milliseconds(10)) }
        let hits = try #require(model.searchResults?.hits)
        #expect(hits.count == document.result.sipMessages.filter { $0.callID == callID }.count)
        #expect(model.selectedPosition == hits.first?.position)
        model.showMatch(offset: 1)
        #expect(model.selectedPosition == hits[1].position)
        model.showMatch(offset: -2)
        #expect(model.selectedPosition == hits.last?.position)  // wraps around
        #expect(model.searchSummary?.hasPrefix("\(hits.count) of \(hits.count)") == true)
        model.searchText = ""
        model.clearSearch()
        #expect(model.searchResults == nil)
    }

    @Test func webrtcSessionsNavigateAndFilter() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-ui-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let captureURL = root.appendingPathComponent("webrtc-session.pcap")
        let fixture = try #require(FixtureCatalog.all.first { $0.fileName == "webrtc-session.pcap" })
        try fixture.make().write(to: captureURL)
        let library = LibraryModel(library: AnalysisLibrary(rootURL: root.appendingPathComponent("Library")), defaults: Self.freshDefaults())
        let item = try #require(library.importCaptures([captureURL]).first)
        for _ in 0..<300 where item.document == nil { try await Task.sleep(for: .milliseconds(20)) }
        let document = try #require(item.document)
        #expect(item.manifest.summary?.webrtcSessionCount == 2)

        let window = WindowModel(library: library, initialAnalysis: item.id)
        window.showWebRTCSession(1)
        #expect(window.location?.route == .section(.webrtc))
        #expect(document.selectedWebRTCSession == 1)
        window.showPackets(matching: WebRTCScreen.filter(for: 1))
        let model = document.packetModel(callIndex: nil)
        for _ in 0..<200 where model.isFiltering { try await Task.sleep(for: .milliseconds(10)) }
        #expect(model.displayedCount == 19)  // checks, the silent STUN server and the rejected TURN allocation
        #expect(WebRTCSessionDetail.callIndex(document.result.webrtc.sessions[0], document.result) == 0)

        let report = ReportExporter.html(for: document.result, name: "webrtc-session.pcap")
        #expect(report.contains("<h2>WebRTC Sessions</h2>"))
        #expect(report.contains("aF1x ↔ bY7q") && report.contains("Failed"))
    }

    @Test func callAudioDecodesAndPlays() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-ui-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let captureURL = root.appendingPathComponent("audio-codecs.pcap")
        let fixture = try #require(FixtureCatalog.all.first { $0.fileName == "audio-codecs.pcap" })
        try fixture.make().write(to: captureURL)
        let library = LibraryModel(library: AnalysisLibrary(rootURL: root.appendingPathComponent("Library")), defaults: Self.freshDefaults())
        let item = try #require(library.importCaptures([captureURL]).first)
        for _ in 0..<300 where item.document == nil { try await Task.sleep(for: .milliseconds(20)) }
        let document = try #require(item.document)

        let player = AudioPlaybackModel()
        player.offer(call: document.result.calls[0], result: document.result)
        #expect(player.tracks.map(\.pan) == [-1, 1])
        player.preload(document: document, callIndex: 0)
        for _ in 0..<200 where player.state == .preparing { try await Task.sleep(for: .milliseconds(10)) }
        #expect(player.state == .ready)
        #expect(abs(player.duration - 3.002) < 0.01)  // callee starts 2 ms after the caller
        #expect(player.tracks[0].audio?.dtmf.map(\.key) == ["1", "5", "#"])
        player.togglePlayback(document: document, callIndex: 0)
        #expect(player.isPlaying)
        try await Task.sleep(for: .milliseconds(600))
        #expect(player.currentTime > 0.2, "position \(player.currentTime)")
        player.pause()
        #expect(!player.isPlaying)
        player.seek(to: 2.5)
        #expect(abs(player.currentTime - 2.5) < 0.01)

        // The SRTP call explains why it cannot be played.
        player.offer(call: document.result.calls[4], result: document.result)
        #expect(!player.canPlay)
        player.preload(document: document, callIndex: 4)
        #expect(player.state == .unavailable(AudioPlaybackModel.reason(.encrypted)))
    }

    @Test func everySectionHasADistinctShortcut() {
        let digits = AnalysisSection.allCases.map(\.shortcutDigit)
        #expect(Set(digits).count == AnalysisSection.allCases.count)
        #expect(AnalysisSection.diagnostics.shortcutDigit == "0")
    }

    @Test func layoutWidthThresholds() {
        #expect(LayoutWidth(width: 500) == .compact)
        #expect(LayoutWidth(width: 759) == .compact)
        #expect(LayoutWidth(width: 760) == .regular)
        #expect(LayoutWidth(width: 1179) == .regular)
        #expect(LayoutWidth(width: 1180) == .wide)
    }
}
