@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// The chunked result archive: what is saved is what is loaded, and damage is detected.
@Suite("Result archive")
struct ResultArchiveTests {
    static func canonical(_ result: AnalysisResult) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try encoder.encode(result)
    }

    @Test func roundTripsAcrossChunks() async throws {
        // Short calls make thousands of SIP messages, so several sections span more than one chunk.
        let directory = Fixtures.temporaryDirectory()
        let capture = directory.appendingPathComponent("busy.pcap")
        try LargeCaptureGenerator(.init(packets: 150_000, concurrentCalls: 1000, callSeconds: 0.3)).write(to: capture)
        let result = try await Fixtures.analyze(file: capture, directory: directory).result
        #expect(result.sipMessages.count > 2 * ResultArchive.chunkSize)
        let library = AnalysisLibrary(rootURL: directory.appendingPathComponent("library"))
        let id = UUID()
        try FileManager.default.createDirectory(at: library.directory(for: id), withIntermediateDirectories: true)
        try library.saveResult(result, for: id)
        let loaded = try library.loadResult(for: id)
        #expect(try Self.canonical(loaded) == Self.canonical(result))

        for name in ["webrtc-session.pcap", "audio-codecs.pcap", "sip-problems.pcap"] {
            let fixture = try await FixtureTests.analyze(name).result
            try library.saveResult(fixture, for: id)
            #expect(try Self.canonical(library.loadResult(for: id)) == Self.canonical(fixture), "\(name)")
        }
    }

    @Test func damagedArchivesAreRejected() async throws {
        let result = try await FixtureTests.analyze("rtcp-call.pcap").result
        let directory = Fixtures.temporaryDirectory()
        let library = AnalysisLibrary(rootURL: directory)
        let id = UUID()
        try FileManager.default.createDirectory(at: library.directory(for: id), withIntermediateDirectories: true)
        try library.saveResult(result, for: id)
        let url = library.url(.result, for: id)
        let original = try Data(contentsOf: url)

        var damaged: [Data] = [original.prefix(original.count - 100), original.prefix(40), Data("WPRESULT1\n".utf8)]
        var huge = original
        huge[ResultArchive.magic.count + 8] = 0x7F  // head length in the exabytes
        damaged.append(huge)
        var missing = original
        missing[ResultArchive.magic.count] = 0xEE  // unknown section
        damaged.append(missing)
        for data in damaged {
            try data.write(to: url)
            #expect(throws: (any Error).self) { try library.loadResult(for: id) }
        }
        try Data("{\"schemaVersion\": 1}".utf8).write(to: url)  // an old JSON result
        #expect(throws: (any Error).self) { try library.loadResult(for: id) }
    }
}
