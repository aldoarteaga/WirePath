@testable import WirePathCore
import Foundation
import WirePathFixtures

enum Fixtures {
    static let server = SimHost("10.20.0.5", userAgent: "WirePath PBX")
    static let phoneA = SimHost("10.20.1.23", userAgent: "Yealink T54W")
    static let phoneB = SimHost("10.20.1.28", userAgent: "Yealink T46U")
    static let caller = SimParty("1003", "Soporte N1", host: phoneA)
    static let callee = SimParty("1008", "Soporte N2", host: phoneB)
    /// 2026-09-26 09:42:15 UTC
    static let baseTime: Double = 1_790_415_735

    static func call(outcome: SimOutcome = .answered(talk: 10, hangupByCaller: true), codec: SimCodec = .pcmu,
                     topology: SimTopology = .proxy(server), forward: SimImpairment = .perfect,
                     reverse: SimImpairment = .perfect, start: Double = 1, seed: UInt64 = 7) -> SimCall {
        SimCall(start: start, caller: caller, callee: callee, topology: topology, outcome: outcome, ringDuration: 3.6,
                codec: codec, forward: forward, reverse: reverse, seed: seed)
    }

    static func temporaryDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-tests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static func artifacts(in directory: URL) -> AnalysisArtifactLocations {
        AnalysisArtifactLocations(directory: directory)
    }

    struct Analysis {
        var output: AnalysisOutput
        var directory: URL
        var captureURL: URL
        var result: AnalysisResult { output.result }

        func store() throws -> PacketStore {
            let a = Fixtures.artifacts(in: directory)
            return try PacketStore(indexURL: a.packetIndex, addressTableURL: a.addressTable,
                                   captureURL: output.analyzedCaptureURL, result: result, flowsURL: a.flows)
        }
    }

    static func analyze(_ capture: SimCapture, format: CaptureWriter.Format = .pcap(nanosecond: false, bigEndian: false),
                        fileName: String = "capture.pcap") async throws -> Analysis {
        let directory = temporaryDirectory()
        let url = directory.appendingPathComponent(fileName)
        try capture.write(to: url, format: format)
        return try await analyze(file: url, directory: directory)
    }

    static func analyze(file url: URL, directory: URL? = nil) async throws -> Analysis {
        let directory = directory ?? temporaryDirectory()
        let output = try await AnalysisEngine.analyze(capture: url, artifacts: artifacts(in: directory))
        return Analysis(output: output, directory: directory, captureURL: url)
    }
}
