import Foundation
import WirePathCore
import WirePathFixtures

// wpbench — benchmarks WirePath's engine on large captures (spec §59): indexing (the full analysis), packet lookup,
// filtering, flow reconstruction, SIP reconstruction and RTP analysis, with peak memory.
//
//   wpbench generate <out.pcap> --packets 5000000 [--calls 200] [--call-seconds 90]   (short calls = SIP-heavy)
//   wpbench run <capture> [--json results.json] [--lookups 100000]
//   wpbench all <directory> [--packets 1000000,5000000]      generate (if missing) and run each size
//
// Build with `swift build -c release` — debug builds are 10–50× slower and not representative.

let arguments = Array(CommandLine.arguments.dropFirst())
func value(_ flag: String) -> String? {
    arguments.firstIndex(of: flag).flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
}
func usage() -> Never {
    print("usage: wpbench generate <out.pcap> --packets N [--calls C] | run <capture> [--json out.json] [--lookups N] | all <dir> [--packets a,b]")
    exit(2)
}

func megabytes(_ bytes: UInt64) -> String { String(format: "%.0f MB", Double(bytes) / 1_048_576) }

func generate(_ url: URL, packets: Int, calls: Int, callSeconds: Double = 90) throws -> LargeCaptureGenerator.Summary {
    let start = Date()
    let generator = LargeCaptureGenerator(.init(packets: packets, concurrentCalls: calls, callSeconds: callSeconds))
    let summary = try generator.write(to: url) { written in
        FileHandle.standardError.write(Data("\rgenerating \(written.formatted()) packets".utf8))
    }
    FileHandle.standardError.write(Data("\n".utf8))
    print("generated \(url.lastPathComponent): \(summary.packets.formatted()) packets, \(megabytes(UInt64(summary.bytes))), "
          + "\(summary.calls) calls, \(summary.tcpConnections) TCP connections, \(String(format: "%.0f", summary.seconds)) s of traffic "
          + "(\(String(format: "%.1f", Date().timeIntervalSince(start))) s)")
    return summary
}

/// Samples the process footprint while `body` runs and returns the peak.
func withPeakMemory<T>(_ body: () async throws -> T) async rethrows -> (T, UInt64) {
    let peak = PeakSampler()
    let sampler = Task.detached {
        while !Task.isCancelled {
            peak.record(EngineBenchmark.memoryFootprint())
            try? await Task.sleep(for: .milliseconds(20))
        }
    }
    let result = try await body()
    sampler.cancel()
    peak.record(EngineBenchmark.memoryFootprint())
    return (result, peak.value)
}

final class PeakSampler: @unchecked Sendable {
    private let lock = NSLock()
    private var peak: UInt64 = 0
    func record(_ value: UInt64) { lock.withLock { peak = max(peak, value) } }
    var value: UInt64 { lock.withLock { peak } }
}

struct Report: Codable {
    var capture: String
    var bytes: Int64
    var packets: Int
    var machine: String
    var measurements: [EngineBenchmark.Measurement]
    var peakAnalysisMemory: UInt64
    var baselineMemory: UInt64
}

func machine() -> String {
    var size = 0
    sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
    var buffer = [CChar](repeating: 0, count: max(1, size))
    sysctlbyname("machdep.cpu.brand_string", &buffer, &size, nil, 0)
    let memory = ProcessInfo.processInfo.physicalMemory
    return "\(String(cString: buffer)) · \(ProcessInfo.processInfo.activeProcessorCount) cores · \(memory / 1_073_741_824) GB"
}

func run(_ url: URL, lookups: Int) async throws -> Report {
    let size = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
    let work = FileManager.default.temporaryDirectory.appendingPathComponent("wpbench-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: work) }
    var measurements: [EngineBenchmark.Measurement] = []
    let baseline = EngineBenchmark.memoryFootprint()
    let clock = ContinuousClock()
    func seconds(_ d: Duration) -> Double { Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18 }

    // Indexing: the complete analysis the app runs on import (index, flows, TCP, SIP, RTP, RTCP, WebRTC, statistics).
    let artifacts = AnalysisArtifactLocations(directory: work)
    var output: AnalysisOutput?
    let (elapsed, peak) = try await withPeakMemory {
        try await clock.measure { output = try await AnalysisEngine.analyze(capture: url, artifacts: artifacts, localCopy: .never) }
    }
    guard let output else { throw CocoaError(.fileReadUnknown) }
    let result = output.result
    measurements.append(.init(stage: "Indexing (full analysis)", seconds: seconds(elapsed), items: result.capture.packetCount, unit: "packets",
                              notes: String(format: "%.0f MB/s · %d flows · %d calls · %d streams", Double(size) / 1e6 / seconds(elapsed),
                                            result.capture.flowCount, result.calls.count, result.streams.count)))
    FileHandle.standardError.write(Data("indexed in \(String(format: "%.2f", seconds(elapsed))) s\n".utf8))

    // Saving and reopening the result, as the app does after analysis and when an analysis is opened.
    let library = AnalysisLibrary(rootURL: work.appendingPathComponent("library"))
    let id = UUID()
    try FileManager.default.createDirectory(at: library.directory(for: id), withIntermediateDirectories: true)
    let (saveTime, savePeak) = try await withPeakMemory { try clock.measure { try library.saveResult(result, for: id) } }
    let resultSize = (try? FileManager.default.attributesOfItem(atPath: library.url(.result, for: id).path)[.size] as? Int64) ?? 0
    measurements.append(.init(stage: "Result save (JSON)", seconds: seconds(saveTime), items: result.capture.packetCount, unit: "packets",
                              notes: "\(megabytes(UInt64(resultSize))) · peak \(megabytes(savePeak))"))
    let (loadTime, loadPeak) = try await withPeakMemory { try clock.measure { _ = try library.loadResult(for: id) } }
    measurements.append(.init(stage: "Result load (JSON)", seconds: seconds(loadTime), items: result.capture.packetCount, unit: "packets",
                              notes: "peak \(megabytes(loadPeak))"))

    // Stages on their own.
    measurements.append(try await EngineBenchmark.decode(url))
    measurements.append(try await EngineBenchmark.flows(url))
    measurements.append(try await EngineBenchmark.sip(url))
    measurements.append(try await EngineBenchmark.rtp(url))

    // Packet lookup: random rows of the list (what scrolling decodes) and full details of a selected packet.
    let store = try PacketStore(indexURL: artifacts.packetIndex, addressTableURL: artifacts.addressTable, captureURL: output.analyzedCaptureURL,
                                result: result, flowsURL: artifacts.flows)
    // Flows as the Flows screen loads them (first use, before anything else touches them).
    var flows: [FlowRecord] = []
    let flowLoad = clock.measure { flows = store.flows() }
    measurements.append(.init(stage: "Flows load", seconds: seconds(flowLoad), items: flows.count, unit: "flows"))

    var random = SeededRandom(seed: 7)
    let count = store.count
    let rows = clock.measure {
        for _ in 0..<lookups { _ = store.row(at: Int(random.next() % UInt64(count))) }
    }
    measurements.append(.init(stage: "Packet lookup (list row)", seconds: seconds(rows), items: lookups, unit: "lookups",
                              notes: String(format: "%.1f µs each", seconds(rows) / Double(lookups) * 1e6)))
    let details = max(1, lookups / 10)
    let detailTime = clock.measure {
        for _ in 0..<details { _ = store.decodedProtocols(at: Int(random.next() % UInt64(count))) }
    }
    measurements.append(.init(stage: "Packet lookup (details + tree)", seconds: seconds(detailTime), items: details, unit: "lookups",
                              notes: String(format: "%.1f µs each", seconds(detailTime) / Double(details) * 1e6)))


    // Filtering: display filters over the whole index.
    let firstAddress = result.capture.addresses.first?.address.description ?? "10.100.1.1"
    for expression in ["sip", "rtp.seq_gap", "ip.addr == \(firstAddress)", "tcp.analysis.flags or sip.status >= 400",
                       "udp.port == 5060 and not rtp", "frame.len > 200 and (dns or tcp)"] {
        let filter = try DisplayFilter(expression, context: store.filterContext)
        var matches = 0
        let time = await clock.measure { matches = await store.filter(filter, scope: .all, callIndex: nil)?.count ?? count }
        measurements.append(.init(stage: "Filter “\(expression)”", seconds: seconds(time), items: count, unit: "packets",
                                  notes: "\(matches.formatted()) matches"))
    }
    return Report(capture: url.lastPathComponent, bytes: size, packets: result.capture.packetCount, machine: machine(),
                  measurements: measurements, peakAnalysisMemory: peak, baselineMemory: baseline)
}

func printReport(_ report: Report) {
    print("\n## \(report.capture) — \(report.packets.formatted()) packets, \(megabytes(UInt64(report.bytes)))")
    print("\(report.machine) · peak memory during analysis \(megabytes(report.peakAnalysisMemory)) (baseline \(megabytes(report.baselineMemory)))\n")
    print("| Stage | Time | Throughput | Notes |")
    print("|---|---:|---:|---|")
    for m in report.measurements {
        let throughput = m.perSecond >= 1e6 ? String(format: "%.2f M %@/s", m.perSecond / 1e6, m.unit)
            : String(format: "%.0f k %@/s", m.perSecond / 1e3, m.unit)
        print("| \(m.stage) | \(String(format: m.seconds < 1 ? "%.3f s" : "%.2f s", m.seconds)) | \(throughput) | \(m.notes ?? "") |")
    }
}

guard let command = arguments.first else { usage() }
switch command {
case "generate":
    guard arguments.count >= 2, let packets = value("--packets").flatMap(Int.init) else { usage() }
    _ = try generate(URL(fileURLWithPath: arguments[1]), packets: packets, calls: value("--calls").flatMap(Int.init) ?? 200,
                     callSeconds: value("--call-seconds").flatMap(Double.init) ?? 90)
case "run":
    guard arguments.count >= 2 else { usage() }
    let report = try await run(URL(fileURLWithPath: arguments[1]), lookups: value("--lookups").flatMap(Int.init) ?? 100_000)
    printReport(report)
    if let json = value("--json") {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(report).write(to: URL(fileURLWithPath: json))
    }
case "all":
    guard arguments.count >= 2 else { usage() }
    let directory = URL(fileURLWithPath: arguments[1], isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let sizes = (value("--packets") ?? "1000000,5000000").split(separator: ",").compactMap { Int($0) }
    var reports: [Report] = []
    for packets in sizes {
        let url = directory.appendingPathComponent("bench-\(packets).pcap")
        if !FileManager.default.fileExists(atPath: url.path) { _ = try generate(url, packets: packets, calls: 200) }
        let report = try await run(url, lookups: 100_000)
        printReport(report)
        reports.append(report)
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(reports).write(to: directory.appendingPathComponent("results.json"))
default:
    usage()
}
