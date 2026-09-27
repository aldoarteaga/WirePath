import WirePathCore
import Foundation

// wpcli — runs the WirePath analysis engine from the terminal (diagnostics, benchmarks, CI).
//
//   wpcli <capture> [--calls] [--streams] [--sip] [--findings] [--json <out.json>] [--filter "<display filter>"]

let arguments = Array(CommandLine.arguments.dropFirst())
guard let path = arguments.first(where: { !$0.hasPrefix("--") }) else {
    print("usage: wpcli <capture.pcap|pcapng|gz> [--calls] [--streams] [--sip] [--findings] [--json out.json] [--filter expr]")
    exit(2)
}
func flag(_ name: String) -> Bool { arguments.contains(name) }
func value(_ name: String) -> String? {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    return arguments[index + 1]
}

let url = URL(fileURLWithPath: path)
let work = FileManager.default.temporaryDirectory.appendingPathComponent("wpcli-\(UUID().uuidString)", isDirectory: true)
try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: work) }
let artifacts = AnalysisArtifactLocations(directory: work)

let started = Date()
let output: AnalysisOutput
do {
    output = try await AnalysisEngine.analyze(capture: url, artifacts: artifacts) { progress in
        FileHandle.standardError.write(Data(String(format: "\r%@ %3.0f%% · %d packets", progress.phase.rawValue,
                                                   progress.fraction * 100, progress.packetsProcessed).utf8))
    }
} catch {
    FileHandle.standardError.write(Data("\nerror: \(error.localizedDescription)\n".utf8))
    exit(1)
}
let elapsed = Date().timeIntervalSince(started)
FileHandle.standardError.write(Data("\n".utf8))
let r = output.result

func fmt(_ value: Double?, _ digits: Int = 2) -> String {
    value.map { String(format: "%.\(digits)f", $0) } ?? "—"
}

print("""
\(r.capture.fileName) · \(r.capture.format.label) · \(ByteCountFormatter.string(fromByteCount: r.capture.fileSize, countStyle: .file))
packets \(r.capture.packetCount) · SIP \(r.capture.sipPackets) · RTP \(r.capture.rtpPackets) · RTCP \(r.capture.rtcpPackets) · duration \(fmt(r.capture.durationSeconds, 3)) s
analysed in \(fmt(elapsed, 3)) s (\(Int(Double(r.capture.packetCount) / max(elapsed, 0.001))) packets/s)
topology: server \(r.topology.sipServer?.description ?? "—") · endpoints \(r.topology.endpoints.count) · trunks \(r.topology.trunks.map(\.description))
calls \(r.voip.totalCalls) · answered \(r.voip.answeredCalls) · failed \(r.voip.failedCalls) · rejected \(r.voip.rejectedCalls) · cancelled \(r.voip.cancelledCalls) · issues \(r.voip.callsWithIssues)
MOS mean \(fmt(r.voip.meanMOS)) min \(fmt(r.voip.minMOS)) · jitter \(fmt(r.voip.meanJitterMs, 1)) ms · loss \(fmt(r.voip.lossPercent))% · histogram \(r.voip.mosHistogram)
sessions \(r.sipSessions.count) · streams \(r.streams.count) · findings \(r.findings.count) · headline “\(r.headline.text)”
""")
if !r.capture.warnings.isEmpty { print("warnings: \(r.capture.warnings)") }

if flag("--calls") {
    print("\nCALLS")
    for call in r.calls {
        let q = call.quality
        print(String(format: "%3d  %@  %8@  %@ %@ → %@ %@  %@  %@  %@  MOS %@  jit %@  loss %@  %@  msgs %d  streams %@  %@",
                     call.id + 1, call.startTime.date.formatted(date: .omitted, time: .standard),
                     call.talkDurationSeconds.map { String(format: "%.1fs", $0) } ?? "—",
                     call.caller.user, call.caller.displayName ?? "", call.callee.user, call.callee.displayName ?? "",
                     call.statusLabel, call.codec?.displayName ?? "—", call.mediaPath.label, fmt(q?.mos), fmt(q?.meanJitterMs, 1),
                     fmt(q?.lossPercent), call.endReason.rawValue, call.messageIndices.count,
                     call.streamIndices.description, call.participants.map(\.label).description))
    }
}
if flag("--streams") {
    print("\nSTREAMS")
    for s in r.streams {
        print("\(s.id + 1)  \(s.ssrcHex)  \(s.source) → \(s.destination)  \(s.codecName) PT\(s.payloadType)  pkts \(s.packetCount) exp \(s.expectedPackets) lost \(s.lostPackets) (\(fmt(s.lossPercent))%) dup \(s.duplicatePackets) ooo \(s.outOfOrderPackets)  jitter mean \(fmt(s.meanJitterMs, 3)) max \(fmt(s.maxJitterMs, 3)) ms  maxΔ \(fmt(s.maxDeltaMs, 1)) ms  MOS \(fmt(s.mos))  call \(s.callIndex.map { "\($0 + 1)" } ?? "—")  sdp \(s.negotiatedInSDP)  bursts \(s.lossBursts.count)")
    }
}
if flag("--sip") {
    print("\nSIP")
    for m in r.sipMessages {
        print("\(m.frameNumber)  \(fmt(m.time.seconds(since: r.capture.firstPacketTime ?? m.time), 6))  \(m.source) → \(m.destination)  \(m.label)  \(m.callID.prefix(24))  cseq \(m.cseq) \(m.cseqMethod)\(m.isRetransmission ? "  (retransmission)" : "")")
    }
}
if flag("--findings") {
    print("\nFINDINGS")
    for f in r.findings { print("[\(f.severity)] \(f.kind.rawValue) call \(f.callIndex.map { "\($0 + 1)" } ?? "—"): \(f.detail)") }
}
if let filterText = value("--filter") {
    let store = try PacketStore(indexURL: artifacts.packetIndex, addressTableURL: artifacts.addressTable,
                                captureURL: output.analyzedCaptureURL, result: r)
    do {
        let filter = try DisplayFilter(filterText, context: store.filterContext)
        let matches = await store.filter(filter, scope: .all, callIndex: nil) ?? []
        print("\nFILTER “\(filterText)” → \(matches.count) packets")
        for position in matches.prefix(40) {
            let row = store.row(at: Int(position))
            print("\(row.frameNumber)  \(row.source) → \(row.destination)  \(row.protocolName)  \(row.length)  \(row.info)")
        }
    } catch {
        print("invalid filter: \(error)")
    }
}
if let jsonPath = value("--json") {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(r).write(to: URL(fileURLWithPath: jsonPath))
    print("\nwrote \(jsonPath)")
}
