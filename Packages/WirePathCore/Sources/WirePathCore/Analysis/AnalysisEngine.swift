import Foundation

public struct AnalysisProgress: Sendable, Equatable {
    public enum Phase: String, Sendable {
        case preparing = "Preparing"
        case copying = "Copying"
        case decompressing = "Decompressing"
        case reading = "Analyzing"
        case correlating = "Correlating calls"
        case finishing = "Finishing"
    }

    public var phase: Phase
    /// 0…1 over the whole analysis.
    public var fraction: Double
    public var packetsProcessed: Int
    /// What the analysis has found so far (shown while it runs).
    public var found: Found

    public struct Found: Sendable, Equatable {
        public var flows = 0
        public var protocols = 0
        public var sipMessages = 0
        public var rtpStreams = 0

        public init(flows: Int = 0, protocols: Int = 0, sipMessages: Int = 0, rtpStreams: Int = 0) {
            self.flows = flows
            self.protocols = protocols
            self.sipMessages = sipMessages
            self.rtpStreams = rtpStreams
        }
    }

    public init(phase: Phase, fraction: Double, packetsProcessed: Int, found: Found = Found()) {
        self.phase = phase
        self.fraction = fraction
        self.packetsProcessed = packetsProcessed
        self.found = found
    }
}

/// Where the engine writes its derived artifacts (chosen by the persistence layer).
public struct AnalysisArtifactLocations: Sendable {
    public var packetIndex: URL
    public var addressTable: URL
    public var sipTexts: URL
    public var flows: URL
    /// Used only for gzip captures, which must be expanded for random access.
    public var decompressedCapture: URL

    public init(packetIndex: URL, addressTable: URL, sipTexts: URL, flows: URL, decompressedCapture: URL) {
        self.packetIndex = packetIndex
        self.addressTable = addressTable
        self.sipTexts = sipTexts
        self.flows = flows
        self.decompressedCapture = decompressedCapture
    }

    /// Standard file names inside one analysis directory.
    public init(directory: URL) {
        self.init(packetIndex: directory.appendingPathComponent("packets.idx"),
                  addressTable: directory.appendingPathComponent("addresses.json"),
                  sipTexts: directory.appendingPathComponent("sip-messages.json"),
                  flows: directory.appendingPathComponent("flows.json"),
                  decompressedCapture: directory.appendingPathComponent("capture.pcap"))
    }
}

public struct AnalysisOutput: Sendable {
    public var result: AnalysisResult
    /// The capture actually analysed (the local copy for .gz inputs and for files on removable, network or
    /// iCloud storage; the original otherwise).
    public var analyzedCaptureURL: URL
    /// True when `analyzedCaptureURL` is a copy inside the analysis folder.
    public var usedDecompressedCopy: Bool
}

/// Entry point of the analysis pipeline. Independent of any UI framework.
///
/// Pipeline: memory-mapped reader → batched parallel decode (all cores) → sequential stateful
/// ingest (IP/TCP reassembly, SIP transactions, RTP statistics) → correlation → index fix-up.
public enum AnalysisEngine {
    /// Bumped whenever results or artifacts change shape; older analyses are re-analyzed on open.
    public static let version = 10

    /// Language of the text the engine writes into results (findings, headlines, call states, warnings): the
    /// first of the user's preferred languages that WirePathCore is localized into. Results keep the language
    /// they were made in, so an analysis is re-made when this changes (see `AnalysisManifest.language`).
    public static var resultLanguage: String {
        CoreLocalization.bundle.preferredLocalizations.first ?? "en"
    }

    public static func analyze(
        capture url: URL,
        artifacts: AnalysisArtifactLocations,
        localCopy: LocalCopy.Policy = .automatic,
        progress: @Sendable (AnalysisProgress) -> Void = { _ in }
    ) async throws -> AnalysisOutput {
        progress(AnalysisProgress(phase: .preparing, fraction: 0, packetsProcessed: 0))
        var source = url
        var copied = false
        let temporarySource = artifacts.decompressedCapture.appendingPathExtension("source")
        defer { try? FileManager.default.removeItem(at: temporarySource) }
        let sourceSize = (try? withExtendedLifetime(SecurityScopedAccess(url)) {
            try url.resourceValues(forKeys: [.fileSizeKey]).fileSize
        }).map { Int64($0) } ?? 0
        let wantsCopy = switch localCopy {
        case .automatic: LocalCopy.isNeeded(for: url)
        case .always: true
        case .never: false
        }
        if wantsCopy {
            if LocalCopy.hasSpace(for: sourceSize, at: artifacts.decompressedCapture) {
                try LocalCopy.copy(url, to: temporarySource, progress: { fraction in
                    progress(AnalysisProgress(phase: .copying, fraction: fraction * 0.15, packetsProcessed: 0))
                }, isCancelled: { Task.isCancelled })
                source = temporarySource
                copied = true
            } else {
                Log.pcap.notice("Not enough free space to copy a capture from removable storage; reading it in place")
            }
        }
        var file = try CaptureFile(url: source)
        guard file.size > 0 else { throw CaptureError.empty }
        let originalSize = Int64(file.size)
        var compressed = false
        if try CaptureFileFormat.detect(file.bytes(offset: 0, length: 64)) == .gzip {
            compressed = true
            let start = copied ? 0.15 : 0
            try GzipDecompressor.decompress(file, to: artifacts.decompressedCapture, progress: { fraction in
                progress(AnalysisProgress(phase: .decompressing, fraction: start + fraction * (0.2 - start), packetsProcessed: 0))
            }, isCancelled: { Task.isCancelled })
            file = try CaptureFile(url: artifacts.decompressedCapture)
        } else if copied {
            // Renaming keeps the mapped inode valid; map it again under its final name.
            try FileManager.default.moveItem(at: temporarySource, to: artifacts.decompressedCapture)
            file = try CaptureFile(url: artifacts.decompressedCapture)
        }
        let usesCopy = compressed || copied
        try Task.checkCancellation()

        let analyzer = try CaptureAnalyzer(file: file, indexURL: artifacts.packetIndex, sipTextsURL: artifacts.sipTexts)
        let base = usesCopy ? 0.2 : 0.0
        try await analyzer.run { fraction, packets, found in
            progress(AnalysisProgress(phase: .reading, fraction: base + fraction * (0.92 - base), packetsProcessed: packets, found: found))
        }
        progress(AnalysisProgress(phase: .correlating, fraction: 0.93, packetsProcessed: analyzer.packetCount, found: analyzer.found))
        try Task.checkCancellation()
        var result = try analyzer.finish(fileName: url.lastPathComponent, fileSize: originalSize, compressed: compressed)
        progress(AnalysisProgress(phase: .finishing, fraction: 0.98, packetsProcessed: analyzer.packetCount, found: analyzer.found))

        try JSONEncoder().encode(analyzer.addressList.map { $0?.description }).write(to: artifacts.addressTable)
        try JSONEncoder().encode(analyzer.flows).write(to: artifacts.flows)
        result.capture.fileName = url.lastPathComponent
        progress(AnalysisProgress(phase: .finishing, fraction: 1, packetsProcessed: analyzer.packetCount, found: analyzer.found))
        return AnalysisOutput(result: result, analyzedCaptureURL: file.url, usedDecompressedCopy: usesCopy)
    }
}

/// Mutable pipeline state for one capture. Used from a single task at a time.
final class CaptureAnalyzer {
    let file: CaptureFile
    private var reader: CaptureReader
    private let writer: PacketIndexWriter
    /// SIP message texts (redacted), written as they are parsed rather than kept in memory.
    private let sipTexts: JSONStringArrayWriter

    var sip = SIPTracker()
    var rtp = RTPTracker()
    private(set) var flowTable = FlowTable()
    private var tcpAnalyzer = TCPAnalyzer()
    private var statistics = StatisticsCollector()
    private var rtcp = RTCPTracker()
    private var webrtc = WebRTCTracker()
    private var fragments = IPFragmentReassembler()
    private var tcp = TCPStreamAssembler()
    private var framers: [TCPStreamAssembler.FlowKey: SIPStreamFramer] = [:]

    private(set) var addressList: [IPAddress?] = [nil]
    private var addressIDs: [IPAddress: UInt32] = [:]
    private var addressPackets: [UInt32: Int] = [:]
    private var protocolTotals: [PacketProtocol: (packets: Int, bytes: Int64)] = [:]
    private var announcementsByEndpoint: [Endpoint: [Int]] = [:]
    private var processedAnnouncements = 0
    private var streamsByEndpoint: [Endpoint: [Int]] = [:]

    private(set) var packetCount = 0
    private var byteCount: Int64 = 0
    private var truncatedPackets = 0
    private var firstTimestamp: Int64?
    private var lastTimestamp: Int64?

    init(file: CaptureFile, indexURL: URL, sipTextsURL: URL) throws {
        self.file = file
        reader = try CaptureReader(file: file)
        writer = try PacketIndexWriter(url: indexURL)
        sipTexts = try JSONStringArrayWriter(url: sipTextsURL)
    }

    // MARK: Reading

    /// Counts for the progress display.
    var found: AnalysisProgress.Found {
        AnalysisProgress.Found(flows: flowTable.flows.count, protocols: protocolTotals.count, sipMessages: sip.messages.count,
                               rtpStreams: rtp.streamCount)
    }

    func run(progress: (Double, Int, AnalysisProgress.Found) -> Void) async throws {
        var frames: [CapturedFrame] = []
        frames.reserveCapacity(32_768)
        var lastReport = Date.distantPast
        while try reader.readBatch(into: &frames, maxCount: 32_768) {
            try Task.checkCancellation()
            let decoded = await FrameDecoding.decodeBatch(frames, file: file)
            try Task.checkCancellation()
            for chunk in decoded {
                for item in chunk { try ingest(item) }
            }
            if Date().timeIntervalSince(lastReport) > 0.1 {
                lastReport = Date()
                progress(reader.fractionRead, packetCount, found)
            }
        }
        try writer.finish()
        try sipTexts.finish()
        progress(1, packetCount, found)
    }

    private func addressID(_ address: IPAddress?) -> UInt32 {
        guard let address else { return 0 }
        if let id = addressIDs[address] { return id }
        let id = UInt32(addressList.count)
        addressList.append(address)
        addressIDs[address] = id
        return id
    }

    private func ingest(_ item: DecodedFrame) throws {
        let frame = item.frame
        let packet = item.packet
        packetCount += 1
        byteCount += Int64(frame.originalLength)
        firstTimestamp = min(firstTimestamp ?? frame.timestampNanos, frame.timestampNanos)
        lastTimestamp = max(lastTimestamp ?? frame.timestampNanos, frame.timestampNanos)

        var record = PacketIndexRecord(
            fileOffset: UInt64(frame.dataOffset), timestampNanos: frame.timestampNanos,
            capturedLength: UInt32(frame.capturedLength), originalLength: UInt32(frame.originalLength),
            sourceAddress: addressID(packet.source), destinationAddress: addressID(packet.destination),
            sourcePort: packet.sourcePort, destinationPort: packet.destinationPort,
            linkType: UInt16(truncatingIfNeeded: frame.linkType.rawValue), interfaceID: UInt16(truncatingIfNeeded: frame.interfaceID))
        record.ipProtocolRaw = packet.network == .ipv4 || packet.network == .ipv6 ? packet.ipProtocol : 0
        if packet.ipProtocol == 6, packet.hasTransportHeader { record.tcpFlags = packet.tcpFlags }
        if packet.truncated {
            record.flags.insert(.malformed)
            truncatedPackets += 1
        }
        if record.sourceAddress != 0 { addressPackets[record.sourceAddress, default: 0] += 1 }
        if record.destinationAddress != 0 { addressPackets[record.destinationAddress, default: 0] += 1 }

        record.protocolKind = baseProtocol(packet)
        let timestamp = Timestamp(nanoseconds: frame.timestampNanos)

        if packet.fragment != nil {
            record.protocolKind = .ipFragment
            let bytes = file.bytes(offset: frame.dataOffset, length: frame.capturedLength)
            if let datagram = fragments.add(frame: bytes, packet: packet, frameNumber: frame.number,
                                            timestampNanos: frame.timestampNanos) {
                handleReassembled(datagram, frame: frame, record: &record, time: timestamp)
            }
        } else {
            switch item.app {
            case .sip(let message):
                if let source = packet.sourceEndpoint, let destination = packet.destinationEndpoint {
                    ingestSIP(message, frame: frame, source: source, destination: destination, transport: .udp,
                              time: timestamp, record: &record)
                }
            case .rtp(let header):
                if let source = packet.sourceEndpoint, let destination = packet.destinationEndpoint {
                    ingestRTP(header, source: source, destination: destination, time: timestamp, wireLength: frame.originalLength,
                              record: &record)
                }
            case .rtcp:
                record.protocolKind = .rtcp
                if let source = packet.sourceEndpoint, let destination = packet.destinationEndpoint {
                    let bytes = file.bytes(offset: frame.dataOffset, length: frame.capturedLength)
                    rtcp.ingest(bytes.slice(packet.payloadOffset, packet.payloadLength), frameNumber: frame.number,
                                time: timestamp, source: source, destination: destination)
                }
            case .known(let proto):
                record.protocolKind = proto
                if packet.ipProtocol == 17, proto == .stun || proto == .turn || proto == .dtls {
                    ingestWebRTC(proto, packet: packet, frame: frame, time: timestamp)
                }
            case .none:
                if packet.ipProtocol == 6, packet.hasTransportHeader, packet.payloadLength > 0 {
                    ingestTCP(packet, frame: frame, time: timestamp, record: &record)
                } else if packet.ipProtocol == 6, packet.hasTransportHeader, packet.tcpFlags & 0x05 != 0 {
                    ingestTCP(packet, frame: frame, time: timestamp, record: &record)
                }
            }
        }

        let flow = flowTable.assign(packet, frameNumber: frame.number, timestampNanos: frame.timestampNanos,
                                    length: frame.originalLength, protocolKind: record.protocolKind)
        record.flowIndex = flow.id
        if packet.ipProtocol == 6, packet.hasTransportHeader {
            record.analysisFlags = tcpAnalyzer.analyze(flow: flow.id, fromInitiator: flow.fromInitiator,
                                                       sequence: packet.tcpSequence, acknowledgment: packet.tcpAcknowledgment,
                                                       flags: packet.tcpFlags, window: packet.tcpWindow,
                                                       payloadLength: packet.payloadLength, timeNanos: frame.timestampNanos)
        }
        statistics.add(timeNanos: frame.timestampNanos, length: frame.originalLength, protocolKind: record.protocolKind)
        var totals = protocolTotals[record.protocolKind] ?? (0, 0)
        totals.packets += 1
        totals.bytes += Int64(frame.originalLength)
        protocolTotals[record.protocolKind] = totals
        try writer.append(record)
    }

    private func baseProtocol(_ packet: DecodedPacket) -> PacketProtocol {
        switch packet.network {
        case .arp: return .arp
        case .none, .other: return packet.etherType == 0 ? .unknown : .ethernet
        case .ipv4, .ipv6:
            switch packet.ipProtocol {
            case 17: return .udp
            case 6: return .tcp
            case 1: return .icmp
            case 58: return .icmpv6
            case 2: return .igmp
            case 132: return .sctp
            default: return packet.network == .ipv4 ? .ipv4 : .ipv6
            }
        }
    }

    // MARK: WebRTC

    private func ingestWebRTC(_ proto: PacketProtocol, packet: DecodedPacket, frame: CapturedFrame, time: Timestamp) {
        guard let source = packet.sourceEndpoint, let destination = packet.destinationEndpoint else { return }
        let payload = file.bytes(offset: frame.dataOffset, length: frame.capturedLength).slice(packet.payloadOffset, packet.payloadLength)
        switch proto {
        case .dtls:
            webrtc.ingestDTLS(payload, frame: frame.number, time: time, source: source, destination: destination)
        case .turn where payload.count >= 4 && payload[0] & 0xC0 == 0x40:
            webrtc.ingestChannelData(payload, frame: frame.number, time: time, source: source, destination: destination)
        default:
            webrtc.ingestSTUN(payload, frame: frame.number, time: time, source: source, destination: destination)
        }
    }

    // MARK: SIP

    private func ingestSIP(_ message: SIPMessage, frame: CapturedFrame, source: Endpoint, destination: Endpoint,
                           transport: TransportKind, time: Timestamp, record: inout PacketIndexRecord) {
        let index = sip.ingest(message, frameNumber: frame.number, time: time, source: source,
                               destination: destination, transport: transport)
        sipTexts.append(SIPRedaction.redact(message.rawText))
        let stored = sip.messages[index]
        record.protocolKind = stored.hasSDP ? .sipSDP : .sip
        record.aux = UInt32(index)
        if let code = message.statusCode {
            record.sipCode = UInt16(code)
            if code >= 400 { record.flags.insert(.sipError) }
        } else {
            record.sipCode = SIPMethodCode.code(for: message.method)
        }
        if stored.hasSDP { record.flags.insert(.hasSDP) }
        if stored.isRetransmission { record.flags.insert(.retransmission) }
        indexNewAnnouncements()
    }

    /// Indexes SDP announcements added since the last call and upgrades streams that started before their SDP.
    private func indexNewAnnouncements() {
        let all = sip.announcements
        guard processedAnnouncements < all.count else { return }
        for index in processedAnnouncements..<all.count {
            let announcement = all[index]
            var candidates = announcementsByEndpoint[announcement.endpoint, default: []]
            candidates.append(index)
            // Only recent announcements matter for choosing a stream's codecs; keep the list short.
            if candidates.count > 64 { candidates.removeFirst(candidates.count - 64) }
            announcementsByEndpoint[announcement.endpoint] = candidates
            // Streams seen before any SDP for this endpoint are upgraded once, then forgotten.
            for stream in streamsByEndpoint.removeValue(forKey: announcement.endpoint) ?? []
            where !rtp.analyzers[stream].negotiatedInSDP {
                rtp.applyNegotiation(RTPNegotiation(codecs: announcement.codecs, ptimeMs: announcement.ptimeMs,
                                                    secure: announcement.secure),
                                     toStream: stream)
            }
        }
        processedAnnouncements = all.count
    }

    private func negotiation(for endpoint: Endpoint, at time: Timestamp) -> RTPNegotiation? {
        guard let candidates = announcementsByEndpoint[endpoint] else { return nil }
        let all = sip.announcements
        // Latest announcement made before the media (small tolerance for capture timestamp skew).
        let limit = time.adding(seconds: 2)
        guard let chosen = candidates.last(where: { all[$0].time <= limit }) ?? candidates.first else { return nil }
        return RTPNegotiation(codecs: all[chosen].codecs, ptimeMs: all[chosen].ptimeMs, secure: all[chosen].secure)
    }

    // MARK: RTP

    private func ingestRTP(_ header: RTPHeader, source: Endpoint, destination: Endpoint, time: Timestamp, wireLength: Int,
                           record: inout PacketIndexRecord) {
        let outcome = rtp.ingest(header, source: source, destination: destination, arrivalNanos: time.nanoseconds) {
            self.negotiation(for: destination, at: time) ?? self.negotiation(for: source, at: time)
        }
        guard let outcome else { return }
        if outcome.streamIndex >= rtpStreamEndpointsIndexed {
            // First packet of a stream without SDP yet: remember its endpoints for a late SDP upgrade.
            if !rtp.analyzers[outcome.streamIndex].negotiatedInSDP {
                streamsByEndpoint[destination, default: []].append(outcome.streamIndex)
                streamsByEndpoint[source, default: []].append(outcome.streamIndex)
            }
            rtpStreamEndpointsIndexed = outcome.streamIndex + 1
        }
        record.protocolKind = .rtp
        record.streamIndex = Int32(outcome.streamIndex)
        rtp.addWireBytes(wireLength, toStream: outcome.streamIndex)
        var flags = record.flags
        if outcome.verdict.sequenceGap {
            flags.insert(.sequenceGap)
            record.aux = UInt32(min(outcome.verdict.lostBefore, Int(UInt32.max)))
        }
        if outcome.verdict.duplicate { flags.insert(.duplicate) }
        if outcome.verdict.outOfOrder { flags.insert(.outOfOrder) }
        if outcome.newSSRC && rtp.analyzers[outcome.streamIndex].packets == 1 { flags.insert(.ssrcChange) }
        record.flags = flags
    }

    private var rtpStreamEndpointsIndexed = 0
    /// Concurrent SIP-over-TCP connections tracked; each holds a reassembly buffer.
    static let maxTCPFramers = 4_096

    // MARK: TCP / reassembly

    private func ingestTCP(_ packet: DecodedPacket, frame: CapturedFrame, time: Timestamp, record: inout PacketIndexRecord) {
        guard let source = packet.sourceEndpoint, let destination = packet.destinationEndpoint else { return }
        let flow = TCPStreamAssembler.FlowKey(source: source, destination: destination)
        if packet.tcpFlags & 0x05 != 0, packet.payloadLength == 0 {
            // FIN or RST: the connection's SIP stream is over.
            framers[flow] = nil
            return
        }
        let bytes = file.bytes(offset: frame.dataOffset, length: frame.capturedLength)
        let payload = bytes.slice(packet.payloadOffset, packet.payloadLength)
        let sipPort = [5060, 5080].contains(Int(source.port)) || [5060, 5080].contains(Int(destination.port))
        guard sipPort || framers[flow] != nil || SIPParser.looksLikeSIP(payload) else { return }
        guard framers[flow] != nil || framers.count < Self.maxTCPFramers else { return }

        var framer = framers[flow] ?? SIPStreamFramer()
        var messages: [SIPMessage] = []
        switch tcp.add(flow: flow, sequence: packet.tcpSequence, flags: packet.tcpFlags, payload: payload) {
        case .data(let data):
            messages = framer.append(data)
        case .gap(let data):
            framer.reset()
            messages = framer.append(data)
        case .duplicate:
            break
        }
        framers[flow] = packet.tcpFlags & 0x05 != 0 ? nil : framer
        for message in messages {
            ingestSIP(message, frame: frame, source: source, destination: destination, transport: .tcp, time: time,
                      record: &record)
        }
    }

    private func handleReassembled(_ datagram: IPFragmentReassembler.Datagram, frame: CapturedFrame,
                                   record: inout PacketIndexRecord, time: Timestamp) {
        guard datagram.ipProtocol == 17, datagram.bytes.count >= 8 else { return }
        datagram.bytes.withUnsafeBytes { raw in
            let sourcePort = UInt16(raw[0]) << 8 | UInt16(raw[1])
            let destinationPort = UInt16(raw[2]) << 8 | UInt16(raw[3])
            record.sourcePort = sourcePort
            record.destinationPort = destinationPort
            record.protocolKind = .udp
            let payload = UnsafeRawBufferPointer(rebasing: raw[8...])
            if SIPParser.looksLikeSIP(payload), let message = SIPParser.parse(payload) {
                ingestSIP(message, frame: frame, source: Endpoint(address: datagram.source, port: sourcePort),
                          destination: Endpoint(address: datagram.destination, port: destinationPort),
                          transport: .udp, time: time, record: &record)
            }
        }
    }

    // MARK: Finish

    /// Flows with their TCP analysis attached (available after `finish`).
    var flows: [FlowRecord] { flowTable.flows }

    func finish(fileName: String, fileSize: Int64, compressed: Bool) throws -> AnalysisResult {
        flowTable.attach(tcpAnalyzer)
        // 1. Accept RTP streams and build their records.
        var streamIDForAnalyzer = [Int](repeating: -1, count: rtp.analyzers.count)
        var streams: [RTPStreamRecord] = []
        for index in rtp.analyzers.indices where rtp.isAccepted(index) {
            streamIDForAnalyzer[index] = streams.count
            var stream = rtp.analyzers[index].makeRecord(id: streams.count)
            stream.wireBytes = rtp.wireBytes[index] ?? 0
            streams.append(stream)
        }

        // 2. Correlate.
        let captureEnd = lastTimestamp.map { Timestamp(nanoseconds: $0) }
        let correlation = CallCorrelator().correlate(CallCorrelator.Input(
            messages: sip.messages, transactions: sip.transactions, sessions: sip.finalizedSessions(),
            announcements: sip.announcements, streams: streams, captureEnd: captureEnd))
        let messages = sip.messages

        // 3. Patch the packet index with final stream/call identifiers.
        try patchIndex(streamIDForAnalyzer: streamIDForAnalyzer, streams: correlation.streams,
                       sessions: correlation.sessions)

        // RTCP: what senders and receivers reported about each stream.
        var finalStreams = correlation.streams
        for (index, summary) in RTCPTracker.summaries(reports: rtcp.reports, streams: finalStreams).enumerated() {
            finalStreams[index].rtcp = summary
        }

        // 4. Summaries.
        var findings = correlation.findings
        findings += RTCPDiagnostics.findings(streams: finalStreams, firstID: findings.count)
        findings += SIPDiagnostics.findings(messages: messages, transactions: sip.transactions, sessions: correlation.sessions,
                                            captureEnd: captureEnd, firstID: findings.count)
        findings += TCPDiagnostics.findings(flows: flowTable.flows, firstID: findings.count)
        let webrtcAnalysis = webrtc.finish(streams: finalStreams, sipMessages: messages, flowTable: flowTable, captureEnd: captureEnd)
        // Media on an ICE session's selected pair is SRTP (WebRTC always encrypts), even without captured SDP.
        for index in webrtcAnalysis.sessions.flatMap(\.streamIndices) where index < finalStreams.count {
            finalStreams[index].secure = true
        }
        findings += WebRTCDiagnostics.findings(webrtcAnalysis, firstID: findings.count)
        if reader.truncatedAtEnd {
            findings.append(Finding(id: findings.count, severity: .info, kind: .captureTruncated,
                                    title: String(localized: "Capture truncated", bundle: CoreLocalization.bundle),
                                    detail: reader.warnings.last ?? String(localized: "The capture file ends in the middle of a packet", bundle: CoreLocalization.bundle),
                                    packetReferences: packetCount > 0 ? [packetCount] : []))
        }
        let voip = SummaryBuilder.voipSummary(calls: correlation.calls, streams: finalStreams, findings: findings)
        let headline = SummaryBuilder.headline(calls: correlation.calls, findings: findings, sipMessageCount: messages.count,
                                               webrtcSessionCount: webrtcAnalysis.sessions.count)

        let format: CaptureFormat
        switch reader.format {
        case .pcap(let nanosecond, _): format = nanosecond ? .pcapNanosecond : .pcap
        default: format = .pcapng
        }
        let protocols = protocolTotals.map { ProtocolCount(name: $0.key.displayName, packets: $0.value.packets, bytes: $0.value.bytes) }
        // Merge entries sharing a display name (e.g. IPv4 and IPv4 fragments).
        var merged: [String: ProtocolCount] = [:]
        for entry in protocols {
            if var existing = merged[entry.name] {
                existing.packets += entry.packets
                existing.bytes += entry.bytes
                merged[entry.name] = existing
            } else {
                merged[entry.name] = entry
            }
        }
        let addresses = addressPackets.compactMap { id, count -> AddressCount? in
            guard let address = addressList[Int(id)] else { return nil }
            return AddressCount(address: address, packets: count)
        }.sorted { $0.packets != $1.packets ? $0.packets > $1.packets : $0.address < $1.address }

        var warnings = reader.warnings
        if flowTable.limitReached {
            warnings.append(String(localized: "More than \(FlowTable.defaultLimit) flows: later conversations are not grouped into flows", bundle: CoreLocalization.bundle))
        }
        if tcpAnalyzer.limitReached {
            warnings.append(String(localized: "More than \(TCPAnalyzer.maxConnections) TCP connections: later connections were not analyzed", bundle: CoreLocalization.bundle))
        }
        if rtcp.limitReached {
            warnings.append(String(localized: "More than \(RTCPTracker.maxReports) RTCP reports: later reports were not analyzed", bundle: CoreLocalization.bundle))
        }
        if webrtc.limitReached {
            warnings.append(String(localized: "WebRTC limits reached (\(WebRTCTracker.maxTransactions) STUN transactions, \(WebRTCTracker.maxSessions) ICE sessions or \(WebRTCTracker.maxAllocations) TURN allocations): later ones were not analyzed", bundle: CoreLocalization.bundle))
        }
        if rtp.streamLimitReached {
            warnings.append(String(localized: "More than \(RTPTracker.maxStreams) RTP streams: later streams were not analyzed", bundle: CoreLocalization.bundle))
        }
        let capture = CaptureSummary(
            fileName: fileName, fileSize: fileSize, format: format, compressed: compressed,
            linkTypes: reader.linkTypes.map(\.description),
            firstPacketTime: firstTimestamp.map { Timestamp(nanoseconds: $0) }, lastPacketTime: captureEnd,
            packetCount: packetCount, byteCount: byteCount,
            sipPackets: (protocolTotals[.sip]?.packets ?? 0) + (protocolTotals[.sipSDP]?.packets ?? 0),
            rtpPackets: correlation.streams.reduce(0) { $0 + $1.packetCount },
            rtcpPackets: protocolTotals[.rtcp]?.packets ?? 0,
            protocols: merged.values.sorted { $0.packets != $1.packets ? $0.packets > $1.packets : $0.name < $1.name }, addresses: addresses,
            truncatedPackets: truncatedPackets, truncatedAtEnd: reader.truncatedAtEnd, warnings: warnings,
            formatVersion: reader.formatVersion, interfaces: reader.interfaceInfos, section: reader.sectionInfo,
            packetComments: reader.packetComments, flowCount: flowTable.flows.count)

        return AnalysisResult(capture: capture, topology: correlation.topology, voip: voip, headline: headline,
                              sipMessages: messages, sipTransactions: sip.transactions, sipSessions: correlation.sessions,
                              calls: correlation.calls, streams: finalStreams, findings: findings,
                              statistics: statistics.finish(protocolTotals: protocolTotals.mapValues(\.packets)),
                              rtcpReports: rtcp.reports, webrtc: webrtcAnalysis)
    }

    private func patchIndex(streamIDForAnalyzer: [Int], streams: [RTPStreamRecord], sessions: [SIPSessionRecord]) throws {
        let index = try MappedPacketIndex(url: writer.url, writable: true)
        let messages = sip.messages
        var rtpDemoted = 0
        var rtpDemotedBytes: Int64 = 0
        for i in 0..<index.count {
            var record = index.record(at: i)
            switch record.protocolKind {
            case .rtp:
                let analyzer = Int(record.streamIndex)
                let finalID = analyzer >= 0 && analyzer < streamIDForAnalyzer.count ? streamIDForAnalyzer[analyzer] : -1
                if finalID >= 0 {
                    record.streamIndex = Int32(finalID)
                    record.callIndex = Int32(streams[finalID].callIndex ?? -1)
                } else {
                    record.protocolKind = .udp
                    record.streamIndex = -1
                    record.flags.subtract([.sequenceGap, .duplicate, .outOfOrder, .ssrcChange])
                    record.aux = 0
                    rtpDemoted += 1
                    rtpDemotedBytes += Int64(record.originalLength)
                }
                index.setRecord(record, at: i)
            case .sip, .sipSDP:
                let messageIndex = Int(record.aux)
                if messageIndex < messages.count, let session = messages[messageIndex].sessionIndex,
                   let call = sessions[session].callIndex {
                    record.callIndex = Int32(call)
                    index.setRecord(record, at: i)
                }
            default:
                continue
            }
        }
        index.sync()
        if rtpDemoted > 0, var rtpTotals = protocolTotals[.rtp] {
            rtpTotals.packets -= rtpDemoted
            rtpTotals.bytes -= rtpDemotedBytes
            protocolTotals[.rtp] = rtpTotals.packets > 0 ? rtpTotals : nil
            var udp = protocolTotals[.udp] ?? (0, 0)
            udp.packets += rtpDemoted
            udp.bytes += rtpDemotedBytes
            protocolTotals[.udp] = udp
        }
    }
}

/// Writes a JSON array of strings incrementally (the stored SIP message texts), with a bounded buffer.
final class JSONStringArrayWriter {
    private let handle: FileHandle
    private var buffer = Data()
    private var count = 0
    private var failure: Error?

    init(url: URL) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try FileHandle(forWritingTo: url)
        buffer.append(UInt8(ascii: "["))
    }

    func append(_ string: String) {
        if count > 0 { buffer.append(UInt8(ascii: ",")) }
        count += 1
        buffer.append(UInt8(ascii: "\""))
        var string = string
        string.withUTF8 { bytes in
            // Copy runs that need no escaping in one go.
            var runStart = 0
            for (i, byte) in bytes.enumerated() where byte < 0x20 || byte == 34 || byte == 92 {
                if i > runStart { buffer.append(UnsafeBufferPointer(rebasing: bytes[runStart..<i])) }
                switch byte {
                case 34: buffer.append(contentsOf: [92, 34])
                case 92: buffer.append(contentsOf: [92, 92])
                case 0x0A: buffer.append(contentsOf: [92, 110])
                case 0x0D: buffer.append(contentsOf: [92, 114])
                case 0x09: buffer.append(contentsOf: [92, 116])
                default:
                    let hex = Array("0123456789abcdef".utf8)
                    buffer.append(contentsOf: [92, 117, 48, 48, hex[Int(byte >> 4)], hex[Int(byte & 0x0F)]])
                }
                runStart = i + 1
            }
            if runStart < bytes.count { buffer.append(UnsafeBufferPointer(rebasing: bytes[runStart...])) }
        }
        buffer.append(UInt8(ascii: "\""))
        if buffer.count > 1 << 20 { flush() }
    }

    private func flush() {
        guard failure == nil else { return }
        do {
            try handle.write(contentsOf: buffer)
        } catch {
            failure = error
        }
        buffer.removeAll(keepingCapacity: true)
    }

    func finish() throws {
        buffer.append(UInt8(ascii: "]"))
        flush()
        try handle.close()
        if let failure { throw failure }
    }
}
