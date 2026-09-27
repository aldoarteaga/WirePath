import Foundation

/// Protocol scopes offered by the Packet Inspector's segmented control.
public enum PacketScope: String, Sendable, CaseIterable {
    case all = "All"
    case sipRTP = "SIP + RTP"
    case sdp = "SDP"
    case rtcp = "RTCP"
    case issues = "Issues"

    func includes(_ record: PacketIndexRecord) -> Bool {
        switch self {
        case .all: return true
        case .sipRTP: return record.protocolKind.isSIP || record.protocolKind == .rtp
        case .sdp: return record.protocolKind == .sipSDP
        case .rtcp: return record.protocolKind == .rtcp
        case .issues:
            return record.flagsRaw & PacketFlags.issues.rawValue != 0
                || record.analysisFlagsRaw & PacketAnalysisFlags.problems.rawValue != 0
        }
    }
}

/// A row of the packet list, decoded on demand for visible rows only.
public struct PacketRow: Sendable, Hashable {
    public var frameNumber: Int
    public var timestampNanos: Int64
    public var source: String
    public var destination: String
    public var protocolName: String
    public var protocolKind: PacketProtocol
    public var length: Int
    public var info: String
    public var flags: PacketFlags
    public var streamIndex: Int?
    public var callIndex: Int?
}

/// Random access to the packets of an analysis: memory-mapped index + memory-mapped original capture.
public final class PacketStore: @unchecked Sendable {
    public let count: Int
    public let captureURL: URL
    private let index: MappedPacketIndex
    private let capture: CaptureFile
    private let addresses: [IPAddress?]
    private let result: AnalysisResult
    private let flowsURL: URL?
    private let flowsLock = NSLock()
    private var loadedFlows: [FlowRecord]?
    public let captureStartNanos: Int64

    public init(indexURL: URL, addressTableURL: URL, captureURL: URL, result: AnalysisResult, flowsURL: URL? = nil) throws {
        self.flowsURL = flowsURL
        index = try MappedPacketIndex(url: indexURL)
        capture = try CaptureFile(url: captureURL)
        capture.adviseRandomAccess()
        self.captureURL = captureURL
        let strings = try JSONDecoder().decode([String?].self, from: Data(contentsOf: addressTableURL))
        addresses = strings.map { $0.flatMap(IPAddress.init) }
        self.result = result
        count = index.count
        captureStartNanos = result.capture.firstPacketTime?.nanoseconds ?? (count > 0 ? index.record(at: 0).timestampNanos : 0)
    }

    /// The index record at `position`, with links to calls and streams that fall outside this analysis
    /// (a damaged or stale index) removed. Positions outside the index give an empty record.
    public func record(at position: Int) -> PacketIndexRecord {
        var record = index.record(at: position)
        if record.callIndex >= 0, Int(record.callIndex) >= result.calls.count { record.callIndex = -1 }
        if record.streamIndex >= 0, Int(record.streamIndex) >= result.streams.count { record.streamIndex = -1 }
        return record
    }

    /// Largest frame prefix decoded and copied for the packet details (the hex view shows what is decoded).
    public static let maxDissectedBytes = 262_144

    /// The captured bytes of a record, clamped to the capture file (empty when the record points outside it).
    private func frameBytes(_ record: PacketIndexRecord, limit: Int = .max) -> UnsafeRawBufferPointer {
        guard let offset = Int(exactly: record.fileOffset) else { return UnsafeRawBufferPointer(start: nil, count: 0) }
        return capture.bytes(offset: offset, length: min(Int(record.capturedLength), limit))
    }

    // MARK: Packet model

    /// Metadata of the packet at `position` (0-based), from the index only.
    public func packet(at position: Int) -> Packet {
        let record = record(at: position)
        let ported = record.sourcePort != 0 || record.destinationPort != 0
        let metadata = PacketMetadata(
            protocolKind: record.protocolKind, source: address(record.sourceAddress), destination: address(record.destinationAddress),
            sourcePort: ported ? record.sourcePort : nil, destinationPort: ported ? record.destinationPort : nil,
            flags: record.flags, flowIndex: record.flowIndex >= 0 ? Int(record.flowIndex) : nil,
            callIndex: record.callIndex >= 0 ? Int(record.callIndex) : nil,
            streamIndex: record.streamIndex >= 0 ? Int(record.streamIndex) : nil,
            sipMessageIndex: record.protocolKind.isSIP && Int(record.aux) < result.sipMessages.count ? Int(record.aux) : nil)
        return Packet(number: position + 1, timestamp: record.timestamp, capturedLength: Int(record.capturedLength),
                      originalLength: Int(record.originalLength), linkType: LinkType(rawValue: UInt32(record.linkType)),
                      interfaceID: Int(record.interfaceID), metadata: metadata)
    }

    public func packetBytes(at position: Int) -> PacketBytes {
        PacketBytes(number: position + 1, data: bytes(at: position))
    }

    public func decodedProtocols(at position: Int) -> DecodedProtocols { dissect(at: position) }

    // MARK: Related objects

    /// All flows of the capture, read from disk the first time they are needed.
    public func flows() -> [FlowRecord] {
        flowsLock.lock()
        defer { flowsLock.unlock() }
        if let loadedFlows { return loadedFlows }
        let flows = flowsURL.flatMap { try? JSONDecoder().decode([FlowRecord].self, from: Data(contentsOf: $0)) } ?? []
        loadedFlows = flows
        return flows
    }

    public func flow(of packet: Packet) -> FlowRecord? {
        guard let index = packet.metadata.flowIndex else { return nil }
        let all = flows()
        return index < all.count ? all[index] : nil
    }

    public func call(of packet: Packet) -> CallRecord? {
        guard let index = packet.metadata.callIndex, index < result.calls.count else { return nil }
        return result.calls[index]
    }

    public func stream(of packet: Packet) -> RTPStreamRecord? {
        guard let index = packet.metadata.streamIndex, index < result.streams.count else { return nil }
        return result.streams[index]
    }

    public func sipMessage(of packet: Packet) -> SIPMessageRecord? {
        packet.metadata.sipMessageIndex.map { result.sipMessages[$0] }
    }

    /// Positions (0-based) of every packet in a flow, in capture order. Cancellable via Task cancellation.
    public func positions(inFlow flowIndex: Int) async -> [UInt32] {
        let target = Int32(flowIndex)
        var matches: [UInt32] = []
        for position in 0..<count {
            if position & 0xFFFF == 0, Task.isCancelled { return matches }
            if index.record(at: position).flowIndex == target { matches.append(UInt32(position)) }
        }
        return matches
    }

    /// Number of entries in the address table (id 0 = no address).
    public var addressCount: Int { addresses.count }

    /// Calls `body` with the captured bytes of a packet (at most `limit`), without copying them.
    public func withBytes<Result>(at position: Int, limit: Int = .max, _ body: (UnsafeRawBufferPointer) -> Result) -> Result {
        body(frameBytes(record(at: position), limit: limit))
    }

    public func address(_ id: UInt32) -> IPAddress? {
        Int(id) < addresses.count ? addresses[Int(id)] : nil
    }

    /// Context for compiling display filters against this store.
    public var filterContext: PacketFilterContext {
        PacketFilterContext(addresses: addresses, captureStartNanos: captureStartNanos,
                            streamSSRCs: result.streams.map(\.ssrc), streamPayloadTypes: result.streams.map(\.payloadType),
                            sipCallIDs: result.sipMessages.map(\.callID), flowProtocols: flows().map(\.ipProtocol),
                            webrtcSessionFlows: result.webrtc.sessions.map(\.flowIndices))
    }

    /// Positions (0-based) of packets matching every criterion. Cancellable via Task cancellation.
    public func filter(_ displayFilter: DisplayFilter?, scope: PacketScope, callIndex: Int?) async -> [UInt32]? {
        if displayFilter == nil && scope == .all && callIndex == nil { return nil }
        var matches: [UInt32] = []
        let call = callIndex.map(Int32.init)
        for position in 0..<count {
            if position & 0xFFFF == 0, Task.isCancelled { return matches }
            let record = index.record(at: position)
            if let call, record.callIndex != call { continue }
            if !scope.includes(record) { continue }
            if let displayFilter, !displayFilter.matches(record, frameNumber: position + 1) { continue }
            matches.append(UInt32(position))
        }
        return matches
    }

    /// Frame bytes (copied).
    public func bytes(at position: Int) -> Data {
        let bytes = frameBytes(record(at: position))
        return bytes.isEmpty ? Data() : Data(bytes)
    }

    public func row(at position: Int) -> PacketRow {
        let record = record(at: position)
        let source = address(record.sourceAddress)?.description ?? ""
        let destination = address(record.destinationAddress)?.description ?? ""
        return PacketRow(frameNumber: position + 1, timestampNanos: record.timestampNanos, source: source,
                         destination: destination, protocolName: record.protocolKind.displayName,
                         protocolKind: record.protocolKind, length: Int(record.originalLength),
                         info: info(for: record), flags: record.flags,
                         streamIndex: record.streamIndex >= 0 ? Int(record.streamIndex) : nil,
                         callIndex: record.callIndex >= 0 ? Int(record.callIndex) : nil)
    }

    public func dissect(at position: Int) -> DissectedPacket {
        let record = record(at: position)
        let stream = record.streamIndex >= 0 ? result.streams[Int(record.streamIndex)] : nil
        let bytes = frameBytes(record, limit: Self.maxDissectedBytes)
        let context = PacketDissector.Context(
            frameNumber: position + 1, timestampNanos: record.timestampNanos, captureStartNanos: captureStartNanos,
            linkType: LinkType(rawValue: UInt32(record.linkType)), interfaceID: Int(record.interfaceID),
            originalLength: Int(record.originalLength),
            codecForPayloadType: { pt in
                if let codec = stream?.codec, codec.payloadType == pt { return codec }
                return CodecCatalog.descriptor(payloadType: pt)
            })
        var dissection = PacketDissector.dissect(bytes, context: context)
        annotateTCP(&dissection, position: position)
        if Int(record.capturedLength) > Self.maxDissectedBytes, !dissection.layers.isEmpty {
            dissection.layers[0].fields.append(ProtocolField(
                id: Int.max, name: "Shown", value: "First \(Self.maxDissectedBytes.formatted()) of \(Int(record.capturedLength).formatted()) captured bytes"))
        }
        return dissection
    }

    /// Adds what only the whole-capture analysis knows to the TCP layer: relative sequence numbers and the
    /// SEQ/ACK analysis flags.
    private func annotateTCP(_ dissection: inout DissectedPacket, position: Int) {
        let record = record(at: position)
        guard record.ipProtocolRaw == 6, let index = dissection.layers.firstIndex(where: { $0.protocolName == "tcp" }) else { return }
        var nextID = (dissection.layers.flatMap(\.fields).map(\.id).max() ?? 0) + 1
        func add(_ name: String, _ value: String, level: Int = 0) {
            dissection.layers[index].fields.append(ProtocolField(id: nextID, name: name, value: value, level: level))
            nextID += 1
        }
        let packet = packet(at: position)
        if let flow = flow(of: packet), let tcp = flow.tcp, flow.ipProtocol == 6,
           let sequenceField = dissection.layers[index].fields.first(where: { $0.name == "Sequence Number" }),
           let sequence = UInt32(sequenceField.value) {
            let fromInitiator = packet.metadata.source == flow.initiator.address && packet.metadata.sourcePort == flow.initiator.port
            if let isn = fromInitiator ? tcp.initiatorISN : tcp.responderISN {
                add("Relative Sequence", "\(sequence &- isn)")
            }
            if record.tcpFlags & 0x10 != 0,
               let ackField = dissection.layers[index].fields.first(where: { $0.name == "Acknowledgment" }),
               let ack = UInt32(ackField.value), let peerISN = fromInitiator ? tcp.responderISN : tcp.initiatorISN {
                add("Relative Acknowledgment", "\(ack &- peerISN)")
            }
            add("Stream", "Flow #\(flow.id + 1)")
        }
        let labels = record.analysisFlags.labels
        if !labels.isEmpty {
            add("SEQ/ACK Analysis", labels.joined(separator: ", "))
        }
    }

    // MARK: Info column

    private func info(for record: PacketIndexRecord) -> String {
        let labels = record.analysisFlags.labels
        let base = baseInfo(for: record)
        return labels.isEmpty ? base : labels.map { "[\($0)]" }.joined(separator: " ") + " " + base
    }

    private func baseInfo(for record: PacketIndexRecord) -> String {
        guard record.flags.contains(.malformed) else { return protocolInfo(for: record) }
        let problem = PacketDecoder.decode(frameBytes(record), linkType: LinkType(rawValue: UInt32(record.linkType))).problem
        switch problem {
        case .ipv4Length?, .ipv6Length?:
            // Headers decoded; the rest was cut, usually by the capture's snapshot length.
            let note = record.capturedLength < record.originalLength ? "[Packet size limited during capture]" : "[Truncated]"
            return "\(protocolInfo(for: record)) \(note)"
        case let problem?:
            return "Malformed: \(problem.message)"
        case nil:
            return protocolInfo(for: record)
        }
    }

    private func protocolInfo(for record: PacketIndexRecord) -> String {
        switch record.protocolKind {
        case .sip, .sipSDP:
            let index = Int(record.aux)
            guard index < result.sipMessages.count else { return "SIP" }
            let message = result.sipMessages[index]
            return message.isRetransmission ? "\(message.infoText) (retransmission)" : message.infoText
        case .rtp:
            return rtpInfo(record)
        case .rtcp:
            guard let payload = payload(of: record), payload.count >= 2 else { return "RTCP" }
            return RTCPDetector.typeName(payload[1])
        case .ipFragment:
            return "Fragmented IP datagram"
        default:
            return transportInfo(record)
        }
    }

    fileprivate func payload(of record: PacketIndexRecord) -> Data? {
        let bytes = frameBytes(record)
        let packet = PacketDecoder.decode(bytes, linkType: LinkType(rawValue: UInt32(record.linkType)))
        guard packet.payloadLength > 0, packet.payloadOffset + packet.payloadLength <= bytes.count else { return nil }
        return Data(UnsafeRawBufferPointer(rebasing: bytes[packet.payloadOffset..<(packet.payloadOffset + packet.payloadLength)]))
    }

    private func rtpInfo(_ record: PacketIndexRecord) -> String {
        guard let payload = payload(of: record),
              let header = payload.withUnsafeBytes({ RTPHeader.parse($0) }) else { return "RTP" }
        let stream = record.streamIndex >= 0 && Int(record.streamIndex) < result.streams.count ? result.streams[Int(record.streamIndex)] : nil
        let codec = stream?.codec?.payloadType == header.payloadType ? stream?.codec : CodecCatalog.descriptor(payloadType: header.payloadType)
        let ptName = codec.map { CodecCatalog.longName(for: $0) } ?? "\(header.payloadType)"
        let base = "PT=\(ptName), SSRC=\(String(format: "0x%08X", header.ssrc)), Seq=\(header.sequenceNumber), Time=\(header.timestamp)\(header.marker ? ", Mark" : "")"
        let flags = record.flags
        if flags.contains(.sequenceGap) {
            let lost = Int(record.aux)
            let expected = header.sequenceNumber &- UInt16(truncatingIfNeeded: lost)
            return "Sequence gap: expected Seq=\(expected), \(lost) packet\(lost == 1 ? "" : "s") lost · \(base)"
        }
        if flags.contains(.duplicate) { return "Duplicate packet · \(base)" }
        if flags.contains(.outOfOrder) { return "Out of order · \(base)" }
        if flags.contains(.ssrcChange) { return "SSRC changed · \(base)" }
        return base
    }

    private func transportInfo(_ record: PacketIndexRecord) -> String {
        switch record.protocolKind {
        case .tcp, .udp:
            let bytes = frameBytes(record)
            let packet = PacketDecoder.decode(bytes, linkType: LinkType(rawValue: UInt32(record.linkType)))
            if record.protocolKind == .udp {
                return "\(record.sourcePort) → \(record.destinationPort) Len=\(packet.payloadLength)"
            }
            return "\(record.sourcePort) → \(record.destinationPort) [\(PacketDissector.tcpFlags(packet.tcpFlags))] Seq=\(packet.tcpSequence) Len=\(packet.payloadLength)"
        case .arp, .icmp, .icmpv6, .dns, .dhcp, .ntp, .stun, .turn, .tls, .http, .ethernet:
            // Protocols whose Info comes from their dissector (decoded for visible rows only).
            return dissectorSummary(record)
        default:
            return record.protocolKind.displayName
        }
    }

    /// The registry's one-line summary for a packet, without the protocol name the Protocol column already shows.
    private func dissectorSummary(_ record: PacketIndexRecord) -> String {
        let bytes = frameBytes(record, limit: 4_096)
        let context = DissectionContext(frameNumber: 0, timestampNanos: record.timestampNanos, captureStartNanos: captureStartNanos,
                                        linkType: LinkType(rawValue: UInt32(record.linkType)), interfaceID: Int(record.interfaceID),
                                        originalLength: Int(record.originalLength),
                                        codecForPayloadType: { CodecCatalog.descriptor(payloadType: $0) })
        let summary = DissectorRegistry.standard.dissect(bytes, context: context).context.summary
        // Summaries start with the protocol name, which the Protocol column already shows.
        let names = Set(PacketProtocol.allCases.map(\.displayName) + ["MDNS", "LLDP", "LLC"])
        if let space = summary.firstIndex(of: " "), names.contains(String(summary[..<space])) {
            return String(summary[summary.index(after: space)...])
        }
        return summary
    }
}

/// One RTP packet's payload, for audio playback.
public struct RTPPayloadSample: Sendable {
    public var streamIndex: Int
    public var sequenceNumber: UInt16
    public var timestamp: UInt32
    public var payloadType: UInt8
    public var arrivalNanos: Int64
    public var payload: Data
    public var marker: Bool = false
    /// 1-based frame number of the packet.
    public var frameNumber: Int?
}

extension PacketStore {
    /// RTP payloads of the given streams, in capture order.
    public func rtpPayloads(streams: Set<Int>, callIndex: Int?) async -> [RTPPayloadSample] {
        let positions = await filter(nil, scope: .sipRTP, callIndex: callIndex) ?? Array(0..<UInt32(count))
        var samples: [RTPPayloadSample] = []
        for position in positions {
            let record = self.record(at: Int(position))
            guard record.protocolKind == .rtp, streams.contains(Int(record.streamIndex)),
                  let payload = payload(of: record) else { continue }
            let parsed: (RTPHeader, Data)? = payload.withUnsafeBytes { raw in
                guard let header = RTPHeader.parse(raw) else { return nil }
                return (header, Data(raw[header.headerLength..<(header.headerLength + header.payloadLength)]))
            }
            guard let (header, data) = parsed else { continue }
            samples.append(RTPPayloadSample(streamIndex: Int(record.streamIndex), sequenceNumber: header.sequenceNumber,
                                            timestamp: header.timestamp, payloadType: header.payloadType,
                                            arrivalNanos: record.timestampNanos, payload: data, marker: header.marker,
                                            frameNumber: Int(position) + 1))
        }
        return samples
    }

    /// Writes the given packets (original bytes and timestamps) to a nanosecond pcap file.
    /// Packets whose link type differs from the first one are skipped (classic pcap has one link type).
    /// Returns the number of packets written.
    public func exportPCAP(positions: [Int], to url: URL) throws -> Int {
        guard let firstPosition = positions.first else { return 0 }
        let linkType = record(at: firstPosition).linkType
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        var buffer = Data()
        func u32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { buffer.append(contentsOf: $0) } }
        func u16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { buffer.append(contentsOf: $0) } }
        u32(0xA1B2_3C4D); u16(2); u16(4); u32(0); u32(0); u32(262_144); u32(UInt32(linkType))
        var written = 0
        for position in positions {
            let record = self.record(at: position)
            guard record.linkType == linkType else { continue }
            let nanos = record.timestampNanos
            u32(UInt32(truncatingIfNeeded: nanos / 1_000_000_000))
            u32(UInt32(truncatingIfNeeded: nanos % 1_000_000_000))
            let data = bytes(at: position)
            u32(UInt32(data.count))
            u32(max(record.originalLength, UInt32(data.count)))
            buffer.append(data)
            written += 1
            if buffer.count > (4 << 20) {
                try handle.write(contentsOf: buffer)
                buffer.removeAll(keepingCapacity: true)
            }
        }
        try handle.write(contentsOf: buffer)
        return written
    }

    /// Loads the raw SIP message texts stored next to an analysis.
    public static func loadSIPTexts(from url: URL) -> [String] {
        (try? JSONDecoder().decode([String].self, from: Data(contentsOf: url))) ?? []
    }
}
