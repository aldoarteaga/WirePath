import Foundation

/// A bidirectional conversation between two endpoints over one IP protocol (the 5-tuple, direction-free).
/// Protocols without ports (ICMP, IGMP…) form one flow per address pair.
public struct FlowRecord: Codable, Sendable, Hashable, Identifiable {
    public var id: Int
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP…).
    public var ipProtocol: UInt8
    /// The endpoint that sent the first packet seen in the capture (not necessarily the real initiator when
    /// the capture started mid-conversation).
    public var initiator: Endpoint
    public var responder: Endpoint
    public var firstTime: Timestamp
    public var lastTime: Timestamp
    public var firstFrame: Int
    public var packetsFromInitiator: Int
    public var packetsFromResponder: Int
    public var bytesFromInitiator: Int64
    public var bytesFromResponder: Int64
    /// Most specific protocol classified in the flow (SIP, RTP, DNS…; UDP/TCP when nothing more specific).
    public var application: PacketProtocol
    /// TCP connection analysis (TCP flows only).
    public var tcp: TCPConnectionStats?

    public var transport: TransportKind {
        switch ipProtocol {
        case 6: return .tcp
        case 17: return .udp
        case 132: return .sctp
        default: return .other
        }
    }

    public var packets: Int { packetsFromInitiator + packetsFromResponder }
    public var bytes: Int64 { bytesFromInitiator + bytesFromResponder }
    public var durationSeconds: Double { lastTime.seconds(since: firstTime) }
}

/// Assigns every IP packet to a flow while the capture is read. Memory is bounded: past `limit` flows, new
/// conversations get no flow (reported through `limitReached`) so a scan-heavy capture cannot exhaust memory.
struct FlowTable {
    struct Key: Hashable {
        var ipProtocol: UInt8
        var low: Endpoint
        var high: Endpoint
    }

    static let defaultLimit = 2_000_000

    private(set) var flows: [FlowRecord] = []
    private var ids: [Key: Int32] = [:]
    private let limit: Int
    private(set) var limitReached = false

    init(limit: Int = FlowTable.defaultLimit) {
        self.limit = limit
    }

    struct Assignment {
        /// Flow index (-1 when the packet has no IP layer or the table is full).
        var id: Int32
        var fromInitiator: Bool

        static let none = Assignment(id: -1, fromInitiator: true)
    }

    mutating func assign(_ packet: DecodedPacket, frameNumber: Int, timestampNanos: Int64, length: Int,
                         protocolKind: PacketProtocol) -> Assignment {
        guard let sourceAddress = packet.source, let destinationAddress = packet.destination else { return .none }
        // Non-first fragments carry no ports; they are left out rather than attached to a wrong flow.
        if let fragment = packet.fragment, fragment.offset != 0 { return .none }
        let ported = packet.hasTransportHeader
        let source = Endpoint(address: sourceAddress, port: ported ? packet.sourcePort : 0)
        let destination = Endpoint(address: destinationAddress, port: ported ? packet.destinationPort : 0)
        let key = source < destination
            ? Key(ipProtocol: packet.ipProtocol, low: source, high: destination)
            : Key(ipProtocol: packet.ipProtocol, low: destination, high: source)
        let time = Timestamp(nanoseconds: timestampNanos)

        if let id = ids[key] {
            let index = Int(id)
            let fromInitiator = flows[index].initiator == source
            if fromInitiator {
                flows[index].packetsFromInitiator += 1
                flows[index].bytesFromInitiator += Int64(length)
            } else {
                flows[index].packetsFromResponder += 1
                flows[index].bytesFromResponder += Int64(length)
            }
            if time > flows[index].lastTime { flows[index].lastTime = time }
            if time < flows[index].firstTime { flows[index].firstTime = time }
            if Self.specificity(protocolKind) > Self.specificity(flows[index].application) {
                flows[index].application = protocolKind
            }
            return Assignment(id: id, fromInitiator: fromInitiator)
        }
        guard flows.count < limit else {
            limitReached = true
            return .none
        }
        let id = Int32(flows.count)
        flows.append(FlowRecord(id: flows.count, ipProtocol: packet.ipProtocol, initiator: source, responder: destination,
                                firstTime: time, lastTime: time, firstFrame: frameNumber, packetsFromInitiator: 1,
                                packetsFromResponder: 0, bytesFromInitiator: Int64(length), bytesFromResponder: 0,
                                application: protocolKind))
        ids[key] = id
        return Assignment(id: id, fromInitiator: true)
    }

    /// The flow between two endpoints over `ipProtocol`, in either direction.
    func flowIndex(ipProtocol: UInt8, _ a: Endpoint, _ b: Endpoint) -> Int32? {
        ids[a < b ? Key(ipProtocol: ipProtocol, low: a, high: b) : Key(ipProtocol: ipProtocol, low: b, high: a)]
    }

    /// Attaches the TCP analyzer's results to their flows.
    mutating func attach(_ analyzer: TCPAnalyzer) {
        for index in flows.indices where flows[index].ipProtocol == 6 {
            flows[index].tcp = analyzer.stats(for: Int32(index))
        }
    }

    /// Records a protocol classified after the packet was assigned (e.g. SIP found by TCP reassembly).
    mutating func classify(_ id: Int32, as protocolKind: PacketProtocol) {
        guard id >= 0, Int(id) < flows.count else { return }
        if Self.specificity(protocolKind) > Self.specificity(flows[Int(id)].application) {
            flows[Int(id)].application = protocolKind
        }
    }

    /// Ranks classifications so a flow keeps its most informative label.
    static func specificity(_ kind: PacketProtocol) -> Int {
        switch kind {
        case .sip, .sipSDP: return 5
        case .rtp, .rtcp: return 4
        case .dns, .dhcp, .ntp, .stun, .turn, .tls, .http, .dtls: return 3
        case .udp, .tcp, .sctp, .icmp, .icmpv6, .igmp: return 1
        default: return 0
        }
    }
}
