import Foundation

/// What follows the bytes a dissector consumed.
public enum NextLayer: Sendable, Equatable {
    case link(LinkType)
    case etherType(UInt16)
    case ipProtocol(UInt8)
    /// UDP or TCP payload: application dissectors decide from ports and content.
    case transportPayload(TransportKind)
    /// Nothing more to decode (or the rest is opaque data).
    case end
}

/// Facts learned by lower layers, available to the dissectors above them.
public struct DissectionContext: Sendable {
    public var frameNumber: Int
    public var timestampNanos: Int64
    public var captureStartNanos: Int64
    public var linkType: LinkType
    public var interfaceID: Int
    public var originalLength: Int
    /// Codec for an RTP payload type (from the stream's SDP when known).
    public var codecForPayloadType: @Sendable (UInt8) -> CodecDescriptor?

    public var source: IPAddress?
    public var destination: IPAddress?
    public var ipProtocol: UInt8 = 0
    public var sourcePort: UInt16 = 0
    public var destinationPort: UInt16 = 0
    /// Set when this frame is a non-first IP fragment (nothing above IP can be decoded from it).
    public var isFragment = false
    /// Short description of the most specific layer decoded so far.
    public var summary = "Frame"

    public init(frameNumber: Int, timestampNanos: Int64, captureStartNanos: Int64, linkType: LinkType, interfaceID: Int,
                originalLength: Int, codecForPayloadType: @escaping @Sendable (UInt8) -> CodecDescriptor?) {
        self.frameNumber = frameNumber
        self.timestampNanos = timestampNanos
        self.captureStartNanos = captureStartNanos
        self.linkType = linkType
        self.interfaceID = interfaceID
        self.originalLength = originalLength
        self.codecForPayloadType = codecForPayloadType
    }

    public func usesPort(_ port: UInt16) -> Bool { sourcePort == port || destinationPort == port }
    public func usesPort(in ports: Set<UInt16>) -> Bool { ports.contains(sourcePort) || ports.contains(destinationPort) }
}

/// The result of one dissector: where the next layer starts and what it is.
public struct DissectionStep: Sendable {
    public var next: NextLayer
    /// Absolute byte range (within the frame) of the next layer.
    public var payload: Range<Int>

    public static let end = DissectionStep(next: .end, payload: 0..<0)

    public init(next: NextLayer, payload: Range<Int>) {
        self.next = next
        self.payload = payload
    }
}

/// One protocol. Adding a protocol means adding a type that conforms and registering it.
///
/// Dissectors receive the whole frame and an absolute range: every read must stay inside `range` (the bounds-safe
/// byte helpers return 0 outside the buffer, but a dissector must not rely on that for its own fields).
public protocol ProtocolDissector: Sendable {
    /// Short identifier, also used by display filters ("eth", "vlan", "arp", "ip", "dns", "tls"…).
    var name: String { get }
    /// Whether this dissector decodes `layer` given the payload bytes and what lower layers found.
    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool
    /// Adds this protocol's layer and fields to `tree` and says what follows.
    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep
}

/// An ordered set of dissectors. The first dissector accepting a layer decodes it, so more specific
/// application protocols are listed before generic ones.
public struct DissectorRegistry: Sendable {
    public let dissectors: [any ProtocolDissector]

    public init(dissectors: [any ProtocolDissector]) {
        self.dissectors = dissectors
    }

    /// Every protocol WirePath decodes, link layer to application layer.
    public static let standard = DissectorRegistry(dissectors: [
        EthernetDissector(), VLANDissector(), MPLSDissector(), PPPoEDissector(), LinuxCookedDissector(),
        LoopbackDissector(), RawIPDissector(), LLDPDissector(),
        ARPDissector(), IPv4Dissector(), IPv6Dissector(), ICMPDissector(), ICMPv6Dissector(),
        UDPDissector(), TCPDissector(),
        // Application protocols: content-validated ones first, port-based ones after, RTP last (loosest heuristic).
        SIPDissector(), STUNDissector(), TURNChannelDataDissector(), DNSDissector(), DHCPDissector(), NTPDissector(),
        HTTPDissector(), TLSDissector(), DTLSDissector(), RTCPDissector(), RTPDissector(),
    ])

    public var protocolNames: [String] { dissectors.map(\.name) }

    public func dissector(named name: String) -> (any ProtocolDissector)? { dissectors.first { $0.name == name } }

    /// Walks `frame` from the link layer up.
    public func dissect(_ frame: UnsafeRawBufferPointer, context: DissectionContext) -> (tree: ProtocolTreeBuilder, context: DissectionContext) {
        var context = context
        var tree = ProtocolTreeBuilder()
        Self.describeFrame(frame, context: context, tree: &tree)
        var step = DissectionStep(next: .link(context.linkType), payload: 0..<frame.count)
        var hops = 0
        while step.next != .end, hops < 24 {
            hops += 1
            let payload = frame.slice(step.payload.lowerBound, step.payload.count)
            guard let dissector = dissectors.first(where: { $0.accepts(step.next, payload: payload, context: context) }) else {
                break
            }
            let next = dissector.dissect(frame, range: step.payload, context: &context, tree: &tree)
            if next.next == .end {
                // The protocol consumed everything it describes; any bytes left inside it are part of it.
                step = next
                break
            }
            // A dissector may only move forward inside the frame.
            guard next.payload.lowerBound >= step.payload.lowerBound, next.payload.upperBound <= frame.count else {
                step = .end
                break
            }
            step = next
        }
        if step.next != .end, !step.payload.isEmpty {
            tree.layer("data", "Data", " \(step.payload.count.formatted()) bytes", range: step.payload)
            tree.field("Data", "\(step.payload.count.formatted()) bytes", step.payload)
        }
        return (tree, context)
    }
}

extension DissectorRegistry {
    /// The "Frame" layer: capture metadata rather than a protocol.
    static func describeFrame(_ frame: UnsafeRawBufferPointer, context: DissectionContext, tree: inout ProtocolTreeBuilder) {
        let count = frame.count
        tree.layer("frame", "Frame \(context.frameNumber.formatted())",
                   " \(context.originalLength.formatted()) bytes on wire (\((context.originalLength * 8).formatted()) bits), \(count.formatted()) captured",
                   range: 0..<count)
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d, yyyy HH:mm:ss"
        let seconds = context.timestampNanos / 1_000_000_000
        let nanos = ((context.timestampNanos % 1_000_000_000) + 1_000_000_000) % 1_000_000_000
        let date = Date(timeIntervalSince1970: Double(context.timestampNanos < 0 && nanos > 0 ? seconds - 1 : seconds))
        tree.field("Arrival Time", formatter.string(from: date) + String(format: ".%09lld", nanos))
        tree.field("Relative Time", String(format: "%.6f s", PacketDissector.relativeSeconds(context)))
        tree.field("Frame Length", "\(context.originalLength.formatted()) bytes")
        tree.field("Capture Length", "\(count.formatted()) bytes")
        tree.field("Link Type", context.linkType.description)
        tree.field("Interface", "\(context.interfaceID)")
    }
}

/// Builds the protocol tree shown in the Packet Inspector, with byte ranges for the hex view.
public enum PacketDissector {
    public typealias Context = DissectionContext

    public static func dissect(_ bytes: UnsafeRawBufferPointer, context: Context,
                               registry: DissectorRegistry = .standard) -> DissectedPacket {
        let decoded = PacketDecoder.decode(bytes, linkType: context.linkType)
        let (tree, final) = registry.dissect(bytes, context: context)
        var layers = tree.layers
        if tree.truncatedTree, !layers.isEmpty {
            layers[layers.count - 1].fields.append(ProtocolField(id: Int.max - 1, name: "Note",
                                                                value: "Only the first \(ProtocolTreeBuilder.maxFields) fields are shown"))
        }
        return DissectedPacket(frameNumber: context.frameNumber, bytes: Data(bytes), layers: layers, summary: final.summary,
                               problem: decoded.problem)
    }

    // MARK: Shared formatting

    static func mac(_ bytes: UnsafeRawBufferPointer, _ offset: Int) -> String {
        guard offset >= 0, offset + 6 <= bytes.count else { return "" }
        return (0..<6).map { String(format: "%02x", bytes[offset + $0]) }.joined(separator: ":")
    }

    static func hex(_ bytes: UnsafeRawBufferPointer, _ offset: Int, _ length: Int, limit: Int = 32) -> String {
        let slice = bytes.slice(offset, min(length, limit))
        let text = slice.map { String(format: "%02x", $0) }.joined()
        return length > limit ? text + "…" : text
    }

    static func etherTypeName(_ type: UInt16) -> String {
        switch type {
        case 0x0800: return "IPv4"
        case 0x86DD: return "IPv6"
        case 0x0806: return "ARP"
        case 0x8100: return "802.1Q"
        case 0x88A8: return "802.1ad"
        case 0x8847, 0x8848: return "MPLS"
        case 0x8863: return "PPPoE Discovery"
        case 0x8864: return "PPPoE Session"
        case 0x88CC: return "LLDP"
        case 0x8035: return "RARP"
        case 0x88F7: return "PTP"
        default: return "Unknown"
        }
    }

    public static func ipProtocolName(_ value: UInt8) -> String {
        switch value {
        case 0: return "Hop-by-Hop Options"
        case 1: return "ICMP"
        case 2: return "IGMP"
        case 6: return "TCP"
        case 17: return "UDP"
        case 41: return "IPv6"
        case 43: return "Routing"
        case 44: return "Fragment"
        case 47: return "GRE"
        case 50: return "ESP"
        case 51: return "AH"
        case 58: return "ICMPv6"
        case 59: return "No Next Header"
        case 60: return "Destination Options"
        case 89: return "OSPF"
        case 103: return "PIM"
        case 112: return "VRRP"
        case 132: return "SCTP"
        default: return "Protocol"
        }
    }

    static func dscpName(_ dscp: Int) -> String {
        switch dscp {
        case 0: return "CS0"
        case 46: return "EF"
        case 44: return "VOICE-ADMIT"
        case 10, 12, 14, 18, 20, 22, 26, 28, 30, 34, 36, 38:
            return "AF\(dscp / 8)\((dscp % 8) / 2)"
        case 8, 16, 24, 32, 40, 48, 56: return "CS\(dscp / 8)"
        default: return "DSCP"
        }
    }

    static func tcpFlags(_ flags: UInt8) -> String {
        let names: [(UInt8, String)] = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"),
                                        (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
        let set = names.filter { flags & $0.0 != 0 }.map(\.1)
        return set.isEmpty ? "None" : set.joined(separator: ", ")
    }

    static func ipv4(_ bytes: UnsafeRawBufferPointer, _ offset: Int) -> String {
        guard offset >= 0, offset + 4 <= bytes.count else { return "" }
        return "\(bytes[offset]).\(bytes[offset + 1]).\(bytes[offset + 2]).\(bytes[offset + 3])"
    }

    static func ipv6(_ bytes: UnsafeRawBufferPointer, _ offset: Int) -> String {
        guard offset >= 0, offset + 16 <= bytes.count else { return "" }
        return IPAddress(bytes: bytes.slice(offset, 16))?.description ?? ""
    }

    /// Relative time of a frame in seconds (overflow-safe).
    static func relativeSeconds(_ context: DissectionContext) -> Double {
        Timestamp(nanoseconds: context.timestampNanos).seconds(since: Timestamp(nanoseconds: context.captureStartNanos))
    }
}
