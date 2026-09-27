import Foundation

/// Protocol classification of a packet, as shown in the Packet Inspector's Protocol column.
public enum PacketProtocol: UInt8, Codable, Sendable, CaseIterable {
    case unknown = 0
    case ethernet
    case arp
    case ipv4
    case ipv6
    case ipFragment
    case icmp
    case icmpv6
    case igmp
    case udp
    case tcp
    case sctp
    case dns
    case dhcp
    case ntp
    case stun
    case tls
    case sip
    case sipSDP
    case rtp
    case rtcp
    case http
    case turn
    case dtls

    public var displayName: String {
        switch self {
        case .unknown: return "Other"
        case .ethernet: return "Ethernet"
        case .arp: return "ARP"
        case .ipv4: return "IPv4"
        case .ipv6: return "IPv6"
        case .ipFragment: return "IPv4"
        case .icmp: return "ICMP"
        case .icmpv6: return "ICMPv6"
        case .igmp: return "IGMP"
        case .udp: return "UDP"
        case .tcp: return "TCP"
        case .sctp: return "SCTP"
        case .dns: return "DNS"
        case .dhcp: return "DHCP"
        case .ntp: return "NTP"
        case .stun: return "STUN"
        case .tls: return "TLS"
        case .sip: return "SIP"
        case .sipSDP: return "SIP/SDP"
        case .rtp: return "RTP"
        case .rtcp: return "RTCP"
        case .http: return "HTTP"
        case .turn: return "TURN"
        case .dtls: return "DTLS"
        }
    }

    public var isSIP: Bool { self == .sip || self == .sipSDP }
}

/// Per-packet flags stored in the index.
public struct PacketFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// RTP: packets were missing right before this one.
    public static let sequenceGap = PacketFlags(rawValue: 1 << 0)
    /// RTP: sequence number already received.
    public static let duplicate = PacketFlags(rawValue: 1 << 1)
    /// RTP: arrived after a higher sequence number.
    public static let outOfOrder = PacketFlags(rawValue: 1 << 2)
    /// SIP: response with status >= 400.
    public static let sipError = PacketFlags(rawValue: 1 << 3)
    /// SIP message carries an SDP body.
    public static let hasSDP = PacketFlags(rawValue: 1 << 4)
    /// RTP: first packet of a new SSRC replacing another on the same 5-tuple.
    public static let ssrcChange = PacketFlags(rawValue: 1 << 5)
    /// Captured length shorter than needed to decode the headers.
    public static let malformed = PacketFlags(rawValue: 1 << 6)
    /// SIP: retransmitted request or response.
    public static let retransmission = PacketFlags(rawValue: 1 << 7)

    /// Packets the "Issues" scope shows.
    public static let issues: PacketFlags = [.sequenceGap, .duplicate, .outOfOrder, .sipError, .ssrcChange, .malformed, .retransmission]
}

/// Compact numeric encoding of SIP methods for the packet index (responses store the status code).
public enum SIPMethodCode {
    public static let methods = ["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "REFER", "NOTIFY",
                                 "INFO", "UPDATE", "PRACK", "SUBSCRIBE", "MESSAGE", "PUBLISH"]
    public static let other: UInt16 = 99

    public static func code(for method: String) -> UInt16 {
        if let index = methods.firstIndex(of: method.uppercased()) { return UInt16(index + 1) }
        return other
    }

    public static func method(for code: UInt16) -> String? {
        guard code >= 1 && code <= UInt16(methods.count) else { return code == other ? "OTHER" : nil }
        return methods[Int(code) - 1]
    }

    public static func isResponse(_ code: UInt16) -> Bool { code >= 100 && code < 700 }
}

/// One fixed-size (64 byte) entry per packet. Written sequentially during analysis and
/// memory-mapped by the Packet Inspector so millions of packets never have to be decoded up front.
///
/// The record is the packet's metadata; its bytes stay in the capture file (`PacketStore.bytes(at:)`) and its
/// protocol tree is decoded on demand (`PacketStore.dissect(at:)`).
public struct PacketIndexRecord: Sendable, Equatable {
    /// Offset of the packet bytes inside the capture file.
    public var fileOffset: UInt64
    public var timestampNanos: Int64
    public var capturedLength: UInt32
    public var originalLength: UInt32
    /// Index into the address table (0 = no IP layer).
    public var sourceAddress: UInt32
    public var destinationAddress: UInt32
    public var sourcePort: UInt16
    public var destinationPort: UInt16
    /// Call this packet belongs to (-1 = none).
    public var callIndex: Int32
    /// RTP stream this packet belongs to (-1 = none).
    public var streamIndex: Int32
    /// SIP status code, or SIPMethodCode for requests (0 = not SIP).
    public var sipCode: UInt16
    public var linkType: UInt16
    public var protocolRaw: UInt8
    public var flagsRaw: UInt8
    public var interfaceID: UInt16
    /// SIP: message index. RTP: packets lost right before this one when `.sequenceGap` is set.
    public var aux: UInt32
    /// Flow (bidirectional 5-tuple) this packet belongs to (-1 = none), see `FlowRecord`.
    public var flowIndex: Int32
    /// Transport analysis flags (`PacketAnalysisFlags`).
    public var analysisFlagsRaw: UInt16
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP…; 0 = no IP layer).
    public var ipProtocolRaw: UInt8 = 0
    /// TCP header flags (SYN 0x02, ACK 0x10, FIN 0x01, RST 0x04…); 0 for other protocols.
    public var tcpFlags: UInt8 = 0

    public init(fileOffset: UInt64 = 0, timestampNanos: Int64 = 0, capturedLength: UInt32 = 0,
                originalLength: UInt32 = 0, sourceAddress: UInt32 = 0, destinationAddress: UInt32 = 0,
                sourcePort: UInt16 = 0, destinationPort: UInt16 = 0, callIndex: Int32 = -1,
                streamIndex: Int32 = -1, sipCode: UInt16 = 0, linkType: UInt16 = 0,
                protocolKind: PacketProtocol = .unknown, flags: PacketFlags = [], interfaceID: UInt16 = 0,
                aux: UInt32 = 0, flowIndex: Int32 = -1, analysisFlags: PacketAnalysisFlags = []) {
        self.fileOffset = fileOffset
        self.timestampNanos = timestampNanos
        self.capturedLength = capturedLength
        self.originalLength = originalLength
        self.sourceAddress = sourceAddress
        self.destinationAddress = destinationAddress
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.callIndex = callIndex
        self.streamIndex = streamIndex
        self.sipCode = sipCode
        self.linkType = linkType
        self.protocolRaw = protocolKind.rawValue
        self.flagsRaw = flags.rawValue
        self.interfaceID = interfaceID
        self.aux = aux
        self.flowIndex = flowIndex
        self.analysisFlagsRaw = analysisFlags.rawValue
    }

    public var protocolKind: PacketProtocol {
        get { PacketProtocol(rawValue: protocolRaw) ?? .unknown }
        set { protocolRaw = newValue.rawValue }
    }

    public var flags: PacketFlags {
        get { PacketFlags(rawValue: flagsRaw) }
        set { flagsRaw = newValue.rawValue }
    }

    public var analysisFlags: PacketAnalysisFlags {
        get { PacketAnalysisFlags(rawValue: analysisFlagsRaw) }
        set { analysisFlagsRaw = newValue.rawValue }
    }

    public var timestamp: Timestamp { Timestamp(nanoseconds: timestampNanos) }
}

