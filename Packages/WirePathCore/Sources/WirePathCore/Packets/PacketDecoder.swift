import Foundation

public enum NetworkKind: UInt8, Sendable {
    case none, ipv4, ipv6, arp, other
}

public struct IPFragment: Sendable, Hashable {
    public var identification: UInt32
    /// Offset of this fragment's data in the original datagram, in bytes.
    public var offset: Int
    public var moreFragments: Bool
}

/// Why a frame could not be decoded completely. The rest of the capture is unaffected.
public enum DecodeProblem: String, Sendable, Codable {
    case linkHeader = "The frame is shorter than its link-layer header"
    case ipv4Header = "Truncated or invalid IPv4 header"
    case ipv4Length = "The IPv4 total length exceeds the captured data"
    case ipv6Header = "Truncated or invalid IPv6 header"
    case ipv6Length = "The IPv6 payload length exceeds the captured data"
    case udpHeader = "Truncated UDP header"
    case tcpHeader = "Truncated or invalid TCP header"

    public var message: String { rawValue }
}

/// Header fields extracted on the hot path. Offsets are relative to the start of the frame.
public struct DecodedPacket: Sendable {
    public var etherType: UInt16 = 0
    public var network: NetworkKind = .none
    public var networkOffset = 0
    public var source: IPAddress?
    public var destination: IPAddress?
    /// Upper-layer protocol number (after IPv6 extension headers).
    public var ipProtocol: UInt8 = 0
    public var ttl: UInt8 = 0
    /// End of the IP datagram inside the frame (excludes Ethernet padding).
    public var networkEnd = 0
    public var fragment: IPFragment?
    public var transportOffset = 0
    public var sourcePort: UInt16 = 0
    public var destinationPort: UInt16 = 0
    public var tcpSequence: UInt32 = 0
    public var tcpAcknowledgment: UInt32 = 0
    public var tcpFlags: UInt8 = 0
    public var tcpWindow: UInt16 = 0
    public var payloadOffset = 0
    public var payloadLength = 0
    /// First problem met while decoding (nil when every header was complete).
    public var problem: DecodeProblem?

    public var truncated: Bool { problem != nil }

    public init() {}

    public var transport: TransportKind {
        switch ipProtocol {
        case 17: return .udp
        case 6: return .tcp
        case 132: return .sctp
        default: return .other
        }
    }

    public var hasTransportHeader: Bool {
        (ipProtocol == 17 || ipProtocol == 6) && transportOffset > 0 && (fragment?.offset ?? 0) == 0
    }

    public var sourceEndpoint: Endpoint? {
        guard let source, hasTransportHeader else { return nil }
        return Endpoint(address: source, port: sourcePort)
    }

    public var destinationEndpoint: Endpoint? {
        guard let destination, hasTransportHeader else { return nil }
        return Endpoint(address: destination, port: destinationPort)
    }

    /// True for non-first fragments, or first fragments of a datagram that continues in other packets.
    public var isFragmented: Bool { fragment != nil }
}

public enum PacketDecoder {
    /// Decodes link, network and transport headers. Never reads outside `bytes`.
    public static func decode(_ bytes: UnsafeRawBufferPointer, linkType: LinkType) -> DecodedPacket {
        var packet = DecodedPacket()
        let count = bytes.count
        var offset = 0
        var etherType: UInt16 = 0

        switch linkType {
        case .ethernet:
            guard count >= 14 else { packet.problem = .linkHeader; return packet }
            etherType = bytes.u16be(12)
            offset = 14
            (etherType, offset) = skipTagsAndEncapsulation(bytes, etherType: etherType, offset: offset)
        case .linuxSLL:
            guard count >= 16 else { packet.problem = .linkHeader; return packet }
            etherType = bytes.u16be(14)
            offset = 16
            (etherType, offset) = skipTagsAndEncapsulation(bytes, etherType: etherType, offset: offset)
        case .linuxSLL2:
            guard count >= 20 else { packet.problem = .linkHeader; return packet }
            etherType = bytes.u16be(0)
            offset = 20
            (etherType, offset) = skipTagsAndEncapsulation(bytes, etherType: etherType, offset: offset)
        case .null, .loop:
            guard count >= 4 else { packet.problem = .linkHeader; return packet }
            var family = bytes.u32le(0)
            if family > 0xFFFF { family = bytes.u32be(0) }
            etherType = family == 2 ? 0x0800 : ([24, 28, 30].contains(family) ? 0x86DD : 0)
            offset = 4
        case .raw, .rawAlt, .rawAlt2, .ipv4, .ipv6:
            guard count >= 1 else { packet.problem = .linkHeader; return packet }
            etherType = bytes[0] >> 4 == 6 ? 0x86DD : 0x0800
        default:
            return packet
        }

        packet.etherType = etherType
        packet.networkOffset = offset
        switch etherType {
        case 0x0800: decodeIPv4(bytes, at: offset, into: &packet)
        case 0x86DD: decodeIPv6(bytes, at: offset, into: &packet)
        case 0x0806: packet.network = .arp
        default: packet.network = .other
        }
        return packet
    }

    /// Skips 802.1Q/802.1ad tags, MPLS labels and PPPoE session headers.
    static func skipTagsAndEncapsulation(_ bytes: UnsafeRawBufferPointer, etherType: UInt16, offset: Int) -> (UInt16, Int) {
        var type = etherType
        var p = offset
        var guardCount = 0
        while guardCount < 8 {
            guardCount += 1
            switch type {
            case 0x8100, 0x88A8, 0x9100:
                guard p + 4 <= bytes.count else { return (type, p) }
                type = bytes.u16be(p + 2)
                p += 4
            case 0x8847, 0x8848:
                // MPLS: walk labels to the bottom of stack, then guess the payload by IP version.
                while p + 4 <= bytes.count {
                    let bottom = bytes[p + 2] & 0x01 != 0
                    p += 4
                    if bottom { break }
                }
                guard p < bytes.count else { return (type, p) }
                let version = bytes[p] >> 4
                return (version == 6 ? 0x86DD : version == 4 ? 0x0800 : 0, p)
            case 0x8864:
                guard p + 8 <= bytes.count else { return (type, p) }
                let ppp = bytes.u16be(p + 6)
                p += 8
                return (ppp == 0x0021 ? 0x0800 : ppp == 0x0057 ? 0x86DD : 0, p)
            default:
                return (type, p)
            }
        }
        return (type, p)
    }

    static func decodeIPv4(_ bytes: UnsafeRawBufferPointer, at offset: Int, into packet: inout DecodedPacket) {
        packet.network = .ipv4
        guard offset + 20 <= bytes.count, bytes[offset] >> 4 == 4 else { packet.problem = .ipv4Header; return }
        let ihl = Int(bytes[offset] & 0x0F) * 4
        guard ihl >= 20, offset + ihl <= bytes.count else { packet.problem = .ipv4Header; return }
        let totalLength = Int(bytes.u16be(offset + 2))
        let identification = UInt32(bytes.u16be(offset + 4))
        let flagsFragment = bytes.u16be(offset + 6)
        packet.ttl = bytes[offset + 8]
        packet.ipProtocol = bytes[offset + 9]
        packet.source = .v4(bytes.u32be(offset + 12))
        packet.destination = .v4(bytes.u32be(offset + 16))
        // totalLength == 0 happens with TSO captures; fall back to the frame end.
        let end = totalLength >= ihl ? min(bytes.count, offset + totalLength) : bytes.count
        if totalLength > 0 && offset + totalLength > bytes.count { packet.problem = .ipv4Length }
        packet.networkEnd = end
        let moreFragments = flagsFragment & 0x2000 != 0
        let fragmentOffset = Int(flagsFragment & 0x1FFF) * 8
        if moreFragments || fragmentOffset > 0 {
            packet.fragment = IPFragment(identification: identification, offset: fragmentOffset, moreFragments: moreFragments)
        }
        let transport = offset + ihl
        packet.payloadOffset = transport
        packet.payloadLength = max(0, end - transport)
        if fragmentOffset == 0 {
            decodeTransport(bytes, at: transport, end: end, into: &packet)
        }
    }

    static func decodeIPv6(_ bytes: UnsafeRawBufferPointer, at offset: Int, into packet: inout DecodedPacket) {
        packet.network = .ipv6
        guard offset + 40 <= bytes.count, bytes[offset] >> 4 == 6 else { packet.problem = .ipv6Header; return }
        let payloadLength = Int(bytes.u16be(offset + 4))
        var next = bytes[offset + 6]
        packet.ttl = bytes[offset + 7]
        packet.source = IPAddress(bytes: UnsafeRawBufferPointer(rebasing: bytes[(offset + 8)..<(offset + 24)]))
        packet.destination = IPAddress(bytes: UnsafeRawBufferPointer(rebasing: bytes[(offset + 24)..<(offset + 40)]))
        let end = payloadLength > 0 ? min(bytes.count, offset + 40 + payloadLength) : bytes.count
        if offset + 40 + payloadLength > bytes.count { packet.problem = .ipv6Length }
        packet.networkEnd = end
        var p = offset + 40
        var hops = 0
        while hops < 8 {
            hops += 1
            switch next {
            case 0, 43, 60:
                guard p + 8 <= end else { packet.ipProtocol = next; return }
                let length = (Int(bytes[p + 1]) + 1) * 8
                next = bytes[p]
                p += length
            case 51:
                guard p + 8 <= end else { packet.ipProtocol = next; return }
                let length = (Int(bytes[p + 1]) + 2) * 4
                next = bytes[p]
                p += length
            case 44:
                guard p + 8 <= end else { packet.ipProtocol = next; return }
                let fragmentField = bytes.u16be(p + 2)
                packet.fragment = IPFragment(identification: bytes.u32be(p + 4),
                                             offset: Int(fragmentField & 0xFFF8),
                                             moreFragments: fragmentField & 0x1 != 0)
                next = bytes[p]
                p += 8
            default:
                hops = 8
            }
        }
        packet.ipProtocol = next
        packet.payloadOffset = min(p, end)
        packet.payloadLength = max(0, end - p)
        if (packet.fragment?.offset ?? 0) == 0 {
            decodeTransport(bytes, at: p, end: end, into: &packet)
        }
    }

    static func decodeTransport(_ bytes: UnsafeRawBufferPointer, at offset: Int, end: Int, into packet: inout DecodedPacket) {
        switch packet.ipProtocol {
        case 17:
            guard offset + 8 <= end else { packet.problem = packet.problem ?? .udpHeader; return }
            packet.transportOffset = offset
            packet.sourcePort = bytes.u16be(offset)
            packet.destinationPort = bytes.u16be(offset + 2)
            let udpLength = Int(bytes.u16be(offset + 4))
            packet.payloadOffset = offset + 8
            let available = end - packet.payloadOffset
            // A fragmented datagram's UDP length covers every fragment; keep what is here.
            packet.payloadLength = udpLength >= 8 && packet.fragment == nil ? min(udpLength - 8, available) : available
        case 6:
            guard offset + 20 <= end else { packet.problem = packet.problem ?? .tcpHeader; return }
            let dataOffset = Int(bytes[offset + 12] >> 4) * 4
            guard dataOffset >= 20, offset + dataOffset <= end else { packet.problem = packet.problem ?? .tcpHeader; return }
            packet.transportOffset = offset
            packet.sourcePort = bytes.u16be(offset)
            packet.destinationPort = bytes.u16be(offset + 2)
            packet.tcpSequence = bytes.u32be(offset + 4)
            packet.tcpAcknowledgment = bytes.u32be(offset + 8)
            packet.tcpFlags = bytes[offset + 13]
            packet.tcpWindow = bytes.u16be(offset + 14)
            packet.payloadOffset = offset + dataOffset
            packet.payloadLength = end - packet.payloadOffset
        default:
            packet.payloadOffset = offset
            packet.payloadLength = max(0, end - offset)
        }
    }
}
