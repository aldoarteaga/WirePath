import Foundation

// Network-layer dissectors: ARP, IPv4, IPv6 (with extension headers), ICMP and ICMPv6.

struct ARPDissector: ProtocolDissector {
    let name = "arp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .etherType(0x0806)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let n = range.lowerBound
        guard range.count >= 28, frame.u8(n + 4) == 6, frame.u8(n + 5) == 4 else {
            tree.layer(name, "Address Resolution Protocol", " Truncated or not Ethernet/IPv4", range: range)
            context.summary = "ARP"
            return .end
        }
        let op = frame.u16be(n + 6)
        let senderMAC = PacketDissector.mac(frame, n + 8), senderIP = PacketDissector.ipv4(frame, n + 14)
        let targetMAC = PacketDissector.mac(frame, n + 18), targetIP = PacketDissector.ipv4(frame, n + 24)
        let gratuitous = senderIP == targetIP
        let kind = op == 1 ? "request" : op == 2 ? "reply" : "opcode \(op)"
        tree.layer(name, "Address Resolution Protocol", " (\(gratuitous ? "gratuitous " : "")\(kind))", range: n..<(n + 28))
        tree.field("Hardware Type", frame.u16be(n) == 1 ? "Ethernet (1)" : "\(frame.u16be(n))", n..<(n + 2))
        tree.field("Protocol Type", String(format: "%@ (0x%04x)", PacketDissector.etherTypeName(frame.u16be(n + 2)), frame.u16be(n + 2)),
                   (n + 2)..<(n + 4))
        tree.field("Opcode", op == 1 ? "request (1)" : op == 2 ? "reply (2)" : "\(op)", (n + 6)..<(n + 8))
        if gratuitous { tree.field("Gratuitous", "Yes") }
        tree.field("Sender MAC", senderMAC, (n + 8)..<(n + 14))
        tree.field("Sender IP", senderIP, (n + 14)..<(n + 18))
        tree.field("Target MAC", targetMAC, (n + 18)..<(n + 24))
        tree.field("Target IP", targetIP, (n + 24)..<(n + 28))
        context.summary = op == 1 ? "ARP Who has \(targetIP)? Tell \(senderIP)" : "ARP \(senderIP) is at \(senderMAC)"
        return .end
    }
}

struct IPv4Dissector: ProtocolDissector {
    let name = "ip"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .etherType(0x0800)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let n = range.lowerBound
        guard range.count >= 20, frame[n] >> 4 == 4 else {
            tree.layer(name, "Internet Protocol Version 4", " Truncated or invalid header", range: range)
            return .end
        }
        let ihl = Int(frame[n] & 0x0F) * 4
        let totalLength = Int(frame.u16be(n + 2))
        let source = PacketDissector.ipv4(frame, n + 12), destination = PacketDissector.ipv4(frame, n + 16)
        let proto = frame[n + 9]
        let headerEnd = min(range.upperBound, n + max(20, ihl))
        tree.layer(name, "Internet Protocol Version 4", " \(source) → \(destination)", range: n..<headerEnd)
        tree.field("Version · Header Length", "4 · \(ihl) bytes", n..<(n + 1))
        let dscp = Int(frame[n + 1] >> 2), ecn = frame[n + 1] & 0x03
        tree.field("DSCP · ECN", "\(PacketDissector.dscpName(dscp)) (\(dscp)) · \(ecn == 0 ? "Not-ECT" : ecn == 3 ? "CE" : "ECT(\(2 - ecn))")",
                   (n + 1)..<(n + 2))
        tree.field("Total Length", "\(totalLength)", (n + 2)..<(n + 4))
        tree.field("Identification", String(format: "0x%04x (%d)", frame.u16be(n + 4), frame.u16be(n + 4)), (n + 4)..<(n + 6))
        let flags = frame.u16be(n + 6)
        var flagText: [String] = []
        if flags & 0x4000 != 0 { flagText.append("Don't fragment") }
        if flags & 0x2000 != 0 { flagText.append("More fragments") }
        let fragmentOffset = Int(flags & 0x1FFF) * 8
        tree.field("Flags · Offset", "\(flagText.isEmpty ? "None" : flagText.joined(separator: ", ")) · \(fragmentOffset)", (n + 6)..<(n + 8))
        tree.field("TTL", "\(frame[n + 8])", (n + 8)..<(n + 9))
        tree.field("Protocol", "\(PacketDissector.ipProtocolName(proto)) (\(proto))", (n + 9)..<(n + 10))
        tree.field("Header Checksum", Self.checksumStatus(frame, n, ihl, range: range), (n + 10)..<(n + 12))
        tree.field("Source", source, (n + 12)..<(n + 16))
        tree.field("Destination", destination, (n + 16)..<(n + 20))
        if ihl > 20, n + ihl <= range.upperBound {
            tree.field("Options", "\(ihl - 20) bytes", (n + 20)..<(n + ihl))
        }
        guard ihl >= 20, n + ihl <= range.upperBound else { return .end }

        context.source = .v4(frame.u32be(n + 12))
        context.destination = .v4(frame.u32be(n + 16))
        context.ipProtocol = proto
        context.summary = "IPv4"
        // The datagram ends at its total length (Ethernet padding excluded); TSO captures carry 0.
        let end = totalLength >= ihl ? min(range.upperBound, n + totalLength) : range.upperBound
        if fragmentOffset > 0 {
            context.isFragment = true
            tree.layer("ip.fragment", "IP Fragment", " offset \(fragmentOffset), \(flags & 0x2000 != 0 ? "more fragments follow" : "last fragment")",
                       range: (n + ihl)..<end)
            tree.field("Data", "\(end - n - ihl) bytes", (n + ihl)..<end)
            context.summary = "IPv4 fragment"
            return .end
        }
        return DissectionStep(next: .ipProtocol(proto), payload: (n + ihl)..<end)
    }

    static func checksumStatus(_ frame: UnsafeRawBufferPointer, _ n: Int, _ ihl: Int, range: Range<Int>) -> String {
        let stored = frame.u16be(n + 10)
        guard ihl >= 20, n + ihl <= range.upperBound else { return String(format: "0x%04x", stored) }
        var sum: UInt32 = 0
        var i = n
        while i + 1 < n + ihl {
            if i != n + 10 { sum &+= UInt32(frame.u16be(i)) }
            i += 2
        }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        let expected = ~UInt16(sum)
        return stored == expected ? String(format: "0x%04x (correct)", stored)
            : String(format: "0x%04x (incorrect, should be 0x%04x)", stored, expected)
    }
}

struct IPv6Dissector: ProtocolDissector {
    let name = "ipv6"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .etherType(0x86DD)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let n = range.lowerBound
        guard range.count >= 40, frame[n] >> 4 == 6 else {
            tree.layer(name, "Internet Protocol Version 6", " Truncated or invalid header", range: range)
            return .end
        }
        let word = frame.u32be(n)
        let payloadLength = Int(frame.u16be(n + 4))
        let source = PacketDissector.ipv6(frame, n + 8), destination = PacketDissector.ipv6(frame, n + 24)
        tree.layer(name, "Internet Protocol Version 6", " \(source) → \(destination)", range: n..<(n + 40))
        tree.field("Traffic Class", String(format: "0x%02x (DSCP %@)", (word >> 20) & 0xFF,
                                           PacketDissector.dscpName(Int((word >> 22) & 0x3F))), n..<(n + 4))
        tree.field("Flow Label", String(format: "0x%05x", word & 0xFFFFF), n..<(n + 4))
        tree.field("Payload Length", "\(payloadLength)", (n + 4)..<(n + 6))
        var next = frame[n + 6]
        tree.field("Next Header", "\(PacketDissector.ipProtocolName(next)) (\(next))", (n + 6)..<(n + 7))
        tree.field("Hop Limit", "\(frame[n + 7])", (n + 7)..<(n + 8))
        tree.field("Source", source, (n + 8)..<(n + 24))
        tree.field("Destination", destination, (n + 24)..<(n + 40))
        context.source = IPAddress(bytes: frame.slice(n + 8, 16))
        context.destination = IPAddress(bytes: frame.slice(n + 24, 16))
        context.summary = "IPv6"

        let end = payloadLength > 0 ? min(range.upperBound, n + 40 + payloadLength) : range.upperBound
        var p = n + 40
        var hops = 0
        while hops < 8, [0, 43, 44, 51, 60].contains(next), p + 8 <= end {
            hops += 1
            let length: Int
            switch next {
            case 44:
                length = 8
                let fragment = frame.u16be(p + 2)
                let offset = Int(fragment & 0xFFF8)
                tree.field("Fragment Header", "offset \(offset), id 0x\(String(format: "%08x", frame.u32be(p + 4)))\(fragment & 1 != 0 ? ", more fragments" : "")",
                           p..<(p + 8), level: 1)
                if offset > 0 {
                    context.isFragment = true
                    context.ipProtocol = frame[p]
                    tree.layer("ip.fragment", "IP Fragment", " offset \(offset)", range: (p + 8)..<end)
                    tree.field("Data", "\(max(0, end - p - 8)) bytes", (p + 8)..<max(p + 8, end))
                    context.summary = "IPv6 fragment"
                    return .end
                }
            case 51:
                length = (Int(frame[p + 1]) + 2) * 4
                tree.field("Authentication Header", "\(length) bytes", p..<min(end, p + length), level: 1)
            default:
                length = (Int(frame[p + 1]) + 1) * 8
                tree.field(PacketDissector.ipProtocolName(next), "\(length) bytes", p..<min(end, p + length), level: 1)
            }
            next = frame[p]
            p += length
        }
        context.ipProtocol = next
        guard p <= end else { return .end }
        return DissectionStep(next: .ipProtocol(next), payload: p..<end)
    }
}

struct ICMPDissector: ProtocolDissector {
    let name = "icmp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .ipProtocol(1)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let p = range.lowerBound
        guard range.count >= 4 else {
            tree.layer(name, "Internet Control Message Protocol", " Truncated", range: range)
            context.summary = "ICMP"
            return .end
        }
        let type = frame[p], code = frame[p + 1]
        let description = Self.describe(type: type, code: code)
        tree.layer(name, "Internet Control Message Protocol", " \(description)", range: range)
        tree.field("Type", "\(type) (\(Self.typeName(type)))", p..<(p + 1))
        tree.field("Code", "\(code)", (p + 1)..<(p + 2))
        tree.field("Checksum", String(format: "0x%04x", frame.u16be(p + 2)), (p + 2)..<(p + 4))
        var summary = "ICMP \(description)"
        if (type == 0 || type == 8 || type == 13 || type == 14), range.count >= 8 {
            let identifier = frame.u16be(p + 4), sequence = frame.u16be(p + 6)
            tree.field("Identifier", String(format: "0x%04x (%d)", identifier, identifier), (p + 4)..<(p + 6))
            tree.field("Sequence Number", "\(sequence)", (p + 6)..<(p + 8))
            if range.count > 8 { tree.field("Data", "\(range.count - 8) bytes", (p + 8)..<range.upperBound) }
            summary += " id=0x\(String(format: "%04x", identifier)), seq=\(sequence)"
        } else if [3, 4, 5, 11, 12].contains(type), range.count >= 28 {
            // Errors quote the offending datagram's IP header and first 8 bytes.
            let quoted = p + 8
            if frame[quoted] >> 4 == 4 {
                let ihl = Int(frame[quoted] & 0x0F) * 4
                let proto = frame[quoted + 9]
                var text = "\(PacketDissector.ipv4(frame, quoted + 12)) → \(PacketDissector.ipv4(frame, quoted + 16)) \(PacketDissector.ipProtocolName(proto))"
                if (proto == 6 || proto == 17), quoted + ihl + 4 <= range.upperBound {
                    text += " \(frame.u16be(quoted + ihl)) → \(frame.u16be(quoted + ihl + 2))"
                }
                if type == 3, code == 4 { tree.field("Next-Hop MTU", "\(frame.u16be(p + 6))", (p + 6)..<(p + 8)) }
                tree.field("Original Datagram", text, quoted..<range.upperBound)
                summary += " (\(text))"
            }
        }
        context.summary = summary
        return .end
    }

    static func typeName(_ type: UInt8) -> String {
        switch type {
        case 0: return "Echo (ping) reply"
        case 3: return "Destination unreachable"
        case 4: return "Source quench"
        case 5: return "Redirect"
        case 8: return "Echo (ping) request"
        case 9: return "Router advertisement"
        case 10: return "Router solicitation"
        case 11: return "Time exceeded"
        case 12: return "Parameter problem"
        case 13: return "Timestamp request"
        case 14: return "Timestamp reply"
        default: return "Type \(type)"
        }
    }

    static func describe(type: UInt8, code: UInt8) -> String {
        switch (type, code) {
        case (3, 0): return "Destination unreachable (Network unreachable)"
        case (3, 1): return "Destination unreachable (Host unreachable)"
        case (3, 2): return "Destination unreachable (Protocol unreachable)"
        case (3, 3): return "Destination unreachable (Port unreachable)"
        case (3, 4): return "Destination unreachable (Fragmentation needed)"
        case (3, 13): return "Destination unreachable (Communication administratively prohibited)"
        case (11, 0): return "Time exceeded (TTL exceeded in transit)"
        case (11, 1): return "Time exceeded (Fragment reassembly time exceeded)"
        default: return typeName(type)
        }
    }
}

struct ICMPv6Dissector: ProtocolDissector {
    let name = "icmpv6"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .ipProtocol(58)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let p = range.lowerBound
        guard range.count >= 4 else {
            tree.layer(name, "Internet Control Message Protocol v6", " Truncated", range: range)
            context.summary = "ICMPv6"
            return .end
        }
        let type = frame[p], code = frame[p + 1]
        tree.layer(name, "Internet Control Message Protocol v6", " \(Self.typeName(type))", range: range)
        tree.field("Type", "\(type) (\(Self.typeName(type)))", p..<(p + 1))
        tree.field("Code", "\(code)", (p + 1)..<(p + 2))
        tree.field("Checksum", String(format: "0x%04x", frame.u16be(p + 2)), (p + 2)..<(p + 4))
        var summary = "ICMPv6 \(Self.typeName(type))"
        switch type {
        case 128, 129:
            guard range.count >= 8 else { break }
            tree.field("Identifier", String(format: "0x%04x", frame.u16be(p + 4)), (p + 4)..<(p + 6))
            tree.field("Sequence Number", "\(frame.u16be(p + 6))", (p + 6)..<(p + 8))
            summary += " id=0x\(String(format: "%04x", frame.u16be(p + 4))), seq=\(frame.u16be(p + 6))"
        case 135, 136:
            guard range.count >= 24 else { break }
            let target = PacketDissector.ipv6(frame, p + 8)
            if type == 136 {
                let flags = frame[p + 4]
                tree.field("Flags", [(0x80, "Router"), (0x40, "Solicited"), (0x20, "Override")]
                    .filter { flags & UInt8($0.0) != 0 }.map(\.1).joined(separator: ", "), (p + 4)..<(p + 5))
            }
            tree.field("Target Address", target, (p + 8)..<(p + 24))
            summary += " for \(target)"
            Self.options(frame, from: p + 24, to: range.upperBound, tree: &tree)
        case 133:
            guard range.count >= 8 else { break }
            Self.options(frame, from: p + 8, to: range.upperBound, tree: &tree)
        case 134:
            guard range.count >= 16 else { break }
            tree.field("Cur Hop Limit", "\(frame[p + 4])", (p + 4)..<(p + 5))
            tree.field("Router Lifetime", "\(frame.u16be(p + 6)) s", (p + 6)..<(p + 8))
            Self.options(frame, from: p + 16, to: range.upperBound, tree: &tree)
        case 2:
            guard range.count >= 8 else { break }
            tree.field("MTU", "\(frame.u32be(p + 4))", (p + 4)..<(p + 8))
        default:
            break
        }
        context.summary = summary
        return .end
    }

    /// Neighbor Discovery options (RFC 4861 §4.6).
    static func options(_ frame: UnsafeRawBufferPointer, from start: Int, to end: Int, tree: inout ProtocolTreeBuilder) {
        var p = start
        var count = 0
        while p + 2 <= end, count < 32 {
            count += 1
            let type = frame[p], length = Int(frame[p + 1]) * 8
            guard length > 0, p + length <= end else { return }
            switch type {
            case 1, 2:
                tree.field(type == 1 ? "Source Link-Layer Address" : "Target Link-Layer Address", PacketDissector.mac(frame, p + 2),
                           p..<(p + length), level: 1)
            case 3 where length >= 32:
                tree.field("Prefix", "\(PacketDissector.ipv6(frame, p + 16))/\(frame[p + 2])", p..<(p + length), level: 1)
            case 5 where length >= 8:
                tree.field("MTU", "\(frame.u32be(p + 4))", p..<(p + length), level: 1)
            default:
                tree.field("Option \(type)", "\(length) bytes", p..<(p + length), level: 1)
            }
            p += length
        }
    }

    static func typeName(_ type: UInt8) -> String {
        switch type {
        case 1: return "Destination Unreachable"
        case 2: return "Packet Too Big"
        case 3: return "Time Exceeded"
        case 4: return "Parameter Problem"
        case 128: return "Echo (ping) request"
        case 129: return "Echo (ping) reply"
        case 130: return "Multicast Listener Query"
        case 131: return "Multicast Listener Report"
        case 133: return "Router Solicitation"
        case 134: return "Router Advertisement"
        case 135: return "Neighbor Solicitation"
        case 136: return "Neighbor Advertisement"
        case 137: return "Redirect"
        case 143: return "Multicast Listener Report v2"
        default: return "Type \(type)"
        }
    }
}
