import Foundation

// Link-layer dissectors: Ethernet II / 802.3, 802.1Q/802.1ad tags, MPLS, PPPoE, Linux cooked capture,
// BSD/OpenBSD loopback, raw IP and LLDP.

struct EthernetDissector: ProtocolDissector {
    let name = "eth"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .link(.ethernet)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        guard range.count >= 14 else {
            tree.layer(name, "Ethernet II", " Truncated header", range: range)
            return .end
        }
        let type = frame.u16be(b + 12)
        let destination = PacketDissector.mac(frame, b), source = PacketDissector.mac(frame, b + 6)
        if type <= 1500 {
            // IEEE 802.3: the field is a length, followed by an LLC header.
            tree.layer(name, "IEEE 802.3 Ethernet", " Src \(source), Dst \(destination)", range: b..<(b + 14))
            tree.field("Destination", destination, b..<(b + 6))
            tree.field("Source", source, (b + 6)..<(b + 12))
            tree.field("Length", "\(type)", (b + 12)..<(b + 14))
            if range.count >= 17 {
                tree.layer("llc", "Logical-Link Control", " DSAP 0x\(String(format: "%02x", frame[b + 14])) SSAP 0x\(String(format: "%02x", frame[b + 15]))",
                           range: (b + 14)..<(b + 17))
                tree.field("DSAP", String(format: "0x%02x", frame[b + 14]), (b + 14)..<(b + 15))
                tree.field("SSAP", String(format: "0x%02x", frame[b + 15]), (b + 15)..<(b + 16))
                tree.field("Control", String(format: "0x%02x", frame[b + 16]), (b + 16)..<(b + 17))
            }
            context.summary = "LLC"
            return DissectionStep(next: .end, payload: min(range.upperBound, b + 17)..<range.upperBound)
        }
        tree.layer(name, "Ethernet II", " Src \(source), Dst \(destination)", range: b..<(b + 14))
        tree.field("Destination", destination + Self.addressNote(frame, b), b..<(b + 6))
        tree.field("Source", source, (b + 6)..<(b + 12))
        tree.field("Type", String(format: "%@ (0x%04x)", PacketDissector.etherTypeName(type), type), (b + 12)..<(b + 14))
        context.summary = "Ethernet"
        return DissectionStep(next: .etherType(type), payload: (b + 14)..<range.upperBound)
    }

    static func addressNote(_ frame: UnsafeRawBufferPointer, _ offset: Int) -> String {
        if (0..<6).allSatisfy({ frame[offset + $0] == 0xFF }) { return " (broadcast)" }
        return frame[offset] & 0x01 != 0 ? " (multicast)" : ""
    }
}

struct VLANDissector: ProtocolDissector {
    let name = "vlan"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        [.etherType(0x8100), .etherType(0x88A8), .etherType(0x9100)].contains(layer)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        guard range.count >= 4 else {
            tree.layer(name, "802.1Q Virtual LAN", " Truncated tag", range: range)
            return .end
        }
        let tci = frame.u16be(b)
        let type = frame.u16be(b + 2)
        let id = tci & 0x0FFF
        tree.layer(name, "802.1Q Virtual LAN", " PRI \(tci >> 13), ID \(id)", range: b..<(b + 4))
        tree.field("Priority", "\(tci >> 13)\(Self.priorityName(Int(tci >> 13)))", b..<(b + 2))
        tree.field("DEI", tci & 0x1000 != 0 ? "Eligible" : "Ineligible", b..<(b + 2))
        tree.field("ID", "\(id)", b..<(b + 2))
        tree.field("Type", String(format: "%@ (0x%04x)", PacketDissector.etherTypeName(type), type), (b + 2)..<(b + 4))
        return DissectionStep(next: .etherType(type), payload: (b + 4)..<range.upperBound)
    }

    static func priorityName(_ pcp: Int) -> String {
        switch pcp {
        case 5: return " (voice)"
        case 6: return " (internetwork control)"
        case 4: return " (video)"
        default: return ""
        }
    }
}

struct MPLSDissector: ProtocolDissector {
    let name = "mpls"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .etherType(0x8847) || layer == .etherType(0x8848)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        var p = range.lowerBound
        tree.layer(name, "MultiProtocol Label Switching", "", range: range)
        var labels: [String] = []
        while p + 4 <= range.upperBound, labels.count < 16 {
            let word = frame.u32be(p)
            labels.append("\(word >> 12)")
            tree.field("Label", "\(word >> 12), TC \((word >> 9) & 7), TTL \(word & 0xFF)\(word & 0x100 != 0 ? ", bottom of stack" : "")", p..<(p + 4))
            p += 4
            if word & 0x100 != 0 { break }
        }
        tree.setSummary(" Label \(labels.joined(separator: ", "))")
        tree.setRange(range.lowerBound..<p)
        guard p < range.upperBound else { return .end }
        let version = frame[p] >> 4
        let next: NextLayer = version == 4 ? .etherType(0x0800) : version == 6 ? .etherType(0x86DD) : .end
        return DissectionStep(next: next, payload: p..<range.upperBound)
    }
}

struct PPPoEDissector: ProtocolDissector {
    let name = "pppoe"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .etherType(0x8864) || layer == .etherType(0x8863)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        guard range.count >= 6 else {
            tree.layer(name, "PPP-over-Ethernet", " Truncated header", range: range)
            return .end
        }
        let code = frame[b + 1]
        let session = frame.u16be(b + 2)
        let length = Int(frame.u16be(b + 4))
        tree.layer(name, "PPP-over-Ethernet", code == 0 ? " Session 0x\(String(format: "%04x", session))" : " Discovery",
                   range: b..<(b + 6))
        tree.field("Version · Type", "\(frame[b] >> 4) · \(frame[b] & 0x0F)", b..<(b + 1))
        tree.field("Code", Self.codeName(code), (b + 1)..<(b + 2))
        tree.field("Session ID", String(format: "0x%04x", session), (b + 2)..<(b + 4))
        tree.field("Payload Length", "\(length)", (b + 4)..<(b + 6))
        guard code == 0, range.count >= 8 else { return .end }
        let ppp = frame.u16be(b + 6)
        tree.field("PPP Protocol", ppp == 0x0021 ? "IPv4 (0x0021)" : ppp == 0x0057 ? "IPv6 (0x0057)" : String(format: "0x%04x", ppp),
                   (b + 6)..<(b + 8))
        let next: NextLayer = ppp == 0x0021 ? .etherType(0x0800) : ppp == 0x0057 ? .etherType(0x86DD) : .end
        return DissectionStep(next: next, payload: (b + 8)..<range.upperBound)
    }

    static func codeName(_ code: UInt8) -> String {
        switch code {
        case 0x00: return "Session Data (0x00)"
        case 0x09: return "PADI (0x09)"
        case 0x07: return "PADO (0x07)"
        case 0x19: return "PADR (0x19)"
        case 0x65: return "PADS (0x65)"
        case 0xA7: return "PADT (0xa7)"
        default: return String(format: "0x%02x", code)
        }
    }
}

struct LinuxCookedDissector: ProtocolDissector {
    let name = "sll"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .link(.linuxSLL) || layer == .link(.linuxSLL2)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        if context.linkType == .linuxSLL2 {
            guard range.count >= 20 else {
                tree.layer(name, "Linux cooked capture v2", " Truncated header", range: range)
                return .end
            }
            let type = frame.u16be(b)
            tree.layer(name, "Linux cooked capture v2", " Protocol \(PacketDissector.etherTypeName(type))", range: b..<(b + 20))
            tree.field("Protocol", String(format: "%@ (0x%04x)", PacketDissector.etherTypeName(type), type), b..<(b + 2))
            tree.field("Interface Index", "\(frame.u32be(b + 4))", (b + 4)..<(b + 8))
            tree.field("Packet Type", Self.packetType(frame.u8(b + 10)), (b + 10)..<(b + 11))
            let length = min(8, Int(frame.u8(b + 11)))
            tree.field("Source", PacketDissector.hex(frame, b + 12, length).chunked(), (b + 12)..<(b + 12 + length))
            return DissectionStep(next: .etherType(type), payload: (b + 20)..<range.upperBound)
        }
        guard range.count >= 16 else {
            tree.layer(name, "Linux cooked capture v1", " Truncated header", range: range)
            return .end
        }
        let type = frame.u16be(b + 14)
        tree.layer(name, "Linux cooked capture v1", " Protocol \(PacketDissector.etherTypeName(type))", range: b..<(b + 16))
        tree.field("Packet Type", Self.packetType(UInt8(truncatingIfNeeded: frame.u16be(b))), b..<(b + 2))
        let length = min(8, Int(frame.u16be(b + 4)))
        tree.field("Source", PacketDissector.hex(frame, b + 6, length).chunked(), (b + 6)..<(b + 6 + length))
        tree.field("Protocol", String(format: "%@ (0x%04x)", PacketDissector.etherTypeName(type), type), (b + 14)..<(b + 16))
        return DissectionStep(next: .etherType(type), payload: (b + 16)..<range.upperBound)
    }

    static func packetType(_ value: UInt8) -> String {
        switch value {
        case 0: return "Unicast to us (0)"
        case 1: return "Broadcast (1)"
        case 2: return "Multicast (2)"
        case 3: return "Unicast to another host (3)"
        case 4: return "Sent by us (4)"
        default: return "\(value)"
        }
    }
}

struct LoopbackDissector: ProtocolDissector {
    let name = "null"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .link(.null) || layer == .link(.loop)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        guard range.count >= 4 else {
            tree.layer(name, "Null/Loopback", " Truncated header", range: range)
            return .end
        }
        var family = frame.u32le(b)
        if family > 0xFFFF { family = frame.u32be(b) }
        let ipv6 = [24, 28, 30].contains(family)
        tree.layer(name, "Null/Loopback", ipv6 ? " IPv6" : family == 2 ? " IPv4" : "", range: b..<(b + 4))
        tree.field("Family", family == 2 ? "IP (2)" : ipv6 ? "IPv6 (\(family))" : "\(family)", b..<(b + 4))
        let next: NextLayer = family == 2 ? .etherType(0x0800) : ipv6 ? .etherType(0x86DD) : .end
        return DissectionStep(next: next, payload: (b + 4)..<range.upperBound)
    }
}

struct RawIPDissector: ProtocolDissector {
    let name = "raw"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        [.link(.raw), .link(.rawAlt), .link(.rawAlt2), .link(.ipv4), .link(.ipv6)].contains(layer)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        guard !range.isEmpty else { return .end }
        let version = frame[range.lowerBound] >> 4
        return DissectionStep(next: version == 6 ? .etherType(0x86DD) : .etherType(0x0800), payload: range)
    }
}

/// Link Layer Discovery Protocol (IEEE 802.1AB): phones and switches announce themselves, often with the voice VLAN.
struct LLDPDissector: ProtocolDissector {
    let name = "lldp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .etherType(0x88CC)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        tree.layer(name, "Link Layer Discovery Protocol", "", range: range)
        var p = range.lowerBound
        var parts: [String] = []
        var count = 0
        while p + 2 <= range.upperBound, count < 64 {
            count += 1
            let header = frame.u16be(p)
            let type = Int(header >> 9), length = Int(header & 0x1FF)
            let value = (p + 2)..<min(range.upperBound, p + 2 + length)
            let text: String
            switch type {
            case 0:
                tree.field("End of LLDPDU", "", p..<value.upperBound)
                tree.setSummary(" " + parts.joined(separator: " "))
                tree.setRange(range.lowerBound..<value.upperBound)
                return .end
            case 1, 2:
                let subtype = frame.u8(p + 2)
                let body = frame.slice(p + 3, max(0, length - 1))
                text = subtype == 4 || subtype == 3 && body.count == 6
                    ? body.map { String(format: "%02x", $0) }.joined(separator: ":")
                    : String(decoding: body, as: UTF8.self)
                parts.append((type == 1 ? "Chassis " : "Port ") + text)
                tree.field(type == 1 ? "Chassis ID" : "Port ID", text, p..<value.upperBound)
            case 3:
                text = "\(frame.u16be(p + 2)) s"
                parts.append("TTL \(text)")
                tree.field("Time to Live", text, p..<value.upperBound)
            case 4, 5, 6:
                text = String(decoding: frame.slice(p + 2, length), as: UTF8.self)
                tree.field(["Port Description", "System Name", "System Description"][type - 4], text, p..<value.upperBound)
            case 127:
                tree.field("Organization Specific", "OUI \(PacketDissector.hex(frame, p + 2, 3).chunked()), subtype \(frame.u8(p + 5))",
                           p..<value.upperBound)
            default:
                tree.field("TLV \(type)", "\(length) bytes", p..<value.upperBound)
            }
            p = value.upperBound
        }
        tree.setSummary(" " + parts.joined(separator: " "))
        context.summary = "LLDP"
        return .end
    }
}

extension String {
    /// "0a1b2c" → "0a:1b:2c".
    func chunked(by size: Int = 2, separator: String = ":") -> String {
        guard !isEmpty else { return self }
        var result: [Substring] = []
        var index = startIndex
        while index < endIndex {
            let next = self.index(index, offsetBy: size, limitedBy: endIndex) ?? endIndex
            result.append(self[index..<next])
            index = next
        }
        return result.joined(separator: separator)
    }
}
