import Foundation

// DNS, DHCP and NTP.

struct DNSDissector: ProtocolDissector {
    let name = "dns"
    static let ports: Set<UInt16> = [53, 5353, 5355]
    static let maxRecords = 256

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        switch layer {
        case .transportPayload(.udp): return context.usesPort(in: Self.ports) && payload.count >= 12
        case .transportPayload(.tcp): return context.usesPort(53) && payload.count >= 14
        default: return false
        }
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        var base = range.lowerBound
        let title = context.usesPort(5353) ? "Multicast Domain Name System" : context.usesPort(5355) ? "Link-local Multicast Name Resolution" : "Domain Name System"
        tree.layer(name, title, "", range: range)
        if context.ipProtocol == 6 {
            tree.field("Length", "\(frame.u16be(base))", base..<(base + 2))
            base += 2
        }
        let message = frame.slice(base, range.upperBound - base)
        guard message.count >= 12 else {
            context.summary = "DNS (truncated)"
            return .end
        }
        let id = message.u16be(0), flags = message.u16be(2)
        let isResponse = flags & 0x8000 != 0
        let opcode = Int((flags >> 11) & 0xF), rcode = Int(flags & 0xF)
        let counts = (0..<4).map { Int(message.u16be(4 + $0 * 2)) }
        tree.field("Transaction ID", String(format: "0x%04x", id), base..<(base + 2))
        var flagParts = [isResponse ? "Response" : "Query", Self.opcodeName(opcode)]
        if flags & 0x0400 != 0 { flagParts.append("Authoritative") }
        if flags & 0x0200 != 0 { flagParts.append("Truncated") }
        if flags & 0x0100 != 0 { flagParts.append("Recursion desired") }
        if flags & 0x0080 != 0 { flagParts.append("Recursion available") }
        if isResponse { flagParts.append(Self.rcodeName(rcode)) }
        tree.field("Flags", String(format: "0x%04x ", flags) + flagParts.joined(separator: ", "), (base + 2)..<(base + 4))
        tree.field("Questions · Answers · Authority · Additional", counts.map(String.init).joined(separator: " · "), (base + 4)..<(base + 12))

        var p = 12
        var questions: [String] = []
        var answers: [String] = []
        for _ in 0..<min(counts[0], Self.maxRecords) {
            guard let (qname, next) = Self.readName(message, p), next + 4 <= message.count else { break }
            let type = message.u16be(next)
            tree.field("Query", "\(qname): type \(Self.typeName(type)), class \(Self.className(message.u16be(next + 2)))",
                       (base + p)..<(base + next + 4))
            questions.append("\(Self.typeName(type)) \(qname)")
            p = next + 4
        }
        let sections = ["Answer", "Authority", "Additional"]
        for (index, section) in sections.enumerated() {
            for _ in 0..<min(counts[index + 1], Self.maxRecords) {
                guard let record = Self.readRecord(message, p) else { break }
                tree.field(section, "\(record.name): type \(Self.typeName(record.type)), TTL \(record.ttl), \(record.data)",
                           (base + p)..<(base + record.end))
                if index == 0 { answers.append("\(Self.typeName(record.type)) \(record.data)") }
                p = record.end
            }
        }
        let kind = opcode == 0 ? "Standard query" : Self.opcodeName(opcode)
        var summary = "\(kind)\(isResponse ? " response" : "") \(String(format: "0x%04x", id))"
        if isResponse, rcode != 0 { summary += " \(Self.rcodeName(rcode))" }
        if !questions.isEmpty { summary += " " + questions.joined(separator: " ") }
        if !answers.isEmpty { summary += " " + answers.prefix(4).joined(separator: " ") }
        tree.setSummary(" " + summary)
        context.summary = (context.usesPort(5353) ? "MDNS " : "DNS ") + summary
        return .end
    }

    struct Record {
        var name: String
        var type: UInt16
        var ttl: UInt32
        var data: String
        var end: Int
    }

    static func readRecord(_ m: UnsafeRawBufferPointer, _ offset: Int) -> Record? {
        guard let (owner, p) = readName(m, offset), p + 10 <= m.count else { return nil }
        let type = m.u16be(p), rdLength = Int(m.u16be(p + 8))
        let start = p + 10
        guard start + rdLength <= m.count else { return nil }
        let ttl = m.u32be(p + 4)
        let data: String
        switch type {
        case 1 where rdLength == 4:
            data = PacketDissector.ipv4(m, start)
        case 28 where rdLength == 16:
            data = PacketDissector.ipv6(m, start)
        case 2, 5, 12:
            data = readName(m, start)?.0 ?? "?"
        case 15 where rdLength >= 3:
            data = "\(m.u16be(start)) \(readName(m, start + 2)?.0 ?? "?")"
        case 16:
            var strings: [String] = []
            var q = start
            while q < start + rdLength, strings.count < 16 {
                let length = Int(m[q])
                strings.append("\"\(String(decoding: m.slice(q + 1, min(length, start + rdLength - q - 1)), as: UTF8.self))\"")
                q += 1 + length
            }
            data = strings.joined(separator: " ")
        case 33 where rdLength >= 7:
            data = "priority \(m.u16be(start)), weight \(m.u16be(start + 2)), port \(m.u16be(start + 4)), \(readName(m, start + 6)?.0 ?? "?")"
        case 35 where rdLength >= 7:
            // NAPTR (ENUM / SIP server discovery): order, preference, flags, service, regexp, replacement.
            var q = start + 4
            var texts: [String] = []
            for _ in 0..<3 {
                guard q < start + rdLength else { break }
                let length = Int(m[q])
                texts.append(String(decoding: m.slice(q + 1, min(length, start + rdLength - q - 1)), as: UTF8.self))
                q += 1 + length
            }
            let replacement = q < start + rdLength ? (readName(m, q)?.0 ?? "?") : ""
            data = "order \(m.u16be(start)), pref \(m.u16be(start + 2)), \(texts.map { "\"\($0)\"" }.joined(separator: " ")) \(replacement)"
        case 6:
            if let (mname, q) = readName(m, start), let (rname, r) = readName(m, q), r + 20 <= start + rdLength {
                data = "\(mname) \(rname) serial \(m.u32be(r))"
            } else {
                data = "\(rdLength) bytes"
            }
        case 41:
            data = "EDNS UDP payload size \(m.u16be(p + 2))"
        default:
            data = "\(rdLength) bytes"
        }
        return Record(name: owner, type: type, ttl: type == 41 ? 0 : ttl, data: data, end: start + rdLength)
    }

    /// Reads a possibly compressed domain name (RFC 1035 §4.1.4). Pointer chains, label lengths and the total name
    /// length are bounded, so malformed or looping names end with nil instead of spinning.
    static func readName(_ m: UnsafeRawBufferPointer, _ offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var p = offset
        var end: Int?
        var jumps = 0
        var total = 0
        while true {
            guard p >= 0, p < m.count else { return nil }
            let length = Int(m[p])
            if length == 0 {
                return (labels.isEmpty ? "<Root>" : labels.joined(separator: "."), end ?? p + 1)
            }
            if length & 0xC0 == 0xC0 {
                guard p + 1 < m.count, jumps < 16 else { return nil }
                if end == nil { end = p + 2 }
                p = (length & 0x3F) << 8 | Int(m[p + 1])
                jumps += 1
                continue
            }
            guard length <= 63, p + 1 + length <= m.count else { return nil }
            total += length + 1
            guard total <= 255 else { return nil }
            labels.append(String(decoding: m.slice(p + 1, length), as: UTF8.self))
            p += 1 + length
        }
    }

    static func typeName(_ type: UInt16) -> String {
        let names: [UInt16: String] = [1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
                                       28: "AAAA", 33: "SRV", 35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG",
                                       47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF", 255: "ANY", 257: "CAA"]
        return names[type] ?? "TYPE\(type)"
    }

    static func className(_ value: UInt16) -> String {
        switch value & 0x7FFF {
        case 1: return value & 0x8000 != 0 ? "IN (cache flush / QU)" : "IN"
        case 3: return "CH"
        case 255: return "ANY"
        default: return "\(value)"
        }
    }

    static func opcodeName(_ opcode: Int) -> String {
        switch opcode {
        case 0: return "Standard query"
        case 1: return "Inverse query"
        case 2: return "Server status"
        case 4: return "Notify"
        case 5: return "Dynamic update"
        default: return "Opcode \(opcode)"
        }
    }

    static func rcodeName(_ rcode: Int) -> String {
        switch rcode {
        case 0: return "No error"
        case 1: return "Format error"
        case 2: return "Server failure"
        case 3: return "No such name"
        case 4: return "Not implemented"
        case 5: return "Refused"
        default: return "Rcode \(rcode)"
        }
    }
}

struct DHCPDissector: ProtocolDissector {
    let name = "dhcp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .transportPayload(.udp) && (context.usesPort(67) || context.usesPort(68))
            && payload.count >= 240 && payload.u32be(236) == 0x6382_5363
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        let m = frame.slice(b, range.count)
        let xid = m.u32be(4)
        tree.layer(name, "Dynamic Host Configuration Protocol", "", range: range)
        tree.field("Message Type (BOOTP)", m[0] == 1 ? "Boot Request (1)" : m[0] == 2 ? "Boot Reply (2)" : "\(m[0])", b..<(b + 1))
        tree.field("Hardware · Hops", "\(m[1] == 1 ? "Ethernet" : "\(m[1])") · \(m[3])", (b + 1)..<(b + 4))
        tree.field("Transaction ID", String(format: "0x%08x", xid), (b + 4)..<(b + 8))
        tree.field("Seconds · Flags", "\(m.u16be(8)) · \(m.u16be(10) & 0x8000 != 0 ? "Broadcast" : "Unicast")", (b + 8)..<(b + 12))
        for (index, label) in ["Client IP", "Your (client) IP", "Next Server IP", "Relay Agent IP"].enumerated() {
            let offset = 12 + index * 4
            tree.field(label, PacketDissector.ipv4(m, offset), (b + offset)..<(b + offset + 4))
        }
        tree.field("Client MAC", PacketDissector.mac(m, 28), (b + 28)..<(b + 34))
        let serverName = m.utf8String(44, 64), bootFile = m.utf8String(108, 128)
        if !serverName.isEmpty { tree.field("Server Host Name", serverName, (b + 44)..<(b + 108)) }
        if !bootFile.isEmpty { tree.field("Boot File", bootFile, (b + 108)..<(b + 236)) }

        var p = 240
        var messageType = "DHCP"
        var count = 0
        while p < m.count, count < 128 {
            count += 1
            let code = m[p]
            if code == 0 { p += 1; continue }
            if code == 255 {
                tree.field("Option (255) End", "", (b + p)..<(b + p + 1), level: 1)
                break
            }
            guard p + 1 < m.count else { break }
            let length = Int(m[p + 1])
            guard p + 2 + length <= m.count else { break }
            let value = m.slice(p + 2, length)
            let (label, text) = Self.option(code, value)
            if code == 53, let first = value.first { messageType = Self.messageType(first) }
            tree.field("Option (\(code)) \(label)", text, (b + p)..<(b + p + 2 + length), level: 1)
            p += 2 + length
        }
        let summary = "DHCP \(messageType) - Transaction ID \(String(format: "0x%08x", xid))"
        tree.setSummary(" \(messageType)")
        context.summary = summary
        return .end
    }

    static func messageType(_ value: UInt8) -> String {
        let names = [1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"]
        return names[Int(value)] ?? "Type \(value)"
    }

    static func addresses(_ value: UnsafeRawBufferPointer) -> String {
        stride(from: 0, to: value.count - 3, by: 4).map { PacketDissector.ipv4(value, $0) }.joined(separator: ", ")
    }

    static func option(_ code: UInt8, _ value: UnsafeRawBufferPointer) -> (String, String) {
        let text = String(decoding: value, as: UTF8.self)
        switch code {
        case 1: return ("Subnet Mask", addresses(value))
        case 3: return ("Router", addresses(value))
        case 6: return ("Domain Name Server", addresses(value))
        case 12: return ("Host Name", text)
        case 15: return ("Domain Name", text)
        case 42: return ("NTP Servers", addresses(value))
        case 43: return ("Vendor-Specific Information", "\(value.count) bytes")
        case 50: return ("Requested IP Address", addresses(value))
        case 51: return ("IP Address Lease Time", value.count >= 4 ? "\(value.u32be(0)) s" : "")
        case 53: return ("DHCP Message Type", value.first.map(messageType) ?? "")
        case 54: return ("DHCP Server Identifier", addresses(value))
        case 55: return ("Parameter Request List", value.map { "\($0)" }.joined(separator: ", "))
        case 58: return ("Renewal Time", value.count >= 4 ? "\(value.u32be(0)) s" : "")
        case 59: return ("Rebinding Time", value.count >= 4 ? "\(value.u32be(0)) s" : "")
        case 60: return ("Vendor Class Identifier", text)
        case 61: return ("Client Identifier", value.count == 7 && value[0] == 1 ? PacketDissector.mac(value, 1) : PacketDissector.hex(value, 0, value.count))
        case 66: return ("TFTP Server Name", text)
        case 67: return ("Bootfile Name", text)
        case 81: return ("Client FQDN", String(decoding: value.slice(3, value.count - 3), as: UTF8.self))
        case 82: return ("Relay Agent Information", "\(value.count) bytes")
        case 120: return ("SIP Servers", value.first == 1 ? addresses(value.slice(1, value.count - 1)) : "\(value.count) bytes")
        case 150: return ("TFTP Server Address", addresses(value))
        default: return ("", "\(value.count) bytes")
        }
    }
}

struct NTPDissector: ProtocolDissector {
    let name = "ntp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .transportPayload(.udp) && context.usesPort(123) && payload.count >= 48
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        let first = frame[b]
        let version = Int((first >> 3) & 7), mode = Int(first & 7)
        let modes = ["reserved", "symmetric active", "symmetric passive", "client", "server", "broadcast", "control", "private"]
        tree.layer(name, "Network Time Protocol", " NTP Version \(version), \(modes[mode])", range: b..<(b + 48))
        tree.field("Leap · Version · Mode", "\(first >> 6) · \(version) · \(modes[mode])", b..<(b + 1))
        tree.field("Stratum", "\(frame[b + 1])", (b + 1)..<(b + 2))
        tree.field("Poll · Precision", "\(Int8(bitPattern: frame[b + 2])) · \(Int8(bitPattern: frame[b + 3]))", (b + 2)..<(b + 4))
        let reference = frame[b + 1] <= 1 ? String(decoding: frame.slice(b + 12, 4), as: UTF8.self).trimmingCharacters(in: .controlCharacters)
            : PacketDissector.ipv4(frame, b + 12)
        tree.field("Reference ID", reference, (b + 12)..<(b + 16))
        for (index, label) in ["Reference Timestamp", "Origin Timestamp", "Receive Timestamp", "Transmit Timestamp"].enumerated() {
            let offset = b + 16 + index * 8
            let value = UInt64(frame.u32be(offset)) << 32 | UInt64(frame.u32be(offset + 4))
            tree.field(label, value == 0 ? "0" : RTCPDissector.ntpTime(value), offset..<(offset + 8))
        }
        context.summary = "NTP Version \(version), \(modes[mode])"
        return .end
    }
}
