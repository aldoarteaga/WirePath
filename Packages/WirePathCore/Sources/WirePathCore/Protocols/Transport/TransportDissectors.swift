import Foundation

// Transport-layer dissectors: UDP and TCP (with options).

struct UDPDissector: ProtocolDissector {
    let name = "udp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .ipProtocol(17)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let t = range.lowerBound
        guard range.count >= 8 else {
            tree.layer(name, "User Datagram Protocol", " Truncated header", range: range)
            context.summary = "UDP"
            return .end
        }
        let source = frame.u16be(t), destination = frame.u16be(t + 2)
        let length = Int(frame.u16be(t + 4))
        tree.layer(name, "User Datagram Protocol", " Src Port \(source), Dst Port \(destination), Len \(length.formatted())",
                   range: t..<(t + 8))
        tree.field("Source Port", "\(source)", t..<(t + 2))
        tree.field("Destination Port", "\(destination)", (t + 2)..<(t + 4))
        tree.field("Length", length >= 8 && length <= range.count ? "\(length)" : "\(length) (captured \(range.count))", (t + 4)..<(t + 6))
        let checksum = frame.u16be(t + 6)
        tree.field("Checksum", checksum == 0 ? "0x0000 (none)" : String(format: "0x%04x", checksum), (t + 6)..<(t + 8))
        context.sourcePort = source
        context.destinationPort = destination
        context.summary = "UDP \(source) → \(destination) Len=\(max(0, length - 8))"
        let end = length >= 8 ? min(range.upperBound, t + length) : range.upperBound
        return DissectionStep(next: .transportPayload(.udp), payload: (t + 8)..<end)
    }
}

struct TCPDissector: ProtocolDissector {
    let name = "tcp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .ipProtocol(6)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let t = range.lowerBound
        guard range.count >= 20 else {
            tree.layer(name, "Transmission Control Protocol", " Truncated header", range: range)
            context.summary = "TCP"
            return .end
        }
        let source = frame.u16be(t), destination = frame.u16be(t + 2)
        let sequence = frame.u32be(t + 4), acknowledgment = frame.u32be(t + 8)
        let headerLength = Int(frame[t + 12] >> 4) * 4
        let flags = frame[t + 13]
        let window = frame.u16be(t + 14)
        let payloadLength = max(0, range.count - headerLength)
        let flagText = PacketDissector.tcpFlags(flags)
        tree.layer(name, "Transmission Control Protocol",
                   " Src Port \(source), Dst Port \(destination), Seq \(sequence)\(flags & 0x10 != 0 ? ", Ack \(acknowledgment)" : ""), Len \(payloadLength)",
                   range: t..<min(range.upperBound, t + max(20, headerLength)))
        tree.field("Source Port", "\(source)", t..<(t + 2))
        tree.field("Destination Port", "\(destination)", (t + 2)..<(t + 4))
        tree.field("Sequence Number", "\(sequence)", (t + 4)..<(t + 8))
        tree.field("Acknowledgment", flags & 0x10 != 0 ? "\(acknowledgment)" : "\(acknowledgment) (not set)", (t + 8)..<(t + 12))
        tree.field("Header Length", "\(headerLength) bytes", (t + 12)..<(t + 13))
        tree.field("Flags", "[\(flagText)]", (t + 12)..<(t + 14))
        tree.field("Window", "\(window)", (t + 14)..<(t + 16))
        tree.field("Checksum", String(format: "0x%04x", frame.u16be(t + 16)), (t + 16)..<(t + 18))
        if flags & 0x20 != 0 { tree.field("Urgent Pointer", "\(frame.u16be(t + 18))", (t + 18)..<(t + 20)) }
        guard headerLength >= 20, t + headerLength <= range.upperBound else {
            tree.field("Header", "Truncated (header length \(headerLength), captured \(range.count))")
            context.summary = "TCP"
            return .end
        }
        if headerLength > 20 { Self.options(frame, from: t + 20, to: t + headerLength, tree: &tree) }
        context.sourcePort = source
        context.destinationPort = destination
        context.summary = "TCP \(source) → \(destination) [\(flagText)] Seq=\(sequence)\(flags & 0x10 != 0 ? " Ack=\(acknowledgment)" : "") Win=\(window) Len=\(payloadLength)"
        guard payloadLength > 0 else { return .end }
        return DissectionStep(next: .transportPayload(.tcp), payload: (t + headerLength)..<range.upperBound)
    }

    /// TCP options (RFC 9293 §3.1, RFC 7323, RFC 2018).
    static func options(_ frame: UnsafeRawBufferPointer, from start: Int, to end: Int, tree: inout ProtocolTreeBuilder) {
        var p = start
        var parts: [String] = []
        var count = 0
        while p < end, count < 40 {
            count += 1
            let kind = frame[p]
            if kind == 0 { break }
            if kind == 1 { p += 1; continue }
            guard p + 1 < end else { break }
            let length = Int(frame[p + 1])
            guard length >= 2, p + length <= end else { break }
            switch kind {
            case 2 where length == 4:
                parts.append("MSS=\(frame.u16be(p + 2))")
            case 3 where length == 3:
                parts.append("WS=\(1 << min(14, Int(frame[p + 2])))")
            case 4:
                parts.append("SACK_PERM")
            case 5:
                var blocks: [String] = []
                var q = p + 2
                while q + 8 <= p + length {
                    blocks.append("\(frame.u32be(q))-\(frame.u32be(q + 4))")
                    q += 8
                }
                parts.append("SACK \(blocks.joined(separator: " "))")
            case 8 where length == 10:
                parts.append("TSval=\(frame.u32be(p + 2)) TSecr=\(frame.u32be(p + 6))")
            default:
                parts.append("Kind \(kind)")
            }
            p += length
        }
        tree.field("Options", parts.isEmpty ? "\(end - start) bytes" : parts.joined(separator: ", "), start..<end)
    }
}
