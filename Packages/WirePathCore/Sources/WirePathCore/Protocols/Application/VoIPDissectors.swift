import Foundation

// SIP (with SDP), RTP and RTCP.

struct SIPDissector: ProtocolDissector {
    let name = "sip"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        guard case .transportPayload = layer else { return false }
        return SIPParser.looksLikeSIP(payload)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let payload = frame.slice(range.lowerBound, range.count)
        guard let message = SIPParser.parse(payload) else {
            tree.layer(name, "Session Initiation Protocol", " Incomplete message", range: range)
            context.summary = "SIP (incomplete)"
            return .end
        }
        let base = range.lowerBound
        let label = message.isRequest ? message.method : "\(message.statusCode ?? 0) \(message.reasonPhrase ?? "")"
        tree.layer(name, "Session Initiation Protocol", " \(label)", range: base..<(base + message.totalLength))
        // Walk lines to recover byte ranges.
        var lines: [(text: String, range: Range<Int>)] = []
        var start = 0
        let limit = min(payload.count, message.totalLength)
        var i = 0
        while i < limit, lines.count < 512 {
            if payload[i] == 0x0A {
                var end = i
                if end > start && payload[end - 1] == 0x0D { end -= 1 }
                lines.append((String(decoding: payload.slice(start, end - start), as: UTF8.self), (base + start)..<(base + end)))
                start = i + 1
            }
            i += 1
        }
        if start < limit, lines.count < 512 {
            lines.append((String(decoding: payload.slice(start, limit - start), as: UTF8.self), (base + start)..<(base + limit)))
        }
        var inBody = false
        var sdpStarted = false
        for (index, line) in lines.enumerated() {
            if index == 0 {
                tree.field(message.isRequest ? "Request-Line" : "Status-Line", line.text, line.range)
                continue
            }
            if !inBody {
                if line.text.isEmpty { inBody = true; continue }
                guard let colon = line.text.firstIndex(of: ":") else { continue }
                let headerName = SIPHeaderParser.canonicalName(line.text[..<colon].trimmingCharacters(in: .whitespaces))
                var value = line.text[line.text.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                if headerName == "Content-Type", let length = message.header("Content-Length") { value += " · \(length) bytes" }
                tree.field(headerName, value, line.range)
            } else if let sdp = message.sdp, line.text.count >= 2, line.text.dropFirst().first == "=" {
                if !sdpStarted {
                    sdpStarted = true
                    let media = sdp.media.first.map { m in
                        let codec = m.payloadTypes.lazy.compactMap { pt in
                            CodecCatalog.descriptor(payloadType: pt, encodingName: m.rtpMaps[pt]?.encodingName,
                                                    clockRate: m.rtpMaps[pt]?.clockRate)
                        }.first { $0.kind.isVoice }
                        return "\(m.mediaType) · \(codec?.displayName ?? "")"
                    } ?? ""
                    tree.layer("sdp", "Session Description Protocol", " \(media)", range: line.range.lowerBound..<(base + message.totalLength))
                }
                let type = line.text.prefix(1)
                let rest = String(line.text.dropFirst(2))
                if type == "a", let colon = rest.firstIndex(of: ":") {
                    tree.field("a=\(rest[..<colon])", String(rest[rest.index(after: colon)...]), line.range)
                } else {
                    tree.field("\(type)=", rest, line.range)
                }
            }
        }
        context.summary = "SIP \(label)".trimmingCharacters(in: .whitespaces)
        return .end
    }
}

struct RTPDissector: ProtocolDissector {
    let name = "rtp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .transportPayload(.udp) && !context.usesPort(in: FrameDecoding.nonRTPPorts) && RTPHeader.parse(payload) != nil
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let p = range.lowerBound
        guard let rtp = RTPHeader.parse(frame.slice(p, range.count)) else { return .end }
        let codec = context.codecForPayloadType(rtp.payloadType)
        let ptName = codec.map { CodecCatalog.longName(for: $0) } ?? "Unknown"
        tree.layer(name, "Real-Time Transport Protocol", " \(codec?.displayName ?? "PT \(rtp.payloadType)") · Seq \(rtp.sequenceNumber)",
                   range: p..<(p + rtp.headerLength))
        tree.field("Version", "2", p..<(p + 1))
        tree.field("Padding · Extension", "\(rtp.padding ? "Yes" : "No") · \(rtp.hasExtension ? "Yes" : "No")", p..<(p + 1))
        tree.field("CSRC Count", "\(rtp.csrcCount)", p..<(p + 1))
        tree.field("Marker", rtp.marker ? "Set" : "Not set", (p + 1)..<(p + 2))
        tree.field("Payload Type", "\(ptName) (\(rtp.payloadType))", (p + 1)..<(p + 2))
        tree.field("Sequence Number", "\(rtp.sequenceNumber)", (p + 2)..<(p + 4))
        tree.field("Timestamp", "\(rtp.timestamp)", (p + 4)..<(p + 8))
        tree.field("SSRC", String(format: "0x%08X", rtp.ssrc), (p + 8)..<(p + 12))
        for index in 0..<rtp.csrcCount {
            let offset = p + 12 + index * 4
            tree.field("CSRC", String(format: "0x%08X", frame.u32be(offset)), offset..<(offset + 4), level: 1)
        }
        if rtp.hasExtension {
            let offset = p + 12 + rtp.csrcCount * 4
            let profile = frame.u16be(offset)
            let words = Int(frame.u16be(offset + 2))
            let kind = profile == 0xBEDE ? "one-byte (RFC 8285)" : profile & 0xFFF0 == 0x1000 ? "two-byte (RFC 8285)" : String(format: "0x%04x", profile)
            tree.field("Header Extension", "\(kind), \(words * 4) bytes", offset..<(p + rtp.headerLength), level: 1)
        }
        tree.field("Payload", "\(rtp.payloadLength) bytes", (p + rtp.headerLength)..<range.upperBound)
        context.summary = "RTP PT=\(codec?.displayName ?? "\(rtp.payloadType)"), SSRC=\(String(format: "0x%08X", rtp.ssrc)), Seq=\(rtp.sequenceNumber), Time=\(rtp.timestamp)\(rtp.marker ? ", Mark" : "")"
        return .end
    }
}

/// RTCP compound packets (RFC 3550 §6, RFC 4585 feedback, RFC 3611 XR).
struct RTCPDissector: ProtocolDissector {
    let name = "rtcp"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .transportPayload(.udp) && !context.usesPort(in: FrameDecoding.nonRTPPorts) && RTCPDetector.looksLikeRTCP(payload)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        var p = range.lowerBound
        var names: [String] = []
        var packets = 0
        while p + 4 <= range.upperBound, packets < 16 {
            packets += 1
            let first = frame[p]
            guard first >> 6 == 2 else { break }
            let count = Int(first & 0x1F)
            let type = frame[p + 1]
            let length = (Int(frame.u16be(p + 2)) + 1) * 4
            let end = min(range.upperBound, p + length)
            let typeName = RTCPDetector.typeName(type)
            names.append(typeName)
            tree.layer(name, "Real-time Transport Control Protocol", " \(typeName)", range: p..<end)
            tree.field("Packet Type", "\(typeName) (\(type))", (p + 1)..<(p + 2))
            tree.field("Length", "\(frame.u16be(p + 2)) words (\(length) bytes)", (p + 2)..<(p + 4))
            if p + 8 <= end {
                tree.field(type == 202 ? "Chunks" : "Sender SSRC", type == 202 ? "\(count)" : String(format: "0x%08X", frame.u32be(p + 4)),
                           (p + 4)..<(p + 8))
            }
            switch type {
            case 200:  // Sender Report
                if p + 28 <= end {
                    let ntp = UInt64(frame.u32be(p + 8)) << 32 | UInt64(frame.u32be(p + 12))
                    tree.field("NTP Timestamp", Self.ntpTime(ntp), (p + 8)..<(p + 16))
                    tree.field("RTP Timestamp", "\(frame.u32be(p + 16))", (p + 16)..<(p + 20))
                    tree.field("Sender's Packet Count", "\(frame.u32be(p + 20))", (p + 20)..<(p + 24))
                    tree.field("Sender's Octet Count", "\(frame.u32be(p + 24))", (p + 24)..<(p + 28))
                    Self.reportBlocks(frame, from: p + 28, count: count, end: end, tree: &tree)
                }
            case 201:  // Receiver Report
                Self.reportBlocks(frame, from: p + 8, count: count, end: end, tree: &tree)
            case 202:  // SDES
                Self.sdes(frame, from: p + 4, chunks: count, end: end, tree: &tree)
            case 203:  // BYE
                if count > 1 { tree.field("Sources", "\(count)") }
            case 205, 206:
                tree.field("Feedback Type", Self.feedbackName(type: type, format: count), p..<(p + 1))
            case 207:
                tree.field("Report Blocks", "\(max(0, end - p - 8)) bytes", min(end, p + 8)..<end)
            default:
                break
            }
            guard length > 0 else { break }
            p += length
        }
        context.summary = "RTCP " + names.joined(separator: ", ")
        return .end
    }

    static func reportBlocks(_ frame: UnsafeRawBufferPointer, from start: Int, count: Int, end: Int, tree: inout ProtocolTreeBuilder) {
        var q = start
        for _ in 0..<count where q + 24 <= end {
            let ssrc = frame.u32be(q)
            let fraction = Double(frame[q + 4]) / 256 * 100
            // Cumulative lost is a signed 24-bit value.
            let raw = Int32(bitPattern: frame.u32be(q + 4) << 8) >> 8
            tree.field("Report Block", String(format: "SSRC 0x%08X", ssrc), q..<(q + 24))
            tree.field("Fraction Lost", String(format: "%.1f %%", fraction), (q + 4)..<(q + 5), level: 1)
            tree.field("Cumulative Lost", "\(raw)", (q + 5)..<(q + 8), level: 1)
            tree.field("Highest Sequence", "\(frame.u32be(q + 8) & 0xFFFF) (cycles \(frame.u32be(q + 8) >> 16))", (q + 8)..<(q + 12), level: 1)
            tree.field("Interarrival Jitter", "\(frame.u32be(q + 12)) timestamp units", (q + 12)..<(q + 16), level: 1)
            let lsr = frame.u32be(q + 16), dlsr = frame.u32be(q + 20)
            tree.field("Last SR", lsr == 0 ? "none" : String(format: "0x%08X", lsr), (q + 16)..<(q + 20), level: 1)
            tree.field("Delay Since Last SR", lsr == 0 ? "—" : String(format: "%.3f s", Double(dlsr) / 65_536), (q + 20)..<(q + 24), level: 1)
            q += 24
        }
    }

    static func sdes(_ frame: UnsafeRawBufferPointer, from start: Int, chunks: Int, end: Int, tree: inout ProtocolTreeBuilder) {
        var q = start
        for _ in 0..<chunks {
            guard q + 4 <= end else { return }
            tree.field("Chunk", String(format: "SSRC 0x%08X", frame.u32be(q)), q..<(q + 4))
            q += 4
            var items = 0
            while q < end, frame[q] != 0, items < 16 {
                items += 1
                let type = frame[q]
                guard q + 2 <= end else { return }
                let length = Int(frame[q + 1])
                let value = String(decoding: frame.slice(q + 2, min(length, end - q - 2)), as: UTF8.self)
                let names = [1: "CNAME", 2: "NAME", 3: "EMAIL", 4: "PHONE", 5: "LOC", 6: "TOOL", 7: "NOTE", 8: "PRIV"]
                tree.field(names[Int(type)] ?? "Item \(type)", value, q..<min(end, q + 2 + length), level: 1)
                q += 2 + length
            }
            // Chunks end with a null item and are padded to 32 bits (relative to the chunk list, not the frame).
            q = start + (((q - start) + 4) & ~3)
        }
    }

    static func feedbackName(type: UInt8, format: Int) -> String {
        if type == 205 {
            switch format {
            case 1: return "Generic NACK"
            case 3: return "TMMBR"
            case 4: return "TMMBN"
            case 15: return "Transport-wide CC"
            default: return "Transport feedback \(format)"
            }
        }
        switch format {
        case 1: return "Picture Loss Indication"
        case 2: return "Slice Loss Indication"
        case 4: return "Full Intra Request"
        case 15: return "Application layer feedback (REMB)"
        default: return "Payload feedback \(format)"
        }
    }

    /// NTP timestamp (seconds since 1900 + fraction) as a UTC date.
    static func ntpTime(_ value: UInt64) -> String {
        let seconds = Double(value >> 32) - 2_208_988_800 + Double(value & 0xFFFF_FFFF) / 4_294_967_296
        guard seconds.isFinite else { return "\(value)" }
        return Date(timeIntervalSince1970: seconds).formatted(.iso8601.year().month().day().time(includingFractionalSeconds: true))
    }
}
