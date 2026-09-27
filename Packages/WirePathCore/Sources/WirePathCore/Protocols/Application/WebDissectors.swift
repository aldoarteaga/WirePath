import Foundation

// HTTP/1.x, TLS record/handshake metadata (never decrypted), STUN/TURN and TURN ChannelData.

struct HTTPDissector: ProtocolDissector {
    let name = "http"
    static let methods: [String] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"]

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .transportPayload(.tcp) && Self.looksLikeHTTP(payload)
    }

    static func looksLikeHTTP(_ payload: UnsafeRawBufferPointer) -> Bool {
        guard payload.count >= 8 else { return false }
        let head = String(decoding: payload.slice(0, 10), as: UTF8.self)
        if head.hasPrefix("HTTP/1.") { return true }
        return methods.contains { head.hasPrefix($0 + " ") }
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        let payload = frame.slice(b, range.count)
        tree.layer(name, "Hypertext Transfer Protocol", "", range: range)
        var start = 0
        var i = 0
        var lineIndex = 0
        var firstLine = ""
        var headersEnd: Int?
        while i < payload.count, lineIndex < 128 {
            if payload[i] == 0x0A {
                var end = i
                if end > start, payload[end - 1] == 0x0D { end -= 1 }
                let text = String(decoding: payload.slice(start, end - start), as: UTF8.self)
                if lineIndex == 0 {
                    firstLine = text
                    tree.field(text.hasPrefix("HTTP/") ? "Status-Line" : "Request-Line", text, (b + start)..<(b + end))
                } else if text.isEmpty {
                    headersEnd = i + 1
                    break
                } else if let colon = text.firstIndex(of: ":") {
                    tree.field(String(text[..<colon]), text[text.index(after: colon)...].trimmingCharacters(in: .whitespaces),
                               (b + start)..<(b + end))
                }
                lineIndex += 1
                start = i + 1
            }
            i += 1
        }
        if let headersEnd, headersEnd < payload.count {
            tree.field("Body", "\(payload.count - headersEnd) bytes in this segment", (b + headersEnd)..<range.upperBound)
        } else if headersEnd == nil {
            tree.field("Headers", "Continue in a later segment")
        }
        tree.setSummary(" \(firstLine)")
        context.summary = "HTTP \(firstLine)"
        return .end
    }
}

struct TLSDissector: ProtocolDissector {
    let name = "tls"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .transportPayload(.tcp) && Self.looksLikeTLS(payload)
    }

    static func looksLikeTLS(_ payload: UnsafeRawBufferPointer) -> Bool {
        guard payload.count >= 5 else { return false }
        return (20...23).contains(payload[0]) && payload[1] == 3 && payload[2] <= 4 && payload.u16be(3) <= 16_384 + 2_048
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        var p = range.lowerBound
        var descriptions: [String] = []
        var records = 0
        while p + 5 <= range.upperBound, records < 32, Self.looksLikeTLS(frame.slice(p, range.upperBound - p)) {
            records += 1
            let type = frame[p]
            let version = frame.u16be(p + 1)
            let length = Int(frame.u16be(p + 3))
            let end = min(range.upperBound, p + 5 + length)
            tree.layer(name, "Transport Layer Security", " \(Self.contentType(type))", range: p..<end)
            tree.field("Content Type", "\(Self.contentType(type)) (\(type))", p..<(p + 1))
            tree.field("Version", Self.versionName(version), (p + 1)..<(p + 3))
            tree.field("Length", "\(length)\(p + 5 + length > range.upperBound ? " (continues in a later segment)" : "")", (p + 3)..<(p + 5))
            if type == 22, p + 9 <= end {
                descriptions.append(Self.handshake(frame, from: p + 5, to: end, tree: &tree))
            } else {
                descriptions.append(Self.contentType(type))
            }
            p = end
        }
        context.summary = "TLS " + descriptions.joined(separator: ", ")
        return .end
    }

    /// Handshake messages: Client/Server Hello details, other types by name. Payloads stay opaque.
    static func handshake(_ frame: UnsafeRawBufferPointer, from start: Int, to end: Int, tree: inout ProtocolTreeBuilder) -> String {
        let type = frame[start]
        let length = Int(frame.u32be(start) & 0x00FF_FFFF)
        let name = handshakeName(type)
        tree.field("Handshake Type", "\(name) (\(type)), \(length) bytes", start..<min(end, start + 4))
        tree.setSummary(" Handshake: \(name)")
        let body = start + 4
        let bodyEnd = min(end, body + length)
        guard type == 1 || type == 2, body + 38 <= bodyEnd else { return name }
        tree.field("Legacy Version", versionName(frame.u16be(body)), body..<(body + 2), level: 1)
        tree.field("Random", PacketDissector.hex(frame, body + 2, 32, limit: 8), (body + 2)..<(body + 34), level: 1)
        let sessionIDLength = Int(frame[body + 34])
        var p = body + 35 + sessionIDLength
        var detail: [String] = []
        if type == 1 {
            guard p + 2 <= bodyEnd else { return name }
            let suitesLength = Int(frame.u16be(p))
            let suitesEnd = min(bodyEnd, p + 2 + suitesLength)
            var suites: [String] = []
            var q = p + 2
            while q + 2 <= suitesEnd, suites.count < 64 {
                suites.append(cipherSuiteName(frame.u16be(q)))
                q += 2
            }
            tree.field("Cipher Suites", "\(suitesLength / 2): " + suites.prefix(6).joined(separator: ", ") + (suites.count > 6 ? ", …" : ""),
                       p..<suitesEnd, level: 1)
            p = suitesEnd
            guard p + 1 <= bodyEnd else { return name }
            p += 1 + Int(frame[p])  // compression methods
        } else {
            guard p + 3 <= bodyEnd else { return name }
            let suite = cipherSuiteName(frame.u16be(p))
            tree.field("Cipher Suite", suite, p..<(p + 2), level: 1)
            detail.append(suite)
            p += 3
        }
        guard p + 2 <= bodyEnd else { return name }
        let extensionsEnd = min(bodyEnd, p + 2 + Int(frame.u16be(p)))
        p += 2
        var count = 0
        while p + 4 <= extensionsEnd, count < 64 {
            count += 1
            let extType = frame.u16be(p), extLength = Int(frame.u16be(p + 2))
            let value = (p + 4)..<min(extensionsEnd, p + 4 + extLength)
            switch extType {
            case 0 where value.count >= 5:
                let host = String(decoding: frame.slice(value.lowerBound + 5, Int(frame.u16be(value.lowerBound + 3))), as: UTF8.self)
                tree.field("Server Name (SNI)", host, p..<value.upperBound, level: 1)
                detail.append("SNI=\(host)")
            case 16 where value.count >= 3:
                var protocols: [String] = []
                var q = value.lowerBound + 2
                while q < value.upperBound, protocols.count < 16 {
                    let length = Int(frame[q])
                    protocols.append(String(decoding: frame.slice(q + 1, min(length, value.upperBound - q - 1)), as: UTF8.self))
                    q += 1 + length
                }
                tree.field("ALPN", protocols.joined(separator: ", "), p..<value.upperBound, level: 1)
            case 43:
                var versions: [String] = []
                if type == 1, !value.isEmpty {
                    var q = value.lowerBound + 1
                    while q + 2 <= value.upperBound, versions.count < 16 {
                        versions.append(versionName(frame.u16be(q)))
                        q += 2
                    }
                } else if value.count >= 2 {
                    versions = [versionName(frame.u16be(value.lowerBound))]
                    detail.append(versions[0])
                }
                tree.field("Supported Versions", versions.joined(separator: ", "), p..<value.upperBound, level: 1)
            default:
                tree.field("Extension", "\(extensionName(extType)) (\(extType)), \(extLength) bytes", p..<value.upperBound, level: 1)
            }
            p = value.upperBound
        }
        return detail.isEmpty ? name : "\(name) (\(detail.joined(separator: ", ")))"
    }

    static func contentType(_ type: UInt8) -> String {
        switch type {
        case 20: return "Change Cipher Spec"
        case 21: return "Alert"
        case 22: return "Handshake"
        case 23: return "Application Data"
        default: return "Type \(type)"
        }
    }

    static func handshakeName(_ type: UInt8) -> String {
        let names = [0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 8: "Encrypted Extensions",
                     11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request", 14: "Server Hello Done",
                     15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished"]
        return names[Int(type)] ?? "Handshake \(type)"
    }

    static func versionName(_ version: UInt16) -> String {
        switch version {
        case 0x0300: return "SSL 3.0"
        case 0x0301: return "TLS 1.0"
        case 0x0302: return "TLS 1.1"
        case 0x0303: return "TLS 1.2"
        case 0x0304: return "TLS 1.3"
        default: return version & 0x0F0F == 0x0A0A ? "GREASE" : String(format: "0x%04x", version)
        }
    }

    static func cipherSuiteName(_ suite: UInt16) -> String {
        let names: [UInt16: String] = [
            0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA", 0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        ]
        if let name = names[suite] { return name }
        return suite & 0x0F0F == 0x0A0A ? "GREASE" : String(format: "0x%04x", suite)
    }

    static func extensionName(_ type: UInt16) -> String {
        let names: [UInt16: String] = [1: "max_fragment_length", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
                                       13: "signature_algorithms", 14: "use_srtp", 18: "signed_certificate_timestamp", 21: "padding",
                                       23: "extended_master_secret", 35: "session_ticket", 41: "pre_shared_key", 42: "early_data",
                                       45: "psk_key_exchange_modes", 51: "key_share", 65281: "renegotiation_info"]
        return names[type] ?? (type & 0x0F0F == 0x0A0A ? "GREASE" : "extension")
    }
}

/// STUN (RFC 8489) and its TURN (RFC 8656) and ICE (RFC 8445) extensions.
struct STUNDissector: ProtocolDissector {
    let name = "stun"
    static let magicCookie: UInt32 = 0x2112_A442

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        guard case .transportPayload = layer else { return false }
        return Self.isSTUN(payload)
    }

    static func isSTUN(_ payload: UnsafeRawBufferPointer) -> Bool {
        guard payload.count >= 20, payload[0] & 0xC0 == 0, payload.u32be(4) == magicCookie else { return false }
        let length = Int(payload.u16be(2))
        return length % 4 == 0 && 20 + length <= payload.count
    }

    /// TURN methods; the rest are STUN/ICE (Binding).
    static func isTURNMethod(_ method: UInt16) -> Bool { (3...9).contains(method) }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        let type = frame.u16be(b)
        let method = (type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2)
        let messageClass = ((type & 0x0010) >> 4) | ((type & 0x0100) >> 7)
        let length = Int(frame.u16be(b + 2))
        let label = "\(Self.methodName(method)) \(Self.className(messageClass))"
        let turn = Self.isTURNMethod(method)
        tree.layer(turn ? "turn" : name, turn ? "Traversal Using Relays around NAT" : "Session Traversal Utilities for NAT",
                   " \(label)", range: b..<(b + 20 + length))
        tree.field("Message Type", String(format: "%@ (0x%04x)", label, type), b..<(b + 2))
        tree.field("Message Length", "\(length)", (b + 2)..<(b + 4))
        tree.field("Magic Cookie", String(format: "0x%08x", Self.magicCookie), (b + 4)..<(b + 8))
        tree.field("Transaction ID", PacketDissector.hex(frame, b + 8, 12), (b + 8)..<(b + 20))

        var p = b + 20
        let end = b + 20 + length
        var notes: [String] = []
        var count = 0
        while p + 4 <= end, count < 64 {
            count += 1
            let attribute = frame.u16be(p), attributeLength = Int(frame.u16be(p + 2))
            let valueStart = p + 4
            let valueEnd = min(end, valueStart + attributeLength)
            let value = frame.slice(valueStart, valueEnd - valueStart)
            let (label, text) = Self.attribute(attribute, value, transactionID: frame.slice(b + 8, 12))
            if [0x0020, 0x0016, 0x0012, 0x0001].contains(attribute), !text.isEmpty { notes.append("\(label): \(text)") }
            if attribute == 0x0009 { notes.append(text) }
            tree.field(label, text, p..<valueEnd, level: 1)
            p = valueStart + ((attributeLength + 3) & ~3)
        }
        context.summary = (turn ? "TURN " : "STUN ") + ([label] + notes.prefix(2)).joined(separator: " ")
        return .end
    }

    static func methodName(_ method: UInt16) -> String {
        let names: [UInt16: String] = [1: "Binding", 3: "Allocate", 4: "Refresh", 6: "Send", 7: "Data", 8: "CreatePermission",
                                       9: "ChannelBind", 10: "Connect", 11: "ConnectionBind", 12: "ConnectionAttempt"]
        return names[method] ?? String(format: "Method 0x%03x", method)
    }

    static func className(_ value: UInt16) -> String {
        ["Request", "Indication", "Success Response", "Error Response"][Int(value & 3)]
    }

    static func xorAddress(_ value: UnsafeRawBufferPointer, transactionID: UnsafeRawBufferPointer) -> String {
        guard value.count >= 8 else { return "" }
        let family = value[1]
        let port = value.u16be(2) ^ 0x2112
        if family == 1 {
            let address = value.u32be(4) ^ magicCookie
            return "\(IPAddress.v4(address)):\(port)"
        }
        guard family == 2, value.count >= 20, transactionID.count == 12 else { return "" }
        let key: [UInt8] = [0x21, 0x12, 0xA4, 0x42] + Array(transactionID)
        let bytes = (0..<16).map { value[4 + $0] ^ key[$0] }
        let address = bytes.withUnsafeBytes { IPAddress(bytes: $0) }
        return "[\(address?.description ?? "?")]:\(port)"
    }

    static func plainAddress(_ value: UnsafeRawBufferPointer) -> String {
        guard value.count >= 8 else { return "" }
        let port = value.u16be(2)
        if value[1] == 1 { return "\(PacketDissector.ipv4(value, 4)):\(port)" }
        return value.count >= 20 ? "[\(PacketDissector.ipv6(value, 4))]:\(port)" : ""
    }

    static func attribute(_ type: UInt16, _ value: UnsafeRawBufferPointer, transactionID: UnsafeRawBufferPointer) -> (String, String) {
        let text = String(decoding: value, as: UTF8.self)
        switch type {
        case 0x0001: return ("MAPPED-ADDRESS", plainAddress(value))
        case 0x0006: return ("USERNAME", text)
        case 0x0008: return ("MESSAGE-INTEGRITY", PacketDissector.hex(value, 0, value.count, limit: 8))
        case 0x0009:
            guard value.count >= 4 else { return ("ERROR-CODE", "") }
            let code = Int(value[2] & 0x07) * 100 + Int(value[3])
            return ("ERROR-CODE", "\(code) \(String(decoding: value.slice(4, value.count - 4), as: UTF8.self))")
        case 0x000A: return ("UNKNOWN-ATTRIBUTES", stride(from: 0, to: value.count - 1, by: 2).map { String(format: "0x%04x", value.u16be($0)) }.joined(separator: ", "))
        case 0x000C: return ("CHANNEL-NUMBER", value.count >= 2 ? String(format: "0x%04x", value.u16be(0)) : "")
        case 0x000D: return ("LIFETIME", value.count >= 4 ? "\(value.u32be(0)) s" : "")
        case 0x0012: return ("XOR-PEER-ADDRESS", xorAddress(value, transactionID: transactionID))
        case 0x0013: return ("DATA", "\(value.count) bytes")
        case 0x0014: return ("REALM", text)
        case 0x0015: return ("NONCE", text)
        case 0x0016: return ("XOR-RELAYED-ADDRESS", xorAddress(value, transactionID: transactionID))
        case 0x0019: return ("REQUESTED-TRANSPORT", value.first == 17 ? "UDP" : value.first == 6 ? "TCP" : "\(value.first ?? 0)")
        case 0x001C: return ("MESSAGE-INTEGRITY-SHA256", PacketDissector.hex(value, 0, value.count, limit: 8))
        case 0x0020: return ("XOR-MAPPED-ADDRESS", xorAddress(value, transactionID: transactionID))
        case 0x0024: return ("PRIORITY", value.count >= 4 ? "\(value.u32be(0))" : "")
        case 0x0025: return ("USE-CANDIDATE", "")
        case 0x8022: return ("SOFTWARE", text)
        case 0x8028: return ("FINGERPRINT", value.count >= 4 ? String(format: "0x%08x", value.u32be(0)) : "")
        case 0x8029: return ("ICE-CONTROLLED", PacketDissector.hex(value, 0, value.count))
        case 0x802A: return ("ICE-CONTROLLING", PacketDissector.hex(value, 0, value.count))
        case 0xC057: return ("GOOG-NETWORK-INFO", value.count >= 4 ? "network \(value.u16be(0)), cost \(value.u16be(2))" : "")
        default: return (String(format: "Attribute 0x%04x", type), "\(value.count) bytes")
        }
    }
}

/// TURN ChannelData messages (RFC 8656 §12.4): relayed application data framed by a channel number.
struct TURNChannelDataDissector: ProtocolDissector {
    let name = "turn.channel"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        guard case .transportPayload = layer, payload.count >= 4, context.usesPort(3478) || context.usesPort(5349) else { return false }
        let channel = payload.u16be(0)
        let length = Int(payload.u16be(2))
        return (0x4000...0x4FFF).contains(channel) && 4 + length <= payload.count && payload.count - (4 + length) < 4
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        let b = range.lowerBound
        let channel = frame.u16be(b), length = Int(frame.u16be(b + 2))
        tree.layer("turn", "TURN ChannelData", String(format: " Channel 0x%04x, %d bytes", channel, length), range: b..<(b + 4))
        tree.field("Channel Number", String(format: "0x%04x", channel), b..<(b + 2))
        tree.field("Length", "\(length)", (b + 2)..<(b + 4))
        context.summary = String(format: "TURN ChannelData 0x%04x, %d bytes", channel, length)
        // The relayed payload is usually RTP/RTCP or DTLS: let the UDP dissectors try it.
        return DissectionStep(next: .transportPayload(.udp), payload: (b + 4)..<(b + 4 + length))
    }
}

/// DTLS records (RFC 6347 / 9147 framing), as used by WebRTC for DTLS-SRTP keying. Handshake types are named;
/// encrypted content stays opaque.
struct DTLSDissector: ProtocolDissector {
    let name = "dtls"

    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
        layer == .transportPayload(.udp) && DTLSDetector.looksLikeDTLS(payload)
    }

    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep {
        var p = range.lowerBound
        var names: [String] = []
        var records = 0
        while p + 13 <= range.upperBound, records < 32, DTLSDetector.looksLikeDTLS(frame.slice(p, range.upperBound - p)) {
            records += 1
            let type = frame[p]
            let version = frame.u16be(p + 1)
            let epoch = frame.u16be(p + 3)
            let sequence = UInt64(frame.u16be(p + 5)) << 32 | UInt64(frame.u32be(p + 7))
            let length = Int(frame.u16be(p + 11))
            let end = min(range.upperBound, p + 13 + length)
            var label = TLSDissector.contentType(type)
            if type == 22, epoch == 0, p + 14 <= end {
                label = TLSDissector.handshakeName(frame[p + 13])
            } else if type == 22 {
                label = "Encrypted Handshake Message"
            }
            names.append(label)
            tree.layer(name, "Datagram Transport Layer Security", " \(label)", range: p..<end)
            tree.field("Content Type", "\(TLSDissector.contentType(type)) (\(type))", p..<(p + 1))
            tree.field("Version", version == 0xFEFD ? "DTLS 1.2" : version == 0xFEFF ? "DTLS 1.0" : String(format: "0x%04x", version), (p + 1)..<(p + 3))
            tree.field("Epoch · Sequence", "\(epoch) · \(sequence)", (p + 3)..<(p + 11))
            tree.field("Length", "\(length)", (p + 11)..<(p + 13))
            if type == 22, epoch == 0, p + 14 <= end { tree.field("Handshake Type", label, (p + 13)..<(p + 14)) }
            p = end
        }
        context.summary = "DTLS " + names.joined(separator: ", ")
        return .end
    }
}
