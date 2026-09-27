import Foundation

/// Byte-level builders for the application protocols in the `application-protocols` fixture. Every message is
/// well-formed (checksums, lengths, STUN fingerprints) so tshark decodes it without warnings.
public enum ProtocolBuilders {
    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
    static func be32(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.bigEndian, Array.init) }
    /// Concatenates byte fields. Long `+` chains of array literals take older compilers too long to type-check.
    static func join(_ parts: [UInt8]...) -> [UInt8] { parts.flatMap { $0 } }

    // MARK: TCP with options

    /// A TCP segment whose header carries `options` (padded to 32 bits).
    public static func tcpFrame(source: String, sourcePort: UInt16, destination: String, destinationPort: UInt16,
                                sequence: UInt32, acknowledgment: UInt32, flags: UInt8, options: [UInt8],
                                payload: [UInt8] = [], identification: UInt16) -> [UInt8] {
        var padded = options
        while padded.count % 4 != 0 { padded.append(1) }  // NOP padding
        let headerLength = 20 + padded.count
        var segment = be16(sourcePort) + be16(destinationPort) + be32(sequence) + be32(acknowledgment)
        segment += [UInt8(headerLength / 4) << 4, flags, 0xFF, 0xFF, 0, 0, 0, 0] + padded + payload
        let pseudo = FrameBuilder.ipv4Bytes(source) + FrameBuilder.ipv4Bytes(destination) + [0, 6] + be16(UInt16(segment.count))
        let sum = FrameBuilder.checksum(pseudo + segment)
        segment[16] = UInt8(sum >> 8)
        segment[17] = UInt8(sum & 0xFF)
        let ip = FrameBuilder.ipv4Header(source: source, destination: destination, protocolNumber: 6, payloadLength: segment.count,
                                         identification: identification)
        return FrameBuilder.ethernet(source: source, destination: destination, etherType: 0x0800, payload: ip + segment)
    }

    /// MSS 1460, SACK permitted, timestamps, window scale 7 — a typical SYN.
    public static let synOptions: [UInt8] = [2, 4, 0x05, 0xB4, 4, 2, 8, 10, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 1, 3, 3, 7]

    // MARK: DHCP

    public static func dhcp(op: UInt8, messageType: UInt8, transactionID: UInt32, clientMAC: [UInt8], yourIP: String = "0.0.0.0",
                            options: [(UInt8, [UInt8])]) -> [UInt8] {
        var message: [UInt8] = [op, 1, 6, 0] + be32(transactionID) + [0, 0, 0x80, 0]
        message += [0, 0, 0, 0] + FrameBuilder.ipv4Bytes(yourIP) + [0, 0, 0, 0] + [0, 0, 0, 0]
        message += clientMAC + [UInt8](repeating: 0, count: 10) + [UInt8](repeating: 0, count: 64 + 128)
        message += [0x63, 0x82, 0x53, 0x63, 53, 1, messageType]
        for (code, value) in options { message += [code, UInt8(value.count)] + value }
        message.append(255)
        while message.count < 300 { message.append(0) }
        return message
    }

    // MARK: DNS

    static func dnsName(_ name: String) -> [UInt8] {
        name.split(separator: ".").flatMap { [UInt8($0.count)] + Array($0.utf8) } + [0]
    }

    /// A DNS response with one question and the given answers (pre-encoded RDATA), names uncompressed.
    public static func dnsResponse(id: UInt16, question: String, type: UInt16, answers: [(type: UInt16, data: [UInt8])]) -> [UInt8] {
        var message = join(be16(id), [0x81, 0x80], be16(1), be16(UInt16(answers.count)), be16(0), be16(0))
        message += join(dnsName(question), be16(type), be16(1))
        for answer in answers {
            message += join([0xC0, 0x0C], be16(answer.type), be16(1), be32(300), be16(UInt16(answer.data.count)), answer.data)
        }
        return message
    }

    public static func srvData(priority: UInt16, weight: UInt16, port: UInt16, target: String) -> [UInt8] {
        be16(priority) + be16(weight) + be16(port) + dnsName(target)
    }

    public static func naptrData(order: UInt16, preference: UInt16, flags: String, service: String, replacement: String) -> [UInt8] {
        func text(_ s: String) -> [UInt8] { [UInt8(s.utf8.count)] + Array(s.utf8) }
        return be16(order) + be16(preference) + text(flags) + text(service) + text("") + dnsName(replacement)
    }

    // MARK: TLS

    static func tlsRecord(_ handshakeType: UInt8, _ body: [UInt8]) -> [UInt8] {
        let handshake = [handshakeType, 0] + be16(UInt16(body.count)) + body
        return [22, 3, 1] + be16(UInt16(handshake.count)) + handshake
    }

    static func tlsExtension(_ type: UInt16, _ data: [UInt8]) -> [UInt8] { be16(type) + be16(UInt16(data.count)) + data }

    public static func tlsClientHello(serverName: String) -> [UInt8] {
        let name = Array(serverName.utf8)
        let sni = tlsExtension(0, be16(UInt16(name.count + 3)) + [0] + be16(UInt16(name.count)) + name)
        let alpnList: [UInt8] = [2] + Array("h2".utf8) + [8] + Array("http/1.1".utf8)
        let alpn = tlsExtension(16, be16(UInt16(alpnList.count)) + alpnList)
        let versions = tlsExtension(43, [4, 0x03, 0x04, 0x03, 0x03])
        let groups = tlsExtension(10, [0, 4, 0x00, 0x1D, 0x00, 0x17])
        let extensions = sni + alpn + versions + groups
        let suites: [UInt8] = be16(6) + [0x13, 0x01, 0x13, 0x02, 0xC0, 0x2F]
        let body = join([0x03, 0x03], [UInt8](repeating: 0x5A, count: 32), [0], suites, [1, 0],
                        be16(UInt16(extensions.count)), extensions)
        return tlsRecord(1, body)
    }

    public static func tlsServerHello() -> [UInt8] {
        let extensions = tlsExtension(43, [0x03, 0x04])
        let body = join([0x03, 0x03], [UInt8](repeating: 0xA5, count: 32), [0], [0x13, 0x01], [0],
                        be16(UInt16(extensions.count)), extensions)
        // TLS 1.3 servers follow with Change Cipher Spec (compatibility) and encrypted records.
        return tlsRecord(2, body) + [20, 3, 3, 0, 1, 1] + [23, 3, 3, 0, 8] + [UInt8](repeating: 0x33, count: 8)
    }

    // MARK: STUN / TURN

    public static let stunCookie: UInt32 = 0x2112_A442

    static func stunAttribute(_ type: UInt16, _ value: [UInt8]) -> [UInt8] {
        var bytes = be16(type) + be16(UInt16(value.count)) + value
        while bytes.count % 4 != 0 { bytes.append(0) }
        return bytes
    }

    /// XOR-MAPPED/RELAYED/PEER-ADDRESS value for an IPv4 address.
    public static func xorAddress(_ ip: String, port: UInt16) -> [UInt8] {
        let address = FrameBuilder.ipv4Bytes(ip).enumerated().map { $0.element ^ be32(stunCookie)[$0.offset] }
        return [0, 1] + be16(port ^ 0x2112) + address
    }

    /// A STUN message; `fingerprint` appends a correct FINGERPRINT attribute (RFC 8489 §14.7).
    public static func stun(type: UInt16, transactionID: [UInt8], attributes: [(UInt16, [UInt8])], fingerprint: Bool = true) -> [UInt8] {
        var body = attributes.flatMap { stunAttribute($0.0, $0.1) }
        func header(_ length: Int) -> [UInt8] { be16(type) + be16(UInt16(length)) + be32(stunCookie) + transactionID }
        if fingerprint {
            let withoutFingerprint = header(body.count + 8) + body
            let crc = GzipWriter.crc32(Data(withoutFingerprint)) ^ 0x5354_554E
            body += stunAttribute(0x8028, be32(crc))
        }
        return header(body.count) + body
    }

    // MARK: IPv6 / ICMPv6

    public static func icmpv6Frame(source: [UInt8], destination: [UInt8], message: [UInt8], hopLimit: UInt8 = 255) -> [UInt8] {
        var body = message
        let pseudo = source + destination + be32(UInt32(body.count)) + [0, 0, 0, 58]
        let sum = FrameBuilder.checksum(pseudo + body)
        body[2] = UInt8(sum >> 8)
        body[3] = UInt8(sum & 0xFF)
        let ip: [UInt8] = [0x60, 0, 0, 0] + be16(UInt16(body.count)) + [58, hopLimit] + source + destination
        return [0x33, 0x33, 0xFF, 0, 0, 0x20, 0x00, 0x1B, 0x21, 0, 0, 0x10, 0x86, 0xDD] + ip + body
    }

    // MARK: RTCP

    /// A compound RTCP packet: Sender Report with one report block, then SDES with a CNAME.
    public static func rtcpSenderReport(ssrc: UInt32, reportee: UInt32, cname: String, ntpSeconds: UInt32,
                                        ntpFraction: UInt32 = 0x8000_0000, rtpTimestamp: UInt32, packets: UInt32, octets: UInt32,
                                        fractionLost: UInt8, cumulativeLost: UInt32, highestSequence: UInt32, jitter: UInt32) -> [UInt8] {
        var sr: [UInt8] = [0x81, 200] + be16(12) + be32(ssrc) + be32(ntpSeconds) + be32(ntpFraction)
        sr += be32(rtpTimestamp) + be32(packets) + be32(octets)
        sr += be32(reportee) + [fractionLost] + Array(be32(cumulativeLost).suffix(3)) + be32(highestSequence) + be32(jitter)
        sr += be32(0) + be32(0)
        var chunk: [UInt8] = be32(ssrc) + [1, UInt8(cname.utf8.count)] + Array(cname.utf8) + [0]
        while chunk.count % 4 != 0 { chunk.append(0) }
        let sdes: [UInt8] = [0x81, 202] + be16(UInt16(chunk.count / 4)) + chunk
        return sr + sdes
    }
}
