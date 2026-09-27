import Foundation

/// Deterministic random numbers (SplitMix64) so generated captures are reproducible.
public struct SeededRandom: RandomNumberGenerator, Sendable {
    private var state: UInt64

    public init(seed: UInt64) { state = seed }

    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    public mutating func uniform() -> Double { Double(next() >> 11) / Double(1 << 53) }

    /// Standard normal sample (Box–Muller).
    public mutating func gaussian() -> Double {
        let u1 = max(uniform(), 1e-12), u2 = uniform()
        return sqrt(-2 * log(u1)) * cos(2 * .pi * u2)
    }

    public mutating func chance(_ probability: Double) -> Bool { uniform() < probability }
}

/// Builds raw Ethernet / IPv4 / IPv6 / UDP / TCP frames.
public enum FrameBuilder {
    public static func mac(for ip: String) -> [UInt8] {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        let tail = parts.count == 4 ? parts : [0, 0, 0, UInt8(truncatingIfNeeded: ip.hashValue)]
        return [0x00, 0x1B, tail[0] ^ 0x21, tail[1], tail[2], tail[3]]
    }

    static func ipv4Bytes(_ ip: String) -> [UInt8] {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        precondition(parts.count == 4, "invalid IPv4 \(ip)")
        return parts
    }

    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < bytes.count {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(sum)
    }

    public static func ethernet(source: String, destination: String, etherType: UInt16, payload: [UInt8],
                                vlan: UInt16? = nil) -> [UInt8] {
        var frame = mac(for: destination) + mac(for: source)
        if let vlan {
            frame += [0x81, 0x00, UInt8(vlan >> 8), UInt8(vlan & 0xFF)]
        }
        frame += [UInt8(etherType >> 8), UInt8(etherType & 0xFF)]
        frame += payload
        if frame.count < 60 { frame += [UInt8](repeating: 0, count: 60 - frame.count) }  // Ethernet padding
        return frame
    }

    public static func ipv4Header(source: String, destination: String, protocolNumber: UInt8, payloadLength: Int,
                                  identification: UInt16, ttl: UInt8 = 64, dscp: UInt8 = 0,
                                  moreFragments: Bool = false, fragmentOffset: Int = 0) -> [UInt8] {
        let total = 20 + payloadLength
        let flags: UInt16 = (moreFragments ? 0x2000 : 0) | UInt16(fragmentOffset / 8)
        var header: [UInt8] = [0x45, dscp << 2, UInt8(total >> 8), UInt8(total & 0xFF),
                               UInt8(identification >> 8), UInt8(identification & 0xFF),
                               UInt8(flags >> 8), UInt8(flags & 0xFF), ttl, protocolNumber, 0, 0]
        header += ipv4Bytes(source) + ipv4Bytes(destination)
        let sum = checksum(header)
        header[10] = UInt8(sum >> 8)
        header[11] = UInt8(sum & 0xFF)
        return header
    }

    public static func udp(sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) -> [UInt8] {
        let length = 8 + payload.count
        return [UInt8(sourcePort >> 8), UInt8(sourcePort & 0xFF), UInt8(destinationPort >> 8), UInt8(destinationPort & 0xFF),
                UInt8(length >> 8), UInt8(length & 0xFF), 0, 0] + payload
    }

    public static func tcp(sourcePort: UInt16, destinationPort: UInt16, sequence: UInt32, acknowledgment: UInt32,
                           flags: UInt8, payload: [UInt8]) -> [UInt8] {
        var segment: [UInt8] = [UInt8(sourcePort >> 8), UInt8(sourcePort & 0xFF), UInt8(destinationPort >> 8), UInt8(destinationPort & 0xFF)]
        segment += withUnsafeBytes(of: sequence.bigEndian, Array.init)
        segment += withUnsafeBytes(of: acknowledgment.bigEndian, Array.init)
        segment += [0x50, flags, 0xFF, 0xFF, 0, 0, 0, 0]
        return segment + payload
    }

    /// A complete Ethernet/IPv4/UDP frame.
    public static func udpFrame(source: String, sourcePort: UInt16, destination: String, destinationPort: UInt16,
                                payload: [UInt8], identification: UInt16, dscp: UInt8 = 0, vlan: UInt16? = nil) -> [UInt8] {
        let datagram = udp(sourcePort: sourcePort, destinationPort: destinationPort, payload: payload)
        let ip = ipv4Header(source: source, destination: destination, protocolNumber: 17, payloadLength: datagram.count,
                            identification: identification, dscp: dscp)
        return ethernet(source: source, destination: destination, etherType: 0x0800, payload: ip + datagram, vlan: vlan)
    }

    /// Splits a UDP datagram into IPv4 fragments of at most `mtu` bytes of IP payload per fragment.
    public static func fragmentedUDPFrames(source: String, sourcePort: UInt16, destination: String, destinationPort: UInt16,
                                           payload: [UInt8], identification: UInt16, mtu: Int = 1480) -> [[UInt8]] {
        let datagram = udp(sourcePort: sourcePort, destinationPort: destinationPort, payload: payload)
        let chunk = mtu / 8 * 8
        var frames: [[UInt8]] = []
        var offset = 0
        while offset < datagram.count {
            let end = min(datagram.count, offset + chunk)
            let piece = Array(datagram[offset..<end])
            let ip = ipv4Header(source: source, destination: destination, protocolNumber: 17, payloadLength: piece.count,
                                identification: identification, moreFragments: end < datagram.count, fragmentOffset: offset)
            frames.append(ethernet(source: source, destination: destination, etherType: 0x0800, payload: ip + piece))
            offset = end
        }
        return frames
    }

    public static func tcpFrame(source: String, sourcePort: UInt16, destination: String, destinationPort: UInt16,
                                sequence: UInt32, acknowledgment: UInt32 = 0, flags: UInt8 = 0x18, payload: [UInt8],
                                identification: UInt16) -> [UInt8] {
        let segment = tcp(sourcePort: sourcePort, destinationPort: destinationPort, sequence: sequence,
                          acknowledgment: acknowledgment, flags: flags, payload: payload)
        let ip = ipv4Header(source: source, destination: destination, protocolNumber: 6, payloadLength: segment.count,
                            identification: identification)
        return ethernet(source: source, destination: destination, etherType: 0x0800, payload: ip + segment)
    }

    /// ARP request (who-has) or reply over Ethernet.
    public static func arpFrame(reply: Bool, senderIP: String, targetIP: String) -> [UInt8] {
        let senderMAC = mac(for: senderIP)
        let targetMAC: [UInt8] = reply ? mac(for: targetIP) : [0, 0, 0, 0, 0, 0]
        let body: [UInt8] = [0, 1, 0x08, 0x00, 6, 4, 0, reply ? 2 : 1] + senderMAC + ipv4Bytes(senderIP) + targetMAC + ipv4Bytes(targetIP)
        var frame = (reply ? mac(for: targetIP) : [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) + senderMAC + [0x08, 0x06] + body
        if frame.count < 60 { frame += [UInt8](repeating: 0, count: 60 - frame.count) }
        return frame
    }

    /// ICMP echo request/reply inside Ethernet/IPv4.
    public static func icmpEchoFrame(source: String, destination: String, reply: Bool, identifier: UInt16, sequence: UInt16,
                                     payload: [UInt8] = Array("WirePath ping".utf8), ttl: UInt8 = 64) -> [UInt8] {
        var message: [UInt8] = [reply ? 0 : 8, 0, 0, 0, UInt8(identifier >> 8), UInt8(identifier & 0xFF),
                                UInt8(sequence >> 8), UInt8(sequence & 0xFF)] + payload
        let sum = checksum(message)
        message[2] = UInt8(sum >> 8)
        message[3] = UInt8(sum & 0xFF)
        let ip = ipv4Header(source: source, destination: destination, protocolNumber: 1, payloadLength: message.count,
                            identification: sequence, ttl: ttl)
        return ethernet(source: source, destination: destination, etherType: 0x0800, payload: ip + message)
    }

    /// DNS A query, or its answer when `answer` is given.
    public static func dnsMessage(id: UInt16, name: String, answer: String? = nil, type: UInt16 = 1) -> [UInt8] {
        var message: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), answer == nil ? 0x01 : 0x81, answer == nil ? 0x00 : 0x80,
                                0, 1, 0, answer == nil ? 0 : 1, 0, 0, 0, 0]
        for label in name.split(separator: ".") { message.append(UInt8(label.count)); message += Array(label.utf8) }
        message += [0, UInt8(type >> 8), UInt8(type & 0xFF), 0, 1]
        if let answer {
            message += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4] + ipv4Bytes(answer)
        }
        return message
    }

    /// Ethernet/IPv6/UDP frame; addresses as 16-byte arrays.
    public static func udp6Frame(source: [UInt8], sourcePort: UInt16, destination: [UInt8], destinationPort: UInt16,
                                 payload: [UInt8]) -> [UInt8] {
        var datagram = udp(sourcePort: sourcePort, destinationPort: destinationPort, payload: payload)
        // The UDP checksum is mandatory over IPv6 (RFC 8200 §8.1): pseudo-header + datagram.
        let length = UInt32(datagram.count)
        let pseudo = source + destination + withUnsafeBytes(of: length.bigEndian, Array.init) + [0, 0, 0, 17]
        let sum = checksum(pseudo + datagram)
        datagram[6] = UInt8((sum == 0 ? 0xFFFF : sum) >> 8)
        datagram[7] = UInt8((sum == 0 ? 0xFFFF : sum) & 0xFF)
        var ip: [UInt8] = [0x60, 0, 0, 0, UInt8(datagram.count >> 8), UInt8(datagram.count & 0xFF), 17, 64]
        ip += source + destination
        let frame: [UInt8] = [0x00, 0x1B, 0x21, 0, 0, 1, 0x00, 0x1B, 0x21, 0, 0, 2, 0x86, 0xDD] + ip + datagram
        return frame
    }
}

public struct TimedFrame: Sendable {
    public var time: Double
    public var bytes: [UInt8]

    public init(time: Double, bytes: [UInt8]) {
        self.time = time
        self.bytes = bytes
    }
}

/// Writes classic pcap or pcapng files, either to memory or incrementally to disk.
public final class CaptureWriter {
    public enum Format: Sendable {
        case pcap(nanosecond: Bool, bigEndian: Bool)
        case pcapng
    }

    public let format: Format
    public let baseTime: Double
    private var output: FileHandle?
    public private(set) var data = Data()
    private var pending = Data()

    public init(format: Format = .pcap(nanosecond: false, bigEndian: false), baseTime: Double, url: URL? = nil,
                linkType: UInt32 = 1) throws {
        self.format = format
        self.baseTime = baseTime
        if let url {
            FileManager.default.createFile(atPath: url.path, contents: nil)
            output = try FileHandle(forWritingTo: url)
        }
        writeHeader(linkType: linkType)
    }

    private func u16(_ v: UInt16, _ big: Bool) -> [UInt8] {
        big ? [UInt8(v >> 8), UInt8(v & 0xFF)] : [UInt8(v & 0xFF), UInt8(v >> 8)]
    }

    private func u32(_ v: UInt32, _ big: Bool) -> [UInt8] {
        big ? [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
            : [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)]
    }

    private func emit(_ bytes: [UInt8]) {
        pending.append(contentsOf: bytes)
        if pending.count > (4 << 20) { flush() }
    }

    private func writeHeader(linkType: UInt32) {
        switch format {
        case .pcap(let ns, let big):
            let magic: UInt32 = ns ? 0xA1B2_3C4D : 0xA1B2_C3D4
            emit(u32(magic, big) + u16(2, big) + u16(4, big) + u32(0, big) + u32(0, big) + u32(262_144, big) + u32(linkType, big))
        case .pcapng:
            // SHB
            let shbBody = u32(0x1A2B_3C4D, false) + u16(1, false) + u16(0, false) + [UInt8](repeating: 0xFF, count: 8)
            let shbLength = UInt32(12 + shbBody.count)
            emit(u32(0x0A0D_0D0A, false) + u32(shbLength, false) + shbBody + u32(shbLength, false))
            // IDB with if_tsresol = 9 (nanoseconds)
            let options = u16(9, false) + u16(1, false) + [9, 0, 0, 0] + u16(0, false) + u16(0, false)
            let idbBody = u16(UInt16(linkType), false) + u16(0, false) + u32(262_144, false) + options
            let idbLength = UInt32(12 + idbBody.count)
            emit(u32(1, false) + u32(idbLength, false) + idbBody + u32(idbLength, false))
        }
    }

    public func write(_ frame: TimedFrame) {
        let absolute = baseTime + frame.time
        let seconds = floor(absolute)
        let fraction = absolute - seconds
        switch format {
        case .pcap(let ns, let big):
            let sub = UInt32(min(ns ? 999_999_999 : 999_999, (fraction * (ns ? 1e9 : 1e6)).rounded()))
            emit(u32(UInt32(seconds), big) + u32(sub, big) + u32(UInt32(frame.bytes.count), big)
                 + u32(UInt32(frame.bytes.count), big) + frame.bytes)
        case .pcapng:
            let nanos = UInt64(seconds) * 1_000_000_000 + UInt64((fraction * 1e9).rounded())
            let padded = (frame.bytes.count + 3) & ~3
            let length = UInt32(32 + padded)
            var block = u32(6, false) + u32(length, false) + u32(0, false)
            block += u32(UInt32(nanos >> 32), false) + u32(UInt32(nanos & 0xFFFF_FFFF), false)
            block += u32(UInt32(frame.bytes.count), false) + u32(UInt32(frame.bytes.count), false)
            block += frame.bytes + [UInt8](repeating: 0, count: padded - frame.bytes.count)
            block += u32(length, false)
            emit(block)
        }
    }

    public func flush() {
        if let output {
            output.write(pending)
        } else {
            data.append(pending)
        }
        pending.removeAll(keepingCapacity: true)
    }

    public func close() {
        flush()
        try? output?.close()
        output = nil
    }
}
