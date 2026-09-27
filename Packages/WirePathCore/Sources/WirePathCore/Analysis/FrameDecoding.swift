import Foundation

/// Application-layer interpretation made during the parallel decode stage.
enum AppLayer: Sendable {
    case none
    indirect case sip(SIPMessage)
    case rtp(RTPHeader)
    case rtcp
    case known(PacketProtocol)
}

struct DecodedFrame: Sendable {
    var frame: CapturedFrame
    var packet: DecodedPacket
    var app: AppLayer
}

enum FrameDecoding {
    /// UDP ports whose traffic is never treated as RTP by the heuristics.
    static let nonRTPPorts: Set<UInt16> = [53, 67, 68, 69, 123, 137, 138, 161, 162, 443, 500, 514, 520, 1812, 1813,
                                            1900, 3478, 4500, 5060, 5061, 5353, 5355]

    static func knownUDP(_ packet: DecodedPacket) -> PacketProtocol? {
        let ports = (packet.sourcePort, packet.destinationPort)
        func either(_ p: UInt16) -> Bool { ports.0 == p || ports.1 == p }
        if either(53) || either(5353) || either(5355) { return .dns }
        if either(67) || either(68) { return .dhcp }
        if either(123) { return .ntp }
        return nil
    }

    /// STUN/TURN recognized by content (the magic cookie), which works on the random ports WebRTC uses.
    static func stunKind(_ payload: UnsafeRawBufferPointer, _ packet: DecodedPacket) -> PacketProtocol? {
        if STUNDissector.isSTUN(payload) {
            let type = payload.u16be(0)
            let method = (type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2)
            return STUNDissector.isTURNMethod(method) ? .turn : .stun
        }
        let turnPort = [3478, 5349].contains(packet.sourcePort) || [3478, 5349].contains(packet.destinationPort)
        if turnPort, payload.count >= 4, (0x4000...0x4FFF).contains(payload.u16be(0)) { return .turn }
        return nil
    }

    /// Protocols recognized in a TCP segment on its own (no reassembly): TLS records, HTTP/1.x start lines, STUN.
    /// Segments continuing a record or message are left as TCP, as Wireshark labels them without reassembly.
    static func knownTCP(_ payload: UnsafeRawBufferPointer, _ packet: DecodedPacket) -> PacketProtocol? {
        guard !payload.isEmpty else { return nil }
        if TLSDissector.looksLikeTLS(payload) { return .tls }
        if HTTPDissector.looksLikeHTTP(payload) { return .http }
        return stunKind(payload, packet)
    }

    /// Stateless decoding of one frame: headers, SIP over UDP, RTP/RTCP headers.
    static func decode(_ frame: CapturedFrame, file: CaptureFile) -> DecodedFrame {
        let bytes = file.bytes(offset: frame.dataOffset, length: frame.capturedLength)
        let packet = PacketDecoder.decode(bytes, linkType: frame.linkType)
        var app = AppLayer.none
        if packet.ipProtocol == 17, packet.hasTransportHeader, packet.fragment == nil, packet.payloadLength > 0 {
            let payload = UnsafeRawBufferPointer(rebasing: bytes[packet.payloadOffset..<(packet.payloadOffset + packet.payloadLength)])
            if SIPParser.looksLikeSIP(payload), let message = SIPParser.parse(payload) {
                app = .sip(message)
            } else if let stun = stunKind(payload, packet) {
                app = .known(stun)
            } else if DTLSDetector.looksLikeDTLS(payload) {
                app = .known(.dtls)
            } else if let known = knownUDP(packet) {
                app = .known(known)
            } else if !nonRTPPorts.contains(packet.sourcePort), !nonRTPPorts.contains(packet.destinationPort) {
                if RTCPDetector.looksLikeRTCP(payload) {
                    app = .rtcp
                } else if let header = RTPHeader.parse(payload) {
                    app = .rtp(header)
                }
            }
        } else if packet.ipProtocol == 6, packet.hasTransportHeader, packet.fragment == nil {
            let payload = bytes.slice(packet.payloadOffset, packet.payloadLength)
            if !SIPParser.looksLikeSIP(payload), let known = knownTCP(payload, packet) { app = .known(known) }
        }
        return DecodedFrame(frame: frame, packet: packet, app: app)
    }

    /// Decodes a batch using all performance cores, as consecutive chunks in capture order (not concatenated: that
    /// would copy the whole batch once more).
    static func decodeBatch(_ frames: [CapturedFrame], file: CaptureFile) async -> [[DecodedFrame]] {
        let chunkSize = 4096
        guard frames.count > chunkSize else { return [frames.map { decode($0, file: file) }] }
        let chunkCount = (frames.count + chunkSize - 1) / chunkSize
        return await withTaskGroup(of: (Int, [DecodedFrame]).self) { group in
            for chunk in 0..<chunkCount {
                let range = (chunk * chunkSize)..<min(frames.count, (chunk + 1) * chunkSize)
                let slice = Array(frames[range])
                group.addTask {
                    (chunk, slice.map { decode($0, file: file) })
                }
            }
            var parts = [[DecodedFrame]](repeating: [], count: chunkCount)
            for await (chunk, decoded) in group { parts[chunk] = decoded }
            return parts
        }
    }
}
