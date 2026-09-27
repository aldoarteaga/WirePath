import Foundation

extension FixtureCatalog {
    /// Test signals shared by the fixture and the tests that check its reconstruction.
    public enum AudioSignals {
        public static func tone(_ hz: Double, rate: Int, from start: Int, count: Int, amplitude: Double = 8000) -> [Int16] {
            (0..<count).map { n in Int16(amplitude * sin(2 * .pi * hz * Double(start + n) / Double(rate))) }
        }

        /// 200 Hz → 3.1 kHz linear sweep at 16 kHz (exercises both G.722 sub-bands).
        public static func sweep(count: Int) -> [Int16] {
            (0..<count).map { n in
                let t = Double(n) / 16000
                return Int16(12000 * sin(2 * .pi * (200 + 1450 * t) * t))
            }
        }

        /// Caller DTMF keys (RFC 4733 events) in the G.711 call: key, start (s), duration (s).
        public static let dtmf: [(event: UInt8, start: Double, duration: Double)] = [(1, 1.0, 0.1), (5, 1.4, 0.1), (11, 1.8, 0.12)]
        /// Caller packets (0-based) dropped in the G.711 call: 100 ms lost.
        public static let lostPackets = 110..<115
        /// Callee silence (comfort noise at −60 dBov) in the G.711 call.
        public static let silence = (startPacket: 50, endPacket: 100, level: UInt8(60))
    }

    /// `audio-codecs.pcap`: five short SIP calls for audio reconstruction. G.711 µ-law with DTMF keys (RFC 4733),
    /// a 100 ms loss and comfort noise (RFC 3389); G.722 with a sweep; L16 at 16 kHz; G.729 (payloads not
    /// decodable: licence-restricted codec); and an SRTP call (RTP/SAVP, encrypted payloads).
    static func audioCodecs() throws -> Data {
        typealias P = ProtocolBuilders
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        var frames: [TimedFrame] = []
        var id: UInt16 = 1
        func udp(_ time: Double, _ from: String, _ fromPort: UInt16, _ to: String, _ toPort: UInt16, _ payload: [UInt8]) {
            id &+= 1
            frames.append(TimedFrame(time: time, bytes: FrameBuilder.udpFrame(source: from, sourcePort: fromPort, destination: to,
                                                                              destinationPort: toPort, payload: payload, identification: id)))
        }
        var random = SeededRandom(seed: 0xA0D1_0C0D)
        let caller = "10.80.1.10", callee = "10.80.1.20"

        struct Codec {
            var profile = "RTP/AVP"
            var payloadType: UInt8
            var rtpmap: String
            var extra: [String] = []
        }

        func sip(_ time: Double, fromCaller: Bool, _ text: String) {
            udp(time, fromCaller ? caller : callee, 5060, fromCaller ? callee : caller, 5060, Array(text.utf8))
        }
        func sdp(_ address: String, port: UInt16, _ codec: Codec) -> String {
            var lines = ["v=0", "o=- 1 1 IN IP4 \(address)", "s=-", "c=IN IP4 \(address)", "t=0 0",
                         "m=audio \(port) \(codec.profile) \(([codec.payloadType] + (codec.extra.isEmpty ? [] : [101, 13])).map(String.init).joined(separator: " "))",
                         "a=rtpmap:\(codec.payloadType) \(codec.rtpmap)"]
            lines += codec.extra
            if codec.profile.contains("SAVP") {
                lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:V2lyZVBhdGggU1JUUCBwbGFjZWhvbGRlciBrZXkh")
            }
            return lines.joined(separator: "\r\n") + "\r\n"
        }
        func message(_ start: String, callID: String, cseq: String, toTag: Bool, body: String = "") -> String {
            var text = "\(start)\r\nVia: SIP/2.0/UDP \(caller):5060;branch=z9hG4bK\(callID)\(cseq.filter { $0 != " " })\r\n"
            text += "From: <sip:2001@\(caller)>;tag=c1\r\nTo: <sip:2002@\(callee)>\(toTag ? ";tag=d2" : "")\r\nCall-ID: \(callID)\r\n"
            text += "CSeq: \(cseq)\r\nMax-Forwards: 70\r\nContact: <sip:2001@\(caller)>\r\n"
            if !body.isEmpty { text += "Content-Type: application/sdp\r\n" }
            return text + "Content-Length: \(body.utf8.count)\r\n\r\n\(body)"
        }

        /// One call: signalling around `media`, which emits the RTP of both directions from `mediaStart`.
        func call(_ start: Double, number: Int, codec: Codec, duration: Double,
                  media: (_ mediaStart: Double, _ callerPort: UInt16, _ calleePort: UInt16) -> Void) {
            let callID = "audio-\(number)@\(caller)"
            let callerPort = UInt16(40_000 + number * 10), calleePort = UInt16(50_000 + number * 10)
            sip(start, fromCaller: true, message("INVITE sip:2002@\(callee) SIP/2.0", callID: callID, cseq: "1 INVITE", toTag: false,
                                                 body: sdp(caller, port: callerPort, codec)))
            sip(start + 0.02, fromCaller: false, message("SIP/2.0 100 Trying", callID: callID, cseq: "1 INVITE", toTag: false))
            sip(start + 0.30, fromCaller: false, message("SIP/2.0 200 OK", callID: callID, cseq: "1 INVITE", toTag: true,
                                                         body: sdp(callee, port: calleePort, codec)))
            sip(start + 0.31, fromCaller: true, message("ACK sip:2002@\(callee) SIP/2.0", callID: callID, cseq: "1 ACK", toTag: true))
            media(start + 0.40, callerPort, calleePort)
            sip(start + 0.50 + duration, fromCaller: true, message("BYE sip:2002@\(callee) SIP/2.0", callID: callID, cseq: "2 BYE", toTag: true))
            sip(start + 0.52 + duration, fromCaller: false, message("SIP/2.0 200 OK", callID: callID, cseq: "2 BYE", toTag: true))
        }

        /// An RTP sender: sequence and timestamp advance per packet; `send` returns nothing when a packet is dropped.
        struct Sender {
            var ssrc: UInt32
            var sequence: UInt16
            var timestamp: UInt32
            func header(_ pt: UInt8, marker: Bool = false, timestamp: UInt32? = nil) -> [UInt8] {
                [0x80, pt | (marker ? 0x80 : 0)] + P.be16(sequence) + P.be32(timestamp ?? self.timestamp) + P.be32(ssrc)
            }
        }

        // 1. G.711 µ-law, 3 s: caller 440 Hz with three DTMF keys and a 100 ms loss; callee 660 Hz with a 1 s pause
        //    announced by comfort noise.
        let pcmu = Codec(payloadType: 0, rtpmap: "PCMU/8000", extra: ["a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-16",
                                                                      "a=rtpmap:13 CN/8000", "a=ptime:20"])
        call(0.0, number: 1, codec: pcmu, duration: 3) { t0, callerPort, calleePort in
            var a = Sender(ssrc: 0xA0D1_0001, sequence: 1000, timestamp: 16_000)
            let events = AudioSignals.dtmf
            var sentEvents = Set<Int>()
            for k in 0..<150 {
                let time = Double(k) * 0.02
                if let index = events.firstIndex(where: { time >= $0.start - 1e-9 && time < $0.start + $0.duration - 1e-9 }) {
                    // RFC 4733: the key's packets replace voice; same timestamp, growing duration, three end packets.
                    guard !sentEvents.contains(index) else { a.timestamp &+= 160; continue }
                    sentEvents.insert(index)
                    let event = events[index]
                    let eventTimestamp = a.timestamp
                    let updates = Int((event.duration / 0.02).rounded())
                    for u in 0..<(updates + 2) {
                        let end = u >= updates - 1
                        let duration = UInt16(min(u + 1, updates) * 160)
                        let payload: [UInt8] = [event.event, (end ? 0x80 : 0) | 10] + P.be16(duration)
                        udp(t0 + time + Double(min(u, updates - 1)) * 0.02 + Double(max(0, u - updates + 1)) * 0.005 + 0.001,
                            caller, callerPort, callee, calleePort, a.header(101, marker: u == 0, timestamp: eventTimestamp) + payload)
                        a.sequence &+= 1
                    }
                    a.timestamp &+= 160
                    continue
                }
                let voice = AudioSignals.tone(440, rate: 8000, from: k * 160, count: 160).map(G711.encodeMuLaw)
                if !AudioSignals.lostPackets.contains(k) {
                    udp(t0 + time + 0.001, caller, callerPort, callee, calleePort, a.header(0, marker: k == 0) + voice)
                }
                a.sequence &+= 1
                a.timestamp &+= 160
            }
            var b = Sender(ssrc: 0xA0D1_0002, sequence: 3000, timestamp: 64_000)
            let silence = AudioSignals.silence
            var announced = false
            for k in 0..<150 {
                let time = Double(k) * 0.02
                if (silence.startPacket..<silence.endPacket).contains(k) {
                    if !announced {
                        announced = true
                        udp(t0 + time + 0.003, callee, calleePort, caller, callerPort, b.header(13) + [silence.level])
                        b.sequence &+= 1
                    }
                    b.timestamp &+= 160
                    continue
                }
                let voice = AudioSignals.tone(660, rate: 8000, from: k * 160, count: 160).map(G711.encodeMuLaw)
                udp(t0 + time + 0.003, callee, calleePort, caller, callerPort,
                    b.header(0, marker: k == 0 || k == silence.endPacket) + voice)
                b.sequence &+= 1
                b.timestamp &+= 160
            }
        }

        // 2. G.722, 2 s: caller sweep, callee 1 kHz (16 kHz audio, 8 kHz RTP clock).
        call(4.0, number: 2, codec: Codec(payloadType: 9, rtpmap: "G722/8000"), duration: 2) { t0, callerPort, calleePort in
            let sweep = G722Encoder().encode(AudioSignals.sweep(count: 32_000))
            let tone = G722Encoder().encode(AudioSignals.tone(1000, rate: 16000, from: 0, count: 32_000))
            var a = Sender(ssrc: 0xA0D1_0003, sequence: 500, timestamp: 1_000)
            var b = Sender(ssrc: 0xA0D1_0004, sequence: 700, timestamp: 9_000)
            for k in 0..<100 {
                let time = t0 + Double(k) * 0.02
                udp(time + 0.001, caller, callerPort, callee, calleePort, a.header(9, marker: k == 0) + Array(sweep[(k * 160)..<(k * 160 + 160)]))
                udp(time + 0.004, callee, calleePort, caller, callerPort, b.header(9, marker: k == 0) + Array(tone[(k * 160)..<(k * 160 + 160)]))
                a.sequence &+= 1; a.timestamp &+= 160
                b.sequence &+= 1; b.timestamp &+= 160
            }
        }

        // 3. L16 at 16 kHz (dynamic payload type), 1 s, 1 kHz caller tone only.
        call(7.0, number: 3, codec: Codec(payloadType: 96, rtpmap: "L16/16000"), duration: 1) { t0, callerPort, calleePort in
            var a = Sender(ssrc: 0xA0D1_0005, sequence: 10, timestamp: 0)
            for k in 0..<50 {
                let samples = AudioSignals.tone(1000, rate: 16000, from: k * 320, count: 320)
                let payload = samples.flatMap { P.be16(UInt16(bitPattern: $0)) }
                udp(t0 + Double(k) * 0.02 + 0.001, caller, callerPort, callee, calleePort, a.header(96, marker: k == 0) + payload)
                a.sequence &+= 1; a.timestamp &+= 320
            }
        }

        // 4. G.729, 1 s (payloads are placeholders: the codec is not decoded).
        call(9.0, number: 4, codec: Codec(payloadType: 18, rtpmap: "G729/8000", extra: []), duration: 1) { t0, callerPort, calleePort in
            var a = Sender(ssrc: 0xA0D1_0006, sequence: 20, timestamp: 0)
            for k in 0..<50 {
                let payload = (0..<20).map { _ in UInt8(truncatingIfNeeded: random.next()) }
                udp(t0 + Double(k) * 0.02 + 0.001, caller, callerPort, callee, calleePort, a.header(18, marker: k == 0) + payload)
                a.sequence &+= 1; a.timestamp &+= 160
            }
        }

        // 5. SRTP (RTP/SAVP with SDES keys, placeholder key), 1 s: payloads are ciphertext.
        call(11.0, number: 5, codec: Codec(profile: "RTP/SAVP", payloadType: 0, rtpmap: "PCMU/8000"), duration: 1) { t0, callerPort, calleePort in
            var a = Sender(ssrc: 0xA0D1_0007, sequence: 30, timestamp: 0)
            for k in 0..<50 {
                let payload = (0..<170).map { _ in UInt8(truncatingIfNeeded: random.next()) }  // 160 bytes + 10-byte auth tag
                udp(t0 + Double(k) * 0.02 + 0.001, caller, callerPort, callee, calleePort, a.header(0, marker: k == 0) + payload)
                a.sequence &+= 1; a.timestamp &+= 160
            }
        }

        for frame in frames.sorted(by: { $0.time < $1.time }) { writer.write(frame) }
        writer.close()
        return writer.data
    }
}
