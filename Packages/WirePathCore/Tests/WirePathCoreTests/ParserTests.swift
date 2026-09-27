@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

@Suite("PCAP engine")
struct CaptureReaderTests {
    func frames(_ format: CaptureWriter.Format) throws -> [CapturedFrame] {
        let writer = try CaptureWriter(format: format, baseTime: 1_000_000_000.123456)
        for i in 0..<3 {
            writer.write(TimedFrame(time: Double(i) * 0.5, bytes: FrameBuilder.udpFrame(
                source: "10.0.0.1", sourcePort: 1000, destination: "10.0.0.2", destinationPort: 2000,
                payload: [UInt8](repeating: UInt8(i), count: 10 + i), identification: UInt16(i))))
        }
        writer.close()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID()).cap")
        try writer.data.write(to: url)
        var reader = try CaptureReader(file: CaptureFile(url: url))
        var result: [CapturedFrame] = []
        while let frame = try reader.next() { result.append(frame) }
        return result
    }

    @Test(arguments: [
        CaptureWriter.Format.pcap(nanosecond: false, bigEndian: false),
        .pcap(nanosecond: true, bigEndian: false),
        .pcap(nanosecond: false, bigEndian: true),
        .pcapng,
    ])
    func readsAllFormats(format: CaptureWriter.Format) throws {
        let frames = try frames(format)
        #expect(frames.count == 3)
        #expect(frames.map(\.number) == [1, 2, 3])
        #expect(frames[0].linkType == .ethernet)
        // Timestamps: 1_000_000_000.123456 s + i * 0.5 s (µs resolution at worst).
        let delta = Double(frames[2].timestampNanos - frames[0].timestampNanos) / 1e9
        #expect(abs(delta - 1.0) < 1e-6)
        #expect(abs(Double(frames[0].timestampNanos) / 1e9 - 1_000_000_000.123456) < 1e-5)
    }

    @Test func truncatedFileEndsGracefully() throws {
        let writer = try CaptureWriter(baseTime: 0)
        for i in 0..<2 {
            writer.write(TimedFrame(time: Double(i), bytes: [UInt8](repeating: 1, count: 64)))
        }
        writer.close()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID()).pcap")
        try writer.data.prefix(writer.data.count - 10).write(to: url)
        var reader = try CaptureReader(file: CaptureFile(url: url))
        var count = 0
        while try reader.next() != nil { count += 1 }
        #expect(count == 1)
        #expect(reader.truncatedAtEnd)
    }

    @Test func rejectsUnknownFormat() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID()).pcap")
        try Data("this is not a capture file at all".utf8).write(to: url)
        #expect(throws: CaptureError.self) { try CaptureReader(file: CaptureFile(url: url)) }
    }

    @Test func pcapngBinaryTimestampResolution() {
        // 2^-10 s units: 1024 units = 1 s.
        #expect(CaptureReader.nanoseconds(1024 * 5 + 512, decimal: false, exponent: 10) == 5_500_000_000)
        #expect(CaptureReader.nanoseconds(123, decimal: true, exponent: 3) == 123_000_000)
        #expect(CaptureReader.nanoseconds(123_456_789_012, decimal: true, exponent: 12) == 123_456_789)
    }
}

@Suite("Packet decoding")
struct PacketDecoderTests {
    @Test func decodesEthernetVLANIPv4UDP() {
        let frame = FrameBuilder.ethernet(source: "10.0.0.1", destination: "10.0.0.2", etherType: 0x0800,
                                          payload: FrameBuilder.ipv4Header(source: "10.0.0.1", destination: "10.0.0.2", protocolNumber: 17, payloadLength: 12, identification: 1)
                                          + FrameBuilder.udp(sourcePort: 5060, destinationPort: 5062, payload: [1, 2, 3, 4]),
                                          vlan: 42)
        let packet = frame.withUnsafeBytes { PacketDecoder.decode($0, linkType: .ethernet) }
        #expect(packet.network == .ipv4)
        #expect(packet.source == IPAddress("10.0.0.1"))
        #expect(packet.destination == IPAddress("10.0.0.2"))
        #expect(packet.sourcePort == 5060 && packet.destinationPort == 5062)
        #expect(packet.payloadLength == 4)  // Ethernet padding excluded via IP total length
    }

    @Test func decodesIPv6() {
        let source: [UInt8] = [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [1]
        let destination: [UInt8] = [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [2]
        let frame = FrameBuilder.udp6Frame(source: source, sourcePort: 4000, destination: destination, destinationPort: 4002, payload: [9, 9])
        let packet = frame.withUnsafeBytes { PacketDecoder.decode($0, linkType: .ethernet) }
        #expect(packet.network == .ipv6)
        #expect(packet.source?.description == "2001:db8::1")
        #expect(packet.destinationPort == 4002)
        #expect(packet.payloadLength == 2)
    }

    @Test func reassemblesIPv4Fragments() {
        let payload = [UInt8](repeating: 0x41, count: 3000)
        let frames = FrameBuilder.fragmentedUDPFrames(source: "10.0.0.1", sourcePort: 5060, destination: "10.0.0.2",
                                                      destinationPort: 5060, payload: payload, identification: 77, mtu: 1480)
        #expect(frames.count == 3)
        var reassembler = IPFragmentReassembler()
        var datagram: IPFragmentReassembler.Datagram?
        for (index, frame) in frames.reversed().enumerated() {  // out of order on purpose
            frame.withUnsafeBytes { raw in
                let packet = PacketDecoder.decode(raw, linkType: .ethernet)
                if let done = reassembler.add(frame: raw, packet: packet, frameNumber: index + 1, timestampNanos: 0) {
                    datagram = done
                }
            }
        }
        #expect(datagram?.bytes.count == 3008)
        #expect(datagram?.bytes.suffix(3000).allSatisfy { $0 == 0x41 } == true)
    }

    @Test func ipAddressFormatting() {
        #expect(IPAddress("fe80::1:0:0:1")?.description == "fe80::1:0:0:1")
        #expect(IPAddress("2001:db8:0:0:1:0:0:1")?.description == "2001:db8::1:0:0:1")
        #expect(IPAddress("::ffff:10.0.0.1") != nil)
        #expect(IPAddress("10.20.1.300") == nil)
        #expect(IPAddress("192.168.1.10")!.isPrivate)
        #expect(!IPAddress("200.31.4.10")!.isPrivate)
    }
}

@Suite("SIP & SDP parsing")
struct SIPParserTests {
    let invite = """
    INVITE sip:1008@pbx.office.lan SIP/2.0\r
    v: SIP/2.0/UDP 10.20.1.23:5060;branch=z9hG4bK-5c1e8a, SIP/2.0/UDP 10.0.0.9;branch=z9hG4bK-x\r
    f: "Soporte N1" <sip:1003@pbx.office.lan>;tag=a83f21\r
    t: <sip:1008@pbx.office.lan>\r
    i: 7f3a9c21@10.20.1.23\r
    CSeq: 1 INVITE\r
    Subject: folded\r
     continuation\r
    c: application/sdp\r
    l: 162\r
    \r
    v=0\r
    o=1003 38211 38211 IN IP4 10.20.1.23\r
    s=-\r
    c=IN IP4 10.20.1.23\r
    t=0 0\r
    m=audio 16384 RTP/AVP 18 101\r
    a=rtpmap:18 G729/8000\r
    a=fmtp:18 annexb=no\r
    a=ptime:20\r

    """

    @Test func parsesRequestWithCompactHeaders() throws {
        let message = try #require(Array(invite.utf8).withUnsafeBytes { SIPParser.parse($0) })
        #expect(message.isRequest)
        #expect(message.method == "INVITE")
        #expect(message.callID == "7f3a9c21@10.20.1.23")
        #expect(message.cseq?.number == 1)
        #expect(message.from?.displayName == "Soporte N1")
        #expect(message.from?.user == "1003")
        #expect(message.from?.tag == "a83f21")
        #expect(message.to?.user == "1008")
        #expect(message.viaValues.count == 2)
        #expect(message.topViaBranch == "z9hG4bK-5c1e8a")
        #expect(message.header("Subject") == "folded continuation")
        let sdp = try #require(message.sdp)
        #expect(sdp.media.first?.port == 16384)
        #expect(sdp.effectiveAddress(for: sdp.media[0]) == "10.20.1.23")
        #expect(sdp.media[0].rtpMaps[18]?.encodingName == "G729")
        #expect(sdp.media[0].ptimeMs == 20)
    }

    @Test func parsesResponse() throws {
        let text = "SIP/2.0 486 Busy Here\r\nVia: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>;tag=2\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        let message = try #require(Array(text.utf8).withUnsafeBytes { SIPParser.parse($0) })
        #expect(!message.isRequest)
        #expect(message.statusCode == 486)
        #expect(message.reasonPhrase == "Busy Here")
        #expect(message.method == "INVITE")
    }

    @Test func detectsSIPCheaply() {
        #expect(Array("OPTIONS sip:x SIP/2.0\r\n".utf8).withUnsafeBytes { SIPParser.looksLikeSIP($0) })
        #expect(Array("SIP/2.0 200 OK\r\n\r\n".utf8).withUnsafeBytes { SIPParser.looksLikeSIP($0) })
        #expect(!Array("GET / HTTP/1.1\r\nHost: x\r\n".utf8).withUnsafeBytes { SIPParser.looksLikeSIP($0) })
    }

    @Test func framesMessagesFromTCPStream() {
        let one = "BYE sip:a@b SIP/2.0\r\nCall-ID: 1\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        let two = "SIP/2.0 200 OK\r\nCall-ID: 1\r\nCSeq: 2 BYE\r\nContent-Length: 4\r\n\r\nabcd"
        var framer = SIPStreamFramer()
        let all = Data((one + two).utf8)
        #expect(framer.append(all.prefix(30)).isEmpty)
        let messages = framer.append(all.dropFirst(30))
        #expect(messages.count == 2)
        #expect(messages[1].body == "abcd")
    }

    @Test func parsesTelAndIPv6URIs() {
        #expect(SIPHeaderParser.userAndHost(of: "tel:+50322607788;phone-context=x").user == "+50322607788")
        let v6 = SIPHeaderParser.userAndHost(of: "sip:alice@[2001:db8::1]:5060")
        #expect(v6.user == "alice" && v6.host == "2001:db8::1")
    }
}

@Suite("RTP statistics")
struct RTPAnalyzerTests {
    let src = Endpoint(address: IPAddress("10.0.0.1")!, port: 20000)
    let dst = Endpoint(address: IPAddress("10.0.0.2")!, port: 30000)

    func header(_ seq: UInt16, _ ts: UInt32, pt: UInt8 = 0) -> RTPHeader {
        RTPHeader(padding: false, hasExtension: false, csrcCount: 0, marker: false, payloadType: pt, sequenceNumber: seq,
                  timestamp: ts, ssrc: 0x1234, headerLength: 12, payloadLength: 160)
    }

    @Test func countsLossDuplicatesAndReordering() {
        var analyzer = RTPStreamAnalyzer(ssrc: 0x1234, source: src, destination: dst, codecs: [:], ptimeMs: 20, negotiatedInSDP: true)
        // Sequence 65534, 65535, 0 (wrap), [1 lost], 2, 2 (dup), 4, 3 (late) ...
        let order: [UInt16] = [65534, 65535, 0, 2, 2, 4, 3, 5]
        var gaps = 0
        for (i, seq) in order.enumerated() {
            let verdict = analyzer.ingest(header(seq, UInt32(i) * 160), arrivalNanos: Int64(i) * 20_000_000)
            if verdict.sequenceGap { gaps += 1 }
        }
        let record = analyzer.makeRecord(id: 0)
        #expect(record.expectedPackets == 8)    // 65534 … 5
        #expect(record.lostPackets == 1)        // seq 1
        #expect(record.duplicatePackets == 1)
        #expect(record.outOfOrderPackets == 1)  // seq 3
        #expect(gaps == 2)                      // before 2 and before 4
        #expect(record.packetCount == 8)
    }

    @Test func jitterIsZeroForPerfectTiming() {
        var analyzer = RTPStreamAnalyzer(ssrc: 1, source: src, destination: dst, codecs: [:], ptimeMs: 20, negotiatedInSDP: true)
        for i in 0..<100 {
            _ = analyzer.ingest(header(UInt16(i), UInt32(i * 160)), arrivalNanos: Int64(i) * 20_000_000)
        }
        let record = analyzer.makeRecord(id: 0)
        #expect(record.maxJitterMs == 0)
        #expect(record.lostPackets == 0)
        #expect(abs(record.meanDeltaMs - 20) < 1e-9)
    }

    @Test func jitterFollowsRFC3550() {
        // Alternating 10 ms early / on time: |D| = 10 ms each step → J converges toward 10 ms.
        var analyzer = RTPStreamAnalyzer(ssrc: 1, source: src, destination: dst, codecs: [:], ptimeMs: 20, negotiatedInSDP: true)
        var expectedJ = 0.0
        var lastTransit: Double?
        for i in 0..<50 {
            let offset: Int64 = i % 2 == 0 ? 0 : 10_000_000
            let arrival = Int64(i) * 20_000_000 + offset
            _ = analyzer.ingest(header(UInt16(i), UInt32(i * 160)), arrivalNanos: arrival)
            let transit = Double(arrival) / 1e9 * 8000 - Double(i * 160)
            if let last = lastTransit { expectedJ += (abs(transit - last) - expectedJ) / 16 }
            lastTransit = transit
        }
        let record = analyzer.makeRecord(id: 0)
        let reported = record.maxJitterMs ?? -1
        #expect(abs(reported - expectedJ / 8) < 1e-6)   // units → ms at 8 kHz
    }

    @Test func dynamicPayloadWithoutClockHasNoJitter() {
        var analyzer = RTPStreamAnalyzer(ssrc: 1, source: src, destination: dst, codecs: [:], ptimeMs: nil, negotiatedInSDP: false)
        for i in 0..<20 { _ = analyzer.ingest(header(UInt16(i), UInt32(i * 960), pt: 111), arrivalNanos: Int64(i) * 20_000_000) }
        let record = analyzer.makeRecord(id: 0)
        #expect(record.meanJitterMs == nil)
        #expect(record.maxJitterMs == nil)
        #expect(record.codec == nil)
    }

    @Test func parsesRTPHeaderWithExtensionAndPadding() {
        var bytes: [UInt8] = [0xB1, 0x12, 0, 5, 0, 0, 0, 160, 0xDE, 0xAD, 0xBE, 0xEF]  // V=2 P=1 X=1 CC=1
        bytes += [0, 0, 0, 1]                  // CSRC
        bytes += [0xBE, 0xDE, 0, 1, 1, 2, 3, 4]  // extension, 1 word
        bytes += [9, 9, 9, 0, 0, 3]            // payload + 3 bytes padding
        let header = bytes.withUnsafeBytes { RTPHeader.parse($0) }
        #expect(header?.headerLength == 24)
        #expect(header?.payloadLength == 3)
        #expect(header?.ssrc == 0xDEADBEEF)
        #expect(header?.payloadType == 18)
    }
}
