@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

typealias PCAPNGBuilder = PCAPNGBlockWriter

extension PCAPNGBlockWriter {
    func write() throws -> URL {
        let url = Fixtures.temporaryDirectory().appendingPathComponent("crafted.pcapng")
        try data.write(to: url)
        return url
    }
}

func readAll(_ url: URL) throws -> (frames: [CapturedFrame], reader: CaptureReader) {
    var reader = try CaptureReader(file: CaptureFile(url: url))
    var frames: [CapturedFrame] = []
    while let frame = try reader.next() { frames.append(frame) }
    return (frames, reader)
}

let sampleFrame = FrameBuilder.udpFrame(source: "10.0.0.1", sourcePort: 5060, destination: "10.0.0.2", destinationPort: 5060,
                                        payload: Array("OPTIONS sip:a@b SIP/2.0\r\n\r\n".utf8), identification: 1)

@Suite("PCAPNG metadata")
struct PCAPNGMetadataTests {
    @Test func readsSectionInterfacesStatisticsAndComments() throws {
        var b = PCAPNGBuilder()
        b.sectionHeader(options: PCAPNGBuilder.option(2, "Mac17,1") + PCAPNGBuilder.option(3, "macOS 27")
                        + PCAPNGBuilder.option(4, "tcpdump 4.99") + PCAPNGBuilder.option(1, "lab capture") + PCAPNGBuilder.endOfOptions)
        b.interface(options: PCAPNGBuilder.option(2, "en0") + PCAPNGBuilder.option(3, "Wi-Fi")
                    + PCAPNGBuilder.option(9, [9]) + PCAPNGBuilder.endOfOptions)
        b.interface(linkType: 101, snapLength: 128, options: PCAPNGBuilder.option(9, [0x80 | 20]) + PCAPNGBuilder.endOfOptions)
        b.enhancedPacket(interface: 0, timestamp: 1_700_000_000_123_456_789, packet: sampleFrame,
                         options: PCAPNGBuilder.option(1, "the interesting one") + PCAPNGBuilder.endOfOptions)
        // 2^-20 s units: 3 s + half a unit-second.
        b.enhancedPacket(interface: 1, timestamp: (3 << 20) | (1 << 19), packet: Array(sampleFrame[14...]))
        b.simplePacket(sampleFrame)
        b.interfaceStatistics(interface: 0, options: PCAPNGBuilder.option(4, PCAPNGBuilder.le64(1_000))
                              + PCAPNGBuilder.option(5, PCAPNGBuilder.le64(7)) + PCAPNGBuilder.option(7, PCAPNGBuilder.le64(3))
                              + PCAPNGBuilder.endOfOptions)
        let (frames, reader) = try readAll(b.write())

        #expect(frames.count == 3)
        #expect(frames[0].timestampNanos == 1_700_000_000_123_456_789)
        #expect(frames[1].timestampNanos == 3_500_000_000)
        #expect(frames[1].linkType == .raw)
        #expect(frames[1].interfaceID == 1)
        #expect(reader.formatVersion == "1.0")
        #expect(reader.sectionInfo == CaptureSectionInfo(hardware: "Mac17,1", operatingSystem: "macOS 27",
                                                         application: "tcpdump 4.99", comments: ["lab capture"]))
        #expect(reader.interfaceInfos.count == 2)
        #expect(reader.interfaceInfos[0].name == "en0")
        #expect(reader.interfaceInfos[0].interfaceDescription == "Wi-Fi")
        #expect(reader.interfaceInfos[0].timestampResolution == "ns")
        #expect(reader.interfaceInfos[0].packetCount == 2)  // EPB + SPB
        #expect(reader.interfaceInfos[0].packetsReceived == 1_000)
        #expect(reader.interfaceInfos[0].packetsDroppedByInterface == 7)
        #expect(reader.interfaceInfos[0].packetsDroppedByOS == 3)
        #expect(reader.interfaceInfos[1].timestampResolution == "2^-20 s")
        #expect(reader.interfaceInfos[1].snapLength == 128)
        #expect(reader.packetComments == [PacketComment(frameNumber: 1, text: "the interesting one")])
        #expect(!reader.truncatedAtEnd)
    }

    @Test func pcapHeaderFieldsAreRead() throws {
        let writer = try CaptureWriter(format: .pcap(nanosecond: true, bigEndian: true), baseTime: 1_000)
        writer.write(TimedFrame(time: 0, bytes: sampleFrame))
        writer.close()
        let url = Fixtures.temporaryDirectory().appendingPathComponent("be.pcap")
        try writer.data.write(to: url)
        let (frames, reader) = try readAll(url)
        #expect(frames.count == 1)
        #expect(reader.formatVersion == "2.4")
        #expect(reader.interfaceInfos.first?.timestampResolution == "ns")
        #expect(reader.interfaceInfos.first?.packetCount == 1)
        #expect(reader.interfaceInfos.first?.snapLength ?? 0 > 0)
    }
}

@Suite("Untrusted captures")
struct UntrustedCaptureTests {
    /// Values that used to trap: 2^-127 s resolution, a huge if_tsoffset, and every binary exponent.
    @Test func extremeTimestampParametersDoNotTrap() throws {
        for exponent in [0, 1, 63, 64, 100, 127] {
            _ = CaptureReader.nanoseconds(UInt64.max, decimal: false, exponent: exponent)
            _ = CaptureReader.nanoseconds(UInt64.max, decimal: true, exponent: exponent)
        }
        var b = PCAPNGBuilder()
        b.sectionHeader()
        b.interface(options: PCAPNGBuilder.option(9, [0xFF]) + PCAPNGBuilder.option(14, PCAPNGBuilder.le64(UInt64.max / 3))
                    + PCAPNGBuilder.endOfOptions)
        b.enhancedPacket(timestamp: UInt64.max, packet: sampleFrame)
        let (frames, _) = try readAll(b.write())
        #expect(frames.count == 1)
    }

    @Test func mismatchedTrailingLengthStopsReading() throws {
        var b = PCAPNGBuilder()
        b.sectionHeader()
        b.interface()
        b.enhancedPacket(timestamp: 1, packet: sampleFrame)
        var damaged = PCAPNGBuilder()
        damaged.block(6, [UInt8](repeating: 0, count: 40), trailingLength: 999)
        b.data.append(damaged.data)
        b.enhancedPacket(timestamp: 2, packet: sampleFrame)
        let (frames, reader) = try readAll(b.write())
        #expect(frames.count == 1)
        #expect(reader.truncatedAtEnd)
        #expect(reader.warnings.contains { $0.contains("length fields disagree") })

        var first = PCAPNGBuilder()
        first.block(0x0A0D_0D0A, PCAPNGBuilder.le32(0x1A2B_3C4D) + [UInt8](repeating: 0, count: 12), trailingLength: 4)
        #expect(throws: CaptureError.self) { _ = try readAll(first.write()) }
    }

    @Test func oversizedDeclaredLengthsAreRejected() throws {
        var b = PCAPNGBuilder()
        b.sectionHeader()
        b.interface()
        // EPB claiming 1 GiB of packet data inside a 48-byte block.
        let body = PCAPNGBuilder.le32(0) + PCAPNGBuilder.le32(0) + PCAPNGBuilder.le32(0)
            + PCAPNGBuilder.le32(0x4000_0000) + PCAPNGBuilder.le32(0x4000_0000) + [UInt8](repeating: 0xAB, count: 16)
        b.block(6, body)
        b.enhancedPacket(timestamp: 5, packet: sampleFrame)
        let (frames, reader) = try readAll(b.write())
        #expect(frames.count == 1)
        #expect(reader.warnings.contains { $0.contains("declares more data") })
    }

    @Test func interfaceFloodIsBounded() throws {
        var b = PCAPNGBuilder()
        b.sectionHeader()
        for _ in 0..<(CaptureReader.Limits.maxInterfaces + 50) { b.interface() }
        b.enhancedPacket(interface: UInt32(CaptureReader.Limits.maxInterfaces + 10), timestamp: 1, packet: sampleFrame)
        let (frames, reader) = try readAll(b.write())
        #expect(reader.interfaceInfos.count == CaptureReader.Limits.maxInterfaces)
        #expect(frames.count == 1)
        #expect(reader.warnings.contains { $0.contains("unknown interface") })
    }

    @Test func truncatedHeadersReportTheirReason() throws {
        let full = FrameBuilder.tcpFrame(source: "10.0.0.1", sourcePort: 5060, destination: "10.0.0.2", destinationPort: 5060,
                                         sequence: 1, payload: Array("hello".utf8), identification: 1)
        let cut = Array(full.prefix(14 + 20 + 10))  // Ethernet + IPv4 + half a TCP header
        let decoded = cut.withUnsafeBytes { PacketDecoder.decode($0, linkType: .ethernet) }
        #expect(decoded.problem == .ipv4Length)
        let tcpOnly = Array(full.prefix(14 + 20)) + [0x13, 0xC4]
        var patched = tcpOnly
        patched[16] = 0; patched[17] = UInt8(tcpOnly.count - 14)  // consistent IPv4 total length
        let short = patched.withUnsafeBytes { PacketDecoder.decode($0, linkType: .ethernet) }
        #expect(short.problem == .tcpHeader)
        let tiny = [UInt8](repeating: 0, count: 6).withUnsafeBytes { PacketDecoder.decode($0, linkType: .ethernet) }
        #expect(tiny.problem == .linkHeader)
    }

    /// Seeded mutation fuzzing of the reader, decoder and dissector: none may trap on damaged input (debug builds
    /// bounds-check every buffer access, so an out-of-range read fails the test). WIREPATH_FUZZ_ITERATIONS and
    /// WIREPATH_FUZZ_SEED run longer or different campaigns.
    @Test func mutatedCapturesNeverCrash() async throws {
        let environment = ProcessInfo.processInfo.environment
        let iterations = environment["WIREPATH_FUZZ_ITERATIONS"].flatMap(Int.init) ?? 60
        let seed = environment["WIREPATH_FUZZ_SEED"].flatMap(UInt64.init) ?? 0xC0FFEE
        let capture = SimCapture(baseTime: Fixtures.baseTime,
                                 calls: [Fixtures.call(outcome: .answered(talk: 2, hangupByCaller: true))])
        var rng = SeededRandom(seed: seed)
        // Corpus: a SIP/RTP call in both formats plus every fixture, so each dissector sees damaged input.
        var corpus = [try capture.write(format: .pcap(nanosecond: false, bigEndian: false)), try capture.write(format: .pcapng)]
        corpus += try FixtureCatalog.all.filter { $0.fileName != "corrupted-capture.pcap" }.map { try $0.make() }
        for original in corpus {
            let directory = Fixtures.temporaryDirectory()
            for iteration in 0..<iterations {
                var bytes = [UInt8](original)
                let mutations = 1 + Int(rng.next() % 40)
                for _ in 0..<mutations {
                    let position = Int(rng.next() % UInt64(bytes.count))
                    switch rng.next() % 4 {
                    case 0: bytes[position] = UInt8(truncatingIfNeeded: rng.next())
                    case 1: bytes[position] ^= 0xFF
                    case 2: bytes[position] = [0x00, 0xFF, 0x7F, 0x80][Int(rng.next() % 4)]
                    default: bytes.removeSubrange(position..<min(bytes.count, position + Int(rng.next() % 64)))
                    }
                    if bytes.isEmpty { bytes = [0] }
                }
                if iteration % 7 == 0 { bytes = Array(bytes.prefix(Int(rng.next() % UInt64(bytes.count)) + 1)) }
                let url = directory.appendingPathComponent("mutated-\(iteration)")
                try Data(bytes).write(to: url)
                guard let file = try? CaptureFile(url: url), var reader = try? CaptureReader(file: file) else { continue }
                var frames = 0
                while let frame = try? reader.next() {
                    frames += 1
                    let payload = file.bytes(offset: frame.dataOffset, length: frame.capturedLength)
                    let context = PacketDissector.Context(frameNumber: frame.number, timestampNanos: frame.timestampNanos,
                                                          captureStartNanos: 0, linkType: frame.linkType, interfaceID: frame.interfaceID,
                                                          originalLength: frame.originalLength,
                                                          codecForPayloadType: { CodecCatalog.descriptor(payloadType: $0) })
                    _ = PacketDissector.dissect(payload, context: context)
                    if frames > 5_000 { break }
                }
                if iteration % 10 == 0 {
                    // Full pipeline on some of them (SIP, SDP, RTP and correlation).
                    _ = try? await Fixtures.analyze(file: url, directory: directory)
                }
            }
        }
    }

    @Test func randomGarbageIsRejectedOrReadSafely() throws {
        var rng = SeededRandom(seed: 42)
        let directory = Fixtures.temporaryDirectory()
        for iteration in 0..<40 {
            var bytes = (0..<(Int(rng.next() % 2_000) + 1)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
            // Give half of them a valid magic so the block/record parsers run.
            if iteration % 2 == 0, bytes.count >= 28 {
                let magic: [UInt8] = iteration % 4 == 0 ? [0xD4, 0xC3, 0xB2, 0xA1] : [0x0A, 0x0D, 0x0D, 0x0A]
                bytes.replaceSubrange(0..<4, with: magic)
                if iteration % 4 != 0 { bytes.replaceSubrange(8..<12, with: [0x4D, 0x3C, 0x2B, 0x1A]) }
            }
            let url = directory.appendingPathComponent("garbage-\(iteration)")
            try Data(bytes).write(to: url)
            guard var reader = try? CaptureReader(file: CaptureFile(url: url)) else { continue }
            var count = 0
            while (try? reader.next()) != nil, count < 10_000 { count += 1 }
        }
    }
}

/// Regression tests for crafted values found by the parser audit.
@Suite("Crafted protocol values")
struct CraftedProtocolTests {
    @Test func negativeContentLengthIsRejected() {
        let text = "OPTIONS sip:a@b SIP/2.0\r\nCall-ID: x\r\nCSeq: 1 OPTIONS\r\nContent-Length: -1000\r\n\r\nbody"
        let bytes = Array(text.utf8)
        let udp = bytes.withUnsafeBytes { SIPParser.parse($0) }
        #expect(udp != nil)
        #expect(udp?.totalLength == bytes.count)
        #expect(bytes.withUnsafeBytes { SIPParser.parse($0, requireContentLength: true) } == nil)
        // Over TCP the framer must not spin on a message it cannot frame.
        var framer = SIPStreamFramer()
        let headerOnly = "OPTIONS sip:a@b SIP/2.0\r\nContent-Length: -52\r\n\r\n"
        #expect(framer.append(Data(headerOnly.utf8)).isEmpty)
    }

    @Test func absurdPacketizationTimesAreIgnored() {
        for value in ["nan", "inf", "1e999", "1e19", "-20", "0"] {
            let sdp = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=ptime:\(value)\r\n"
            #expect(SDPParser.parse(sdp)?.media.first?.ptimeMs == nil)
        }
        let valid = "v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\na=ptime:30\r\n"
        #expect(SDPParser.parse(valid)?.media.first?.ptimeMs == 30)
    }

    @Test func tcpSequenceJumpOfHalfTheSpaceDoesNotTrap() {
        var assembler = TCPStreamAssembler()
        let flow = TCPStreamAssembler.FlowKey(source: Endpoint(address: .v4(1), port: 5060), destination: Endpoint(address: .v4(2), port: 5060))
        let data = [UInt8](repeating: 0x41, count: 10)
        _ = assembler.add(flow: flow, sequence: 0, flags: 0x02, payload: UnsafeRawBufferPointer(start: nil, count: 0))
        _ = data.withUnsafeBytes { assembler.add(flow: flow, sequence: 1, flags: 0x18, payload: $0) }
        _ = data.withUnsafeBytes { assembler.add(flow: flow, sequence: 11 &+ 0x8000_0000, flags: 0x18, payload: $0) }
        _ = data.withUnsafeBytes { assembler.add(flow: flow, sequence: 11 &- 0x8000_0000, flags: 0x18, payload: $0) }
    }

    @Test func rtpTimestampsGoingBackwardsOrFarApartAreBounded() {
        func header(_ seq: UInt16) -> RTPHeader {
            RTPHeader(padding: false, hasExtension: false, csrcCount: 0, marker: false, payloadType: 0, sequenceNumber: seq,
                      timestamp: UInt32(seq) * 160, ssrc: 1, headerLength: 12, payloadLength: 160)
        }
        var analyzer = RTPStreamAnalyzer(ssrc: 1, source: Endpoint(address: .v4(1), port: 4000),
                                         destination: Endpoint(address: .v4(2), port: 4000), codecs: [:], ptimeMs: nil,
                                         negotiatedInSDP: false)
        _ = analyzer.ingest(header(1), arrivalNanos: 10_000_000_000)
        _ = analyzer.ingest(header(2), arrivalNanos: 9_000_000_000)      // 1 s before the first packet
        _ = analyzer.ingest(header(3), arrivalNanos: Int64.max - 5)      // absurdly far in the future
        _ = analyzer.ingest(header(10), arrivalNanos: Int64.min + 5)     // and in the past, with a gap
        let record = analyzer.makeRecord(id: 0)
        #expect(record.series.jitterMs.count <= RTPStreamAnalyzer.maxSeriesBins)
        #expect(record.series.lost.count <= RTPStreamAnalyzer.maxSeriesBins)
        #expect(record.series.lossBinSeconds >= RTPStreamAnalyzer.lossBin)
        #expect(record.packetCount == 4)
    }
}

/// Regression tests for resource bounds and damaged saved analyses.
@Suite("Bounded state")
struct BoundedStateTests {
    @Test func tcpFramerStaysLinearOnOneByteSegments() {
        let headers = (0..<400).map { "X-Filler-\($0): \(String(repeating: "a", count: 40))\r\n" }.joined()
        let message = "INVITE sip:b@c SIP/2.0\r\nCall-ID: slow\r\nCSeq: 1 INVITE\r\n\(headers)Content-Length: 4\r\n\r\nbody"
        var framer = SIPStreamFramer()
        var received: [SIPMessage] = []
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            for byte in Data(("\r\n\r\n" + message).utf8) { received += framer.append(Data([byte])) }
        }
        #expect(received.count == 1)
        #expect(received.first?.body == "body")
        #expect(elapsed < .seconds(2))  // quadratic re-parsing took minutes for this input
    }

    @Test func filterNestingAndLengthAreBounded() {
        let context = PacketFilterContext(addresses: [nil], captureStartNanos: 0, streamSSRCs: [], streamPayloadTypes: [], sipCallIDs: [])
        #expect(throws: DisplayFilterError.self) { try DisplayFilter(String(repeating: "(", count: 10_000) + "sip", context: context) }
        #expect(throws: DisplayFilterError.self) { try DisplayFilter(String(repeating: "!", count: 100) + "sip", context: context) }
        #expect(throws: DisplayFilterError.self) {
            try DisplayFilter(Array(repeating: "sip", count: 600).joined(separator: " or "), context: context)
        }
        let long = try? DisplayFilter(Array(repeating: "sip", count: 300).joined(separator: " or "), context: context)
        #expect(long?.matches(PacketIndexRecord(protocolKind: .sip), frameNumber: 1) == true)
        #expect(long?.matches(PacketIndexRecord(protocolKind: .rtp), frameNumber: 1) == false)
    }

    @Test func fragmentFloodIsBoundedAndRealDatagramsStillReassemble() {
        var reassembler = IPFragmentReassembler()
        func fragment(id: UInt16, offset: Int, more: Bool, payload: [UInt8]) -> (bytes: [UInt8], packet: DecodedPacket) {
            let ip = FrameBuilder.ipv4Header(source: "10.0.0.1", destination: "10.0.0.2", protocolNumber: 17,
                                             payloadLength: payload.count, identification: id, moreFragments: more,
                                             fragmentOffset: offset)
            let frame = FrameBuilder.ethernet(source: "10.0.0.1", destination: "10.0.0.2", etherType: 0x0800, payload: ip + payload)
            return (frame, frame.withUnsafeBytes { PacketDecoder.decode($0, linkType: .ethernet) })
        }
        for id in 0..<5_000 {
            let piece = fragment(id: UInt16(id), offset: 8, more: true, payload: [UInt8](repeating: 1, count: 8))
            _ = piece.bytes.withUnsafeBytes { reassembler.add(frame: $0, packet: piece.packet, frameNumber: id, timestampNanos: 0) }
        }
        let datagram = FrameBuilder.udp(sourcePort: 1, destinationPort: 2, payload: [UInt8](repeating: 7, count: 24))
        let first = fragment(id: 60_000, offset: 0, more: true, payload: Array(datagram[0..<16]))
        let repeated = first
        let last = fragment(id: 60_000, offset: 16, more: false, payload: Array(datagram[16...]))
        #expect(first.bytes.withUnsafeBytes { reassembler.add(frame: $0, packet: first.packet, frameNumber: 1, timestampNanos: 0) } == nil)
        #expect(repeated.bytes.withUnsafeBytes { reassembler.add(frame: $0, packet: repeated.packet, frameNumber: 2, timestampNanos: 0) } == nil)
        let assembled = last.bytes.withUnsafeBytes { reassembler.add(frame: $0, packet: last.packet, frameNumber: 3, timestampNanos: 0) }
        #expect(assembled?.bytes == Data(datagram))
        #expect(assembled?.frameNumbers == [1, 3])
    }

    @Test func damagedIndexFilesAreReadSafely() async throws {
        let analysis = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()]))
        let url = Fixtures.artifacts(in: analysis.directory).packetIndex
        var data = try Data(contentsOf: url)
        let full = try analysis.store().count
        data.replaceSubrange(8..<16, with: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])  // absurd count
        data.removeLast(100)                                                                   // cut mid-record
        try data.write(to: url)
        let store = try analysis.store()
        #expect(store.count < full)
        #expect(store.record(at: store.count + 10) == PacketIndexRecord())
        #expect(store.bytes(at: -1).isEmpty)
        _ = store.dissect(at: store.count)

        var wrongMagic = data
        wrongMagic[0] ^= 0xFF
        try wrongMagic.write(to: url)
        #expect(throws: (any Error).self) { _ = try analysis.store() }
    }

    @Test func damagedSavedResultsAreRejected() async throws {
        let analysis = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()]))
        let library = AnalysisLibrary(rootURL: Fixtures.temporaryDirectory())
        let manifest = AnalysisManifest(displayName: "a.pcap", originalFileName: "a.pcap", originalPath: "/nonexistent",
                                        bookmark: nil, fileSize: 1, state: .ready, engineVersion: AnalysisEngine.version)
        try library.save(manifest)
        var damaged = analysis.result
        #expect(damaged.isStructurallyValid)
        damaged.calls[0].streamIndices = [999]
        try library.saveResult(damaged, for: manifest.id)
        #expect(throws: (any Error).self) { _ = try library.loadResult(for: manifest.id) }

        // A manifest whose id disagrees with its folder is read under the folder's id.
        var impostor = manifest
        impostor.id = UUID()
        let folder = library.directory(for: manifest.id)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(impostor).write(to: folder.appendingPathComponent("analysis.json"))
        #expect(library.loadManifests().map(\.id) == [manifest.id])
    }
}

@Suite("Flows & packet model")
struct FlowAndPacketModelTests {
    @Test func everyIPPacketBelongsToAFlow() async throws {
        let analysis = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()]))
        let store = try analysis.store()
        let flows = store.flows()
        #expect(analysis.result.capture.flowCount == flows.count)
        #expect(flows.contains { $0.application.isSIP && $0.transport == .udp })
        // Symmetric RTP: both directions of the media share one bidirectional flow.
        let rtpFlows = flows.filter { $0.application == .rtp }
        #expect(!rtpFlows.isEmpty)
        #expect(rtpFlows.allSatisfy { $0.packetsFromInitiator > 0 && $0.packetsFromResponder > 0 })
        #expect(rtpFlows.reduce(0) { $0 + $1.packets } == analysis.result.capture.rtpPackets)
        #expect(flows.reduce(0) { $0 + $1.packets } == store.count)
        for position in 0..<store.count {
            let packet = store.packet(at: position)
            let flow = try #require(store.flow(of: packet))
            let endpoints = [flow.initiator, flow.responder]
            #expect(endpoints.contains { $0.address == packet.metadata.source })
            if packet.metadata.protocolKind == .rtp {
                #expect(store.stream(of: packet) != nil)
                #expect(store.call(of: packet) != nil)
            }
            if packet.metadata.protocolKind.isSIP {
                #expect(store.sipMessage(of: packet)?.frameNumber == packet.number)
            }
        }
        let sipFlow = try #require(flows.first { $0.application.isSIP })
        let positions = await store.positions(inFlow: sipFlow.id)
        #expect(positions.count == sipFlow.packets)
        #expect(store.packetBytes(at: 0).data.count == store.packet(at: 0).capturedLength)
    }

    @Test func flowTableIsBounded() {
        var table = FlowTable(limit: 2)
        var packet = DecodedPacket()
        packet.network = .ipv4
        packet.ipProtocol = 17
        packet.transportOffset = 34
        for port in UInt16(1)...5 {
            packet.source = .v4(0x0A00_0001)
            packet.destination = .v4(0x0A00_0002)
            packet.sourcePort = port
            packet.destinationPort = 9
            _ = table.assign(packet, frameNumber: Int(port), timestampNanos: 0, length: 60, protocolKind: .udp)
        }
        #expect(table.flows.count == 2)
        #expect(table.limitReached)
        // Reverse direction maps to the same flow.
        packet.source = .v4(0x0A00_0002)
        packet.destination = .v4(0x0A00_0001)
        packet.sourcePort = 9
        packet.destinationPort = 1
        #expect(table.assign(packet, frameNumber: 9, timestampNanos: 1, length: 60, protocolKind: .dns).id == 0)
        #expect(table.flows[0].packetsFromResponder == 1)
        #expect(table.flows[0].application == .dns)
    }
}
