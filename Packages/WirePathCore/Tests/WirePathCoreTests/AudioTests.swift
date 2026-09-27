@testable import WirePathCore
import AVFAudio
import Foundation
import Testing
import WirePathFixtures

/// Audio reconstruction on `audio-codecs.pcap` and the codec decoders. The G.722 decoder is bit-exact with ffmpeg's
/// (CRC of ffmpeg's decode of the same bytes); tshark agrees on the fixture's streams, loss and RFC 4733 events.
@Suite("Audio")
struct AudioTests {
    /// Power of `hz` in `samples` (Goertzel), normalised by length.
    static func power(_ samples: ArraySlice<Int16>, hz: Double, rate: Int) -> Double {
        let coefficient = 2 * cos(2 * .pi * hz / Double(rate))
        var s1 = 0.0, s2 = 0.0
        for sample in samples {
            let s = Double(sample) + coefficient * s1 - s2
            s2 = s1
            s1 = s
        }
        return (s1 * s1 + s2 * s2 - coefficient * s1 * s2) / Double(max(1, samples.count))
    }

    static func rms(_ samples: ArraySlice<Int16>) -> Double {
        (samples.reduce(0.0) { $0 + Double($1) * Double($1) } / Double(max(1, samples.count))).squareRoot()
    }

    static func audio(_ streams: [Int]) async throws -> (AnalysisResult, [ReconstructedAudio]) {
        let analysis = try await FixtureTests.analyze("audio-codecs.pcap")
        let store = try analysis.store()
        let records = streams.map { analysis.result.streams[$0] }
        return (analysis.result, await store.reconstructAudio(records, callIndex: nil))
    }

    // MARK: Decoders

    @Test func g722IsBitExactWithTheReferenceDecoder() throws {
        let encoded = G722Encoder().encode(FixtureCatalog.AudioSignals.sweep(count: 32_000))
        let decoded = try encoded.withUnsafeBytes { try G722Decoder().decode($0) }
        #expect(decoded.count == 32_000)
        let bytes = decoded.withUnsafeBytes { Data($0) }  // little-endian, like ffmpeg's s16le output
        #expect(GzipWriter.crc32(bytes) == 0xC551_A2D5)
    }

    @Test func g711DecodesWhatTheEncoderProduces() throws {
        for value in stride(from: -32_000, through: 32_000, by: 97) {
            let sample = Int16(value)
            let mu = try [G711.encodeMuLaw(sample)].withUnsafeBytes { try G711Decoder(.muLaw).decode($0) }[0]
            let a = try [G711.encodeALaw(sample)].withUnsafeBytes { try G711Decoder(.aLaw).decode($0) }[0]
            // Logarithmic quantisation: the error grows with the magnitude (≤ 1/16 of it, plus the smallest step).
            let tolerance = abs(value) / 16 + 16
            #expect(abs(Int(mu) - value) <= tolerance, "µ-law \(value) → \(mu)")
            #expect(abs(Int(a) - value) <= tolerance, "A-law \(value) → \(a)")
        }
    }

    @Test func l16RejectsPartialFrames() {
        #expect(throws: AudioDecodeError.invalidPayload) {
            try [UInt8]([1, 2, 3]).withUnsafeBytes { try L16Decoder(sampleRate: 16000, channels: 1).decode($0) }
        }
    }

    /// Encodes a tone with the system encoder and decodes it with WirePath's decoder (both through AudioToolbox).
    static func systemRoundTrip(formatID: AudioFormatID, rate: Double, framesPerPacket: UInt32, decoder: any AudioDecoder)
        throws -> [Int16] {
        var description = AudioStreamBasicDescription(mSampleRate: rate, mFormatID: formatID, mFormatFlags: 0, mBytesPerPacket: 0,
                                                      mFramesPerPacket: framesPerPacket, mBytesPerFrame: 0, mChannelsPerFrame: 1,
                                                      mBitsPerChannel: 0, mReserved: 0)
        let compressedFormat = try #require(AVAudioFormat(streamDescription: &description))
        let pcmFormat = try #require(AVAudioFormat(commonFormat: .pcmFormatFloat32, sampleRate: rate, channels: 1, interleaved: false))
        let encoder = try #require(AVAudioConverter(from: pcmFormat, to: compressedFormat))
        let frames = AVAudioFrameCount(rate)  // 1 s
        let input = try #require(AVAudioPCMBuffer(pcmFormat: pcmFormat, frameCapacity: frames))
        input.frameLength = frames
        for n in 0..<Int(frames) { input.floatChannelData?[0][n] = Float(0.3 * sin(2 * .pi * 440 * Double(n) / rate)) }
        let output = AVAudioCompressedBuffer(format: compressedFormat, packetCapacity: 200, maximumPacketSize: max(encoder.maximumOutputPacketSize, 1))
        nonisolated(unsafe) var supplied = false
        var error: NSError?
        _ = encoder.convert(to: output, error: &error) { _, status in
            if supplied { status.pointee = .endOfStream; return nil }
            supplied = true
            status.pointee = .haveData
            return input
        }
        #expect(error == nil)
        var decoded: [Int16] = []
        let descriptions = try #require(output.packetDescriptions)
        for index in 0..<Int(output.packetCount) {
            let packet = descriptions[index]
            let bytes = UnsafeRawBufferPointer(start: output.data + Int(packet.mStartOffset), count: Int(packet.mDataByteSize))
            decoded += try decoder.decode(bytes)
        }
        return decoded
    }

    @Test func opusDecodesThroughTheSystemCodec() throws {
        let decoder = try #require(SystemAudioDecoder.opus())
        let decoded = try Self.systemRoundTrip(formatID: kAudioFormatOpus, rate: 48000, framesPerPacket: 960, decoder: decoder)
        #expect(decoded.count > 40_000)
        let middle = decoded[12_000..<36_000]
        #expect(Self.power(middle, hz: 440, rate: 48000) > 50 * Self.power(middle, hz: 1_000, rate: 48000))
    }

    @Test func iLBCDecodesThroughTheSystemCodec() throws {
        let decoder = try #require(ILBCDecoder())
        let decoded = try Self.systemRoundTrip(formatID: kAudioFormatiLBC, rate: 8000, framesPerPacket: 160, decoder: decoder)
        #expect(decoded.count > 7_000)
        let middle = decoded[2_000..<6_000]
        #expect(Self.power(middle, hz: 440, rate: 8000) > 20 * Self.power(middle, hz: 1_000, rate: 8000))
    }

    // MARK: Reconstruction

    @Test func g711CallWithDTMFLossAndComfortNoise() async throws {
        let (result, audio) = try await Self.audio([0, 1])
        #expect(result.streams[0].payloadFormats?.map(\.kind) == [.pcmu, .telephoneEvent])
        #expect(result.streams[1].payloadFormats?.map(\.kind) == [.pcmu, .comfortNoise])
        let caller = try #require(audio.first { $0.streamIndex == 0 })
        #expect(caller.sampleRate == 8000)
        #expect(caller.samples.count == 150 * 160)  // 3 s: voice, DTMF and the concealed loss
        #expect(caller.dtmf.map(\.key) == ["1", "5", "#"])
        #expect(caller.dtmf.map(\.durationSeconds) == [0.1, 0.1, 0.12])
        #expect(caller.dtmf.allSatisfy { $0.ended && $0.volume == 10 })
        #expect(caller.gaps == [AudioGap(startSample: 110 * 160, frames: 5 * 160, cause: .lost(packets: 5))])
        #expect(caller.lostPackets == 5)
        let voice = caller.samples[0..<8000]
        #expect(Self.power(voice, hz: 440, rate: 8000) > 100 * Self.power(voice, hz: 660, rate: 8000))
        // Key "1" (697 + 1209 Hz) rendered where the event was.
        let key = caller.samples[8000..<8800]
        #expect(Self.power(key, hz: 697, rate: 8000) > 20 * Self.power(key, hz: 440, rate: 8000))
        #expect(Self.power(key, hz: 1209, rate: 8000) > 20 * Self.power(key, hz: 440, rate: 8000))
        #expect(Self.rms(caller.samples[(110 * 160)..<(115 * 160)]) == 0)  // concealed as silence

        let callee = try #require(audio.first { $0.streamIndex == 1 })
        #expect(callee.comfortNoisePackets == 1)
        #expect(callee.gaps == [AudioGap(startSample: 8000, frames: 8000, cause: .silence)])
        let noise = Self.rms(callee.samples[8000..<16_000])  // −60 dBov ≈ 32.8
        #expect(noise > 25 && noise < 40, "comfort noise RMS \(noise)")
        let tone = callee.samples[16_000..<24_000]
        #expect(Self.power(tone, hz: 660, rate: 8000) > 100 * Self.power(tone, hz: 440, rate: 8000))
    }

    @Test func g722AndL16Streams() async throws {
        let (_, audio) = try await Self.audio([2, 3, 4])
        let sweep = try #require(audio.first { $0.streamIndex == 2 })
        #expect(sweep.sampleRate == 16000 && sweep.samples.count == 32_000)
        // The QMF pair delays the signal by 22 samples; ADPCM keeps it within ~25 dB.
        let source = FixtureCatalog.AudioSignals.sweep(count: 32_000)
        var signal = 0.0, noise = 0.0
        for n in 0..<(32_000 - 22) {
            signal += Double(source[n]) * Double(source[n])
            noise += pow(Double(source[n]) - Double(sweep.samples[n + 22]), 2)
        }
        #expect(10 * log10(signal / noise) > 20)
        let tone = try #require(audio.first { $0.streamIndex == 3 })
        #expect(Self.power(tone.samples[4000..<20_000], hz: 1000, rate: 16000) > 100 * Self.power(tone.samples[4000..<20_000], hz: 3000, rate: 16000))

        let l16 = try #require(audio.first { $0.streamIndex == 4 })
        #expect(l16.sampleRate == 16000)
        #expect(l16.samples == FixtureCatalog.AudioSignals.tone(1000, rate: 16000, from: 0, count: 16_000))
    }

    @Test func playabilityExplainsWhatCannotBePlayed() async throws {
        let (result, audio) = try await Self.audio([5, 6])
        #expect(audio.isEmpty)
        let registry = AudioCodecRegistry.standard
        #expect(registry.playability(of: result.streams[0]) == .playable(decoder: "G.711 µ-law (built in)"))
        #expect(registry.playability(of: result.streams[2]).isPlayable)
        #expect(registry.playability(of: result.streams[5]) == .unsupported(codec: "G.729", reason: .licensing))
        #expect(result.streams[6].secure == true)
        #expect(registry.playability(of: result.streams[6]) == .encrypted)

        // Extensible: a registered decoder makes a codec playable.
        final class Silence: AudioDecoder {
            let sampleRate = 8000
            func decode(_ payload: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16] { [Int16](repeating: 0, count: 160) }
        }
        var custom = AudioCodecRegistry.standard
        custom.register(.g729, name: "Test decoder") { _ in Silence() }
        #expect(custom.playability(of: result.streams[5]) == .playable(decoder: "Test decoder"))
        let decoded = AudioReconstructor(registry: custom)
        let store = try await FixtureTests.analyze("audio-codecs.pcap").store()
        #expect(await store.reconstructAudio([result.streams[5]], callIndex: nil, reconstructor: decoded).first?.samples.count == 8000)
    }

    @Test func webrtcMediaIsEncrypted() async throws {
        let result = try await FixtureTests.analyze("webrtc-session.pcap").result
        #expect(result.streams.allSatisfy { $0.secure == true })
        #expect(AudioCodecRegistry.standard.playability(of: result.streams[0]) == .encrypted)
    }

    @Test func orderingHandlesWrapAndDuplicates() {
        func packet(_ sequence: UInt16) -> AudioReconstructor.Packet {
            .init(sequenceNumber: sequence, timestamp: 0, payloadType: 0, arrivalNanos: 0, payload: Data())
        }
        let ordered = AudioReconstructor.order([packet(65_534), packet(0), packet(65_535), packet(1), packet(0)])
        #expect(ordered.map(\.0) == [65_534, 65_535, 65_536, 65_537])
    }

    @Test func hostileTimestampsStayBounded() throws {
        var stream = try #require(FixtureCatalog.all.isEmpty ? nil : RTPStreamRecord.placeholder)
        let pcmu = CodecDescriptor(kind: .pcmu, encodingName: "PCMU", payloadType: 0, clockRate: 8000)
        stream.codec = pcmu
        stream.payloadFormats = [pcmu, CodecDescriptor(kind: .g722, encodingName: "G722", payloadType: 9, clockRate: 8000),
                                 CodecDescriptor(kind: .comfortNoise, encodingName: "CN", payloadType: 13, clockRate: 8000),
                                 CodecDescriptor(kind: .telephoneEvent, encodingName: "telephone-event", payloadType: 101, clockRate: 8000)]
        var random = SeededRandom(seed: 42)
        var packets: [AudioReconstructor.Packet] = []
        for n in 0..<400 {
            let payload = Data((0..<Int(random.next() % 400)).map { _ in UInt8(truncatingIfNeeded: random.next()) })
            packets.append(.init(sequenceNumber: UInt16(truncatingIfNeeded: random.next() % 600), timestamp: UInt32(truncatingIfNeeded: random.next()),
                                 payloadType: [0, 9, 13, 101, 77][Int(random.next() % 5)], arrivalNanos: Int64(n) * 20_000_000, payload: payload))
        }
        let audio = try #require(AudioReconstructor().reconstruct(stream: stream, packets: packets))
        #expect(audio.samples.count <= AudioReconstructor.maxSamples)
        #expect(audio.decodedPackets > 0)
    }

    // MARK: Playback and export

    @MainActor @Test func engineRendersEachDirectionOnItsSide() async throws {
        let (_, audio) = try await Self.audio([0, 1])
        let tracks = AudioTrack.aligned([(audio[0], -1), (audio[1], 1)])
        let mix = try AudioEngine.renderOffline(tracks, sampleRate: 8000)
        #expect(mix.count >= 2 * 23_000)
        let left = mix.enumerated().filter { $0.offset % 2 == 0 && $0.offset / 2 < 8000 }.map { Int16(clamping: Int($0.element * 32767)) }
        let right = mix.enumerated().filter { $0.offset % 2 == 1 && $0.offset / 2 < 8000 }.map { Int16(clamping: Int($0.element * 32767)) }
        #expect(Self.power(left[...], hz: 440, rate: 8000) > 100 * Self.power(right[...], hz: 440, rate: 8000))
        #expect(Self.power(right[...], hz: 660, rate: 8000) > 100 * Self.power(left[...], hz: 660, rate: 8000))
    }

    @Test func wavExport() async throws {
        let (_, audio) = try await Self.audio([0, 1])
        let mono = AudioExport.wav(audio[0])
        #expect(mono.prefix(4) == Data("RIFF".utf8))
        #expect(mono.count == 44 + audio[0].samples.count * 2)
        let stereo = AudioExport.stereoWAV(AudioTrack.aligned([(audio[0], -1), (audio[1], 1)]))
        #expect(stereo[22] == 2 && stereo[24] == 0x40 && stereo[25] == 0x1F)  // 2 channels, 8000 Hz
    }

    // MARK: Privacy

    @Test func storedSIPTextsHaveNoSecrets() async throws {
        let text = "INVITE sip:a@b SIP/2.0\r\nAuthorization: Digest username=\"2001\", response=\"0123abcd\", nonce=\"x\"\r\n\r\n"
            + "a=ice-pwd:supersecret\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:S3CR3TKEY|2^20|1:32\r\n"
        let redacted = SIPRedaction.redact(text)
        #expect(!redacted.contains("0123abcd") && !redacted.contains("supersecret") && !redacted.contains("S3CR3TKEY"))
        #expect(redacted.contains("username=\"2001\"") && redacted.contains("|2^20|1:32") && redacted.contains("nonce=\"x\""))

        let analysis = try await FixtureTests.analyze("audio-codecs.pcap")
        let stored = try String(contentsOf: Fixtures.artifacts(in: analysis.directory).sipTexts, encoding: .utf8)
        #expect(stored.contains("inline:[redacted]"))
        #expect(!stored.contains("V2lyZVBhdGgg"))
    }
}

extension RTPStreamRecord {
    /// A minimal stream for decoder-level tests.
    static var placeholder: RTPStreamRecord {
        RTPStreamRecord(id: 0, ssrc: 1, source: Endpoint(address: .v4(1), port: 1), destination: Endpoint(address: .v4(2), port: 2),
                        payloadType: 0, codec: nil, ptimeMs: 20, firstTime: Timestamp(nanoseconds: 0), lastTime: Timestamp(nanoseconds: 0),
                        packetCount: 0, payloadBytes: 0, expectedPackets: 0, lostPackets: 0, duplicatePackets: 0, outOfOrderPackets: 0,
                        sequenceGaps: 0, markerPackets: 0, payloadTypeChanges: 0, meanJitterMs: nil, maxJitterMs: nil, maxJitterTime: nil,
                        meanDeltaMs: 0, maxDeltaMs: 0, burstRatio: 1, lossBursts: [], series: .empty(origin: Timestamp(nanoseconds: 0)),
                        negotiatedInSDP: true)
    }
}
