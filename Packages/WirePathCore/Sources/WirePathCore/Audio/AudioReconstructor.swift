import Foundation

/// A DTMF key press carried as an RFC 4733 telephone-event.
public struct DTMFEvent: Codable, Sendable, Hashable {
    /// "0"–"9", "*", "#", "A"–"D" (or "Event N" for other RFC 4733 events).
    public var key: String
    public var time: Timestamp
    public var durationSeconds: Double
    /// Power level, in −dBm0.
    public var volume: Int
    /// Frame of the event's first packet.
    public var frameNumber: Int?
    /// Whether the end packet was captured.
    public var ended: Bool

    public static func key(for event: UInt8) -> String {
        switch event {
        case 0...9: return String(event)
        case 10: return "*"
        case 11: return "#"
        case 12...15: return String(UnicodeScalar(UInt8(ascii: "A") + event - 12))
        default: return String(localized: "Event \(event)", bundle: CoreLocalization.bundle)
        }
    }

    /// Row and column frequencies (ITU-T Q.23) for keypad events.
    public static func frequencies(for event: UInt8) -> (Double, Double)? {
        let rows = [697.0, 770, 852, 941], columns = [1209.0, 1336, 1477, 1633]
        let layout: [UInt8: (Int, Int)] = [1: (0, 0), 2: (0, 1), 3: (0, 2), 12: (0, 3), 4: (1, 0), 5: (1, 1), 6: (1, 2), 13: (1, 3),
                                           7: (2, 0), 8: (2, 1), 9: (2, 2), 14: (2, 3), 10: (3, 0), 0: (3, 1), 11: (3, 2), 15: (3, 3)]
        guard let (row, column) = layout[event] else { return nil }
        return (rows[row], columns[column])
    }
}

/// A gap in the reconstructed audio and how it was filled.
public struct AudioGap: Sendable, Hashable {
    public enum Cause: Sendable, Hashable {
        /// Packets missing from the capture (sequence numbers skipped): concealed by the decoder.
        case lost(packets: Int)
        /// The sender paused (silence suppression / DTX): silence, or comfort noise when CN was sent.
        case silence
    }

    public var startSample: Int
    public var frames: Int
    public var cause: Cause
}

/// One stream's decoded audio, placed on its RTP timeline.
public struct ReconstructedAudio: Sendable {
    public var streamIndex: Int
    public var sampleRate: Int
    /// Mono 16-bit PCM.
    public var samples: [Int16]
    /// Capture time of the first sample.
    public var startTime: Timestamp
    public var gaps: [AudioGap]
    public var dtmf: [DTMFEvent]
    /// Voice packets decoded / that failed to decode (damaged, or a payload type without a decoder).
    public var decodedPackets: Int
    public var failedPackets: Int
    public var comfortNoisePackets: Int
    /// Reconstruction stopped at `AudioReconstructor.maxSamples`.
    public var truncated: Bool

    public var durationSeconds: Double { sampleRate > 0 ? Double(samples.count) / Double(sampleRate) : 0 }
    public var lostPackets: Int {
        gaps.reduce(0) { total, gap in
            if case .lost(let packets) = gap.cause { return total + packets }
            return total
        }
    }
}

/// RTP stream → codec decoder → audio buffer (spec §48): orders one stream's packets by sequence number, places each
/// decoded payload at its RTP timestamp, conceals losses, fills silence suppression (with comfort noise when CN
/// packets say so) and renders RFC 4733 DTMF events as tones. Independent of SIP and of the UI.
public struct AudioReconstructor: Sendable {
    /// At most this many samples per stream (64 MB of 16-bit PCM: 11 min at 48 kHz, 35 min at 16 kHz, 70 min at 8 kHz).
    public static let maxSamples = 32 * 1024 * 1024
    /// A timestamp jump larger than this (or backwards) is a discontinuity: the stream is re-anchored on arrival time.
    static let maxTimestampJumpSeconds = 30.0

    public var registry: AudioCodecRegistry

    public init(registry: AudioCodecRegistry = .standard) {
        self.registry = registry
    }

    /// The payloads of one packet with its capture metadata.
    public struct Packet: Sendable {
        public var sequenceNumber: UInt16
        public var timestamp: UInt32
        public var payloadType: UInt8
        public var marker: Bool
        public var arrivalNanos: Int64
        public var frameNumber: Int?
        public var payload: Data

        public init(sequenceNumber: UInt16, timestamp: UInt32, payloadType: UInt8, marker: Bool = false, arrivalNanos: Int64,
                    frameNumber: Int? = nil, payload: Data) {
            self.sequenceNumber = sequenceNumber
            self.timestamp = timestamp
            self.payloadType = payloadType
            self.marker = marker
            self.arrivalNanos = arrivalNanos
            self.frameNumber = frameNumber
            self.payload = payload
        }
    }

    /// Reconstructs one stream. Returns nil when no voice or DTMF could be rendered.
    public func reconstruct(stream: RTPStreamRecord, packets: [Packet]) -> ReconstructedAudio? {
        guard stream.secure != true else { return nil }
        let formats = Dictionary((stream.payloadFormats ?? []).map { ($0.payloadType, $0) }, uniquingKeysWith: { a, _ in a })
        func format(_ pt: UInt8) -> CodecDescriptor? {
            formats[pt] ?? (pt == stream.payloadType ? stream.codec : nil) ?? CodecCatalog.descriptor(payloadType: pt)
        }
        guard let voice = stream.codec.flatMap({ $0.kind.isVoice ? $0 : nil })
                ?? formats.values.filter({ $0.kind.isVoice }).min(by: { $0.payloadType < $1.payloadType }),
              let primary = registry.makeDecoder(for: voice) else { return nil }
        let rate = primary.sampleRate
        let clock = Double(voice.clockRate ?? rate)
        var decoders: [UInt8: any AudioDecoder] = [voice.payloadType: primary]

        // Order by extended sequence number; drop duplicates.
        let ordered = Self.order(packets)
        guard let first = ordered.first?.1 else { return nil }

        var samples: [Int16] = []
        var gaps: [AudioGap] = []
        var events: [UInt32: DTMFEvent] = [:]
        var eventCodes: [UInt32: (code: UInt8, position: Int, clock: Double)] = [:]
        var decoded = 0, failed = 0, cnPackets = 0
        var truncated = false
        var noiseLevel: Int?  // −dBov from the last CN packet, while the sender is silent
        var noise = SeededNoise(seed: UInt64(stream.ssrc))

        // Timeline: RTP timestamp → sample position, re-anchored on arrival time across discontinuities.
        var anchorTimestamp = Int64(first.timestamp)
        var anchorPosition = 0
        var anchorArrival = first.arrivalNanos
        var lastExtended = Int64(first.timestamp)
        var previousSequence: Int64?

        func position(for timestamp: UInt32, arrival: Int64) -> Int {
            // Unwrap the 32-bit timestamp around the last one seen.
            let delta = Int64(Int32(bitPattern: timestamp &- UInt32(truncatingIfNeeded: lastExtended)))
            let extended = lastExtended + delta
            let seconds = Double(extended - anchorTimestamp) / clock
            if seconds < -1 || seconds > Self.maxTimestampJumpSeconds + Timestamp(nanoseconds: arrival).seconds(since: Timestamp(nanoseconds: anchorArrival)) {
                // Discontinuity (new timestamp base, or a jump the arrival times don't support).
                let elapsed = max(0, Timestamp(nanoseconds: arrival).seconds(since: Timestamp(nanoseconds: anchorArrival)))
                anchorPosition += Int(min(Double(Self.maxSamples), elapsed * Double(rate)))
                anchorTimestamp = extended
                anchorArrival = arrival
            }
            lastExtended = max(lastExtended, extended)
            return anchorPosition + Int((Double(extended - anchorTimestamp) / clock * Double(rate)).rounded())
        }

        func append(_ chunk: [Int16], at start: Int) {
            guard start < Self.maxSamples else {
                truncated = true
                return
            }
            if start > samples.count {
                let gap = start - samples.count
                if let level = noiseLevel {
                    samples += noise.samples(gap, level: level)
                } else {
                    samples += [Int16](repeating: 0, count: gap)
                }
            }
            // Overlap (a late or re-timed packet): keep what is already there.
            let skip = max(0, samples.count - start)
            guard skip < chunk.count else { return }
            let room = Self.maxSamples - samples.count
            if chunk.count - skip > room { truncated = true }
            samples += chunk[skip..<min(chunk.count, skip + room)]
        }

        for (extendedSequence, packet) in ordered {
            let lostBefore = previousSequence.map { Int(max(0, extendedSequence - $0 - 1)) } ?? 0
            previousSequence = extendedSequence
            guard let codec = format(packet.payloadType) else {
                failed += 1
                continue
            }
            let start = position(for: packet.timestamp, arrival: packet.arrivalNanos)
            guard start >= 0 else { continue }
            switch codec.kind {
            case .telephoneEvent:
                guard packet.payload.count >= 4 else { continue }
                let code = packet.payload[packet.payload.startIndex]
                let flags = packet.payload[packet.payload.startIndex + 1]
                let duration = Int(packet.payload[packet.payload.startIndex + 2]) << 8 | Int(packet.payload[packet.payload.startIndex + 3])
                let eventClock = Double(codec.clockRate ?? 8000)
                if events[packet.timestamp] == nil {
                    guard events.count < 10_000 else { continue }
                    events[packet.timestamp] = DTMFEvent(
                        key: DTMFEvent.key(for: code), time: Timestamp(nanoseconds: packet.arrivalNanos), durationSeconds: 0,
                        volume: Int(flags & 0x3F), frameNumber: packet.frameNumber, ended: false)
                    eventCodes[packet.timestamp] = (code, start, eventClock)
                }
                if var event = events[packet.timestamp] {
                    event.durationSeconds = max(event.durationSeconds, Double(duration) / eventClock)
                    if flags & 0x80 != 0 { event.ended = true }
                    events[packet.timestamp] = event
                }
            case .comfortNoise:
                cnPackets += 1
                // RFC 3389: the first byte is the noise level in −dBov; the sender is silent until its next voice packet.
                noiseLevel = packet.payload.first.map { Int($0 & 0x7F) } ?? 127
            default:
                guard codec.kind.isVoice else { continue }
                if decoders[codec.payloadType] == nil, let decoder = registry.makeDecoder(for: codec) {
                    decoders[codec.payloadType] = decoder
                }
                guard let decoder = decoders[codec.payloadType] else {
                    failed += 1
                    continue
                }
                let chunk: [Int16]
                do {
                    chunk = try packet.payload.withUnsafeBytes { raw throws(AudioDecodeError) in try decoder.decode(raw) }
                } catch {
                    failed += 1
                    continue
                }
                decoded += 1
                let resampled = decoder.sampleRate == rate ? chunk : Self.resample(chunk, from: decoder.sampleRate, to: rate)
                if start > samples.count {
                    let missing = start - samples.count
                    if lostBefore > 0 {
                        gaps.append(AudioGap(startSample: samples.count, frames: missing, cause: .lost(packets: lostBefore)))
                        noiseLevel = nil
                        append(decoder.conceal(frames: missing), at: samples.count)
                    } else if !eventCodes.values.contains(where: { $0.position >= samples.count && $0.position < start }) {
                        // The sender paused (not for a DTMF key, whose tone fills the space): filled with comfort noise
                        // when CN announced a level, else silence.
                        gaps.append(AudioGap(startSample: samples.count, frames: missing, cause: .silence))
                    }
                }
                append(resampled, at: start)
                noiseLevel = nil
            }
            if truncated { break }
        }

        // DTMF: replace the audio under each event with its dual tone (events render even without voice decoding).
        for (timestamp, info) in eventCodes {
            guard let event = events[timestamp], let (low, high) = DTMFEvent.frequencies(for: info.code) else { continue }
            let frames = min(Int(event.durationSeconds * Double(rate)), Self.maxSamples - info.position, rate * 10)
            guard frames > 0 else { continue }
            if samples.count < info.position + frames { samples += [Int16](repeating: 0, count: info.position + frames - samples.count) }
            let amplitude = 16_000 * pow(10, -Double(event.volume) / 20)
            for n in 0..<frames {
                let t = Double(n) / Double(rate)
                samples[info.position + n] = Int16(clamping: Int(amplitude * (sin(2 * .pi * low * t) + sin(2 * .pi * high * t)) / 2))
            }
        }
        guard !samples.isEmpty else { return nil }
        let startTime = Timestamp(nanoseconds: first.arrivalNanos)
        return ReconstructedAudio(streamIndex: stream.id, sampleRate: rate, samples: samples, startTime: startTime, gaps: gaps,
                                  dtmf: events.values.sorted { $0.time < $1.time }, decodedPackets: decoded, failedPackets: failed,
                                  comfortNoisePackets: cnPackets, truncated: truncated)
    }

    /// Packets sorted by extended (wrap-corrected) sequence number, duplicates removed.
    static func order(_ packets: [Packet]) -> [(Int64, Packet)] {
        guard let first = packets.first else { return [] }
        var highest = Int64(first.sequenceNumber)
        var seen = Set<Int64>()
        var result: [(Int64, Packet)] = []
        result.reserveCapacity(packets.count)
        for packet in packets {
            let delta = Int64(Int16(bitPattern: packet.sequenceNumber &- UInt16(truncatingIfNeeded: highest)))
            let extended = highest + delta
            highest = max(highest, extended)
            if seen.insert(extended).inserted { result.append((extended, packet)) }
        }
        return result.sorted { $0.0 < $1.0 }
    }

    /// Linear interpolation, for a payload whose codec runs at another rate than the stream's main codec.
    static func resample(_ samples: [Int16], from source: Int, to target: Int) -> [Int16] {
        guard source > 0, target > 0, !samples.isEmpty else { return [] }
        let count = samples.count * target / source
        return (0..<count).map { n in
            let position = Double(n) * Double(source) / Double(target)
            let i = Int(position)
            let fraction = position - Double(i)
            let a = Double(samples[min(i, samples.count - 1)]), b = Double(samples[min(i + 1, samples.count - 1)])
            return Int16(clamping: Int(a + (b - a) * fraction))
        }
    }
}

/// Deterministic white noise at a level in −dBov, for comfort noise.
struct SeededNoise: Sendable {
    private var state: UInt64

    init(seed: UInt64) { state = seed | 1 }

    mutating func samples(_ count: Int, level: Int) -> [Int16] {
        let amplitude = 32767 * pow(10, -Double(level) / 20) * 1.732  // uniform noise with that RMS
        return (0..<count).map { _ in
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            let uniform = Double(state >> 11) / Double(1 << 53) * 2 - 1
            return Int16(clamping: Int(uniform * amplitude))
        }
    }
}
