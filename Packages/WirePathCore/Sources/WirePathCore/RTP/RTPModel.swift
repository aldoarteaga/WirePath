import Foundation

/// A period with concentrated packet loss inside one RTP stream.
public struct LossBurst: Codable, Sendable, Hashable {
    public var start: Timestamp
    public var end: Timestamp
    public var lostPackets: Int

    public init(start: Timestamp, end: Timestamp, lostPackets: Int) {
        self.start = start
        self.end = end
        self.lostPackets = lostPackets
    }
}

/// Time series used by the jitter / packet-loss charts. Bins are relative to `origin`.
public struct StreamSeries: Codable, Sendable, Hashable {
    public var origin: Timestamp
    public var jitterBinSeconds: Double
    /// Maximum RFC 3550 jitter (ms) observed in each bin; `nil` where the bin has no packets.
    public var jitterMs: [Double?]
    public var lossBinSeconds: Double
    /// Packets lost per bin (placed between the neighbouring received packets).
    public var lost: [Int]
    /// Packets received per bin.
    public var received: [Int]

    public init(origin: Timestamp, jitterBinSeconds: Double, jitterMs: [Double?], lossBinSeconds: Double,
                lost: [Int], received: [Int]) {
        self.origin = origin
        self.jitterBinSeconds = jitterBinSeconds
        self.jitterMs = jitterMs
        self.lossBinSeconds = lossBinSeconds
        self.lost = lost
        self.received = received
    }

    public static func empty(origin: Timestamp) -> StreamSeries {
        StreamSeries(origin: origin, jitterBinSeconds: 0.5, jitterMs: [], lossBinSeconds: 1, lost: [], received: [])
    }
}

/// Per-SSRC statistics for one unidirectional RTP flow.
public struct RTPStreamRecord: Codable, Sendable, Identifiable {
    public var id: Int
    public var ssrc: UInt32
    public var source: Endpoint
    public var destination: Endpoint
    public var payloadType: UInt8
    public var codec: CodecDescriptor?
    public var ptimeMs: Double?
    public var firstTime: Timestamp
    public var lastTime: Timestamp
    public var packetCount: Int
    /// First / last sequence number observed (in sequence order) and 16-bit wrap-arounds between them.
    public var firstSequence: UInt16?
    public var lastSequence: UInt16?
    public var sequenceCycles: Int?
    public var payloadBytes: Int64
    /// Packets expected from the extended sequence range.
    public var expectedPackets: Int
    public var lostPackets: Int
    public var duplicatePackets: Int
    public var outOfOrderPackets: Int
    public var sequenceGaps: Int
    public var markerPackets: Int
    public var payloadTypeChanges: Int
    /// `nil` when the RTP clock rate is unknown (dynamic payload type without SDP).
    public var meanJitterMs: Double?
    public var maxJitterMs: Double?
    public var maxJitterTime: Timestamp?
    public var meanDeltaMs: Double
    public var maxDeltaMs: Double
    /// Gilbert-model burst ratio (G.107 BurstR) derived from the loss pattern.
    public var burstRatio: Double
    public var lossBursts: [LossBurst]
    public var series: StreamSeries
    /// True when the stream matched media negotiated in SDP; false when detected heuristically.
    public var negotiatedInSDP: Bool
    /// Previous SSRC on the same 5-tuple when this stream replaced it.
    public var replacesSSRC: UInt32?
    public var callIndex: Int?
    /// Estimated MOS for this direction (nil when it cannot be computed for the codec).
    public var mos: Double?
    public var rFactor: Double?
    /// Bytes of the frames carrying the stream (headers included), for the on-the-wire bitrate.
    public var wireBytes: Int64 = 0
    /// What RTCP reported about the stream, when its sender or receiver sent RTCP.
    public var rtcp: RTCPStreamSummary?
    /// Every payload type seen in the stream with its codec (voice, telephone-event, comfort noise). Optional so
    /// results saved before it existed still decode.
    public var payloadFormats: [CodecDescriptor]?
    /// True when the payload is encrypted (SRTP negotiated in SDP, or media of a WebRTC session).
    public var secure: Bool?

    public init(id: Int, ssrc: UInt32, source: Endpoint, destination: Endpoint, payloadType: UInt8,
                codec: CodecDescriptor?, ptimeMs: Double?, firstTime: Timestamp, lastTime: Timestamp,
                packetCount: Int, payloadBytes: Int64, expectedPackets: Int, lostPackets: Int,
                duplicatePackets: Int, outOfOrderPackets: Int, sequenceGaps: Int, markerPackets: Int,
                payloadTypeChanges: Int, meanJitterMs: Double?, maxJitterMs: Double?, maxJitterTime: Timestamp?, meanDeltaMs: Double,
                maxDeltaMs: Double, burstRatio: Double, lossBursts: [LossBurst], series: StreamSeries,
                negotiatedInSDP: Bool, replacesSSRC: UInt32? = nil, callIndex: Int? = nil, mos: Double? = nil,
                rFactor: Double? = nil, payloadFormats: [CodecDescriptor]? = nil, secure: Bool? = nil) {
        self.payloadFormats = payloadFormats
        self.secure = secure
        self.id = id
        self.ssrc = ssrc
        self.source = source
        self.destination = destination
        self.payloadType = payloadType
        self.codec = codec
        self.ptimeMs = ptimeMs
        self.firstTime = firstTime
        self.lastTime = lastTime
        self.packetCount = packetCount
        self.payloadBytes = payloadBytes
        self.expectedPackets = expectedPackets
        self.lostPackets = lostPackets
        self.duplicatePackets = duplicatePackets
        self.outOfOrderPackets = outOfOrderPackets
        self.sequenceGaps = sequenceGaps
        self.markerPackets = markerPackets
        self.payloadTypeChanges = payloadTypeChanges
        self.meanJitterMs = meanJitterMs
        self.maxJitterMs = maxJitterMs
        self.maxJitterTime = maxJitterTime
        self.meanDeltaMs = meanDeltaMs
        self.maxDeltaMs = maxDeltaMs
        self.burstRatio = burstRatio
        self.lossBursts = lossBursts
        self.series = series
        self.negotiatedInSDP = negotiatedInSDP
        self.replacesSSRC = replacesSSRC
        self.callIndex = callIndex
        self.mos = mos
        self.rFactor = rFactor
    }

    public var durationSeconds: Double { lastTime.seconds(since: firstTime) }

    /// Lost packets as a percentage of expected packets (never negative).
    public var lossPercent: Double {
        guard expectedPackets > 0 else { return 0 }
        return max(0, Double(lostPackets)) / Double(expectedPackets) * 100
    }

    /// Packets per second over the stream's duration (nil for streams shorter than a packet interval).
    public var packetsPerSecond: Double? {
        let seconds = durationSeconds
        return seconds > 0 && packetCount > 1 ? Double(packetCount - 1) / seconds : nil
    }

    /// RTP payload bitrate (codec rate), bits per second.
    public var payloadBitrate: Double? {
        let seconds = durationSeconds
        return seconds > 0 && packetCount > 1 ? Double(payloadBytes) * 8 * Double(packetCount - 1) / Double(packetCount) / seconds : nil
    }

    /// Bitrate on the wire (Ethernet/IP/UDP/RTP headers included), bits per second.
    public var wireBitrate: Double? {
        let seconds = durationSeconds
        return seconds > 0 && packetCount > 1 && wireBytes > 0
            ? Double(wireBytes) * 8 * Double(packetCount - 1) / Double(packetCount) / seconds : nil
    }

    public var ssrcHex: String { String(format: "0x%08X", ssrc) }
    public var codecName: String { codec?.displayName ?? "PT \(payloadType)" }
}
