import Foundation

/// Codec information negotiated for a media endpoint (from SDP).
public struct RTPNegotiation: Sendable {
    public var codecs: [UInt8: CodecDescriptor]
    public var ptimeMs: Int?
    /// Negotiated as SRTP: the payloads are encrypted.
    public var secure: Bool

    public init(codecs: [UInt8: CodecDescriptor], ptimeMs: Int?, secure: Bool = false) {
        self.codecs = codecs
        self.ptimeMs = ptimeMs
        self.secure = secure
    }
}

/// Routes RTP packets to per-SSRC analyzers and decides which candidate flows really are RTP.
public struct RTPTracker: Sendable {
    public struct StreamKey: Hashable, Sendable {
        public var source: Endpoint
        public var destination: Endpoint
        public var ssrc: UInt32
    }

    private struct FlowKey: Hashable, Sendable {
        var source: Endpoint
        var destination: Endpoint
    }

    public private(set) var analyzers: [RTPStreamAnalyzer] = []
    private var indexByKey: [StreamKey: Int] = [:]
    private var latestOnFlow: [FlowKey: Int] = [:]
    private var ssrcCountOnFlow: [FlowKey: Int] = [:]
    /// Flows that produced too many distinct SSRCs without SDP — not RTP.
    private var rejectedFlows: Set<FlowKey> = []
    /// Streams that started a new SSRC on an existing 5-tuple (analyzer index → true).
    public private(set) var ssrcChangeStreams: Set<Int> = []

    /// Bounds that keep a crafted capture from creating unlimited stream state.
    public static let maxStreams = 100_000
    public static let maxSSRCsPerFlow = 16
    public static let maxSSRCsPerNegotiatedFlow = 256
    /// Set when `maxStreams` was reached and later streams were ignored.
    public private(set) var streamLimitReached = false

    public init() {}

    public var streamCount: Int { analyzers.count }

    /// Feeds a packet. `negotiation` is consulted only when a new stream is created.
    public mutating func ingest(_ header: RTPHeader, source: Endpoint, destination: Endpoint, arrivalNanos: Int64,
                                negotiation: () -> RTPNegotiation?) -> (streamIndex: Int, verdict: RTPPacketVerdict, newSSRC: Bool)? {
        let key = StreamKey(source: source, destination: destination, ssrc: header.ssrc)
        var newSSRC = false
        let index: Int
        if let existing = indexByKey[key] {
            index = existing
        } else {
            let flow = FlowKey(source: source, destination: destination)
            if rejectedFlows.contains(flow) { return nil }
            let negotiated = negotiation()
            let ssrcCount = ssrcCountOnFlow[flow, default: 0] + 1
            ssrcCountOnFlow[flow] = ssrcCount
            if ssrcCount > (negotiated == nil ? Self.maxSSRCsPerFlow : Self.maxSSRCsPerNegotiatedFlow) {
                rejectedFlows.insert(flow)
                return nil
            }
            guard analyzers.count < Self.maxStreams else {
                streamLimitReached = true
                return nil
            }
            index = analyzers.count
            var analyzer = RTPStreamAnalyzer(ssrc: header.ssrc, source: source, destination: destination,
                                             codecs: negotiated?.codecs ?? [:], ptimeMs: negotiated?.ptimeMs,
                                             negotiatedInSDP: negotiated != nil)
            analyzer.secure = negotiated?.secure ?? false
            if let previous = latestOnFlow[flow] {
                analyzer.replacesSSRC = analyzers[previous].ssrc
                ssrcChangeStreams.insert(index)
                newSSRC = true
            }
            latestOnFlow[flow] = index
            analyzers.append(analyzer)
            indexByKey[key] = index
        }
        let verdict = analyzers[index].ingest(header, arrivalNanos: arrivalNanos)
        return (index, verdict, newSSRC)
    }

    /// Frame bytes of each stream's packets (for the on-the-wire bitrate).
    private(set) var wireBytes: [Int: Int64] = [:]

    mutating func addWireBytes(_ bytes: Int, toStream index: Int) {
        wireBytes[index, default: 0] += Int64(bytes)
    }

    /// Late SDP knowledge (e.g. announcement captured after media started) upgrades a stream.
    public mutating func applyNegotiation(_ negotiation: RTPNegotiation, toStream index: Int) {
        guard !analyzers[index].negotiatedInSDP else { return }
        analyzers[index].negotiatedInSDP = true
        analyzers[index].codecs.merge(negotiation.codecs) { current, _ in current }
        if analyzers[index].ptimeMs == nil { analyzers[index].ptimeMs = negotiation.ptimeMs }
        if negotiation.secure { analyzers[index].secure = true }
    }

    /// Whether a stream qualifies as RTP: negotiated in SDP, or heuristically consistent.
    public func isAccepted(_ index: Int) -> Bool {
        let analyzer = analyzers[index]
        if analyzer.negotiatedInSDP { return analyzer.packets >= 1 }
        if rejectedFlows.contains(FlowKey(source: analyzer.source, destination: analyzer.destination)) { return false }
        guard analyzer.packets >= 8 else { return false }
        let durationSeconds = Timestamp(nanoseconds: analyzer.lastArrival).seconds(since: Timestamp(nanoseconds: analyzer.firstArrival))
        return analyzer.sequentialRatio >= 0.8 && durationSeconds >= 0.1
    }
}
