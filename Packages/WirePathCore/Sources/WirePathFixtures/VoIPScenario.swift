import Foundation

// A small network simulator that produces realistic SIP/RTP captures with known impairments.
// Used by the unit tests (ground truth for the analyzers) and by `wpsamplegen`.

public struct SimHost: Sendable, Hashable {
    public var ip: String
    public var port: UInt16
    public var userAgent: String

    public init(_ ip: String, port: UInt16 = 5060, userAgent: String = "WirePathSim/1.0") {
        self.ip = ip
        self.port = port
        self.userAgent = userAgent
    }
}

public struct SimParty: Sendable, Hashable {
    public var user: String
    public var displayName: String?
    public var host: SimHost
    public var domain: String

    public init(_ user: String, _ displayName: String?, host: SimHost, domain: String = "pbx.office.lan") {
        self.user = user
        self.displayName = displayName
        self.host = host
        self.domain = domain
    }
}

public enum SimCodec: Sendable {
    case pcmu, pcma, g729, opus, g722

    var payloadType: UInt8 {
        switch self {
        case .pcmu: return 0
        case .pcma: return 8
        case .g729: return 18
        case .opus: return 111
        case .g722: return 9
        }
    }

    var rtpmap: String {
        switch self {
        case .pcmu: return "PCMU/8000"
        case .pcma: return "PCMA/8000"
        case .g729: return "G729/8000"
        case .opus: return "opus/48000/2"
        case .g722: return "G722/8000"
        }
    }

    var clockRate: Int { self == .opus ? 48000 : 8000 }

    var fmtp: String? {
        switch self {
        case .g729: return "annexb=no"
        case .opus: return "useinbandfec=1"
        default: return nil
        }
    }
}

public struct SimSpike: Sendable {
    public var time: Double
    public var amplitudeMs: Double
    public var width: Double

    public init(time: Double, amplitudeMs: Double, width: Double) {
        self.time = time
        self.amplitudeMs = amplitudeMs
        self.width = width
    }
}

public struct SimLossWindow: Sendable {
    public var start: Double
    public var end: Double
    public var probability: Double

    public init(start: Double, end: Double, probability: Double) {
        self.start = start
        self.end = end
        self.probability = probability
    }
}

/// Network behaviour for one media direction. Times are relative to the start of that direction's media.
public struct SimImpairment: Sendable {
    public var baseDelayMs: Double = 1.5
    /// Standard deviation of the per-packet delay variation.
    public var jitterMs: Double = 0.6
    public var randomLoss: Double = 0
    public var lossWindows: [SimLossWindow] = []
    public var spikes: [SimSpike] = []
    public var reorderProbability: Double = 0
    public var duplicateProbability: Double = 0
    public var ssrcChangeAt: Double?
    /// Drop every packet (one-way audio).
    public var silent = false
    /// Explicit sequence numbers (0-based packet index) to drop — exact loss for tests.
    public var dropIndices: Set<Int> = []

    public init(baseDelayMs: Double = 1.5, jitterMs: Double = 0.6, randomLoss: Double = 0,
                lossWindows: [SimLossWindow] = [], spikes: [SimSpike] = [], reorderProbability: Double = 0,
                duplicateProbability: Double = 0, ssrcChangeAt: Double? = nil, silent: Bool = false,
                dropIndices: Set<Int> = []) {
        self.baseDelayMs = baseDelayMs
        self.jitterMs = jitterMs
        self.randomLoss = randomLoss
        self.lossWindows = lossWindows
        self.spikes = spikes
        self.reorderProbability = reorderProbability
        self.duplicateProbability = duplicateProbability
        self.ssrcChangeAt = ssrcChangeAt
        self.silent = silent
        self.dropIndices = dropIndices
    }

    /// Perfect network: constant delay, no loss — deterministic ground truth for tests.
    public static let perfect = SimImpairment(baseDelayMs: 1, jitterMs: 0)
}

public enum SimOutcome: Sendable {
    case answered(talk: Double, hangupByCaller: Bool)
    /// Final error from the callee (486, 603…) or, with `fromServer`, from the SIP server (503…).
    case rejected(code: Int, reason: String, fromServer: Bool)
    /// Callee never answers; the server retransmits the INVITE and finally sends 408.
    case timeout
    case cancelled(after: Double)
}

public enum SimTopology: Sendable {
    case direct
    /// Stateful proxy: one Call-ID across both legs, media flows directly between the phones.
    case proxy(SimHost)
    /// Back-to-back user agent: a second Call-ID for the outgoing leg; optionally anchors media.
    case b2bua(SimHost, anchorMedia: Bool)
}

public struct SimCall: Sendable {
    public var start: Double
    public var caller: SimParty
    public var callee: SimParty
    public var topology: SimTopology
    public var outcome: SimOutcome
    public var ringDuration: Double
    public var codec: SimCodec
    public var ptimeMs: Int
    public var forward: SimImpairment
    public var reverse: SimImpairment
    public var sipOverTCP: Bool
    /// When set, SIP datagrams larger than this IP payload size are IPv4-fragmented.
    public var fragmentMTU: Int?
    public var seed: UInt64

    public init(start: Double, caller: SimParty, callee: SimParty, topology: SimTopology, outcome: SimOutcome,
                ringDuration: Double = 3.6, codec: SimCodec = .pcmu, ptimeMs: Int = 20,
                forward: SimImpairment = SimImpairment(), reverse: SimImpairment = SimImpairment(),
                sipOverTCP: Bool = false, fragmentMTU: Int? = nil, seed: UInt64 = 1) {
        self.start = start
        self.caller = caller
        self.callee = callee
        self.topology = topology
        self.outcome = outcome
        self.ringDuration = ringDuration
        self.codec = codec
        self.ptimeMs = ptimeMs
        self.forward = forward
        self.reverse = reverse
        self.sipOverTCP = sipOverTCP
        self.fragmentMTU = fragmentMTU
        self.seed = seed
    }
}

// MARK: - Packet sources

protocol PacketSource {
    var nextTime: Double? { get }
    mutating func pop() -> TimedFrame?
}

struct FrameListSource: PacketSource {
    var frames: [TimedFrame]
    var index = 0

    init(_ frames: [TimedFrame]) { self.frames = frames.sorted { $0.time < $1.time } }
    var nextTime: Double? { index < frames.count ? frames[index].time : nil }
    mutating func pop() -> TimedFrame? {
        guard index < frames.count else { return nil }
        defer { index += 1 }
        return frames[index]
    }
}

/// Lazily generates one RTP direction, emitting packets in arrival order.
struct RTPDirectionSource: PacketSource {
    let sourceIP: String, sourcePort: UInt16, destinationIP: String, destinationPort: UInt16
    let codec: SimCodec
    let ptime: Double
    let start: Double
    let end: Double
    let impairment: SimImpairment
    let toneHz: Double
    var rng: SeededRandom
    var ssrc: UInt32
    var sequence: UInt16
    var timestamp: UInt32
    var packetIndex = 0
    var ipID: UInt16
    var buffer: [TimedFrame] = []
    var changedSSRC = false
    let maxDelay: Double

    init(sourceIP: String, sourcePort: UInt16, destinationIP: String, destinationPort: UInt16, codec: SimCodec,
         ptimeMs: Int, start: Double, end: Double, impairment: SimImpairment, toneHz: Double, seed: UInt64) {
        self.sourceIP = sourceIP
        self.sourcePort = sourcePort
        self.destinationIP = destinationIP
        self.destinationPort = destinationPort
        self.codec = codec
        self.ptime = Double(ptimeMs) / 1000
        self.start = start
        self.end = end
        self.impairment = impairment
        self.toneHz = toneHz
        rng = SeededRandom(seed: seed)
        ssrc = UInt32(truncatingIfNeeded: rng.next())
        sequence = UInt16(truncatingIfNeeded: rng.next() & 0x7FFF)
        timestamp = UInt32(truncatingIfNeeded: rng.next() & 0x0FFF_FFFF)
        ipID = UInt16(truncatingIfNeeded: rng.next())
        maxDelay = (impairment.baseDelayMs + 6 * impairment.jitterMs + (impairment.spikes.map(\.amplitudeMs).max() ?? 0)) / 1000
            + 3 * Double(ptimeMs) / 1000
        fill()
    }

    var nextTime: Double? { buffer.first?.time }

    mutating func pop() -> TimedFrame? {
        guard !buffer.isEmpty else { return nil }
        let frame = buffer.removeFirst()
        fill()
        return frame
    }

    private var nextSendTime: Double { start + Double(packetIndex) * ptime }

    private mutating func fill() {
        guard !impairment.silent else { return }
        while nextSendTime < end && (buffer.isEmpty || nextSendTime < buffer[0].time + maxDelay) {
            generateOne()
        }
    }

    private mutating func insert(_ frame: TimedFrame) {
        let position = buffer.firstIndex { $0.time > frame.time } ?? buffer.count
        buffer.insert(frame, at: position)
    }

    private mutating func generateOne() {
        let send = nextSendTime
        let relative = send - start
        let k = packetIndex
        packetIndex += 1
        if let change = impairment.ssrcChangeAt, !changedSSRC, relative >= change {
            changedSSRC = true
            ssrc = UInt32(truncatingIfNeeded: rng.next())
            sequence = UInt16(truncatingIfNeeded: rng.next() & 0x7FFF)
            timestamp = UInt32(truncatingIfNeeded: rng.next() & 0x0FFF_FFFF)
        }
        let seq = sequence
        let ts = timestamp
        sequence &+= 1
        timestamp &+= UInt32(Double(codec.clockRate) * ptime)

        var lossProbability = impairment.randomLoss
        for window in impairment.lossWindows where relative >= window.start && relative < window.end {
            lossProbability = max(lossProbability, window.probability)
        }
        let dropped = impairment.dropIndices.contains(k) || (lossProbability > 0 && rng.chance(lossProbability))
        // Always consume the same random numbers so impairments don't shift each other.
        let noise = abs(rng.gaussian()) * impairment.jitterMs
        let reorder = rng.chance(impairment.reorderProbability)
        let duplicate = rng.chance(impairment.duplicateProbability)
        if dropped { return }

        var delayMs = impairment.baseDelayMs + noise
        for spike in impairment.spikes {
            delayMs += spike.amplitudeMs * exp(-pow((relative - spike.time) / spike.width, 2))
        }
        if reorder { delayMs += ptime * 1500 }
        let payload = makePayload(index: k)
        var rtp: [UInt8] = [0x80, codec.payloadType | (k == 0 ? 0x80 : 0), UInt8(seq >> 8), UInt8(seq & 0xFF)]
        rtp += [UInt8(ts >> 24), UInt8((ts >> 16) & 0xFF), UInt8((ts >> 8) & 0xFF), UInt8(ts & 0xFF)]
        rtp += [UInt8(ssrc >> 24), UInt8((ssrc >> 16) & 0xFF), UInt8((ssrc >> 8) & 0xFF), UInt8(ssrc & 0xFF)]
        rtp += payload
        ipID &+= 1
        let frame = FrameBuilder.udpFrame(source: sourceIP, sourcePort: sourcePort, destination: destinationIP,
                                          destinationPort: destinationPort, payload: rtp, identification: ipID, dscp: 46)
        let arrival = send + delayMs / 1000
        insert(TimedFrame(time: arrival, bytes: frame))
        if duplicate { insert(TimedFrame(time: arrival + 0.0008, bytes: frame)) }
    }

    private mutating func makePayload(index: Int) -> [UInt8] {
        switch codec {
        case .pcmu, .pcma:
            let samples = Int(8000 * ptime)
            return (0..<samples).map { n in
                let t = Double(index * samples + n) / 8000
                let value = Int16(3000 * sin(2 * .pi * toneHz * t))
                return codec == .pcmu ? G711.encodeMuLaw(value) : G711.encodeALaw(value)
            }
        case .g729:
            return (0..<Int(10 * ptime * 100)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
        case .g722:
            return (0..<Int(8000 * ptime)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
        case .opus:
            return (0..<(60 + Int(rng.next() % 20))).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
        }
    }
}

/// G.711 encoders (classic reference algorithm), used to put an audible tone in generated captures.
public enum G711 {
    public static func encodeMuLaw(_ sample: Int16) -> UInt8 {
        let segmentEnds = [0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF]
        var pcm = Int(sample) >> 2
        let mask: Int
        if pcm < 0 { pcm = -pcm; mask = 0x7F } else { mask = 0xFF }
        pcm = min(pcm, 8159) + (0x84 >> 2)
        guard let segment = segmentEnds.firstIndex(where: { pcm <= $0 }) else { return UInt8(0x7F ^ mask) }
        return UInt8(((segment << 4) | ((pcm >> (segment + 1)) & 0x0F)) ^ mask)
    }

    public static func encodeALaw(_ sample: Int16) -> UInt8 {
        let segmentEnds = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF]
        var pcm = Int(sample) >> 3
        let mask: Int
        if pcm >= 0 { mask = 0xD5 } else { mask = 0x55; pcm = -pcm - 1 }
        guard let segment = segmentEnds.firstIndex(where: { pcm <= $0 }) else { return UInt8(0x7F ^ mask) }
        let value = (segment << 4) | (segment < 2 ? (pcm >> 1) & 0x0F : (pcm >> segment) & 0x0F)
        return UInt8(value ^ mask)
    }
}
