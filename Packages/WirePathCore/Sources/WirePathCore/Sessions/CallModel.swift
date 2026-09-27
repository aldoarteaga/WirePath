import Foundation

public enum CallState: String, Codable, Sendable {
    /// Answered (2xx) and terminated by BYE inside the capture.
    case completed
    /// Answered but no BYE captured (still up when the capture ended).
    case answered
    /// Provisional responses only when the capture ended.
    case ringing
    /// Final 4xx/5xx/6xx response other than an explicit rejection.
    case failed
    /// Actively declined by the callee (486, 600, 603).
    case rejected
    /// Cancelled by the caller before answer (CANCEL / 487).
    case cancelled
    /// No final response to the INVITE at all.
    case noAnswer

    public var wasAnswered: Bool { self == .completed || self == .answered }
    public var isFailure: Bool { self == .failed || self == .rejected || self == .noAnswer }
}

public enum CallEndReason: String, Codable, Sendable {
    case byeFromCaller, byeFromCallee, cancel, failureResponse, captureEnded, unknown

    public var label: String {
        switch self {
        case .byeFromCaller: return String(localized: "BYE from caller", bundle: CoreLocalization.bundle)
        case .byeFromCallee: return String(localized: "BYE from callee", bundle: CoreLocalization.bundle)
        case .cancel: return String(localized: "CANCEL from caller", bundle: CoreLocalization.bundle)
        case .failureResponse: return String(localized: "Rejected", bundle: CoreLocalization.bundle)
        case .captureEnded: return String(localized: "Still active at capture end", bundle: CoreLocalization.bundle)
        case .unknown: return String(localized: "Unknown", bundle: CoreLocalization.bundle)
        }
    }
}

/// How the media flowed relative to the SIP signalling path.
public enum MediaPath: Codable, Sendable, Hashable {
    /// RTP flows directly between the two user agents.
    case direct
    /// RTP is anchored on a relay (SBC/PBX) at this address.
    case relayed(IPAddress)
    /// No media captured or not determinable.
    case unknown

    public var label: String {
        switch self {
        case .direct: return String(localized: "Direct media", bundle: CoreLocalization.bundle)
        case .relayed(let address): return String(localized: "Media via \(address.description)", bundle: CoreLocalization.bundle)
        case .unknown: return String(localized: "No media", bundle: CoreLocalization.bundle)
        }
    }
}

public struct CallParty: Codable, Sendable, Hashable {
    public var user: String
    public var displayName: String?
    public var uri: String
    /// Signalling address of the party's user agent.
    public var signalling: Endpoint

    public init(user: String, displayName: String?, uri: String, signalling: Endpoint) {
        self.user = user
        self.displayName = displayName
        self.uri = uri
        self.signalling = signalling
    }
}

/// A participant column in the SIP ladder diagram.
public struct CallParticipant: Codable, Sendable, Hashable {
    public var address: IPAddress
    public var label: String

    public init(address: IPAddress, label: String) {
        self.address = address
        self.label = label
    }
}

/// Per-direction quality figures for a call (forward = caller → callee).
public struct DirectionQuality: Codable, Sendable, Hashable {
    public var streamIndices: [Int]
    public var packets: Int
    public var expected: Int
    public var lost: Int
    public var duplicates: Int
    public var outOfOrder: Int
    public var meanJitterMs: Double?
    public var maxJitterMs: Double?
    public var mos: Double?

    public init(streamIndices: [Int], packets: Int, expected: Int, lost: Int, duplicates: Int, outOfOrder: Int,
                meanJitterMs: Double?, maxJitterMs: Double?, mos: Double?) {
        self.streamIndices = streamIndices
        self.packets = packets
        self.expected = expected
        self.lost = lost
        self.duplicates = duplicates
        self.outOfOrder = outOfOrder
        self.meanJitterMs = meanJitterMs
        self.maxJitterMs = maxJitterMs
        self.mos = mos
    }

    public var lossPercent: Double {
        expected > 0 ? max(0, Double(lost)) / Double(expected) * 100 : 0
    }
}

public struct CallQuality: Codable, Sendable, Hashable {
    public var forward: DirectionQuality?
    public var reverse: DirectionQuality?
    /// Worst-direction MOS estimate; nil when no direction could be estimated.
    public var mos: Double?
    /// Mean jitter over both directions (packet-weighted); nil when unknown.
    public var meanJitterMs: Double?
    public var maxJitterMs: Double?
    /// Loss over both directions.
    public var lossPercent: Double?
    public var lostPackets: Int
    public var rtpPackets: Int

    public init(forward: DirectionQuality?, reverse: DirectionQuality?, mos: Double?, meanJitterMs: Double?,
                maxJitterMs: Double?, lossPercent: Double?, lostPackets: Int, rtpPackets: Int) {
        self.forward = forward
        self.reverse = reverse
        self.mos = mos
        self.meanJitterMs = meanJitterMs
        self.maxJitterMs = maxJitterMs
        self.lossPercent = lossPercent
        self.lostPackets = lostPackets
        self.rtpPackets = rtpPackets
    }
}

/// A reconstructed voice call (one INVITE session, or several B2BUA legs merged).
public struct CallRecord: Codable, Sendable, Identifiable {
    public var id: Int
    public var callIDs: [String]
    public var sessionIndices: [Int]
    public var messageIndices: [Int]
    public var caller: CallParty
    public var callee: CallParty
    public var participants: [CallParticipant]
    public var startTime: Timestamp
    public var ringingTime: Timestamp?
    public var answerTime: Timestamp?
    public var endTime: Timestamp
    public var state: CallState
    public var finalStatusCode: Int?
    public var finalReason: String?
    public var endReason: CallEndReason
    public var codec: CodecDescriptor?
    public var ptimeMs: Int?
    public var mediaPath: MediaPath
    public var streamIndices: [Int]
    public var quality: CallQuality?
    public var severity: Severity
    public var findingIndices: [Int]
    /// True when several Call-IDs were merged as legs of one B2BUA call.
    public var mergedLegs: Bool

    public init(id: Int, callIDs: [String], sessionIndices: [Int], messageIndices: [Int], caller: CallParty,
                callee: CallParty, participants: [CallParticipant], startTime: Timestamp, ringingTime: Timestamp?,
                answerTime: Timestamp?, endTime: Timestamp, state: CallState, finalStatusCode: Int?,
                finalReason: String?, endReason: CallEndReason, codec: CodecDescriptor?, ptimeMs: Int?,
                mediaPath: MediaPath, streamIndices: [Int], quality: CallQuality?, severity: Severity,
                findingIndices: [Int], mergedLegs: Bool) {
        self.id = id
        self.callIDs = callIDs
        self.sessionIndices = sessionIndices
        self.messageIndices = messageIndices
        self.caller = caller
        self.callee = callee
        self.participants = participants
        self.startTime = startTime
        self.ringingTime = ringingTime
        self.answerTime = answerTime
        self.endTime = endTime
        self.state = state
        self.finalStatusCode = finalStatusCode
        self.finalReason = finalReason
        self.endReason = endReason
        self.codec = codec
        self.ptimeMs = ptimeMs
        self.mediaPath = mediaPath
        self.streamIndices = streamIndices
        self.quality = quality
        self.severity = severity
        self.findingIndices = findingIndices
        self.mergedLegs = mergedLegs
    }

    /// Talk time (answer → end); nil for unanswered calls.
    public var talkDurationSeconds: Double? {
        guard let answerTime else { return nil }
        return endTime.seconds(since: answerTime)
    }

    /// Post-dial delay (INVITE → answer).
    public var setupSeconds: Double? {
        guard let answerTime else { return nil }
        return answerTime.seconds(since: startTime)
    }

    public var totalDurationSeconds: Double { endTime.seconds(since: startTime) }

    /// "200 OK", "486 Busy Here", "Cancelled"…
    public var statusLabel: String {
        if let code = finalStatusCode {
            let reason = finalReason ?? SIPStatus.reasonPhrase(for: code)
            return reason.isEmpty ? "\(code)" : "\(code) \(reason)"
        }
        switch state {
        case .ringing: return String(localized: "Ringing", bundle: CoreLocalization.bundle)
        case .noAnswer: return String(localized: "No final response", bundle: CoreLocalization.bundle)
        case .completed: return String(localized: "Completed", bundle: CoreLocalization.bundle)
        case .answered: return String(localized: "Answered", bundle: CoreLocalization.bundle)
        case .failed: return String(localized: "Failed", bundle: CoreLocalization.bundle)
        case .rejected: return String(localized: "Rejected", bundle: CoreLocalization.bundle)
        case .cancelled: return String(localized: "Cancelled", bundle: CoreLocalization.bundle)
        }
    }
}
