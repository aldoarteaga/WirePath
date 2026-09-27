import Foundation

public enum FindingKind: String, Codable, Sendable {
    case sipFailure
    case poorQuality
    case packetLoss
    case lossBurst
    case highJitter
    case jitterSpike
    case oneWayAudio
    case noMedia
    case ssrcChange
    case outOfOrder
    case duplicates
    case noFinalResponse
    case sipRetransmissions
    case captureTruncated
    case sipTimeout
    case missingACK
    case authenticationFailure
    case sipErrorResponses
    case registrationFailure
    case tcpRetransmissions
    case tcpReset
    case tcpUnanswered
    case highRoundTrip
    case reportedQuality
    case iceFailure
    case candidateProblem
    case stunError
    case stunTimeout
    case turnAllocationFailure
    case turnRelay
    case dtlsFailure
    case noMediaAfterICE

    /// Protocol the diagnostic is about.
    public var protocolName: String {
        switch self {
        case .sipFailure, .noFinalResponse, .sipRetransmissions, .sipTimeout, .missingACK, .authenticationFailure,
             .sipErrorResponses, .registrationFailure:
            return "SIP"
        case .poorQuality, .packetLoss, .lossBurst, .highJitter, .jitterSpike, .oneWayAudio, .noMedia, .ssrcChange,
             .outOfOrder, .duplicates:
            return "RTP"
        case .highRoundTrip, .reportedQuality: return "RTCP"
        case .tcpRetransmissions, .tcpReset, .tcpUnanswered: return "TCP"
        case .captureTruncated: return "Capture"
        case .iceFailure, .candidateProblem, .dtlsFailure, .noMediaAfterICE: return "WebRTC"
        case .stunError, .stunTimeout: return "STUN"
        case .turnAllocationFailure, .turnRelay: return "TURN"
        }
    }
}

/// Something worth the user's attention, always backed by measured evidence.
public struct Finding: Codable, Sendable, Identifiable {
    public var id: Int
    public var severity: Severity
    public var kind: FindingKind
    public var title: String
    public var detail: String
    public var callIndex: Int?
    public var streamIndex: Int?
    public var time: Timestamp?
    public var endTime: Timestamp?
    /// Frame numbers of the packets that show the problem (at most `maxPacketReferences`).
    public var packetReferences: [Int]
    /// A display filter selecting the relevant packets, when a set of frames would be too many to list.
    public var packetFilter: String?
    /// WebRTC session the diagnostic is about (index into `AnalysisResult.webrtc.sessions`).
    public var webrtcSessionIndex: Int?

    public static let maxPacketReferences = 200

    public var protocolName: String { kind.protocolName }

    /// A display filter that shows the diagnostic's packets (nil when it has no packet evidence).
    public var displayFilter: String? {
        if let packetFilter { return packetFilter }
        guard !packetReferences.isEmpty else { return nil }
        return "frame.number in {" + packetReferences.map(String.init).joined(separator: " ") + "}"
    }

    public init(id: Int, severity: Severity, kind: FindingKind, title: String, detail: String, callIndex: Int? = nil,
                streamIndex: Int? = nil, time: Timestamp? = nil, endTime: Timestamp? = nil, packetReferences: [Int] = [],
                packetFilter: String? = nil, webrtcSessionIndex: Int? = nil) {
        self.webrtcSessionIndex = webrtcSessionIndex
        self.packetReferences = Array(packetReferences.prefix(Self.maxPacketReferences))
        self.packetFilter = packetFilter
        self.id = id
        self.severity = severity
        self.kind = kind
        self.title = title
        self.detail = detail
        self.callIndex = callIndex
        self.streamIndex = streamIndex
        self.time = time
        self.endTime = endTime
    }
}

public enum CaptureFormat: String, Codable, Sendable {
    case pcap, pcapNanosecond, pcapng

    public var label: String {
        switch self {
        case .pcap: return "pcap"
        case .pcapNanosecond: return "pcap (ns)"
        case .pcapng: return "pcapng"
        }
    }
}

public struct ProtocolCount: Codable, Sendable, Hashable {
    public var name: String
    public var packets: Int
    public var bytes: Int64

    public init(name: String, packets: Int, bytes: Int64) {
        self.name = name
        self.packets = packets
        self.bytes = bytes
    }
}

public struct AddressCount: Codable, Sendable, Hashable {
    public var address: IPAddress
    public var packets: Int

    public init(address: IPAddress, packets: Int) {
        self.address = address
        self.packets = packets
    }
}

/// Facts about the capture file itself.
public struct CaptureSummary: Codable, Sendable {
    public var fileName: String
    public var fileSize: Int64
    public var format: CaptureFormat
    public var compressed: Bool
    public var linkTypes: [String]
    public var firstPacketTime: Timestamp?
    public var lastPacketTime: Timestamp?
    public var packetCount: Int
    public var byteCount: Int64
    public var sipPackets: Int
    public var rtpPackets: Int
    public var rtcpPackets: Int
    public var protocols: [ProtocolCount]
    public var addresses: [AddressCount]
    public var truncatedPackets: Int
    /// Set when the file ended in the middle of a record.
    public var truncatedAtEnd: Bool
    public var warnings: [String]
    /// pcap "2.4", pcapng section "1.0".
    public var formatVersion: String
    public var interfaces: [CaptureInterfaceInfo]
    /// pcapng Section Header metadata (capture hardware, OS, application, comments).
    public var section: CaptureSectionInfo?
    public var packetComments: [PacketComment]
    public var flowCount: Int

    public init(fileName: String, fileSize: Int64, format: CaptureFormat, compressed: Bool, linkTypes: [String],
                firstPacketTime: Timestamp?, lastPacketTime: Timestamp?, packetCount: Int, byteCount: Int64,
                sipPackets: Int, rtpPackets: Int, rtcpPackets: Int, protocols: [ProtocolCount],
                addresses: [AddressCount], truncatedPackets: Int, truncatedAtEnd: Bool, warnings: [String],
                formatVersion: String = "", interfaces: [CaptureInterfaceInfo] = [], section: CaptureSectionInfo? = nil,
                packetComments: [PacketComment] = [], flowCount: Int = 0) {
        self.fileName = fileName
        self.fileSize = fileSize
        self.format = format
        self.compressed = compressed
        self.linkTypes = linkTypes
        self.firstPacketTime = firstPacketTime
        self.lastPacketTime = lastPacketTime
        self.packetCount = packetCount
        self.byteCount = byteCount
        self.sipPackets = sipPackets
        self.rtpPackets = rtpPackets
        self.rtcpPackets = rtcpPackets
        self.protocols = protocols
        self.addresses = addresses
        self.truncatedPackets = truncatedPackets
        self.truncatedAtEnd = truncatedAtEnd
        self.warnings = warnings
        self.formatVersion = formatVersion
        self.interfaces = interfaces
        self.section = section
        self.packetComments = packetComments
        self.flowCount = flowCount
    }

    public var durationSeconds: Double {
        guard let first = firstPacketTime, let last = lastPacketTime else { return 0 }
        return last.seconds(since: first)
    }
}

/// SIP topology inferred from the signalling (only filled when the evidence is unambiguous).
public struct NetworkTopology: Codable, Sendable {
    /// Address that relays or terminates most SIP sessions (proxy / PBX / B2BUA).
    public var sipServer: IPAddress?
    /// User agents that originate or receive calls (excluding the server and trunks).
    public var endpoints: [IPAddress]
    /// Public (non-private) SIP peers exchanging calls with the server.
    public var trunks: [IPAddress]

    public init(sipServer: IPAddress?, endpoints: [IPAddress], trunks: [IPAddress]) {
        self.sipServer = sipServer
        self.endpoints = endpoints
        self.trunks = trunks
    }
}

public struct DurationStats: Codable, Sendable, Hashable {
    public var mean: Double
    public var min: Double
    public var max: Double
    public var total: Double

    public init(mean: Double, min: Double, max: Double, total: Double) {
        self.mean = mean
        self.min = min
        self.max = max
        self.total = total
    }

    public init?(_ values: [Double]) {
        guard let minimum = values.min(), let maximum = values.max() else { return nil }
        let total = values.reduce(0, +)
        self.init(mean: total / Double(values.count), min: minimum, max: maximum, total: total)
    }
}

/// Aggregate VoIP figures shown on the Overview.
public struct VoIPSummary: Codable, Sendable {
    public var totalCalls: Int
    public var answeredCalls: Int
    public var failedCalls: Int
    public var rejectedCalls: Int
    public var cancelledCalls: Int
    public var callsWithIssues: Int
    public var talkTime: DurationStats?
    public var meanMOS: Double?
    public var minMOS: Double?
    /// Counts per MOS bucket: < 3.1, 3.1–3.6, 3.6–4.0, 4.0–4.3, ≥ 4.3.
    public var mosHistogram: [Int]
    public var callsWithMOS: Int
    public var meanJitterMs: Double?
    public var maxJitterMs: Double?
    public var lossPercent: Double?
    public var lostPackets: Int
    public var expectedPackets: Int
    public var outOfOrderPackets: Int
    public var duplicatePackets: Int
    public var sipErrorResponses: [Int]
    /// (codec family, number of calls) sorted by usage.
    public var codecUsage: [CodecUsage]

    public init(totalCalls: Int, answeredCalls: Int, failedCalls: Int, rejectedCalls: Int, cancelledCalls: Int,
                callsWithIssues: Int, talkTime: DurationStats?, meanMOS: Double?, minMOS: Double?,
                mosHistogram: [Int], callsWithMOS: Int, meanJitterMs: Double?, maxJitterMs: Double?,
                lossPercent: Double?, lostPackets: Int, expectedPackets: Int, outOfOrderPackets: Int,
                duplicatePackets: Int, sipErrorResponses: [Int], codecUsage: [CodecUsage]) {
        self.totalCalls = totalCalls
        self.answeredCalls = answeredCalls
        self.failedCalls = failedCalls
        self.rejectedCalls = rejectedCalls
        self.cancelledCalls = cancelledCalls
        self.callsWithIssues = callsWithIssues
        self.talkTime = talkTime
        self.meanMOS = meanMOS
        self.minMOS = minMOS
        self.mosHistogram = mosHistogram
        self.callsWithMOS = callsWithMOS
        self.meanJitterMs = meanJitterMs
        self.maxJitterMs = maxJitterMs
        self.lossPercent = lossPercent
        self.lostPackets = lostPackets
        self.expectedPackets = expectedPackets
        self.outOfOrderPackets = outOfOrderPackets
        self.duplicatePackets = duplicatePackets
        self.sipErrorResponses = sipErrorResponses
        self.codecUsage = codecUsage
    }

    /// Calls that did not connect (failed + rejected + no answer).
    public var unansweredFailures: Int { failedCalls + rejectedCalls }
}

public struct CodecUsage: Codable, Sendable, Hashable {
    public var name: String
    public var calls: Int

    public init(name: String, calls: Int) {
        self.name = name
        self.calls = calls
    }
}

/// One-line status shown under an analysis in the sidebar.
public struct AnalysisHeadline: Codable, Sendable, Hashable {
    public var severity: Severity
    public var text: String

    public init(severity: Severity, text: String) {
        self.severity = severity
        self.text = text
    }
}

/// Everything WirePath derived from one capture.
public struct AnalysisResult: Codable, Sendable {
    public static let schemaVersion = 6

    public var schemaVersion: Int
    public var capture: CaptureSummary
    public var topology: NetworkTopology
    public var voip: VoIPSummary
    public var headline: AnalysisHeadline
    public var sipMessages: [SIPMessageRecord]
    public var sipTransactions: [SIPTransactionRecord]
    public var sipSessions: [SIPSessionRecord]
    public var calls: [CallRecord]
    public var streams: [RTPStreamRecord]
    public var findings: [Finding]
    /// Traffic over time, packet sizes and rates.
    public var statistics: CaptureStatistics?
    /// Sender, receiver and extended reports read from RTCP.
    public var rtcpReports: [RTCPReportRecord]
    /// ICE sessions, STUN transactions, TURN allocations and DTLS.
    public var webrtc: WebRTCAnalysis

    public init(capture: CaptureSummary, topology: NetworkTopology, voip: VoIPSummary, headline: AnalysisHeadline,
                sipMessages: [SIPMessageRecord], sipTransactions: [SIPTransactionRecord],
                sipSessions: [SIPSessionRecord], calls: [CallRecord], streams: [RTPStreamRecord],
                findings: [Finding], statistics: CaptureStatistics? = nil, rtcpReports: [RTCPReportRecord] = [],
                webrtc: WebRTCAnalysis = .empty) {
        self.webrtc = webrtc
        self.statistics = statistics
        self.rtcpReports = rtcpReports
        self.schemaVersion = Self.schemaVersion
        self.capture = capture
        self.topology = topology
        self.voip = voip
        self.headline = headline
        self.sipMessages = sipMessages
        self.sipTransactions = sipTransactions
        self.sipSessions = sipSessions
        self.calls = calls
        self.streams = streams
        self.findings = findings
    }
}

/// Lightweight counters stored with each analysis so the sidebar renders without loading results.
public struct AnalysisSummaryInfo: Codable, Sendable, Hashable {
    public var packetCount: Int
    public var callCount: Int
    public var answeredCalls: Int
    public var failedCalls: Int
    public var sipSessionCount: Int
    public var rtpStreamCount: Int
    public var durationSeconds: Double
    public var firstPacketTime: Timestamp?
    public var lastPacketTime: Timestamp?
    public var headline: AnalysisHeadline
    /// Optional so manifests written before flows (or WebRTC analysis) existed still decode.
    public var flowCount: Int?
    public var webrtcSessionCount: Int?

    public init(packetCount: Int, callCount: Int, answeredCalls: Int, failedCalls: Int, sipSessionCount: Int,
                rtpStreamCount: Int, durationSeconds: Double, firstPacketTime: Timestamp?, lastPacketTime: Timestamp?,
                headline: AnalysisHeadline, flowCount: Int? = nil, webrtcSessionCount: Int? = nil) {
        self.flowCount = flowCount
        self.webrtcSessionCount = webrtcSessionCount
        self.packetCount = packetCount
        self.callCount = callCount
        self.answeredCalls = answeredCalls
        self.failedCalls = failedCalls
        self.sipSessionCount = sipSessionCount
        self.rtpStreamCount = rtpStreamCount
        self.durationSeconds = durationSeconds
        self.firstPacketTime = firstPacketTime
        self.lastPacketTime = lastPacketTime
        self.headline = headline
    }

    public init(result: AnalysisResult) {
        self.init(packetCount: result.capture.packetCount, callCount: result.calls.count,
                  answeredCalls: result.voip.answeredCalls, failedCalls: result.voip.unansweredFailures,
                  sipSessionCount: result.sipSessions.count, rtpStreamCount: result.streams.count,
                  durationSeconds: result.capture.durationSeconds, firstPacketTime: result.capture.firstPacketTime,
                  lastPacketTime: result.capture.lastPacketTime, headline: result.headline,
                  flowCount: result.capture.flowCount, webrtcSessionCount: result.webrtc.sessions.count)
    }
}

extension AnalysisResult {
    /// True when every cross-reference (call → streams/messages/sessions/findings, stream → call, message →
    /// session/transaction…) points inside its target array. Saved results are read back from disk and may be
    /// damaged; screens index these arrays directly, so a result that fails this check is never shown.
    public var isStructurallyValid: Bool {
        func valid(_ index: Int?, _ count: Int) -> Bool { index.map { $0 >= 0 && $0 < count } ?? true }
        func valid(_ indices: [Int], _ count: Int) -> Bool { indices.allSatisfy { $0 >= 0 && $0 < count } }
        let messages = sipMessages.count, transactions = sipTransactions.count, sessions = sipSessions.count
        for call in calls {
            guard valid(call.streamIndices, streams.count), valid(call.messageIndices, messages),
                  valid(call.sessionIndices, sessions), valid(call.findingIndices, findings.count) else { return false }
            if let quality = call.quality {
                for direction in [quality.forward, quality.reverse].compactMap({ $0 })
                where !valid(direction.streamIndices, streams.count) { return false }
            }
        }
        for stream in streams where !valid(stream.callIndex, calls.count) { return false }
        for finding in findings where !valid(finding.callIndex, calls.count) || !valid(finding.streamIndex, streams.count)
            || !valid(finding.webrtcSessionIndex, webrtc.sessions.count) {
            return false
        }
        let webrtcTransactions = webrtc.transactions.count
        guard valid(webrtc.serverBindings, webrtcTransactions) else { return false }
        for session in webrtc.sessions {
            guard valid(session.selectedPair, session.pairs.count), valid(session.streamIndices, streams.count),
                  valid(session.turnAllocations, webrtc.allocations.count), valid(session.transactionIndices, webrtcTransactions),
                  valid(session.serverBindingIndices, webrtcTransactions),
                  session.peerAddresses.count == 2, session.pairs.allSatisfy({ (0...1).contains($0.checkingPeer) })
            else { return false }
        }
        for message in sipMessages where !valid(message.sessionIndex, sessions) || !valid(message.transactionIndex, transactions) {
            return false
        }
        for transaction in sipTransactions
        where !valid(transaction.requestIndex, messages) || !valid(transaction.responseIndices, messages) { return false }
        for session in sipSessions {
            guard valid(session.messageIndices, messages), valid(session.transactionIndices, transactions),
                  valid(session.callIndex, calls.count) else { return false }
        }
        return true
    }
}
