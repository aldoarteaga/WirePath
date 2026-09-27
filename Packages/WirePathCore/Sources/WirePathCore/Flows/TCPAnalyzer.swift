import Foundation

/// How a TCP connection's opening was observed.
public enum TCPHandshake: String, Codable, Sendable {
    /// SYN, SYN/ACK and ACK were all captured.
    case complete
    /// SYN and SYN/ACK seen, but not the final ACK.
    case synAckSeen
    /// Only SYNs: the server never answered (or its answer was not captured).
    case unanswered
    /// The capture started after the connection was opened.
    case notCaptured
}

/// How a TCP connection ended within the capture.
public enum TCPTermination: String, Codable, Sendable {
    /// FIN in both directions.
    case graceful
    /// FIN from one side only.
    case halfClosed
    case resetByInitiator
    case resetByResponder
    /// Still open when the capture ended.
    case open
}

/// Per-connection results of the TCP analyzer, stored with the connection's flow.
public struct TCPConnectionStats: Codable, Sendable, Hashable {
    public var handshake: TCPHandshake
    public var termination: TCPTermination
    /// SYN → final ACK of the handshake (both halves of the round trip), when the handshake was captured.
    public var initialRTTMs: Double?
    public var initiatorISN: UInt32?
    public var responderISN: UInt32?
    public var payloadBytesFromInitiator: Int64
    public var payloadBytesFromResponder: Int64
    public var retransmissions: Int
    public var outOfOrder: Int
    /// Gaps in the sequence space: data sent but never captured.
    public var segmentsNotCaptured: Int
    public var duplicateACKs: Int
    public var zeroWindows: Int
    public var keepAlives: Int

    public var problemCount: Int { retransmissions + outOfOrder + segmentsNotCaptured + duplicateACKs + zeroWindows }
}

/// Transport-analysis flags stored per packet in the index (`PacketIndexRecord.analysisFlags`).
public struct PacketAnalysisFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    /// Data already sent (and not filling a recent gap) sent again.
    public static let retransmission = PacketAnalysisFlags(rawValue: 1 << 0)
    /// Data filling a gap shortly after later data arrived.
    public static let outOfOrder = PacketAnalysisFlags(rawValue: 1 << 1)
    /// The sequence number jumped: the preceding data was not captured.
    public static let previousSegmentNotCaptured = PacketAnalysisFlags(rawValue: 1 << 2)
    /// A pure ACK repeating the previous acknowledgment and window.
    public static let duplicateACK = PacketAnalysisFlags(rawValue: 1 << 3)
    public static let zeroWindow = PacketAnalysisFlags(rawValue: 1 << 4)
    public static let keepAlive = PacketAnalysisFlags(rawValue: 1 << 5)
    /// Acknowledges data this capture never saw.
    public static let ackedUnseenSegment = PacketAnalysisFlags(rawValue: 1 << 6)
    public static let reset = PacketAnalysisFlags(rawValue: 1 << 7)
    /// A pure ACK repeating the acknowledgment with a new window.
    public static let windowUpdate = PacketAnalysisFlags(rawValue: 1 << 8)

    /// Flags the "Issues" scope and the TCP problem counters include.
    public static let problems: PacketAnalysisFlags = [.retransmission, .outOfOrder, .previousSegmentNotCaptured,
                                                        .duplicateACK, .zeroWindow, .ackedUnseenSegment, .reset]

    /// Wireshark-style labels, most important first.
    public var labels: [String] {
        var result: [String] = []
        if contains(.retransmission) { result.append("TCP Retransmission") }
        if contains(.outOfOrder) { result.append("TCP Out-Of-Order") }
        if contains(.previousSegmentNotCaptured) { result.append("TCP Previous segment not captured") }
        if contains(.duplicateACK) { result.append("TCP Dup ACK") }
        if contains(.zeroWindow) { result.append("TCP ZeroWindow") }
        if contains(.keepAlive) { result.append("TCP Keep-Alive") }
        if contains(.ackedUnseenSegment) { result.append("TCP ACKed unseen segment") }
        if contains(.windowUpdate) { result.append("TCP Window Update") }
        if contains(.reset) { result.append("TCP Reset") }
        return result
    }
}

/// Follows every TCP connection's sequence and acknowledgment numbers during the sequential pass, flagging
/// retransmissions, out-of-order data, gaps, duplicate ACKs, zero windows and keep-alives (the heuristics match
/// Wireshark's TCP analysis closely enough that both flag the same packets on ordinary captures).
///
/// Memory is bounded: at most `maxConnections` connections are followed, and at most 16 open gaps per direction.
struct TCPAnalyzer {
    static let maxConnections = 500_000
    static let maxGaps = 16
    /// Out-of-order window when no round-trip time was measured (Wireshark uses 3 ms as well).
    static let defaultReorderWindowNanos: Int64 = 3_000_000

    private struct Gap {
        var start: UInt32
        var end: UInt32
    }

    private struct Direction {
        var isn: UInt32?
        /// One past the highest sequence number sent (including SYN/FIN).
        var nextSeq: UInt32?
        var highestTime: Int64 = 0
        var gaps: [Gap] = []
        var lastAck: UInt32?
        var lastWindow: UInt16 = 0
        var sentData = false
        var fin = false
        var payloadBytes: Int64 = 0
    }

    private struct Connection {
        var directions = [Direction(), Direction()]
        var synTime: Int64?
        var synAckTime: Int64?
        var handshakeAckTime: Int64?
        var reset: Int?
        var stats = TCPConnectionStats(handshake: .notCaptured, termination: .open, initialRTTMs: nil, initiatorISN: nil,
                                       responderISN: nil, payloadBytesFromInitiator: 0, payloadBytesFromResponder: 0,
                                       retransmissions: 0, outOfOrder: 0, segmentsNotCaptured: 0, duplicateACKs: 0,
                                       zeroWindows: 0, keepAlives: 0)
        var seenPackets = 0
    }

    private var connections: [Int32: Connection] = [:]
    private(set) var limitReached = false

    /// Analyzes one TCP segment of flow `flow`; `fromInitiator` is the direction within the flow.
    mutating func analyze(flow: Int32, fromInitiator: Bool, sequence seq: UInt32, acknowledgment ack: UInt32, flags: UInt8,
                          window: UInt16, payloadLength: Int, timeNanos: Int64) -> PacketAnalysisFlags {
        guard flow >= 0 else { return [] }
        if connections[flow] == nil {
            guard connections.count < Self.maxConnections else {
                limitReached = true
                return []
            }
            connections[flow] = Connection()
        }
        // Mutated in place: no copy of the connection state per packet.
        return Self.analyze(&connections[flow, default: Connection()], fromInitiator: fromInitiator, seq: seq, ack: ack,
                            flags: flags, window: window, payloadLength: payloadLength, time: timeNanos)
    }

    private static func after(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) > 0 }

    private static func analyze(_ c: inout Connection, fromInitiator: Bool, seq: UInt32, ack: UInt32, flags: UInt8,
                                window: UInt16, payloadLength: Int, time: Int64) -> PacketAnalysisFlags {
        let d = fromInitiator ? 0 : 1, r = 1 - d
        let syn = flags & 0x02 != 0, fin = flags & 0x01 != 0, rst = flags & 0x04 != 0, ackSet = flags & 0x10 != 0
        let length = UInt32(clamping: payloadLength)
        let consumed = length &+ (syn ? 1 : 0) &+ (fin ? 1 : 0)
        var result: PacketAnalysisFlags = []
        c.seenPackets += 1

        // Handshake bookkeeping.
        if syn && !ackSet {
            c.synTime = c.synTime ?? time
            c.directions[d].isn = seq
            if d == 0 { c.stats.initiatorISN = seq }
        } else if syn && ackSet {
            c.synAckTime = c.synAckTime ?? time
            c.directions[d].isn = seq
            if d == 1 { c.stats.responderISN = seq }
        } else if ackSet, c.synAckTime != nil, c.handshakeAckTime == nil, d == 0 {
            c.handshakeAckTime = time
        }
        if rst {
            result.insert(.reset)
            c.reset = c.reset ?? d
        }
        if window == 0 && !syn && !fin && !rst {
            result.insert(.zeroWindow)
            c.stats.zeroWindows += 1
        }

        // Sequence analysis.
        var direction = c.directions[d]
        let reorderWindow = max(defaultReorderWindowNanos, c.stats.initialRTTMs.map { Timestamp.clampedNanoseconds($0 * 1e6) } ?? 0)
        if let next = direction.nextSeq, length <= 1, !syn, !fin, !rst, seq == next &- 1 {
            result.insert(.keepAlive)
            c.stats.keepAlives += 1
        } else if consumed > 0, let next = direction.nextSeq {
            if after(seq, next) {
                result.insert(.previousSegmentNotCaptured)
                c.stats.segmentsNotCaptured += 1
                if direction.gaps.count < maxGaps { direction.gaps.append(Gap(start: next, end: seq)) }
            } else if after(next, seq) {
                // Data at or below the highest byte already sent.
                if let index = direction.gaps.firstIndex(where: { !after($0.start, seq) && after($0.end, seq) }) {
                    // Capture timestamps are untrusted: the wrapping difference can only misclassify, never trap.
                    let recent = time &- direction.highestTime < reorderWindow
                    if recent {
                        result.insert(.outOfOrder)
                        c.stats.outOfOrder += 1
                    } else {
                        result.insert(.retransmission)
                        c.stats.retransmissions += 1
                    }
                    // The segment fills (part of) the gap.
                    let end = seq &+ consumed
                    if !after(direction.gaps[index].end, end) {
                        direction.gaps.remove(at: index)
                    } else {
                        direction.gaps[index].start = end
                    }
                } else {
                    result.insert(.retransmission)
                    c.stats.retransmissions += 1
                }
            }
        }
        if consumed > 0 {
            let end = seq &+ consumed
            if direction.nextSeq.map({ after(end, $0) }) ?? true {
                direction.nextSeq = end
                direction.highestTime = time
            }
        }
        if length > 0 {
            direction.sentData = true
            direction.payloadBytes += Int64(length)
        }
        if fin { direction.fin = true }

        // Acknowledgment analysis.
        if ackSet {
            let peer = c.directions[r]
            if let peerNext = peer.nextSeq, after(ack, peerNext) {
                result.insert(.ackedUnseenSegment)
            }
            let pure = length == 0 && !syn && !fin && !rst
            if pure, let lastAck = direction.lastAck, lastAck == ack, peer.sentData {
                if window == direction.lastWindow {
                    result.insert(.duplicateACK)
                    c.stats.duplicateACKs += 1
                } else {
                    result.insert(.windowUpdate)
                }
            }
            direction.lastAck = ack
            direction.lastWindow = window
        }
        c.directions[d] = direction

        if c.stats.initialRTTMs == nil, let synTime = c.synTime, let ackTime = c.handshakeAckTime {
            c.stats.initialRTTMs = Timestamp(nanoseconds: ackTime).seconds(since: Timestamp(nanoseconds: synTime)) * 1_000
        }
        return result
    }

    /// Final statistics for a flow's connection, or nil when the flow is not TCP (or was not followed).
    func stats(for flow: Int32) -> TCPConnectionStats? {
        guard let connection = connections[flow] else { return nil }
        var stats = connection.stats
        stats.payloadBytesFromInitiator = connection.directions[0].payloadBytes
        stats.payloadBytesFromResponder = connection.directions[1].payloadBytes
        if connection.synTime != nil {
            stats.handshake = connection.handshakeAckTime != nil ? .complete : connection.synAckTime != nil ? .synAckSeen : .unanswered
        } else {
            stats.handshake = connection.synAckTime != nil ? .synAckSeen : .notCaptured
        }
        if let reset = connection.reset {
            stats.termination = reset == 0 ? .resetByInitiator : .resetByResponder
        } else if connection.directions[0].fin && connection.directions[1].fin {
            stats.termination = .graceful
        } else if connection.directions[0].fin || connection.directions[1].fin {
            stats.termination = .halfClosed
        }
        return stats
    }
}
