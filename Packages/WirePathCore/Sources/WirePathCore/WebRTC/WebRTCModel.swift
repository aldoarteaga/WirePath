import Foundation

/// One STUN request and its outcome (RFC 8489 transaction), matched by transaction ID.
public struct STUNTransactionRecord: Codable, Sendable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        /// ICE connectivity check between peers (Binding with a `remote:local` USERNAME).
        case iceCheck
        /// Binding to a STUN server (server-reflexive candidate discovery).
        case serverBinding
        /// TURN Allocate, Refresh, CreatePermission or ChannelBind.
        case turn
    }

    public enum Outcome: Codable, Sendable, Hashable {
        case success
        case error(code: Int, reason: String)
        case noResponse
        /// The capture ended before a response could arrive.
        case pending
    }

    public var id: Int
    public var kind: Kind
    public var method: UInt16
    public var methodName: String
    /// Sender and receiver of the request (for relayed checks: the relayed address and the peer).
    public var client: Endpoint
    public var server: Endpoint
    public var relayed: Bool
    public var requestFrames: [Int]
    public var responseFrame: Int?
    public var requestTime: Timestamp
    /// Time of the last retransmission (equal to `requestTime` when the request was sent once).
    public var lastRequestTime: Timestamp
    public var responseTime: Timestamp?
    public var outcome: Outcome
    /// ICE checks only: "remote-ufrag:local-ufrag" (no passwords, and no TURN usernames, are kept).
    public var username: String?
    public var useCandidate: Bool
    /// The request carried MESSAGE-INTEGRITY (long- or short-term credentials).
    public var authenticated: Bool
    public var controlling: Bool?
    public var mappedAddress: Endpoint?
    public var relayedAddress: Endpoint?

    /// Request-to-response time; nil for retransmitted requests, where the answered copy is unknown (Karn's rule).
    public var rttMs: Double? {
        guard requestFrames.count == 1 else { return nil }
        return responseTime.map { $0.seconds(since: requestTime) * 1_000 }
    }
    public var retransmissions: Int { max(0, requestFrames.count - 1) }
}

/// A candidate pair checked by ICE, as seen from the capture point.
public struct ICECandidatePairRecord: Codable, Sendable, Hashable, Identifiable {
    public enum State: String, Codable, Sendable { case succeeded, failed, inProgress }

    public var id: Int
    /// The side that sent the checks (its candidate) and the side that answered.
    public var local: Endpoint
    public var remote: Endpoint
    public var localKind: ICECandidate.Kind
    public var remoteKind: ICECandidate.Kind
    /// Which peer (0 = A, 1 = B) sent the checks.
    public var checkingPeer: Int
    public var checks: Int
    public var successes: Int
    public var errors: Int
    public var timeouts: Int
    public var nominated: Bool
    public var relayed: Bool
    public var meanRTTMs: Double?
    public var firstTime: Timestamp
    public var lastTime: Timestamp
    public var state: State
}

/// A candidate observed for a peer (from SDP, STUN or TURN).
public struct ObservedCandidate: Codable, Sendable, Hashable {
    public enum Source: String, Codable, Sendable { case sdp, connectivityCheck, stunServer, turnServer }

    public var endpoint: Endpoint
    public var kind: ICECandidate.Kind
    public var source: Source
    public var peer: Int?
}

/// DTLS seen on a flow (WebRTC's DTLS-SRTP keying).
public struct DTLSFlowSummary: Codable, Sendable, Hashable {
    public var a: Endpoint
    public var b: Endpoint
    public var records: Int
    public var clientHelloFrame: Int?
    public var serverHelloFrame: Int?
    /// Change Cipher Spec or encrypted records from both sides: keys were agreed.
    public var established: Bool
    public var alerts: Int
}

/// A TURN allocation (RFC 8656): the relay a client obtained and how it used it.
public struct TURNAllocationRecord: Codable, Sendable, Hashable, Identifiable {
    public struct Channel: Codable, Sendable, Hashable {
        public var number: UInt16
        public var peer: Endpoint
    }

    public var id: Int
    public var client: Endpoint
    public var server: Endpoint
    public var relayedAddress: Endpoint?
    public var mappedAddress: Endpoint?
    public var lifetime: UInt32?
    public var allocateRequests: Int
    /// 401 answers to unauthenticated requests and 438 (stale nonce): the normal request for credentials.
    public var challenges: Int
    /// Other error codes answered by the server (401 here means the credentials sent were rejected).
    public var errorCodes: [Int]
    public var succeeded: Bool
    public var refreshes: Int
    public var released: Bool
    public var permissions: [IPAddress]
    public var channels: [Channel]
    public var channelDataPackets: Int
    public var channelDataBytes: Int64
    public var sendIndications: Int
    public var dataIndications: Int
    public var firstTime: Timestamp
    public var lastTime: Timestamp

    public var relayedPackets: Int { channelDataPackets + sendIndications + dataIndications }
}

/// A WebRTC (ICE) session reconstructed from connectivity checks: two peers, their candidates and pairs, the
/// selected pair, DTLS and the media that flowed over it.
public struct WebRTCSessionRecord: Codable, Sendable, Hashable, Identifiable {
    public enum State: String, Codable, Sendable {
        case connected
        case failed
        /// Checks were still running when the capture ended.
        case checking
    }

    public var id: Int
    /// ICE username fragments of peer A (the first to send a check) and peer B.
    public var ufrags: [String]
    public var peerAddresses: [[IPAddress]]
    public var pairs: [ICECandidatePairRecord]
    public var candidates: [ObservedCandidate]
    public var selectedPair: Int?
    public var state: State
    /// Peer controlling the nomination (0 = A, 1 = B), when the checks said so.
    public var controllingPeer: Int?
    public var dtls: DTLSFlowSummary?
    /// RTP streams carried on the selected pair (indices into `AnalysisResult.streams`).
    public var streamIndices: [Int]
    /// TURN allocations made from the session's sockets or whose relay took part in the checks.
    public var turnAllocations: [Int]
    public var usesRelay: Bool
    /// Flows belonging to the session (checks, DTLS, media, TURN), for the `webrtc` filter.
    public var flowIndices: [Int]
    /// Connectivity checks (indices into `WebRTCAnalysis.transactions`).
    public var transactionIndices: [Int]
    /// Bindings to STUN servers made from the session's sockets (candidate gathering).
    public var serverBindingIndices: [Int]
    public var firstTime: Timestamp
    public var lastTime: Timestamp
    /// SIP Call-ID when the session's SDP was signalled over (unencrypted) SIP.
    public var callID: String?

    public var selected: ICECandidatePairRecord? { selectedPair.flatMap { $0 < pairs.count ? pairs[$0] : nil } }
}

/// Everything the WebRTC analysis found.
public struct WebRTCAnalysis: Codable, Sendable, Hashable {
    public var sessions: [WebRTCSessionRecord]
    public var transactions: [STUNTransactionRecord]
    public var allocations: [TURNAllocationRecord]
    /// Server-reflexive discoveries against STUN servers outside any ICE session.
    public var serverBindings: [Int]

    public static let empty = WebRTCAnalysis(sessions: [], transactions: [], allocations: [], serverBindings: [])
    public var isEmpty: Bool { sessions.isEmpty && transactions.isEmpty && allocations.isEmpty }
}
