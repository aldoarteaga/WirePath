import Foundation

/// A SIP name-addr / addr-spec header value (From, To, Contact…) broken into parts.
public struct SIPAddress: Codable, Sendable, Hashable {
    public var displayName: String?
    public var uri: String
    /// User part of the URI ("1003" in sip:1003@pbx.office.lan).
    public var user: String?
    public var host: String?
    public var tag: String?

    public init(displayName: String? = nil, uri: String, user: String? = nil, host: String? = nil, tag: String? = nil) {
        self.displayName = displayName
        self.uri = uri
        self.user = user
        self.host = host
        self.tag = tag
    }

    /// Best short identity: the user part, else the full URI.
    public var shortIdentity: String { user ?? uri }
}

/// Media parameters negotiated in an SDP body, kept compact for the result model.
public struct SDPMediaSummary: Codable, Sendable, Hashable {
    public var mediaType: String
    public var endpoint: Endpoint?
    public var transportProtocol: String
    public var payloadTypes: [UInt8]
    public var codecs: [CodecDescriptor]
    public var ptimeMs: Int?
    public var direction: String
    /// ICE username fragment and candidates (WebRTC-style SDP), and the DTLS role.
    public var iceUfrag: String?
    public var candidates: [ICECandidate]
    public var dtlsSetup: String?

    public init(mediaType: String, endpoint: Endpoint?, transportProtocol: String, payloadTypes: [UInt8],
                codecs: [CodecDescriptor], ptimeMs: Int?, direction: String, iceUfrag: String? = nil,
                candidates: [ICECandidate] = [], dtlsSetup: String? = nil) {
        self.iceUfrag = iceUfrag
        self.candidates = candidates
        self.dtlsSetup = dtlsSetup
        self.mediaType = mediaType
        self.endpoint = endpoint
        self.transportProtocol = transportProtocol
        self.payloadTypes = payloadTypes
        self.codecs = codecs
        self.ptimeMs = ptimeMs
        self.direction = direction
    }
}

/// One SIP request or response seen in the capture.
public struct SIPMessageRecord: Codable, Sendable, Identifiable {
    public var id: Int
    public var frameNumber: Int
    public var time: Timestamp
    public var source: Endpoint
    public var destination: Endpoint
    public var transport: TransportKind
    public var isRequest: Bool
    /// Request method, or the CSeq method for responses.
    public var method: String
    public var requestURI: String?
    public var statusCode: Int?
    public var reasonPhrase: String?
    public var callID: String
    public var from: SIPAddress
    public var to: SIPAddress
    public var cseq: Int
    public var cseqMethod: String
    public var viaBranch: String?
    public var viaCount: Int
    public var contact: String?
    public var userAgent: String?
    public var sdpMedia: [SDPMediaSummary]
    public var byteLength: Int
    public var isRetransmission: Bool
    public var sessionIndex: Int?
    public var transactionIndex: Int?
    /// The request carries an Authorization or Proxy-Authorization header (a response to a digest challenge).
    public var hasCredentials: Bool = false

    public init(id: Int, frameNumber: Int, time: Timestamp, source: Endpoint, destination: Endpoint,
                transport: TransportKind, isRequest: Bool, method: String, requestURI: String?, statusCode: Int?,
                reasonPhrase: String?, callID: String, from: SIPAddress, to: SIPAddress, cseq: Int,
                cseqMethod: String, viaBranch: String?, viaCount: Int, contact: String?, userAgent: String?,
                sdpMedia: [SDPMediaSummary], byteLength: Int, isRetransmission: Bool = false,
                sessionIndex: Int? = nil, transactionIndex: Int? = nil) {
        self.id = id
        self.frameNumber = frameNumber
        self.time = time
        self.source = source
        self.destination = destination
        self.transport = transport
        self.isRequest = isRequest
        self.method = method
        self.requestURI = requestURI
        self.statusCode = statusCode
        self.reasonPhrase = reasonPhrase
        self.callID = callID
        self.from = from
        self.to = to
        self.cseq = cseq
        self.cseqMethod = cseqMethod
        self.viaBranch = viaBranch
        self.viaCount = viaCount
        self.contact = contact
        self.userAgent = userAgent
        self.sdpMedia = sdpMedia
        self.byteLength = byteLength
        self.isRetransmission = isRetransmission
        self.sessionIndex = sessionIndex
        self.transactionIndex = transactionIndex
    }

    public var hasSDP: Bool { !sdpMedia.isEmpty }

    /// "INVITE" or "180 Ringing".
    public var label: String {
        if isRequest { return method }
        return "\(statusCode ?? 0) \(reasonPhrase ?? "")".trimmingCharacters(in: .whitespaces)
    }

    /// Wireshark-style info column text.
    public var infoText: String {
        if isRequest { return "Request: \(method) \(requestURI ?? "")" }
        let status = "Status: \(statusCode ?? 0) \(reasonPhrase ?? "")"
        return cseqMethod == "INVITE" && (statusCode ?? 0) >= 200 ? "\(status) (INVITE)" : status
    }
}

/// A client transaction: one request plus the responses matched by Via branch and CSeq.
public struct SIPTransactionRecord: Codable, Sendable, Identifiable {
    public var id: Int
    public var method: String
    public var cseq: Int
    public var branch: String?
    public var requestIndex: Int?
    public var responseIndices: [Int]
    public var finalStatusCode: Int?
    public var startTime: Timestamp
    public var endTime: Timestamp
    public var retransmissions: Int

    public init(id: Int, method: String, cseq: Int, branch: String?, requestIndex: Int?, responseIndices: [Int],
                finalStatusCode: Int?, startTime: Timestamp, endTime: Timestamp, retransmissions: Int) {
        self.id = id
        self.method = method
        self.cseq = cseq
        self.branch = branch
        self.requestIndex = requestIndex
        self.responseIndices = responseIndices
        self.finalStatusCode = finalStatusCode
        self.startTime = startTime
        self.endTime = endTime
        self.retransmissions = retransmissions
    }

    public var durationSeconds: Double { endTime.seconds(since: startTime) }
}

public enum SIPSessionState: String, Codable, Sendable {
    /// INVITE answered with 2xx and terminated with BYE.
    case completed
    /// INVITE answered, no BYE captured.
    case established
    /// INVITE sent, provisional responses only.
    case early
    /// INVITE rejected with a final non-2xx response.
    case failed
    /// INVITE cancelled by the caller.
    case cancelled
    /// Request never got a final response.
    case noResponse
    /// Non-INVITE session (REGISTER, OPTIONS, SUBSCRIBE…) that got a 2xx.
    case succeeded
}

/// All SIP traffic sharing one Call-ID ("SIP Dialogs" in the sidebar).
public struct SIPSessionRecord: Codable, Sendable, Identifiable {
    public var id: Int
    public var callID: String
    public var initialMethod: String
    public var from: SIPAddress
    public var to: SIPAddress
    public var messageIndices: [Int]
    public var transactionIndices: [Int]
    public var dialogTags: [String]
    public var startTime: Timestamp
    public var endTime: Timestamp
    public var state: SIPSessionState
    public var finalStatusCode: Int?
    public var callIndex: Int?

    public init(id: Int, callID: String, initialMethod: String, from: SIPAddress, to: SIPAddress,
                messageIndices: [Int], transactionIndices: [Int], dialogTags: [String], startTime: Timestamp,
                endTime: Timestamp, state: SIPSessionState, finalStatusCode: Int?, callIndex: Int? = nil) {
        self.id = id
        self.callID = callID
        self.initialMethod = initialMethod
        self.from = from
        self.to = to
        self.messageIndices = messageIndices
        self.transactionIndices = transactionIndices
        self.dialogTags = dialogTags
        self.startTime = startTime
        self.endTime = endTime
        self.state = state
        self.finalStatusCode = finalStatusCode
        self.callIndex = callIndex
    }

    public var durationSeconds: Double { endTime.seconds(since: startTime) }
}

/// Standard reason phrases for common SIP status codes (RFC 3261 §21 and extensions).
public enum SIPStatus {
    public static func reasonPhrase(for code: Int) -> String {
        switch code {
        case 100: return "Trying"
        case 180: return "Ringing"
        case 181: return "Call Is Being Forwarded"
        case 182: return "Queued"
        case 183: return "Session Progress"
        case 200: return "OK"
        case 202: return "Accepted"
        case 301: return "Moved Permanently"
        case 302: return "Moved Temporarily"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 407: return "Proxy Authentication Required"
        case 408: return "Request Timeout"
        case 480: return "Temporarily Unavailable"
        case 481: return "Call/Transaction Does Not Exist"
        case 486: return "Busy Here"
        case 487: return "Request Terminated"
        case 488: return "Not Acceptable Here"
        case 491: return "Request Pending"
        case 500: return "Server Internal Error"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Server Time-out"
        case 600: return "Busy Everywhere"
        case 603: return "Decline"
        case 604: return "Does Not Exist Anywhere"
        case 606: return "Not Acceptable"
        default: return ""
        }
    }
}
