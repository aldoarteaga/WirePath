import Foundation

/// Where one side of a session said it wants to receive media (from an SDP `c=`/`m=` pair).
public struct MediaAnnouncement: Sendable, Hashable {
    public var callID: String
    public var messageIndex: Int
    public var time: Timestamp
    /// Address/port on which the announcing party receives RTP.
    public var endpoint: Endpoint
    /// Signalling source of the SDP (the announcing user agent or its proxy).
    public var announcedBy: Endpoint
    public var codecs: [UInt8: CodecDescriptor]
    public var payloadTypes: [UInt8]
    public var ptimeMs: Int?
    public var direction: String
    public var isRequest: Bool
    /// The media profile is secure RTP (RTP/SAVP, RTP/SAVPF, UDP/TLS/RTP/SAVPF…): payloads are encrypted.
    public var secure: Bool = false
}

/// Stateful SIP analysis: records every message, matches transactions and groups sessions by Call-ID.
public struct SIPTracker: Sendable {
    public private(set) var messages: [SIPMessageRecord] = []
    public private(set) var transactions: [SIPTransactionRecord] = []
    public private(set) var announcements: [MediaAnnouncement] = []

    private struct SessionBuilder: Sendable {
        var callID: String
        var initialMethod: String
        var from: SIPAddress
        var to: SIPAddress
        var messageIndices: [Int] = []
        var transactionIndices: [Int] = []
        var tags: [String] = []
        var tagSet: Set<String> = []
        var start: Timestamp
        var end: Timestamp
    }

    private struct TransactionKey: Hashable, Sendable {
        var callID: String
        var branch: String
        var method: String
        var cseq: Int
    }

    private var sessions: [SessionBuilder] = []
    private var sessionByCallID: [String: Int] = [:]
    private var transactionByKey: [TransactionKey: Int] = [:]
    private struct ResponseKey: Hashable, Sendable {
        var transaction: Int
        var status: Int
        var toTag: String
        var source: Endpoint
        var destination: Endpoint
    }
    private var seenResponses: Set<ResponseKey> = []
    /// Strings repeated across a dialog's messages (Call-ID, URIs, tags, user agents) are stored once.
    private var strings: Set<String> = []
    static let maxInternedStrings = 500_000

    private mutating func intern(_ value: String) -> String {
        // Short strings are stored inline anyway; only heap-allocated ones are worth sharing.
        guard value.utf8.count > 15, strings.count < Self.maxInternedStrings || strings.contains(value) else { return value }
        return strings.insert(value).memberAfterInsert
    }

    private mutating func intern(_ value: String?) -> String? { value.map { intern($0) } }

    private mutating func intern(_ address: SIPAddress) -> SIPAddress {
        var address = address
        address.uri = intern(address.uri)
        address.displayName = intern(address.displayName)
        address.user = intern(address.user)
        address.host = intern(address.host)
        address.tag = intern(address.tag)
        return address
    }

    public init() {}

    /// Records a parsed message and returns its index.
    @discardableResult
    public mutating func ingest(_ message: SIPMessage, frameNumber: Int, time: Timestamp, source: Endpoint,
                                destination: Endpoint, transport: TransportKind) -> Int {
        let callID = intern(message.callID ?? "(no Call-ID)")
        let cseq = message.cseq ?? (0, message.method)
        let from = intern(message.from ?? SIPAddress(uri: ""))
        let to = intern(message.to ?? SIPAddress(uri: ""))
        let index = messages.count
        let sdp = message.sdp
        let media = sdp.map { Self.mediaSummaries($0) } ?? []

        var record = SIPMessageRecord(
            id: index, frameNumber: frameNumber, time: time, source: source, destination: destination,
            transport: transport, isRequest: message.isRequest, method: message.isRequest ? message.method : cseq.method,
            requestURI: intern(message.requestURI), statusCode: message.statusCode, reasonPhrase: intern(message.reasonPhrase),
            callID: callID, from: from, to: to, cseq: cseq.number, cseqMethod: cseq.method,
            viaBranch: message.topViaBranch, viaCount: message.viaValues.count, contact: intern(message.contact),
            userAgent: intern(message.userAgent), sdpMedia: media, byteLength: message.totalLength)
        record.hasCredentials = message.isRequest
            && (message.header("Authorization") != nil || message.header("Proxy-Authorization") != nil)

        // Session (Call-ID) grouping.
        let sessionIndex: Int
        if let existing = sessionByCallID[callID] {
            sessionIndex = existing
        } else {
            sessionIndex = sessions.count
            sessionByCallID[callID] = sessionIndex
            sessions.append(SessionBuilder(callID: callID, initialMethod: message.isRequest ? message.method : cseq.method,
                                           from: from, to: to, start: time, end: time))
        }
        record.sessionIndex = sessionIndex

        // Transaction matching: top Via branch + CSeq method (RFC 3261 §17.1.3).
        let branch = message.topViaBranch ?? "rfc2543-\(cseq.number)"
        let key = TransactionKey(callID: callID, branch: branch, method: cseq.method, cseq: cseq.number)
        if message.isRequest {
            if let existing = transactionByKey[key], transactions[existing].requestIndex != nil {
                record.isRetransmission = true
                transactions[existing].retransmissions += 1
                transactions[existing].endTime = max(transactions[existing].endTime, time)
                record.transactionIndex = existing
            } else {
                let tIndex = transactions.count
                transactions.append(SIPTransactionRecord(id: tIndex, method: cseq.method, cseq: cseq.number,
                                                         branch: message.topViaBranch, requestIndex: index,
                                                         responseIndices: [], finalStatusCode: nil, startTime: time,
                                                         endTime: time, retransmissions: 0))
                transactionByKey[key] = tIndex
                sessions[sessionIndex].transactionIndices.append(tIndex)
                record.transactionIndex = tIndex
            }
        } else {
            let tIndex: Int
            if let existing = transactionByKey[key] {
                tIndex = existing
            } else {
                // Response without a captured request (capture started mid-transaction).
                tIndex = transactions.count
                transactions.append(SIPTransactionRecord(id: tIndex, method: cseq.method, cseq: cseq.number,
                                                         branch: message.topViaBranch, requestIndex: nil,
                                                         responseIndices: [], finalStatusCode: nil, startTime: time,
                                                         endTime: time, retransmissions: 0))
                transactionByKey[key] = tIndex
                sessions[sessionIndex].transactionIndices.append(tIndex)
            }
            let signature = ResponseKey(transaction: tIndex, status: message.statusCode ?? 0, toTag: to.tag ?? "", source: source,
                                        destination: destination)
            if seenResponses.contains(signature) {
                record.isRetransmission = true
                transactions[tIndex].retransmissions += 1
            } else {
                seenResponses.insert(signature)
            }
            transactions[tIndex].responseIndices.append(index)
            transactions[tIndex].endTime = max(transactions[tIndex].endTime, time)
            if let code = message.statusCode, code >= 200, transactions[tIndex].finalStatusCode == nil {
                transactions[tIndex].finalStatusCode = code
            }
            record.transactionIndex = tIndex
            // Dialog tags per Call-ID (forked responses); bounded so a flood of tags cannot grow without limit.
            if let tag = to.tag, !tag.isEmpty, sessions[sessionIndex].tags.count < 64,
               sessions[sessionIndex].tagSet.insert(tag).inserted {
                sessions[sessionIndex].tags.append(tag)
            }
        }

        sessions[sessionIndex].messageIndices.append(index)
        sessions[sessionIndex].end = max(sessions[sessionIndex].end, time)
        messages.append(record)

        if let sdp, !record.isRetransmission {
            registerAnnouncements(sdp, callID: callID, messageIndex: index, time: time, source: source,
                                  isRequest: message.isRequest)
        }
        return index
    }

    private mutating func registerAnnouncements(_ sdp: SessionDescription, callID: String, messageIndex: Int,
                                                time: Timestamp, source: Endpoint, isRequest: Bool) {
        for media in sdp.media where media.mediaType == "audio" || media.mediaType == "video" {
            guard media.port != 0, let addressText = sdp.effectiveAddress(for: media),
                  let address = IPAddress(addressText) else { continue }
            let codecs = Self.codecs(for: media)
            announcements.append(MediaAnnouncement(
                callID: callID, messageIndex: messageIndex, time: time,
                endpoint: Endpoint(address: address, port: media.port), announcedBy: source,
                codecs: codecs, payloadTypes: media.payloadTypes, ptimeMs: media.ptimeMs,
                direction: sdp.effectiveDirection(for: media).rawValue, isRequest: isRequest,
                secure: media.transportProtocol.uppercased().contains("SAVP")))
        }
    }

    static func codecs(for media: MediaDescription) -> [UInt8: CodecDescriptor] {
        var result: [UInt8: CodecDescriptor] = [:]
        for pt in media.payloadTypes {
            let map = media.rtpMaps[pt]
            if let descriptor = CodecCatalog.descriptor(payloadType: pt, encodingName: map?.encodingName,
                                                        clockRate: map?.clockRate, channels: map?.channels) {
                result[pt] = descriptor
            }
        }
        return result
    }

    static func mediaSummaries(_ sdp: SessionDescription) -> [SDPMediaSummary] {
        sdp.media.map { media in
            let endpoint = sdp.effectiveAddress(for: media).flatMap(IPAddress.init).map { Endpoint(address: $0, port: media.port) }
            let codecs = codecs(for: media)
            let ice = sdp.effectiveICE(for: media)
            return SDPMediaSummary(mediaType: media.mediaType, endpoint: endpoint,
                                   transportProtocol: media.transportProtocol, payloadTypes: media.payloadTypes,
                                   codecs: media.payloadTypes.compactMap { codecs[$0] }, ptimeMs: media.ptimeMs,
                                   direction: sdp.effectiveDirection(for: media).rawValue, iceUfrag: ice.ufrag,
                                   candidates: ice.candidates, dtlsSetup: ice.setup)
        }
    }

    // MARK: Finalisation

    /// Builds session records once all packets have been ingested.
    public func finalizedSessions() -> [SIPSessionRecord] {
        sessions.enumerated().map { index, builder in
            let (state, finalCode) = sessionState(builder)
            return SIPSessionRecord(id: index, callID: builder.callID, initialMethod: builder.initialMethod,
                                    from: builder.from, to: builder.to, messageIndices: builder.messageIndices,
                                    transactionIndices: builder.transactionIndices, dialogTags: builder.tags,
                                    startTime: builder.start, endTime: builder.end, state: state,
                                    finalStatusCode: finalCode)
        }
    }

    private func sessionState(_ session: SessionBuilder) -> (SIPSessionState, Int?) {
        let txs = session.transactionIndices.map { transactions[$0] }
        if session.initialMethod == "INVITE" {
            let invites = txs.filter { $0.method == "INVITE" }
            // The initial INVITE is the lowest CSeq; re-INVITEs do not change the call outcome.
            let firstCSeq = invites.map(\.cseq).min()
            let initial = invites.filter { $0.cseq == firstCSeq }
            // Prefer the caller-facing transaction: the earliest one.
            let callerFacing = initial.min { $0.startTime < $1.startTime }
            let answered = initial.contains { ($0.finalStatusCode ?? 0) / 100 == 2 }
            if answered {
                let hasBye = txs.contains { $0.method == "BYE" }
                return (hasBye ? .completed : .established, 200)
            }
            let cancelled = txs.contains { $0.method == "CANCEL" }
            let code = callerFacing?.finalStatusCode ?? initial.compactMap(\.finalStatusCode).first
            if cancelled && (code == nil || code == 487) { return (.cancelled, code) }
            if let code, code >= 300 { return (.failed, code) }
            let provisional = initial.contains { !$0.responseIndices.isEmpty }
            return (provisional ? .early : .noResponse, nil)
        }
        let initial = txs.first
        if let code = initial?.finalStatusCode {
            return (code / 100 == 2 ? .succeeded : .failed, code)
        }
        return (.noResponse, nil)
    }
}
