import Foundation

/// SIP problems that are not tied to one call's outcome: transaction timeouts, missing ACKs, authentication
/// failures, error responses to non-INVITE requests and signalling retransmissions. Each diagnostic links to the
/// packets that show it.
enum SIPDiagnostics {
    /// RFC 3261 Timer B / F (64 × T1): a client transaction without a final response after this has timed out.
    static let transactionTimeout = 32.0

    static func findings(messages: [SIPMessageRecord], transactions: [SIPTransactionRecord], sessions: [SIPSessionRecord],
                         captureEnd: Timestamp?, firstID: Int) -> [Finding] {
        var result: [Finding] = []
        func callIndex(_ message: SIPMessageRecord) -> Int? {
            message.sessionIndex.flatMap { $0 < sessions.count ? sessions[$0].callIndex : nil }
        }
        func add(_ severity: Severity, _ kind: FindingKind, _ title: String, _ detail: String, frames: [Int],
                 time: Timestamp?, call: Int? = nil) {
            result.append(Finding(id: firstID + result.count, severity: severity, kind: kind, title: title, detail: detail,
                                  callIndex: call, time: time, packetReferences: frames.sorted()))
        }
        let end = captureEnd ?? messages.map(\.time).max()
        func observedLongEnough(after time: Timestamp) -> Bool {
            guard let end else { return false }
            return end.seconds(since: time) >= transactionTimeout
        }

        // ACKs by Call-ID, CSeq number and sender (each hop acknowledges its own INVITE).
        var acks: Set<AckKey> = []
        for message in messages where message.isRequest && message.method == "ACK" {
            acks.insert(AckKey(callID: message.callID, cseq: message.cseq, sender: message.source.address))
        }

        var timeouts: [String: (frames: [Int], count: Int, first: Timestamp)] = [:]
        var authFailures: [String: (frames: [Int], count: Int, first: Timestamp, registration: Bool)] = [:]
        var errors: [Int: (reason: String, frames: [Int], count: Int, first: Timestamp, sources: Set<IPAddress>)] = [:]
        var registrationFailures: [String: (frames: [Int], count: Int, first: Timestamp, code: Int)] = [:]

        for transaction in transactions {
            guard let requestIndex = transaction.requestIndex, requestIndex < messages.count else { continue }
            let request = messages[requestIndex]
            guard request.method != "ACK" else { continue }
            let responses = transaction.responseIndices.filter { $0 < messages.count }.map { messages[$0] }
            let finals = responses.filter { ($0.statusCode ?? 0) >= 200 }

            // Timeout: no final response although the capture kept running past Timer B/F. (INVITEs without a final
            // response are reported with their call.)
            if finals.isEmpty, request.method != "INVITE", observedLongEnough(after: request.time) {
                let key = "\(request.method) → \(request.destination.address)"
                var entry = timeouts[key] ?? ([], 0, request.time)
                entry.count += 1
                entry.frames.append(request.frameNumber)
                timeouts[key] = entry
            }

            guard let final = finals.first, let code = final.statusCode else { continue }

            // Missing ACK for an INVITE's final response (2xx: new transaction; 3xx–6xx: same transaction).
            if request.method == "INVITE",
               !acks.contains(AckKey(callID: request.callID, cseq: request.cseq, sender: request.source.address)) {
                let retransmitted = finals.count > 1
                if retransmitted || observedLongEnough(after: final.time) {
                    let frames = finals.map(\.frameNumber)
                    let status = "\(code) \(final.reasonPhrase ?? "")".trimmingCharacters(in: .whitespaces)
                    let detail = finals.count > 1
                        ? String(localized: "\(final.source.address.description) sent \(status) for Call-ID \(request.callID) \(finals.count) times; no ACK from \(request.source.address.description) followed", bundle: CoreLocalization.bundle)
                        : String(localized: "\(final.source.address.description) sent \(status) for Call-ID \(request.callID); no ACK from \(request.source.address.description) followed", bundle: CoreLocalization.bundle)
                    add(.warning, .missingACK, String(localized: "Missing ACK for \(code)", bundle: CoreLocalization.bundle), detail, frames: [request.frameNumber] + frames, time: final.time,
                        call: callIndex(request))
                }
            }

            // Authentication: credentials were sent and still challenged or refused.
            if request.hasCredentials, [401, 403, 407].contains(code) {
                let key = "\(request.method) \(request.from.user ?? request.from.uri) → \(request.destination.address)"
                var entry = authFailures[key] ?? ([], 0, request.time, request.method == "REGISTER")
                entry.count += 1
                entry.frames += [request.frameNumber, final.frameNumber]
                authFailures[key] = entry
            } else if request.method == "REGISTER", code >= 300, ![401, 407].contains(code) {
                let key = "\(request.from.user ?? request.from.uri) → \(request.destination.address)"
                var entry = registrationFailures[key] ?? ([], 0, request.time, code)
                entry.count += 1
                entry.frames += [request.frameNumber, final.frameNumber]
                registrationFailures[key] = entry
            }

            // Error responses to other requests (INVITE outcomes are reported per call).
            if request.method != "INVITE", request.method != "REGISTER", code >= 400, ![401, 407, 487].contains(code) {
                var entry = errors[code] ?? (final.reasonPhrase ?? "", [], 0, final.time, [])
                entry.count += 1
                entry.frames.append(final.frameNumber)
                entry.sources.insert(final.source.address)
                errors[code] = entry
            }
        }

        for (key, entry) in timeouts.sorted(by: { $0.value.first < $1.value.first }) {
            add(.warning, .sipTimeout, String(localized: "SIP transaction timeout", bundle: CoreLocalization.bundle),
                String(localized: "\(key): \(entry.count) requests got no final response within \(Int(transactionTimeout)) s", bundle: CoreLocalization.bundle),
                frames: entry.frames, time: entry.first)
        }
        for (key, entry) in authFailures.sorted(by: { $0.value.first < $1.value.first }) {
            add(entry.registration ? .error : .warning, .authenticationFailure, String(localized: "Authentication failed", bundle: CoreLocalization.bundle),
                String(localized: "\(key) · credentials were rejected \(entry.count) times (wrong password, realm or user)", bundle: CoreLocalization.bundle),
                frames: entry.frames, time: entry.first)
        }
        for (key, entry) in registrationFailures.sorted(by: { $0.value.first < $1.value.first }) {
            add(.error, .registrationFailure, String(localized: "Registration failed", bundle: CoreLocalization.bundle),
                String(localized: "REGISTER \(key) · \(entry.code) response \(entry.count) times", bundle: CoreLocalization.bundle),
                frames: entry.frames, time: entry.first)
        }
        for (code, entry) in errors.sorted(by: { $0.key < $1.key }) {
            let sources = entry.sources.sorted().prefix(3).map(\.description).joined(separator: ", ")
            add(code >= 500 && code < 600 ? .error : .warning, .sipErrorResponses, "SIP \(code) \(entry.reason)",
                String(localized: "\(entry.count) × \(code) \(entry.reason) (\(Self.statusClass(code))) from \(sources)", bundle: CoreLocalization.bundle),
                frames: entry.frames, time: entry.first)
        }

        // Retransmissions outside calls (REGISTER, OPTIONS keep-alives, SUBSCRIBE…): lost signalling.
        let retransmitted = messages.filter { $0.isRetransmission && $0.cseqMethod != "INVITE" && $0.method != "ACK" }
        if retransmitted.count >= 3 {
            let methods = Set(retransmitted.map(\.cseqMethod)).sorted().joined(separator: ", ")
            add(.info, .sipRetransmissions, String(localized: "SIP retransmissions", bundle: CoreLocalization.bundle),
                String(localized: "\(retransmitted.count) retransmitted \(methods) messages outside calls (signalling loss or slow responses)", bundle: CoreLocalization.bundle),
                frames: retransmitted.map(\.frameNumber), time: retransmitted.first?.time)
        }
        return result
    }

    struct AckKey: Hashable {
        var callID: String
        var cseq: Int
        var sender: IPAddress
    }

    static func statusClass(_ code: Int) -> String {
        switch code {
        case 400..<500: return String(localized: "client error", bundle: CoreLocalization.bundle)
        case 500..<600: return String(localized: "server error", bundle: CoreLocalization.bundle)
        case 600..<700: return String(localized: "global failure", bundle: CoreLocalization.bundle)
        default: return String(localized: "status \(code)", bundle: CoreLocalization.bundle)
        }
    }
}

/// TCP problems from the connection analysis, one diagnostic per affected connection.
enum TCPDiagnostics {
    /// Diagnostics reported individually; further affected connections are summarized in one line.
    static let maxConnections = 100

    static func findings(flows: [FlowRecord], firstID: Int) -> [Finding] {
        var result: [Finding] = []
        var skipped = 0
        for flow in flows where flow.ipProtocol == 6 {
            guard result.count < maxConnections else {
                if let tcp = flow.tcp, tcp.retransmissions > 0 || tcp.handshake == .unanswered { skipped += 1 }
                continue
            }
            guard let tcp = flow.tcp else { continue }
            let endpoints = "\(flow.initiator) → \(flow.responder)"
            let filter = "flow == \(flow.id + 1)"
            func add(_ severity: Severity, _ kind: FindingKind, _ title: String, _ detail: String, packetFilter: String) {
                result.append(Finding(id: firstID + result.count, severity: severity, kind: kind, title: title, detail: detail,
                                      time: flow.firstTime, packetFilter: packetFilter))
            }
            if tcp.handshake == .unanswered {
                add(.warning, .tcpUnanswered, String(localized: "TCP connection not answered", bundle: CoreLocalization.bundle),
                    flow.application.isSIP ? String(localized: "\(endpoints) · SYN without SYN/ACK (SIP over TCP)", bundle: CoreLocalization.bundle)
                        : String(localized: "\(endpoints) · SYN without SYN/ACK", bundle: CoreLocalization.bundle), packetFilter: filter)
            }
            let segments = max(1, flow.packets)
            // An unanswered connection's retransmissions are its SYN retries, already reported above.
            if tcp.handshake != .unanswered,
               tcp.retransmissions >= 3 || (tcp.retransmissions > 0 && Double(tcp.retransmissions) / Double(segments) > 0.02) {
                add(.warning, .tcpRetransmissions, String(localized: "TCP retransmissions", bundle: CoreLocalization.bundle),
                    tcp.segmentsNotCaptured > 0
                        ? String(localized: "\(endpoints) · \(tcp.retransmissions) retransmitted segments of \(flow.packets) packets, \(tcp.segmentsNotCaptured) gaps", bundle: CoreLocalization.bundle)
                        : String(localized: "\(endpoints) · \(tcp.retransmissions) retransmitted segments of \(flow.packets) packets", bundle: CoreLocalization.bundle),
                    packetFilter: "\(filter) and tcp.analysis.flags")
            }
            if tcp.termination == .resetByInitiator || tcp.termination == .resetByResponder {
                let who = tcp.termination == .resetByInitiator ? flow.initiator : flow.responder
                add(flow.application.isSIP ? .warning : .info, .tcpReset, String(localized: "TCP connection reset", bundle: CoreLocalization.bundle),
                    String(localized: "\(endpoints) · reset by \(who.description)", bundle: CoreLocalization.bundle), packetFilter: "\(filter) and tcp.flags.reset")
            }
        }
        if skipped > 0 {
            result.append(Finding(id: firstID + result.count, severity: .info, kind: .tcpRetransmissions, title: String(localized: "More TCP problems", bundle: CoreLocalization.bundle),
                                  detail: String(localized: "\(skipped) more connections with retransmissions or unanswered SYNs", bundle: CoreLocalization.bundle),
                                  packetFilter: "tcp.analysis.retransmission or (tcp.flags.syn and not tcp.flags.ack)"))
        }
        return result
    }
}
