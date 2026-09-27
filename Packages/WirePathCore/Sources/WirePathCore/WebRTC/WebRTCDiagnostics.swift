import Foundation

/// WebRTC problems backed by the packets that show them: ICE sessions that never connected, failing candidate
/// pairs, STUN errors and unreachable STUN servers, TURN allocation failures and relay use, and sessions whose
/// DTLS handshake or media never followed a successful ICE check.
enum WebRTCDiagnostics {
    static func findings(_ analysis: WebRTCAnalysis, firstID: Int) -> [Finding] {
        var result: [Finding] = []
        let transactions = analysis.transactions
        func frames(_ indices: [Int]) -> [Int] {
            indices.filter { $0 < transactions.count }.flatMap { transactions[$0].requestFrames + (transactions[$0].responseFrame.map { [$0] } ?? []) }
                .sorted()
        }
        func add(_ severity: Severity, _ kind: FindingKind, _ title: String, _ detail: String, time: Timestamp?, frames: [Int] = [],
                 filter: String? = nil, session: Int? = nil) {
            result.append(Finding(id: firstID + result.count, severity: severity, kind: kind, title: title, detail: detail, time: time,
                                  packetReferences: frames, packetFilter: frames.count > Finding.maxPacketReferences ? filter : nil,
                                  webrtcSessionIndex: session))
        }

        for session in analysis.sessions {
            let name = session.ufrags.joined(separator: " ↔ ")
            let sessionFrames = frames(session.transactionIndices)
            switch session.state {
            case .failed:
                let checks = session.pairs.reduce(0) { $0 + $1.checks }
                let requests = session.transactionIndices.reduce(0) { $0 + ($1 < transactions.count ? transactions[$1].requestFrames.count : 0) }
                let errors = session.pairs.reduce(0) { $0 + $1.errors }
                let pairs = session.pairs.count
                let tried = String(localized: "ICE \(name): \(checks) connectivity checks (\(requests) requests) on \(pairs) candidate pairs", bundle: CoreLocalization.bundle)
                let detail = errors > 0 ? String(localized: "\(tried), \(errors) refused; no pair succeeded", bundle: CoreLocalization.bundle)
                    : String(localized: "\(tried), none answered; no pair succeeded", bundle: CoreLocalization.bundle)
                add(.error, .iceFailure, String(localized: "ICE connectivity failed", bundle: CoreLocalization.bundle), detail, time: session.firstTime, frames: sessionFrames,
                    filter: "stun and webrtc.session == \(session.id + 1)", session: session.id)
            case .connected:
                // Pairs that failed while another succeeded are normal (ICE tries them all); report them only when
                // every pair between two addresses failed, which usually means a firewall or a wrong candidate.
                let failed = session.pairs.filter { $0.state == .failed }
                if !failed.isEmpty, failed.count * 2 >= session.pairs.count {
                    let list = failed.prefix(4).map { "\($0.local) → \($0.remote) (\($0.localKind.rawValue)/\($0.remoteKind.rawValue))" }
                        .joined(separator: ", ")
                    add(.info, .candidateProblem, String(localized: "Candidate pairs failed", bundle: CoreLocalization.bundle),
                        String(localized: "ICE \(name): \(failed.count) of \(session.pairs.count) pairs failed: \(list)", bundle: CoreLocalization.bundle) + (failed.count > 4 ? "…" : ""),
                        time: session.firstTime,
                        frames: frames(failed.flatMap { pair in session.transactionIndices.filter {
                            $0 < transactions.count && transactions[$0].client == pair.local && transactions[$0].server == pair.remote } }),
                        session: session.id)
                }
                if let selected = session.selected {
                    if session.dtls == nil && session.streamIndices.isEmpty {
                        add(.warning, .noMediaAfterICE, String(localized: "No media after ICE", bundle: CoreLocalization.bundle),
                            String(localized: "ICE \(name) connected on \(selected.local.description) ↔ \(selected.remote.description) but no DTLS or RTP followed on that pair", bundle: CoreLocalization.bundle),
                            time: selected.lastTime, frames: sessionFrames, session: session.id)
                    } else if let dtls = session.dtls, !dtls.established || dtls.alerts > 0 {
                        let frames = [dtls.clientHelloFrame, dtls.serverHelloFrame].compactMap { $0 }
                        let path = "\(dtls.a) ↔ \(dtls.b)"
                        add(.warning, .dtlsFailure, dtls.alerts > 0 ? String(localized: "DTLS alert", bundle: CoreLocalization.bundle) : String(localized: "DTLS handshake incomplete", bundle: CoreLocalization.bundle),
                            dtls.alerts > 0
                                ? String(localized: "\(path): \(dtls.records) DTLS records, \(dtls.alerts) alerts — SRTP keys may not have been agreed", bundle: CoreLocalization.bundle)
                                : String(localized: "\(path): \(dtls.records) DTLS records, keys not confirmed by both sides — SRTP keys may not have been agreed", bundle: CoreLocalization.bundle),
                            time: session.firstTime, frames: frames, session: session.id)
                    }
                    if session.usesRelay {
                        add(.info, .turnRelay, String(localized: "Media relayed through TURN", bundle: CoreLocalization.bundle),
                            String(localized: "ICE \(name) selected a relay candidate (\(selected.local.description) → \(selected.remote.description)); media takes the longer path through the TURN server", bundle: CoreLocalization.bundle),
                            time: selected.firstTime, session: session.id)
                    }
                }
            case .checking:
                break
            }
        }

        // Sessions whose sockets made each STUN server binding and TURN allocation (for linking diagnostics).
        var bindingOwner: [Int: Int] = [:], allocationOwner: [Int: Int] = [:]
        for session in analysis.sessions {
            for index in session.serverBindingIndices where bindingOwner[index] == nil { bindingOwner[index] = session.id }
            for index in session.turnAllocations where allocationOwner[index] == nil { allocationOwner[index] = session.id }
        }

        // STUN error responses to connectivity checks (487 role conflict is resolved automatically).
        var checkErrors: [Int: (reason: String, frames: [Int], count: Int, first: Timestamp)] = [:]
        // Unanswered Binding requests to STUN servers.
        var unreachable: [Endpoint: (frames: [Int], count: Int, first: Timestamp, session: Int?)] = [:]  // count = request packets
        for transaction in transactions {
            switch (transaction.kind, transaction.outcome) {
            case (.iceCheck, .error(let code, let reason)) where code != 487,
                 (.serverBinding, .error(let code, let reason)):
                var entry = checkErrors[code] ?? (reason, [], 0, transaction.requestTime)
                entry.count += 1
                entry.frames += transaction.requestFrames.prefix(1) + (transaction.responseFrame.map { [$0] } ?? [])
                checkErrors[code] = entry
            case (.serverBinding, .noResponse):
                var entry = unreachable[transaction.server] ?? ([], 0, transaction.requestTime, bindingOwner[transaction.id])
                entry.count += transaction.requestFrames.count
                entry.frames += transaction.requestFrames
                unreachable[transaction.server] = entry
            default:
                break
            }
        }
        for (code, entry) in checkErrors.sorted(by: { $0.key < $1.key }) {
            add(.warning, .stunError, "STUN \(code) \(entry.reason)".trimmingCharacters(in: .whitespaces),
                String(localized: "\(entry.count) STUN Binding requests answered with \(code)", bundle: CoreLocalization.bundle), time: entry.first,
                frames: entry.frames.sorted(), filter: "stun")
        }
        for (server, entry) in unreachable.sorted(by: { $0.key < $1.key }) {
            let answered = transactions.contains { $0.kind == .serverBinding && $0.server == server && $0.outcome == .success }
            guard !answered else { continue }
            add(.warning, .stunTimeout, String(localized: "STUN server not responding", bundle: CoreLocalization.bundle),
                String(localized: "\(entry.count) Binding requests to \(server.description) (retransmissions included) got no answer; server-reflexive candidates could not be gathered", bundle: CoreLocalization.bundle),
                time: entry.first, frames: entry.frames.sorted(), filter: "stun and ip.addr == \(server.address)", session: entry.session)
        }

        // TURN allocations refused (401/438 challenges are the normal first step).
        for allocation in analysis.allocations where !allocation.succeeded && (!allocation.errorCodes.isEmpty || allocation.allocateRequests > 0) {
            let related = transactions.indices.filter {
                transactions[$0].kind == .turn && transactions[$0].client == allocation.client && transactions[$0].server == allocation.server
            }
            let codes = Array(Set(allocation.errorCodes)).sorted()
            let unanswered = related.contains { transactions[$0].outcome == .noResponse }
            guard !codes.isEmpty || unanswered else { continue }
            let codeList = codes.map(String.init).joined(separator: ", ")
            let why = codes.isEmpty ? String(localized: "the server never answered", bundle: CoreLocalization.bundle)
                : codes.contains(401) ? String(localized: "the server answered \(codeList) (credentials rejected)", bundle: CoreLocalization.bundle)
                : String(localized: "the server answered \(codeList)", bundle: CoreLocalization.bundle)
            add(.error, .turnAllocationFailure, String(localized: "TURN allocation failed", bundle: CoreLocalization.bundle),
                String(localized: "\(allocation.client.description) could not allocate a relay on \(allocation.server.description): \(why)", bundle: CoreLocalization.bundle),
                time: allocation.firstTime, frames: frames(related), filter: "turn and ip.addr == \(allocation.server.address)",
                session: allocationOwner[allocation.id])
        }
        return result
    }
}
