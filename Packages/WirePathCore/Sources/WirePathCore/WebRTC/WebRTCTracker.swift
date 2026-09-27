import Foundation

/// Reconstructs WebRTC (ICE) sessions during the sequential pass, from STUN connectivity checks, STUN server
/// bindings, TURN allocations (including checks relayed through ChannelData or Send/Data indications) and DTLS.
/// Signalling is usually encrypted (WebSocket/HTTPS); unencrypted SDP, when captured, adds its candidates.
///
/// All state is bounded so a capture full of STUN cannot exhaust memory.
struct WebRTCTracker {
    static let maxTransactions = 100_000
    static let maxSessions = 10_000
    static let maxPairsPerSession = 64
    static let maxAllocations = 10_000
    static let maxDTLSFlows = 10_000
    /// Checks without any success for this long before the capture ends count as a failed session.
    static let failureWindowSeconds = 5.0
    static let noResponseAfterFirst = 2.0
    static let noResponseAfterLast = 1.0

    private(set) var transactions: [STUNTransactionRecord] = []
    private var pendingByID: [String: Int] = [:]
    private(set) var allocations: [TURNAllocationRecord] = []
    private var allocationByKey: [EndpointPair: Int] = [:]
    private var sessions: [SessionBuilder] = []
    private var sessionByKey: [String: Int] = [:]
    private var dtls: [EndpointPair: DTLSBuilder] = [:]
    private(set) var limitReached = false

    struct EndpointPair: Hashable {
        var a: Endpoint
        var b: Endpoint

        /// Direction-free key.
        static func unordered(_ x: Endpoint, _ y: Endpoint) -> EndpointPair { x < y ? EndpointPair(a: x, b: y) : EndpointPair(a: y, b: x) }
    }

    private struct PairBuilder {
        var local: Endpoint
        var remote: Endpoint
        var peer: Int
        var relayed: Bool
        var checks = 0
        var successes = 0
        var errors = 0
        var nominated = false
        var rtts: [Double] = []
        var first: Timestamp
        var last: Timestamp
        var transactions: [Int] = []
    }

    private struct SessionBuilder {
        var ufrags: [String]
        var pairs: [EndpointPair: PairBuilder] = [:]
        var pairOrder: [EndpointPair] = []
        var controllingPeer: Int?
        var first: Timestamp
        var last: Timestamp
        var transactions: [Int] = []
    }

    private struct DTLSBuilder {
        var a: Endpoint
        var b: Endpoint
        var records = 0
        var clientHello: Int?
        var serverHello: Int?
        var keyedFromA = false
        var keyedFromB = false
        var alerts = 0
    }

    // MARK: Ingest

    /// A STUN message on a UDP 5-tuple. `relayedAs` gives the (local, remote) endpoints when the message was carried
    /// inside a TURN relay (the relay's address and the peer).
    mutating func ingestSTUN(_ bytes: UnsafeRawBufferPointer, frame: Int, time: Timestamp, source: Endpoint, destination: Endpoint,
                             relayedAs: (source: Endpoint, destination: Endpoint)? = nil) {
        guard let message = STUNParser.parse(bytes) else { return }
        let from = relayedAs?.source ?? source, to = relayedAs?.destination ?? destination
        switch message.messageClass {
        case .request:
            request(message, frame: frame, time: time, from: from, to: to, relayed: relayedAs != nil, transport: (source, destination))
        case .successResponse, .errorResponse:
            response(message, frame: frame, time: time)
        case .indication:
            indication(message, bytes: bytes, frame: frame, time: time, source: source, destination: destination)
        }
    }

    /// TURN ChannelData between a client and its TURN server; relayed STUN and DTLS inside are analyzed too.
    mutating func ingestChannelData(_ bytes: UnsafeRawBufferPointer, frame: Int, time: Timestamp, source: Endpoint, destination: Endpoint) {
        guard bytes.count >= 4 else { return }
        let channel = bytes.u16be(0)
        let length = Int(bytes.u16be(2))
        let clientToServer = allocationByKey[EndpointPair(a: source, b: destination)] != nil
        guard let index = allocationByKey[EndpointPair(a: source, b: destination)] ?? allocationByKey[EndpointPair(a: destination, b: source)]
        else { return }
        allocations[index].channelDataPackets += 1
        allocations[index].channelDataBytes += Int64(length)
        allocations[index].lastTime = max(allocations[index].lastTime, time)
        guard let relayed = allocations[index].relayedAddress,
              let peer = allocations[index].channels.first(where: { $0.number == channel })?.peer else { return }
        let inner = bytes.slice(4, min(length, bytes.count - 4))
        let endpoints = clientToServer ? (relayed, peer) : (peer, relayed)
        if STUNParser.parse(inner) != nil {
            ingestSTUN(inner, frame: frame, time: time, source: source, destination: destination, relayedAs: endpoints)
        } else if DTLSDetector.looksLikeDTLS(inner) {
            ingestDTLS(inner, frame: frame, time: time, source: endpoints.0, destination: endpoints.1)
        }
    }

    mutating func ingestDTLS(_ bytes: UnsafeRawBufferPointer, frame: Int, time: Timestamp, source: Endpoint, destination: Endpoint) {
        let key = EndpointPair.unordered(source, destination)
        guard dtls[key] != nil || dtls.count < Self.maxDTLSFlows else { return }
        var entry = dtls[key] ?? DTLSBuilder(a: key.a, b: key.b)
        var p = 0
        var records = 0
        while p + 13 <= bytes.count, records < 32, DTLSDetector.looksLikeDTLS(bytes.slice(p, bytes.count - p)) {
            records += 1
            let type = bytes[p], epoch = bytes.u16be(p + 3), length = Int(bytes.u16be(p + 11))
            entry.records += 1
            if type == 22, epoch == 0, p + 14 <= bytes.count {
                if bytes[p + 13] == 1 { entry.clientHello = entry.clientHello ?? frame }
                if bytes[p + 13] == 2 { entry.serverHello = entry.serverHello ?? frame }
            }
            // Change Cipher Spec, or anything in a later epoch, means this side has its keys.
            if type == 20 || epoch > 0 {
                if source == entry.a { entry.keyedFromA = true } else { entry.keyedFromB = true }
            }
            if type == 21, epoch == 0 { entry.alerts += 1 }
            p += 13 + length
        }
        dtls[key] = entry
    }

    private mutating func request(_ message: STUNMessage, frame: Int, time: Timestamp, from: Endpoint, to: Endpoint, relayed: Bool,
                                  transport: (Endpoint, Endpoint)) {
        if let existing = pendingByID[message.transactionID] {
            // Retransmission of the same request.
            if transactions[existing].requestFrames.count < 16 { transactions[existing].requestFrames.append(frame) }
            transactions[existing].lastRequestTime = max(transactions[existing].lastRequestTime, time)
            return
        }
        guard transactions.count < Self.maxTransactions else {
            limitReached = true
            return
        }
        let kind: STUNTransactionRecord.Kind = message.isTURN ? .turn : message.isICECheck ? .iceCheck : .serverBinding
        let index = transactions.count
        transactions.append(STUNTransactionRecord(
            id: index, kind: kind, method: message.method, methodName: message.methodName, client: from, server: to, relayed: relayed,
            requestFrames: [frame], responseFrame: nil, requestTime: time, lastRequestTime: time, responseTime: nil, outcome: .pending,
            // Only ICE ufrags are kept; a TURN USERNAME identifies a long-term credential and is not needed.
            username: kind == .iceCheck ? message.username : nil, useCandidate: message.useCandidate, authenticated: message.hasIntegrity,
            controlling: message.iceControlling ? true : message.iceControlled ? false : nil,
            mappedAddress: nil, relayedAddress: nil))
        pendingByID[message.transactionID] = index

        switch kind {
        case .iceCheck:
            recordCheck(message, transaction: index, time: time, from: from, to: to, relayed: relayed)
        case .turn:
            turnRequest(message, time: time, client: transport.0, server: transport.1)
        case .serverBinding:
            break
        }
    }

    private mutating func recordCheck(_ message: STUNMessage, transaction: Int, time: Timestamp, from: Endpoint, to: Endpoint,
                                      relayed: Bool) {
        guard let username = message.username else { return }
        let parts = username.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return }
        let senderUfrag = parts[1], receiverUfrag = parts[0]
        let key = [senderUfrag, receiverUfrag].sorted().joined(separator: "\u{1F}")
        let sessionIndex: Int
        if let existing = sessionByKey[key] {
            sessionIndex = existing
        } else {
            guard sessions.count < Self.maxSessions else {
                limitReached = true
                return
            }
            sessionIndex = sessions.count
            sessions.append(SessionBuilder(ufrags: [senderUfrag, receiverUfrag], first: time, last: time))
            sessionByKey[key] = sessionIndex
        }
        var session = sessions[sessionIndex]
        let peer = session.ufrags.firstIndex(of: senderUfrag) ?? 0
        if message.iceControlling { session.controllingPeer = peer }
        if message.iceControlled, session.controllingPeer == nil { session.controllingPeer = 1 - peer }
        let pairKey = EndpointPair(a: from, b: to)
        if session.pairs[pairKey] == nil, session.pairs.count < Self.maxPairsPerSession {
            session.pairs[pairKey] = PairBuilder(local: from, remote: to, peer: peer, relayed: relayed, first: time, last: time)
            session.pairOrder.append(pairKey)
        }
        if var pair = session.pairs[pairKey] {
            pair.checks += 1
            pair.last = max(pair.last, time)
            pair.transactions.append(transaction)
            session.pairs[pairKey] = pair
        }
        session.last = max(session.last, time)
        session.transactions.append(transaction)
        sessions[sessionIndex] = session
    }

    private mutating func response(_ message: STUNMessage, frame: Int, time: Timestamp) {
        guard let index = pendingByID[message.transactionID], transactions[index].responseFrame == nil else { return }
        transactions[index].responseFrame = frame
        transactions[index].responseTime = time
        if message.messageClass == .successResponse {
            transactions[index].outcome = .success
            transactions[index].mappedAddress = message.xorMappedAddress ?? message.mappedAddress
            transactions[index].relayedAddress = message.xorRelayedAddress
        } else {
            transactions[index].outcome = .error(code: message.errorCode ?? 0, reason: message.errorReason ?? "")
        }
        let transaction = transactions[index]
        switch transaction.kind {
        case .iceCheck:
            checkAnswered(transaction, success: message.messageClass == .successResponse)
        case .turn:
            turnResponse(message, transaction: transaction, time: time)
        case .serverBinding:
            break
        }
    }

    private mutating func checkAnswered(_ transaction: STUNTransactionRecord, success: Bool) {
        let pairKey = EndpointPair(a: transaction.client, b: transaction.server)
        for index in sessions.indices where sessions[index].pairs[pairKey]?.transactions.contains(transaction.id) == true {
            guard var pair = sessions[index].pairs[pairKey] else { continue }
            if success {
                pair.successes += 1
                if transaction.useCandidate { pair.nominated = true }
                if let rtt = transaction.rttMs, pair.rtts.count < 1_000 { pair.rtts.append(rtt) }
            } else {
                pair.errors += 1
            }
            sessions[index].pairs[pairKey] = pair
            return
        }
    }

    // MARK: TURN

    private mutating func allocationIndex(client: Endpoint, server: Endpoint, time: Timestamp) -> Int? {
        let key = EndpointPair(a: client, b: server)
        if let existing = allocationByKey[key] { return existing }
        guard allocations.count < Self.maxAllocations else {
            limitReached = true
            return nil
        }
        let index = allocations.count
        allocations.append(TURNAllocationRecord(
            id: index, client: client, server: server, relayedAddress: nil, mappedAddress: nil, lifetime: nil, allocateRequests: 0,
            challenges: 0, errorCodes: [], succeeded: false, refreshes: 0, released: false, permissions: [], channels: [],
            channelDataPackets: 0, channelDataBytes: 0, sendIndications: 0, dataIndications: 0, firstTime: time, lastTime: time))
        allocationByKey[key] = index
        return index
    }

    private mutating func turnRequest(_ message: STUNMessage, time: Timestamp, client: Endpoint, server: Endpoint) {
        guard let index = allocationIndex(client: client, server: server, time: time) else { return }
        allocations[index].lastTime = max(allocations[index].lastTime, time)
        switch message.method {
        case STUNMethod.allocate:
            allocations[index].allocateRequests += 1
        case STUNMethod.refresh:
            allocations[index].refreshes += 1
            if message.lifetime == 0 { allocations[index].released = true }
        case STUNMethod.createPermission:
            for peer in message.xorPeerAddresses where !allocations[index].permissions.contains(peer.address)
                && allocations[index].permissions.count < 64 {
                allocations[index].permissions.append(peer.address)
            }
        case STUNMethod.channelBind:
            if let number = message.channelNumber, let peer = message.xorPeerAddresses.first,
               !allocations[index].channels.contains(where: { $0.number == number }), allocations[index].channels.count < 64 {
                allocations[index].channels.append(.init(number: number, peer: peer))
            }
        default:
            break
        }
    }

    private mutating func turnResponse(_ message: STUNMessage, transaction: STUNTransactionRecord, time: Timestamp) {
        guard let index = allocationByKey[EndpointPair(a: transaction.client, b: transaction.server)] else { return }
        allocations[index].lastTime = max(allocations[index].lastTime, time)
        if message.messageClass == .errorResponse {
            let code = message.errorCode ?? 0
            // An unauthenticated request answered 401 (or a stale nonce, 438) is the normal challenge; a 401 to a
            // request that carried credentials means they were rejected.
            if (code == 401 && !transaction.authenticated) || code == 438 {
                allocations[index].challenges += 1
            } else if allocations[index].errorCodes.count < 32 {
                allocations[index].errorCodes.append(code)
            }
            return
        }
        if message.method == STUNMethod.allocate {
            allocations[index].succeeded = true
            allocations[index].relayedAddress = message.xorRelayedAddress ?? allocations[index].relayedAddress
            allocations[index].mappedAddress = message.xorMappedAddress ?? allocations[index].mappedAddress
        }
        if let lifetime = message.lifetime { allocations[index].lifetime = lifetime }
    }

    private mutating func indication(_ message: STUNMessage, bytes: UnsafeRawBufferPointer, frame: Int, time: Timestamp,
                                     source: Endpoint, destination: Endpoint) {
        switch message.method {
        case STUNMethod.send:
            // Client → server: data for a peer (possibly an ICE check or DTLS through the relay).
            guard let index = allocationByKey[EndpointPair(a: source, b: destination)] else { return }
            allocations[index].sendIndications += 1
            allocations[index].lastTime = max(allocations[index].lastTime, time)
            relayedPayload(message, bytes: bytes, allocation: index, frame: frame, time: time, source: source, destination: destination,
                           towardsPeer: true)
        case STUNMethod.data:
            guard let index = allocationByKey[EndpointPair(a: destination, b: source)] else { return }
            allocations[index].dataIndications += 1
            allocations[index].lastTime = max(allocations[index].lastTime, time)
            relayedPayload(message, bytes: bytes, allocation: index, frame: frame, time: time, source: source, destination: destination,
                           towardsPeer: false)
        default:
            break
        }
    }

    private mutating func relayedPayload(_ message: STUNMessage, bytes: UnsafeRawBufferPointer, allocation: Int, frame: Int,
                                         time: Timestamp, source: Endpoint, destination: Endpoint, towardsPeer: Bool) {
        guard let range = message.dataRange, let peer = message.xorPeerAddresses.first,
              let relayed = allocations[allocation].relayedAddress else { return }
        let inner = bytes.slice(range.lowerBound, range.count)
        let endpoints = towardsPeer ? (relayed, peer) : (peer, relayed)
        if STUNParser.parse(inner) != nil {
            ingestSTUN(inner, frame: frame, time: time, source: source, destination: destination, relayedAs: endpoints)
        } else if DTLSDetector.looksLikeDTLS(inner) {
            ingestDTLS(inner, frame: frame, time: time, source: endpoints.0, destination: endpoints.1)
        }
    }

    // MARK: Finish

    func finish(streams: [RTPStreamRecord], sipMessages: [SIPMessageRecord], flowTable: FlowTable, captureEnd: Timestamp?) -> WebRTCAnalysis {
        var transactions = self.transactions
        // Requests never answered: "no response" once the capture ran on past the retransmissions (2 s after the
        // first request and 1 s after the last); otherwise the capture may simply have ended too soon.
        for index in transactions.indices where transactions[index].responseFrame == nil {
            let first = captureEnd.map { $0.seconds(since: transactions[index].requestTime) } ?? 0
            let last = captureEnd.map { $0.seconds(since: transactions[index].lastRequestTime) } ?? 0
            transactions[index].outcome = first >= Self.noResponseAfterFirst && last >= Self.noResponseAfterLast ? .noResponse : .pending
        }

        // What the capture tells about each endpoint's candidate type.
        var relayAddresses: Set<Endpoint> = []
        var reflexive: Set<Endpoint> = []
        for allocation in allocations {
            if let relayed = allocation.relayedAddress { relayAddresses.insert(relayed) }
            if let mapped = allocation.mappedAddress { reflexive.insert(mapped) }
        }
        for transaction in transactions where transaction.kind == .serverBinding {
            if let mapped = transaction.mappedAddress { reflexive.insert(mapped) }
        }
        var sdpCandidates: [Endpoint: (ICECandidate.Kind, String?)] = [:]
        var callIDByUfrag: [String: String] = [:]
        for message in sipMessages {
            for media in message.sdpMedia {
                if let ufrag = media.iceUfrag { callIDByUfrag[ufrag] = message.callID }
                for candidate in media.candidates where candidate.transport == "udp" {
                    if let address = IPAddress(candidate.address) {
                        sdpCandidates[Endpoint(address: address, port: candidate.port)] = (candidate.kind, media.iceUfrag)
                    }
                }
            }
        }
        func kind(of endpoint: Endpoint) -> ICECandidate.Kind {
            if relayAddresses.contains(endpoint) { return .relay }
            if let known = sdpCandidates[endpoint] { return known.0 }
            if reflexive.contains(endpoint) { return .srflx }
            return .host
        }

        var records: [WebRTCSessionRecord] = []
        for (sessionIndex, session) in sessions.enumerated() {
            var pairs: [ICECandidatePairRecord] = []
            for key in session.pairOrder {
                guard let pair = session.pairs[key] else { continue }
                let answered = pair.transactions.filter { transactions[$0].responseFrame != nil }.count
                let timeouts = pair.transactions.filter { transactions[$0].outcome == .noResponse }.count
                let state: ICECandidatePairRecord.State = pair.successes > 0 ? .succeeded
                    : (answered + timeouts == pair.transactions.count && timeouts + pair.errors > 0 ? .failed : .inProgress)
                pairs.append(ICECandidatePairRecord(
                    id: pairs.count, local: pair.local, remote: pair.remote, localKind: kind(of: pair.local), remoteKind: kind(of: pair.remote),
                    checkingPeer: pair.peer, checks: pair.checks, successes: pair.successes, errors: pair.errors, timeouts: timeouts,
                    nominated: pair.nominated, relayed: pair.relayed,
                    meanRTTMs: pair.rtts.isEmpty ? nil : pair.rtts.reduce(0, +) / Double(pair.rtts.count),
                    firstTime: pair.first, lastTime: pair.last, state: state))
            }
            let succeeded = pairs.filter { $0.state == .succeeded }
            let selected = (succeeded.filter(\.nominated).max { $0.lastTime < $1.lastTime }
                ?? succeeded.max { $0.successes < $1.successes })?.id
            let quietFor = captureEnd.map { $0.seconds(since: session.last) } ?? 0
            let state: WebRTCSessionRecord.State = selected != nil ? .connected
                : (pairs.allSatisfy { $0.state == .failed } || quietFor >= Self.failureWindowSeconds ? .failed : .checking)

            // Addresses and candidates per peer.
            var peerAddresses: [[IPAddress]] = [[], []]
            var candidates: [ObservedCandidate] = []
            func addCandidate(_ endpoint: Endpoint, peer: Int, source: ObservedCandidate.Source, kind candidateKind: ICECandidate.Kind? = nil) {
                guard !candidates.contains(where: { $0.endpoint == endpoint }), candidates.count < 128 else { return }
                candidates.append(ObservedCandidate(endpoint: endpoint, kind: candidateKind ?? kind(of: endpoint), source: source, peer: peer))
                if peer < 2, !peerAddresses[peer].contains(endpoint.address) { peerAddresses[peer].append(endpoint.address) }
            }
            for pair in pairs {
                addCandidate(pair.local, peer: pair.checkingPeer, source: .connectivityCheck)
                addCandidate(pair.remote, peer: 1 - pair.checkingPeer, source: .connectivityCheck)
            }
            for (endpoint, info) in sdpCandidates {
                if let ufrag = info.1, let peer = session.ufrags.firstIndex(of: ufrag) {
                    addCandidate(endpoint, peer: peer, source: .sdp, kind: info.0)
                }
            }

            // Gathering from the session's own sockets: STUN server bindings and TURN allocations (failed ones too).
            let sockets = Set(pairs.filter { !$0.relayed }.flatMap { [$0.local, $0.remote] })
            func peer(of socket: Endpoint) -> Int? { candidates.first { $0.endpoint == socket }?.peer }
            let bindings = transactions.indices.filter { transactions[$0].kind == .serverBinding && sockets.contains(transactions[$0].client) }
            for index in bindings {
                if let mapped = transactions[index].mappedAddress, let owner = peer(of: transactions[index].client) {
                    addCandidate(mapped, peer: owner, source: .stunServer, kind: .srflx)
                }
            }
            let relayedInChecks = Set(candidates.filter { $0.kind == .relay }.map(\.endpoint))
            let turn = allocations.filter { allocation in
                allocation.relayedAddress.map(relayedInChecks.contains) ?? false || sockets.contains(allocation.client)
            }.map(\.id)
            for index in turn {
                let allocation = allocations[index]
                guard let owner = peer(of: allocation.client) ?? candidates.first(where: { $0.endpoint == allocation.relayedAddress })?.peer
                else { continue }
                if let relayed = allocation.relayedAddress { addCandidate(relayed, peer: owner, source: .turnServer, kind: .relay) }
                if let mapped = allocation.mappedAddress { addCandidate(mapped, peer: owner, source: .turnServer, kind: .srflx) }
            }
            candidates.sort { ($0.peer ?? 2, $0.kind.rawValue, $0.endpoint) < ($1.peer ?? 2, $1.kind.rawValue, $1.endpoint) }
            peerAddresses = peerAddresses.map { $0.sorted() }

            // DTLS and media on the selected pair.
            let chosen = selected.map { pairs[$0] }
            let dtlsEntry = chosen.flatMap { dtls[EndpointPair.unordered($0.local, $0.remote)] }
            let streamIndices = chosen.map { pair in
                streams.indices.filter { index in
                    let stream = streams[index]
                    return (stream.source == pair.local && stream.destination == pair.remote)
                        || (stream.source == pair.remote && stream.destination == pair.local)
                }
            } ?? []

            var flowIndices: Set<Int> = []
            for pair in pairs where !pair.relayed {
                if let flow = flowTable.flowIndex(ipProtocol: 17, pair.local, pair.remote) { flowIndices.insert(Int(flow)) }
            }
            for index in turn {
                let allocation = allocations[index]
                if let flow = flowTable.flowIndex(ipProtocol: 17, allocation.client, allocation.server) { flowIndices.insert(Int(flow)) }
            }
            for index in bindings {
                let binding = transactions[index]
                if let flow = flowTable.flowIndex(ipProtocol: 17, binding.client, binding.server) { flowIndices.insert(Int(flow)) }
            }

            records.append(WebRTCSessionRecord(
                id: sessionIndex, ufrags: session.ufrags, peerAddresses: peerAddresses, pairs: pairs, candidates: candidates,
                selectedPair: selected, state: state, controllingPeer: session.controllingPeer,
                dtls: dtlsEntry.map { DTLSFlowSummary(a: $0.a, b: $0.b, records: $0.records, clientHelloFrame: $0.clientHello,
                                                      serverHelloFrame: $0.serverHello, established: $0.keyedFromA && $0.keyedFromB,
                                                      alerts: $0.alerts) },
                streamIndices: streamIndices, turnAllocations: turn, usesRelay: chosen?.relayed == true || chosen?.localKind == .relay
                    || chosen?.remoteKind == .relay,
                flowIndices: flowIndices.sorted(), transactionIndices: session.transactions, serverBindingIndices: bindings, firstTime: session.first, lastTime: session.last,
                callID: session.ufrags.lazy.compactMap { callIDByUfrag[$0] }.first))
        }
        let inSessions = Set(records.flatMap(\.serverBindingIndices))
        let bindings = transactions.indices.filter { transactions[$0].kind == .serverBinding && !inSessions.contains($0) }
        return WebRTCAnalysis(sessions: records, transactions: transactions, allocations: allocations, serverBindings: bindings)
    }
}
