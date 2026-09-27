import Foundation

/// Builds calls from SIP sessions, links RTP streams through SDP, computes quality and findings.
public struct CallCorrelator: Sendable {
    public struct Input: Sendable {
        public var messages: [SIPMessageRecord]
        public var transactions: [SIPTransactionRecord]
        public var sessions: [SIPSessionRecord]
        public var announcements: [MediaAnnouncement]
        public var streams: [RTPStreamRecord]
        public var captureEnd: Timestamp?

        public init(messages: [SIPMessageRecord], transactions: [SIPTransactionRecord], sessions: [SIPSessionRecord],
                    announcements: [MediaAnnouncement], streams: [RTPStreamRecord], captureEnd: Timestamp?) {
            self.messages = messages
            self.transactions = transactions
            self.sessions = sessions
            self.announcements = announcements
            self.streams = streams
            self.captureEnd = captureEnd
        }
    }

    public struct Output: Sendable {
        public var calls: [CallRecord]
        public var sessions: [SIPSessionRecord]
        public var streams: [RTPStreamRecord]
        public var findings: [Finding]
        public var topology: NetworkTopology
    }

    public init() {}

    public func correlate(_ input: Input) -> Output {
        var sessions = input.sessions
        var streams = input.streams
        let messages = input.messages

        // 1. Group INVITE sessions into calls (merging B2BUA legs).
        let inviteSessions = sessions.filter { $0.initialMethod == "INVITE" }.sorted { $0.startTime < $1.startTime }
        let groups = groupLegs(inviteSessions, messages: messages)
        let topology = inferTopology(sessions: sessions, messages: messages)

        // 2. Assign streams to calls using SDP announcements and time windows.
        let announcementsByCallID = Dictionary(grouping: input.announcements, by: \.callID)
        var callWindows: [(start: Timestamp, end: Timestamp)] = []
        for group in groups {
            guard let start = group.map(\.startTime).min(), var end = group.map(\.endTime).max() else {
                callWindows.append((Timestamp(nanoseconds: 0), Timestamp(nanoseconds: 0)))
                continue
            }
            if let captureEnd = input.captureEnd, group.contains(where: { $0.state == .established }) {
                end = max(end, captureEnd)
            }
            callWindows.append((start, end))
        }
        // Announcements per call, and the calls that announced each endpoint (with when), so every stream is scored
        // only against the calls whose SDP names one of its endpoints (not against every call).
        let announcedByCall = groups.map { group in group.flatMap { announcementsByCallID[$0.callID] ?? [] } }
        var callsByEndpoint: [Endpoint: [(call: Int, time: Timestamp)]] = [:]
        for (callIndex, announced) in announcedByCall.enumerated() {
            for announcement in announced { callsByEndpoint[announcement.endpoint, default: []].append((callIndex, announcement.time)) }
        }
        var streamsByCall = [[Int]](repeating: [], count: groups.count)
        for (streamIndex, stream) in streams.enumerated() {
            var best: (call: Int, score: Double)?
            var candidates: [Int: (destination: Bool, source: Bool)] = [:]
            for entry in callsByEndpoint[stream.destination] ?? [] where entry.time <= stream.lastTime {
                candidates[entry.call, default: (false, false)].destination = true
            }
            for entry in callsByEndpoint[stream.source] ?? [] where entry.time <= stream.lastTime {
                candidates[entry.call, default: (false, false)].source = true
            }
            for (callIndex, match) in candidates {
                let window = callWindows[callIndex]
                // Media may start slightly before the 200 OK (early media) and linger briefly after BYE.
                guard stream.lastTime >= window.start.adding(seconds: -1),
                      stream.firstTime <= window.end.adding(seconds: 5) else { continue }
                // Prefer the call whose window overlaps the stream the most (ties: the earlier call).
                let overlap = min(stream.lastTime, window.end).seconds(since: max(stream.firstTime, window.start))
                let score = (match.destination ? 1000 : 0) + overlap
                if let current = best, score < current.score || (score == current.score && callIndex > current.call) { continue }
                best = (callIndex, score)
            }
            if let call = best?.call { streamsByCall[call].append(streamIndex) }
        }

        // 3. Build call records.
        var calls: [CallRecord] = []
        for (callIndex, group) in groups.enumerated() {
            let ownedStreams = streamsByCall[callIndex]
            let call = buildCall(id: callIndex, legs: group, messages: messages, transactions: input.transactions,
                                 announcements: announcedByCall[callIndex],
                                 streamIndices: ownedStreams, streams: streams, captureEnd: input.captureEnd,
                                 topology: topology)
            calls.append(call)
            for leg in group { sessions[leg.id].callIndex = callIndex }
            for s in ownedStreams { streams[s].callIndex = callIndex }
        }

        // 4. Per-stream MOS.
        for index in streams.indices {
            let stream = streams[index]
            if let kind = stream.codec?.kind,
               let r = EModel.rFactor(codec: kind, packetLossPercent: stream.lossPercent, burstRatio: stream.burstRatio) {
                streams[index].rFactor = r
                streams[index].mos = EModel.mos(fromR: r)
            }
        }
        for index in calls.indices {
            calls[index].quality = quality(for: calls[index], streams: streams)
        }

        // 5. Findings.
        var findings: [Finding] = []
        for index in calls.indices {
            let callFindings = FindingDetector.findings(for: calls[index], streams: streams, messages: messages,
                                                        firstID: findings.count)
            calls[index].findingIndices = callFindings.map(\.id)
            calls[index].severity = callSeverity(calls[index], findings: callFindings)
            findings += callFindings
        }
        return Output(calls: calls, sessions: sessions, streams: streams, findings: findings, topology: topology)
    }

    // MARK: - Leg grouping

    /// Merges B2BUA legs: an INVITE leaving the node that received another INVITE shortly before, for the same
    /// called user and calling user, is treated as the second leg of the same call.
    func groupLegs(_ sessions: [SIPSessionRecord], messages: [SIPMessageRecord]) -> [[SIPSessionRecord]] {
        struct LegKey: Hashable {
            var called: String?
            var calling: String?
            /// Leg 1's destination, which must be leg 2's source.
            var node: IPAddress
        }
        var groups: [[SIPSessionRecord]] = []
        var groupOfPosition: [Int] = []
        let invites = sessions.map { firstInvite(of: $0, messages: messages) }
        // Earlier INVITEs by (called, calling, where they went): a leg is looked up among those only, not among every
        // session of the last seconds (which is quadratic on busy captures).
        var earlier: [LegKey: [Int]] = [:]
        for (position, session) in sessions.enumerated() {
            // Pick the closest preceding leg (within 2 s) that this INVITE could continue.
            var best: (group: Int, delay: Double)?
            if let invite = invites[position] {
                let called = normalizedUser(invite.to.user ?? requestUser(invite))
                let calling = normalizedUser(invite.from.user)
                if invite.to.user != nil || requestUser(invite) != nil {
                    for j in (earlier[LegKey(called: called, calling: calling, node: invite.source.address)] ?? []).reversed() {
                        guard let otherInvite = invites[j] else { continue }
                        let delay = invite.time.seconds(since: otherInvite.time)
                        if delay > 5 { break }  // positions are in start-time order
                        // Leg 2 is sent by the node that received leg 1, and not back to leg 1's sender.
                        guard delay >= 0, delay <= 2, invite.destination.address != otherInvite.source.address else { continue }
                        if delay < best?.delay ?? .infinity { best = (groupOfPosition[j], delay) }
                    }
                }
                earlier[LegKey(called: called, calling: calling, node: invite.destination.address), default: []].append(position)
            }
            if let best {
                groups[best.group].append(session)
                groupOfPosition.append(best.group)
            } else {
                groupOfPosition.append(groups.count)
                groups.append([session])
            }
        }
        return groups
    }

    private func firstInvite(of session: SIPSessionRecord, messages: [SIPMessageRecord]) -> SIPMessageRecord? {
        session.messageIndices.lazy.map { messages[$0] }.first { $0.isRequest && $0.method == "INVITE" }
    }

    private func requestUser(_ message: SIPMessageRecord) -> String? {
        message.requestURI.flatMap { SIPHeaderParser.userAndHost(of: $0).user }
    }

    private func normalizedUser(_ user: String?) -> String? {
        guard let user else { return nil }
        let digits = user.filter(\.isNumber)
        // Compare phone numbers by their last digits so "+50322607788" matches "22607788".
        if digits.count >= 7 { return String(digits.suffix(8)) }
        return user.lowercased()
    }

    // MARK: - Call building

    private func buildCall(id: Int, legs: [SIPSessionRecord], messages: [SIPMessageRecord],
                           transactions: [SIPTransactionRecord], announcements: [MediaAnnouncement],
                           streamIndices: [Int], streams: [RTPStreamRecord], captureEnd: Timestamp?,
                           topology: NetworkTopology) -> CallRecord {
        let sortedLegs = legs.sorted { $0.startTime < $1.startTime }
        let firstLeg = sortedLegs[0]
        let messageIndices = legs.flatMap(\.messageIndices).sorted { messages[$0].time < messages[$1].time }
        let callMessages = messageIndices.map { messages[$0] }
        let initialInvite = callMessages.first { $0.isRequest && $0.method == "INVITE" } ?? callMessages[0]

        // The callee is the far end of the last INVITE hop (proxies forward the INVITE with the same Call-ID,
        // B2BUAs on a second leg). With forking, prefer the hop whose transaction was answered.
        let initialHops = callMessages.filter {
            $0.isRequest && $0.method == "INVITE" && !$0.isRetransmission && $0.cseq == initialInvite.cseq
        }
        let answeredHops = initialHops.filter { hop in
            hop.transactionIndex.map { (transactions[$0].finalStatusCode ?? 0) / 100 == 2 } ?? false
        }
        let lastInvite = (answeredHops.last ?? initialHops.last) ?? initialInvite

        let caller = CallParty(user: initialInvite.from.user ?? initialInvite.from.uri,
                               displayName: initialInvite.from.displayName, uri: initialInvite.from.uri,
                               signalling: initialInvite.source)
        let calleeAddress = lastInvite.to
        let callee = CallParty(user: calleeAddress.user ?? requestUser(lastInvite) ?? calleeAddress.uri,
                               displayName: calleeAddress.displayName ?? displayNameFromResponses(callMessages),
                               uri: calleeAddress.uri, signalling: lastInvite.destination)

        // Timing on the caller-facing leg.
        let callerLegMessages = firstLeg.messageIndices.map { messages[$0] }
        let ringing = callerLegMessages.first { !$0.isRequest && $0.cseqMethod == "INVITE" && ($0.statusCode == 180 || $0.statusCode == 183) }?.time
        let answer = callerLegMessages.first { !$0.isRequest && $0.cseqMethod == "INVITE" && ($0.statusCode ?? 0) / 100 == 2 && $0.cseq == initialInvite.cseq }?.time

        var state: CallState
        let code = firstLeg.finalStatusCode
        switch firstLeg.state {
        case .completed: state = .completed
        case .established: state = .answered
        case .early: state = .ringing
        case .cancelled: state = .cancelled
        case .noResponse: state = .noAnswer
        case .failed:
            state = [486, 600, 603].contains(code ?? 0) ? .rejected : .failed
        case .succeeded: state = .completed
        }

        // End: 200 OK to BYE, else the BYE, else last message.
        let bye = callMessages.first { $0.isRequest && $0.method == "BYE" }
        let byeOK = bye.flatMap { b in callMessages.first { !$0.isRequest && $0.cseqMethod == "BYE" && $0.time >= b.time } }
        var end = byeOK?.time ?? bye?.time ?? callMessages.last?.time ?? initialInvite.time
        var endReason: CallEndReason
        if let bye {
            endReason = bye.source.address == caller.signalling.address || bye.from.tag == initialInvite.from.tag
                ? .byeFromCaller : .byeFromCallee
        } else if state == .cancelled {
            endReason = .cancel
        } else if state.isFailure {
            endReason = .failureResponse
        } else if state == .answered {
            endReason = .captureEnded
            let lastMedia = streamIndices.map { streams[$0].lastTime }.max()
            end = max(end, lastMedia ?? end, captureEnd ?? end)
        } else {
            endReason = .unknown
        }
        if state.isFailure || state == .cancelled || state == .noAnswer {
            end = callMessages.last { $0.cseqMethod == "INVITE" || $0.method == "CANCEL" || $0.method == "ACK" }?.time ?? end
        }

        // Codec: the answer's first voice payload type, confirmed by the media when possible.
        let voiceStreams = streamIndices.map { streams[$0] }.filter { $0.codec?.kind.isVoice ?? true }
        let mediaCodec = voiceStreams.max { $0.packetCount < $1.packetCount }?.codec
        let answerCodec = announcements.filter { !$0.isRequest }.sorted { $0.time < $1.time }.first.flatMap { a in
            a.payloadTypes.lazy.compactMap { a.codecs[$0] }.first { $0.kind.isVoice }
        }
        let offerCodec = announcements.sorted { $0.time < $1.time }.first.flatMap { a in
            a.payloadTypes.lazy.compactMap { a.codecs[$0] }.first { $0.kind.isVoice }
        }
        let codec = mediaCodec ?? answerCodec ?? (state.wasAnswered ? offerCodec : nil)
        let ptime = announcements.compactMap(\.ptimeMs).first
            ?? voiceStreams.compactMap(\.ptimeMs).first.map { Int($0.rounded()) }

        // Participants in first-appearance order, with friendly labels.
        var participantOrder: [IPAddress] = []
        for message in callMessages {
            for address in [message.source.address, message.destination.address] where !participantOrder.contains(address) {
                participantOrder.append(address)
            }
        }
        let participants = participantOrder.map { address -> CallParticipant in
            if address == caller.signalling.address { return CallParticipant(address: address, label: String(localized: "\(caller.user) · Caller", bundle: CoreLocalization.bundle)) }
            if address == callee.signalling.address { return CallParticipant(address: address, label: String(localized: "\(callee.user) · Callee", bundle: CoreLocalization.bundle)) }
            if address == topology.sipServer { return CallParticipant(address: address, label: String(localized: "SIP Server", bundle: CoreLocalization.bundle)) }
            if topology.trunks.contains(address) { return CallParticipant(address: address, label: String(localized: "SIP Trunk", bundle: CoreLocalization.bundle)) }
            return CallParticipant(address: address, label: String(localized: "Proxy", bundle: CoreLocalization.bundle))
        }

        // Media path.
        let mediaPath: MediaPath
        let uaAddresses: Set<IPAddress> = [caller.signalling.address, callee.signalling.address]
        if voiceStreams.isEmpty {
            mediaPath = .unknown
        } else {
            let mediaAddresses = Set(voiceStreams.flatMap { [$0.source.address, $0.destination.address] })
            if mediaAddresses.isSubset(of: uaAddresses) {
                mediaPath = .direct
            } else if let relay = mediaAddresses.subtracting(uaAddresses).sorted().first {
                mediaPath = .relayed(relay)
            } else {
                mediaPath = .direct
            }
        }

        return CallRecord(
            id: id, callIDs: sortedLegs.map(\.callID), sessionIndices: sortedLegs.map(\.id),
            messageIndices: messageIndices, caller: caller, callee: callee, participants: participants,
            startTime: initialInvite.time, ringingTime: ringing, answerTime: answer, endTime: max(end, initialInvite.time),
            state: state, finalStatusCode: state.wasAnswered ? 200 : code,
            finalReason: state.wasAnswered ? "OK" : code.map { c in
                callerLegMessages.last { $0.statusCode == c }?.reasonPhrase ?? SIPStatus.reasonPhrase(for: c)
            },
            endReason: endReason, codec: codec, ptimeMs: ptime, mediaPath: mediaPath,
            streamIndices: streamIndices.sorted { streams[$0].firstTime < streams[$1].firstTime },
            quality: nil, severity: .ok, findingIndices: [], mergedLegs: legs.count > 1)
    }

    private func displayNameFromResponses(_ messages: [SIPMessageRecord]) -> String? {
        messages.first { !$0.isRequest && $0.to.displayName != nil }?.to.displayName
    }

    // MARK: - Quality

    func quality(for call: CallRecord, streams: [RTPStreamRecord]) -> CallQuality? {
        let voice = call.streamIndices.filter { streams[$0].codec?.kind.isVoice ?? true }
        guard !voice.isEmpty else { return nil }
        // Forward = caller → callee. Relayed media legs are classified by the user agent they touch.
        let callerAddress = call.caller.signalling.address
        let calleeAddress = call.callee.signalling.address
        var forward: [Int] = [], reverse: [Int] = []
        for index in voice {
            let stream = streams[index]
            if stream.source.address == callerAddress || stream.destination.address == calleeAddress {
                forward.append(index)
            } else if stream.destination.address == callerAddress || stream.source.address == calleeAddress {
                reverse.append(index)
            } else {
                // Neither end is a known user agent (e.g. relay to relay): keep the first seen as forward.
                if forward.isEmpty || !reverse.isEmpty { forward.append(index) } else { reverse.append(index) }
            }
        }
        let forwardQuality = directionQuality(forward, streams: streams)
        let reverseQuality = directionQuality(reverse, streams: streams)
        let directions = [forwardQuality, reverseQuality].compactMap { $0 }
        let mosValues = directions.compactMap(\.mos)
        let packets = directions.reduce(0) { $0 + $1.packets }
        let expected = directions.reduce(0) { $0 + $1.expected }
        let lost = directions.reduce(0) { $0 + $1.lost }
        let jitterDirections = directions.filter { $0.meanJitterMs != nil && $0.packets > 0 }
        let meanJitter: Double? = jitterDirections.isEmpty ? nil
            : jitterDirections.reduce(0) { $0 + ($1.meanJitterMs ?? 0) * Double($1.packets) } / Double(jitterDirections.reduce(0) { $0 + $1.packets })
        return CallQuality(forward: forwardQuality, reverse: reverseQuality, mos: mosValues.min(),
                           meanJitterMs: meanJitter, maxJitterMs: directions.compactMap(\.maxJitterMs).max(),
                           lossPercent: expected > 0 ? max(0, Double(lost)) / Double(expected) * 100 : nil,
                           lostPackets: max(0, lost), rtpPackets: packets)
    }

    private func directionQuality(_ indices: [Int], streams: [RTPStreamRecord]) -> DirectionQuality? {
        guard !indices.isEmpty else { return nil }
        let items = indices.map { streams[$0] }
        let packets = items.reduce(0) { $0 + $1.packetCount }
        let expected = items.reduce(0) { $0 + $1.expectedPackets }
        let lost = items.reduce(0) { $0 + $1.lostPackets }
        let withJitter = items.filter { $0.meanJitterMs != nil }
        let meanJitter: Double? = withJitter.isEmpty ? nil
            : withJitter.reduce(0) { $0 + ($1.meanJitterMs ?? 0) * Double($1.packetCount) } / Double(max(1, withJitter.reduce(0) { $0 + $1.packetCount }))
        // MOS for the direction: E-model on the aggregated loss with the dominant stream's codec and burstiness.
        guard let dominant = items.max(by: { $0.packetCount < $1.packetCount }) else { return nil }
        let lossPercent = expected > 0 ? max(0, Double(lost)) / Double(expected) * 100 : 0
        let mos = dominant.codec.flatMap { EModel.mos(codec: $0.kind, packetLossPercent: lossPercent, burstRatio: dominant.burstRatio) }
        return DirectionQuality(streamIndices: indices, packets: packets, expected: expected, lost: lost,
                                duplicates: items.reduce(0) { $0 + $1.duplicatePackets },
                                outOfOrder: items.reduce(0) { $0 + $1.outOfOrderPackets },
                                meanJitterMs: meanJitter, maxJitterMs: items.compactMap(\.maxJitterMs).max(), mos: mos)
    }

    private func callSeverity(_ call: CallRecord, findings: [Finding]) -> Severity {
        var severity: Severity = call.state.isFailure ? .error : .ok
        if let quality = call.quality {
            severity = max(severity, QualityThresholds.severity(mos: quality.mos))
            severity = max(severity, QualityThresholds.severity(jitterMs: quality.meanJitterMs))
            severity = max(severity, QualityThresholds.severity(lossPercent: quality.lossPercent))
        }
        for finding in findings where finding.kind == .oneWayAudio || finding.kind == .noMedia {
            severity = max(severity, finding.severity)
        }
        return severity
    }

    // MARK: - Topology

    func inferTopology(sessions: [SIPSessionRecord], messages: [SIPMessageRecord]) -> NetworkTopology {
        // A SIP server is an address that takes part in most sessions (and in more than one).
        var participation: [IPAddress: Int] = [:]
        var relays: Set<IPAddress> = []
        for session in sessions {
            var addresses: Set<IPAddress> = []
            var inviteReceivers: Set<IPAddress> = []
            var inviteSenders: Set<IPAddress> = []
            for index in session.messageIndices {
                let message = messages[index]
                addresses.insert(message.source.address)
                addresses.insert(message.destination.address)
                if message.isRequest && message.method == "INVITE" && !message.isRetransmission {
                    inviteReceivers.insert(message.destination.address)
                    inviteSenders.insert(message.source.address)
                }
            }
            relays.formUnion(inviteReceivers.intersection(inviteSenders))
            for address in addresses { participation[address, default: 0] += 1 }
        }
        let total = sessions.count
        let server = participation.filter { $0.value > 1 && Double($0.value) >= Double(total) * 0.5 }
            .max { a, b in a.value != b.value ? a.value < b.value : a.key > b.key }?.key
        let sipServer = server ?? (relays.count == 1 ? relays.first : nil)
        let others = participation.keys.filter { $0 != sipServer }
        let trunks = sipServer == nil ? [] : others.filter { !$0.isPrivate }.sorted()
        let endpoints = others.filter { $0.isPrivate || sipServer == nil }.sorted()
        return NetworkTopology(sipServer: sipServer, endpoints: endpoints, trunks: trunks)
    }
}
