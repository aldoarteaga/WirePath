import Foundation

/// Turns a `SimCall` into SIP frames plus lazy RTP sources.
struct CallGenerator {
    let call: SimCall
    var rng: SeededRandom
    var frames: [TimedFrame] = []
    var rtpSources: [RTPDirectionSource] = []
    var ipID: UInt16
    var tcpSequence: [String: UInt32] = [:]
    var tcpOpened: Set<String> = []

    init(call: SimCall) {
        self.call = call
        rng = SeededRandom(seed: call.seed &* 0x9E37_79B9 &+ 17)
        ipID = UInt16(truncatingIfNeeded: rng.next())
    }

    mutating func token(_ length: Int = 8) -> String {
        let alphabet = Array("0123456789abcdef")
        return String((0..<length).map { _ in alphabet[Int(rng.next() % 16)] })
    }

    mutating func callID(for host: SimHost) -> String {
        "\(token(8))-\(token(4))-\(token(4))-\(token(4))-\(token(12))@\(host.ip)"
    }

    // MARK: Message text

    func nameAddr(_ party: SimParty, tag: String?) -> String {
        let display = party.displayName.map { "\"\($0)\" " } ?? ""
        let tagText = tag.map { ";tag=\($0)" } ?? ""
        return "\(display)<sip:\(party.user)@\(party.domain)>\(tagText)"
    }

    func sdp(user: String, ip: String, port: UInt16, sessionID: String) -> String {
        let codec = call.codec
        var lines = [
            "v=0",
            "o=\(user) \(sessionID) \(sessionID) IN IP4 \(ip)",
            "s=WirePathSim",
            "c=IN IP4 \(ip)",
            "t=0 0",
            "m=audio \(port) RTP/AVP \(codec.payloadType) 101",
            "a=rtpmap:\(codec.payloadType) \(codec.rtpmap)",
        ]
        if let fmtp = codec.fmtp { lines.append("a=fmtp:\(codec.payloadType) \(fmtp)") }
        lines += ["a=rtpmap:101 telephone-event/8000", "a=fmtp:101 0-16", "a=ptime:\(call.ptimeMs)", "a=sendrecv"]
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    struct Dialog {
        var callID: String
        var from: SimParty
        var to: SimParty
        var fromTag: String
        var toTag: String?
        var requestURI: String
        var cseq = 1
    }

    func message(startLine: String, vias: [String], dialog: Dialog, cseq: Int, method: String, contact: SimHost?,
                 ua: String, body: String?, toTag: String?, extra: [String] = []) -> String {
        var headers = vias.map { "Via: \($0)" }
        headers.append("Max-Forwards: 70")
        headers.append("From: \(nameAddr(dialog.from, tag: dialog.fromTag))")
        headers.append("To: \(nameAddr(dialog.to, tag: toTag))")
        headers.append("Call-ID: \(dialog.callID)")
        headers.append("CSeq: \(cseq) \(method)")
        if let contact { headers.append("Contact: <sip:\(dialog.from.user)@\(contact.ip):\(contact.port)>") }
        headers.append("User-Agent: \(ua)")
        headers += extra
        if let body {
            headers.append("Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, REFER")
            headers.append("Content-Type: application/sdp")
            headers.append("Content-Length: \(body.utf8.count)")
            return startLine + "\r\n" + headers.joined(separator: "\r\n") + "\r\n\r\n" + body
        }
        headers.append("Content-Length: 0")
        return startLine + "\r\n" + headers.joined(separator: "\r\n") + "\r\n\r\n"
    }

    func via(_ host: SimHost, branch: String) -> String {
        "SIP/2.0/\(call.sipOverTCP ? "TCP" : "UDP") \(host.ip):\(host.port);branch=z9hG4bK-\(branch)"
    }

    // MARK: Emission

    mutating func emit(_ time: Double, from: SimHost, to: SimHost, _ text: String) {
        let payload = Array(text.utf8)
        ipID &+= 1
        if call.sipOverTCP {
            let key = "\(from.ip):\(from.port)>\(to.ip):\(to.port)"
            let reverseKey = "\(to.ip):\(to.port)>\(from.ip):\(from.port)"
            let connection = [key, reverseKey].sorted().joined()
            if !tcpOpened.contains(connection) {
                tcpOpened.insert(connection)
                let isn1 = UInt32(truncatingIfNeeded: rng.next()), isn2 = UInt32(truncatingIfNeeded: rng.next())
                frames.append(TimedFrame(time: time - 0.0006, bytes: FrameBuilder.tcpFrame(source: from.ip, sourcePort: from.port, destination: to.ip, destinationPort: to.port, sequence: isn1, flags: 0x02, payload: [], identification: ipID)))
                frames.append(TimedFrame(time: time - 0.0004, bytes: FrameBuilder.tcpFrame(source: to.ip, sourcePort: to.port, destination: from.ip, destinationPort: from.port, sequence: isn2, acknowledgment: isn1 &+ 1, flags: 0x12, payload: [], identification: ipID)))
                tcpSequence[key] = isn1 &+ 1
                tcpSequence[reverseKey] = isn2 &+ 1
            }
            let sequence = tcpSequence[key] ?? 1
            // Split long messages across two segments to exercise stream reassembly.
            let pieces: [[UInt8]] = payload.count > 600 ? [Array(payload[..<400]), Array(payload[400...])] : [payload]
            var seq = sequence
            for (index, piece) in pieces.enumerated() {
                frames.append(TimedFrame(time: time + Double(index) * 0.0001, bytes: FrameBuilder.tcpFrame(
                    source: from.ip, sourcePort: from.port, destination: to.ip, destinationPort: to.port,
                    sequence: seq, flags: 0x18, payload: piece, identification: ipID)))
                seq &+= UInt32(piece.count)
            }
            tcpSequence[key] = seq
            return
        }
        if let mtu = call.fragmentMTU, payload.count + 8 > mtu {
            for (index, frame) in FrameBuilder.fragmentedUDPFrames(source: from.ip, sourcePort: from.port, destination: to.ip,
                                                                   destinationPort: to.port, payload: payload,
                                                                   identification: ipID, mtu: mtu).enumerated() {
                frames.append(TimedFrame(time: time + Double(index) * 0.00005, bytes: frame))
            }
            return
        }
        frames.append(TimedFrame(time: time, bytes: FrameBuilder.udpFrame(
            source: from.ip, sourcePort: from.port, destination: to.ip, destinationPort: to.port, payload: payload,
            identification: ipID, dscp: 24)))
    }

    // MARK: Flow

    mutating func generate() {
        let a = call.caller.host
        let b = call.callee.host
        let t0 = call.start
        let callerPort = UInt16(16384 + 2 * Int(rng.next() % 2000))
        let calleePort = UInt16(16384 + 2 * Int(rng.next() % 2000))
        let sessionA = String(10_000 + rng.next() % 89_999), sessionB = String(10_000 + rng.next() % 89_999)
        let sdpA = sdp(user: call.caller.user, ip: a.ip, port: callerPort, sessionID: sessionA)
        let sdpB = sdp(user: call.callee.user, ip: b.ip, port: calleePort, sessionID: sessionB)

        var server: SimHost?
        var b2bua = false
        var anchor = false
        switch call.topology {
        case .direct: break
        case .proxy(let host): server = host
        case .b2bua(let host, let anchorMedia): server = host; b2bua = true; anchor = anchorMedia
        }

        let leg1CallID = callID(for: a)
        var leg1 = Dialog(callID: leg1CallID, from: call.caller, to: call.callee, fromTag: token(6), toTag: nil,
                          requestURI: "sip:\(call.callee.user)@\(call.callee.domain)")
        var leg2 = leg1
        if b2bua, let server {
            leg2 = Dialog(callID: callID(for: server), from: call.caller, to: call.callee, fromTag: token(6), toTag: nil,
                          requestURI: "sip:\(call.callee.user)@\(b.ip):\(b.port)")
        } else {
            leg2.requestURI = "sip:\(call.callee.user)@\(b.ip):\(b.port)"
        }
        let calleeTag = token(6)
        let serverTag = token(6)

        let branchA = token(6)
        let branchS = token(6)
        let viaA = via(a, branch: branchA)
        let viaS = server.map { via($0, branch: branchS) }
        // Vias on the second leg: proxies stack theirs, B2BUAs start fresh, direct calls have one leg only.
        let leg2Vias: [String] = server == nil ? [viaA] : (b2bua ? [viaS!] : [viaS!, viaA])
        let leg2From = server ?? a
        let serverSDPToA = anchor ? sdp(user: "pbx", ip: server!.ip, port: callerPort &+ 10_000, sessionID: sessionB) : sdpB
        let serverSDPToB = anchor ? sdp(user: "pbx", ip: server!.ip, port: calleePort &+ 10_000, sessionID: sessionA) : sdpA
        let tagToCaller = b2bua ? serverTag : calleeTag

        let invite1 = message(startLine: "INVITE \(leg1.requestURI) SIP/2.0", vias: [viaA], dialog: leg1, cseq: 1,
                              method: "INVITE", contact: a, ua: a.userAgent, body: sdpA, toTag: nil)
        emit(t0, from: a, to: server ?? b, invite1)

        var t = t0
        if let server {
            emit(t0 + 0.002, from: server, to: a, message(startLine: "SIP/2.0 100 Trying", vias: [viaA], dialog: leg1, cseq: 1, method: "INVITE", contact: nil, ua: server.userAgent, body: nil, toTag: nil))
            if case .rejected(let code, let reason, true) = call.outcome {
                emit(t0 + 0.041, from: server, to: a, message(startLine: "SIP/2.0 \(code) \(reason)", vias: [viaA], dialog: leg1, cseq: 1, method: "INVITE", contact: nil, ua: server.userAgent, body: nil, toTag: serverTag))
                var ack = leg1
                ack.toTag = serverTag
                emit(t0 + 0.043, from: a, to: server, message(startLine: "ACK \(leg1.requestURI) SIP/2.0", vias: [viaA], dialog: ack, cseq: 1, method: "ACK", contact: nil, ua: a.userAgent, body: nil, toTag: serverTag))
                return
            }
            t = t0 + 0.004
            emit(t, from: server, to: b, message(startLine: "INVITE \(leg2.requestURI) SIP/2.0", vias: leg2Vias, dialog: leg2, cseq: 1, method: "INVITE", contact: server, ua: server.userAgent, body: serverSDPToB, toTag: nil))
        }
        let calleeReceives = server ?? a

        if case .timeout = call.outcome {
            // INVITE retransmissions (Timer A) toward a callee that never responds, then 408.
            var interval = 0.5
            var rt = t
            while rt + interval < t0 + 8 {
                rt += interval
                interval *= 2
                emit(rt, from: leg2From, to: b, message(startLine: "INVITE \(leg2.requestURI) SIP/2.0", vias: leg2Vias, dialog: leg2, cseq: 1, method: "INVITE", contact: leg2From, ua: leg2From.userAgent, body: server == nil ? sdpA : serverSDPToB, toTag: nil))
            }
            let responder = server ?? b
            emit(t0 + 8, from: responder, to: a, message(startLine: "SIP/2.0 408 Request Timeout", vias: [viaA], dialog: leg1, cseq: 1, method: "INVITE", contact: nil, ua: responder.userAgent, body: nil, toTag: serverTag))
            var ack = leg1
            ack.toTag = serverTag
            emit(t0 + 8.002, from: a, to: responder, message(startLine: "ACK \(leg1.requestURI) SIP/2.0", vias: [viaA], dialog: ack, cseq: 1, method: "ACK", contact: nil, ua: a.userAgent, body: nil, toTag: serverTag))
            return
        }

        // Callee: 100 Trying, 180 Ringing
        emit(t + 0.015, from: b, to: calleeReceives, message(startLine: "SIP/2.0 100 Trying", vias: leg2Vias, dialog: leg2, cseq: 1, method: "INVITE", contact: nil, ua: b.userAgent, body: nil, toTag: nil))
        emit(t + 0.208, from: b, to: calleeReceives, message(startLine: "SIP/2.0 180 Ringing", vias: leg2Vias, dialog: leg2, cseq: 1, method: "INVITE", contact: b, ua: b.userAgent, body: nil, toTag: calleeTag))
        if let server {
            emit(t + 0.210, from: server, to: a, message(startLine: "SIP/2.0 180 Ringing", vias: [viaA], dialog: leg1, cseq: 1, method: "INVITE", contact: server, ua: server.userAgent, body: nil, toTag: tagToCaller))
        }

        switch call.outcome {
        case .rejected(let code, let reason, _):
            let tr = t0 + call.ringDuration
            emit(tr, from: b, to: calleeReceives, message(startLine: "SIP/2.0 \(code) \(reason)", vias: leg2Vias, dialog: leg2, cseq: 1, method: "INVITE", contact: nil, ua: b.userAgent, body: nil, toTag: calleeTag))
            var ack2 = leg2
            ack2.toTag = calleeTag
            emit(tr + 0.002, from: calleeReceives, to: b, message(startLine: "ACK \(leg2.requestURI) SIP/2.0", vias: [server.map { via($0, branch: branchS) } ?? viaA], dialog: ack2, cseq: 1, method: "ACK", contact: nil, ua: calleeReceives.userAgent, body: nil, toTag: calleeTag))
            if let server {
                emit(tr + 0.003, from: server, to: a, message(startLine: "SIP/2.0 \(code) \(reason)", vias: [viaA], dialog: leg1, cseq: 1, method: "INVITE", contact: nil, ua: server.userAgent, body: nil, toTag: tagToCaller))
                var ack1 = leg1
                ack1.toTag = tagToCaller
                emit(tr + 0.005, from: a, to: server, message(startLine: "ACK \(leg1.requestURI) SIP/2.0", vias: [viaA], dialog: ack1, cseq: 1, method: "ACK", contact: nil, ua: a.userAgent, body: nil, toTag: tagToCaller))
            }
        case .cancelled(let after):
            let tc = t0 + after
            let target = server ?? b
            emit(tc, from: a, to: target, message(startLine: "CANCEL \(leg1.requestURI) SIP/2.0", vias: [viaA], dialog: leg1, cseq: 1, method: "CANCEL", contact: nil, ua: a.userAgent, body: nil, toTag: nil))
            emit(tc + 0.002, from: target, to: a, message(startLine: "SIP/2.0 200 OK", vias: [viaA], dialog: leg1, cseq: 1, method: "CANCEL", contact: nil, ua: target.userAgent, body: nil, toTag: tagToCaller))
            if let server {
                emit(tc + 0.003, from: server, to: b, message(startLine: "CANCEL \(leg2.requestURI) SIP/2.0", vias: [via(server, branch: branchS)], dialog: leg2, cseq: 1, method: "CANCEL", contact: nil, ua: server.userAgent, body: nil, toTag: nil))
                emit(tc + 0.012, from: b, to: server, message(startLine: "SIP/2.0 200 OK", vias: [via(server, branch: branchS)], dialog: leg2, cseq: 1, method: "CANCEL", contact: nil, ua: b.userAgent, body: nil, toTag: calleeTag))
            }
            emit(tc + 0.014, from: b, to: calleeReceives, message(startLine: "SIP/2.0 487 Request Terminated", vias: leg2Vias, dialog: leg2, cseq: 1, method: "INVITE", contact: nil, ua: b.userAgent, body: nil, toTag: calleeTag))
            var ack2 = leg2
            ack2.toTag = calleeTag
            emit(tc + 0.016, from: calleeReceives, to: b, message(startLine: "ACK \(leg2.requestURI) SIP/2.0", vias: [server.map { via($0, branch: branchS) } ?? viaA], dialog: ack2, cseq: 1, method: "ACK", contact: nil, ua: calleeReceives.userAgent, body: nil, toTag: calleeTag))
            if let server {
                emit(tc + 0.017, from: server, to: a, message(startLine: "SIP/2.0 487 Request Terminated", vias: [viaA], dialog: leg1, cseq: 1, method: "INVITE", contact: nil, ua: server.userAgent, body: nil, toTag: tagToCaller))
                var ack1 = leg1
                ack1.toTag = tagToCaller
                emit(tc + 0.019, from: a, to: server, message(startLine: "ACK \(leg1.requestURI) SIP/2.0", vias: [viaA], dialog: ack1, cseq: 1, method: "ACK", contact: nil, ua: a.userAgent, body: nil, toTag: tagToCaller))
            }
        case .answered(let talk, let hangupByCaller):
            let ta = t0 + call.ringDuration
            emit(ta, from: b, to: calleeReceives, message(startLine: "SIP/2.0 200 OK", vias: leg2Vias, dialog: leg2, cseq: 1, method: "INVITE", contact: b, ua: b.userAgent, body: server == nil ? sdpB : (anchor ? sdpB : sdpB), toTag: calleeTag))
            if let server {
                emit(ta + 0.002, from: server, to: a, message(startLine: "SIP/2.0 200 OK", vias: [viaA], dialog: leg1, cseq: 1, method: "INVITE", contact: server, ua: server.userAgent, body: serverSDPToA, toTag: tagToCaller))
            }
            leg1.toTag = tagToCaller
            leg2.toTag = calleeTag
            let ackBranchA = token(6), ackBranchS = token(6)
            emit(ta + 0.020, from: a, to: server ?? b, message(startLine: "ACK \(leg1.requestURI) SIP/2.0", vias: [via(a, branch: ackBranchA)], dialog: leg1, cseq: 1, method: "ACK", contact: nil, ua: a.userAgent, body: nil, toTag: tagToCaller))
            if let server {
                let vias = b2bua ? [via(server, branch: ackBranchS)] : [via(server, branch: ackBranchS), via(a, branch: ackBranchA)]
                emit(ta + 0.022, from: server, to: b, message(startLine: "ACK \(leg2.requestURI) SIP/2.0", vias: vias, dialog: leg2, cseq: 1, method: "ACK", contact: nil, ua: server.userAgent, body: nil, toTag: calleeTag))
            }

            // Media
            let mediaStart = ta + 0.039
            let mediaEnd = ta + talk
            var seedBase = call.seed &* 7919
            func nextSeed() -> UInt64 { seedBase &+= 104_729; return seedBase }
            if anchor, let server {
                let pS1 = callerPort &+ 10_000, pS2 = calleePort &+ 10_000
                rtpSources.append(RTPDirectionSource(sourceIP: a.ip, sourcePort: callerPort, destinationIP: server.ip, destinationPort: pS1, codec: call.codec, ptimeMs: call.ptimeMs, start: mediaStart, end: mediaEnd, impairment: call.forward, toneHz: 440, seed: nextSeed()))
                rtpSources.append(RTPDirectionSource(sourceIP: server.ip, sourcePort: pS2, destinationIP: b.ip, destinationPort: calleePort, codec: call.codec, ptimeMs: call.ptimeMs, start: mediaStart + 0.001, end: mediaEnd, impairment: call.forward, toneHz: 440, seed: nextSeed()))
                rtpSources.append(RTPDirectionSource(sourceIP: b.ip, sourcePort: calleePort, destinationIP: server.ip, destinationPort: pS2, codec: call.codec, ptimeMs: call.ptimeMs, start: mediaStart + 0.004, end: mediaEnd, impairment: call.reverse, toneHz: 660, seed: nextSeed()))
                rtpSources.append(RTPDirectionSource(sourceIP: server.ip, sourcePort: pS1, destinationIP: a.ip, destinationPort: callerPort, codec: call.codec, ptimeMs: call.ptimeMs, start: mediaStart + 0.005, end: mediaEnd, impairment: call.reverse, toneHz: 660, seed: nextSeed()))
            } else {
                rtpSources.append(RTPDirectionSource(sourceIP: a.ip, sourcePort: callerPort, destinationIP: b.ip, destinationPort: calleePort, codec: call.codec, ptimeMs: call.ptimeMs, start: mediaStart, end: mediaEnd, impairment: call.forward, toneHz: 440, seed: nextSeed()))
                rtpSources.append(RTPDirectionSource(sourceIP: b.ip, sourcePort: calleePort, destinationIP: a.ip, destinationPort: callerPort, codec: call.codec, ptimeMs: call.ptimeMs, start: mediaStart + 0.004, end: mediaEnd, impairment: call.reverse, toneHz: 660, seed: nextSeed()))
            }

            // BYE
            let tb = mediaEnd + 0.042
            if hangupByCaller {
                let byeBranch = token(6), byeBranchS = token(6)
                emit(tb, from: a, to: server ?? b, message(startLine: "BYE \(leg1.requestURI) SIP/2.0", vias: [via(a, branch: byeBranch)], dialog: leg1, cseq: 2, method: "BYE", contact: nil, ua: a.userAgent, body: nil, toTag: tagToCaller))
                if let server {
                    let vias = b2bua ? [via(server, branch: byeBranchS)] : [via(server, branch: byeBranchS), via(a, branch: byeBranch)]
                    emit(tb + 0.002, from: server, to: b, message(startLine: "BYE \(leg2.requestURI) SIP/2.0", vias: vias, dialog: leg2, cseq: 2, method: "BYE", contact: nil, ua: server.userAgent, body: nil, toTag: calleeTag))
                    emit(tb + 0.029, from: b, to: server, message(startLine: "SIP/2.0 200 OK", vias: vias, dialog: leg2, cseq: 2, method: "BYE", contact: nil, ua: b.userAgent, body: nil, toTag: calleeTag))
                    emit(tb + 0.031, from: server, to: a, message(startLine: "SIP/2.0 200 OK", vias: [via(a, branch: byeBranch)], dialog: leg1, cseq: 2, method: "BYE", contact: nil, ua: server.userAgent, body: nil, toTag: tagToCaller))
                } else {
                    emit(tb + 0.029, from: b, to: a, message(startLine: "SIP/2.0 200 OK", vias: [via(a, branch: byeBranch)], dialog: leg1, cseq: 2, method: "BYE", contact: nil, ua: b.userAgent, body: nil, toTag: tagToCaller))
                }
            } else {
                // Callee hangs up: From/To are reversed in requests sent by the callee.
                let byeBranch = token(6), byeBranchS = token(6)
                var reversed2 = Dialog(callID: leg2.callID, from: call.callee, to: call.caller, fromTag: calleeTag, toTag: leg2.fromTag, requestURI: "sip:\(call.caller.user)@\((server ?? a).ip)")
                reversed2.cseq = 1
                let viaB = via(b, branch: byeBranch)
                emit(tb, from: b, to: server ?? a, message(startLine: "BYE \(reversed2.requestURI) SIP/2.0", vias: [viaB], dialog: reversed2, cseq: 1, method: "BYE", contact: nil, ua: b.userAgent, body: nil, toTag: leg2.fromTag))
                if let server {
                    let reversed1 = Dialog(callID: leg1.callID, from: call.callee, to: call.caller, fromTag: tagToCaller, toTag: leg1.fromTag, requestURI: "sip:\(call.caller.user)@\(a.ip)")
                    let vias = b2bua ? [via(server, branch: byeBranchS)] : [via(server, branch: byeBranchS), viaB]
                    emit(tb + 0.002, from: server, to: a, message(startLine: "BYE \(reversed1.requestURI) SIP/2.0", vias: vias, dialog: reversed1, cseq: 1, method: "BYE", contact: nil, ua: server.userAgent, body: nil, toTag: leg1.fromTag))
                    emit(tb + 0.030, from: a, to: server, message(startLine: "SIP/2.0 200 OK", vias: vias, dialog: reversed1, cseq: 1, method: "BYE", contact: nil, ua: a.userAgent, body: nil, toTag: leg1.fromTag))
                    emit(tb + 0.032, from: server, to: b, message(startLine: "SIP/2.0 200 OK", vias: [viaB], dialog: reversed2, cseq: 1, method: "BYE", contact: nil, ua: server.userAgent, body: nil, toTag: leg2.fromTag))
                } else {
                    emit(tb + 0.030, from: a, to: b, message(startLine: "SIP/2.0 200 OK", vias: [viaB], dialog: reversed2, cseq: 1, method: "BYE", contact: nil, ua: a.userAgent, body: nil, toTag: leg2.fromTag))
                }
            }
        case .timeout:
            break
        }
    }
}

// MARK: - Capture composition

/// A whole capture: calls plus optional background traffic, written in timestamp order.
public struct SimCapture: Sendable {
    public var baseTime: Double
    public var calls: [SimCall]
    /// OPTIONS keep-alives (same Call-ID) from `from` to `to` every `interval` seconds over `duration`.
    public var keepAlive: (from: SimHost, to: SimHost, interval: Double, duration: Double)?
    /// A REGISTER refresh from a phone to the server.
    public var registration: (phone: SimParty, server: SimHost, at: Double)?
    /// Periodic DNS lookups and ARP traffic to make the packet list realistic.
    public var backgroundNoise: (hosts: [String], dnsServer: String, duration: Double)?

    public init(baseTime: Double, calls: [SimCall]) {
        self.baseTime = baseTime
        self.calls = calls
    }

    /// Writes the capture to `url` (streamed) or returns it in memory when `url` is nil.
    @discardableResult
    public func write(to url: URL? = nil, format: CaptureWriter.Format = .pcap(nanosecond: false, bigEndian: false)) throws -> Data {
        let writer = try CaptureWriter(format: format, baseTime: baseTime, url: url)
        var fixed: [TimedFrame] = []
        var rtp: [RTPDirectionSource] = []
        for call in calls {
            var generator = CallGenerator(call: call)
            generator.generate()
            fixed += generator.frames
            rtp += generator.rtpSources
        }
        fixed += backgroundFrames()
        var sources: [any PacketSource] = [FrameListSource(fixed)]
        sources += rtp.map { $0 as any PacketSource }

        // k-way merge with a binary heap keyed by next timestamp.
        var heap: [(time: Double, source: Int)] = []
        func push(_ item: (time: Double, source: Int)) {
            heap.append(item)
            var i = heap.count - 1
            while i > 0 {
                let parent = (i - 1) / 2
                if heap[parent].time <= heap[i].time { break }
                heap.swapAt(parent, i)
                i = parent
            }
        }
        func popMin() -> (time: Double, source: Int)? {
            guard !heap.isEmpty else { return nil }
            let top = heap[0]
            heap[0] = heap[heap.count - 1]
            heap.removeLast()
            var i = 0
            while true {
                let l = 2 * i + 1, r = l + 1
                var smallest = i
                if l < heap.count && heap[l].time < heap[smallest].time { smallest = l }
                if r < heap.count && heap[r].time < heap[smallest].time { smallest = r }
                if smallest == i { break }
                heap.swapAt(i, smallest)
                i = smallest
            }
            return top
        }
        for (index, source) in sources.enumerated() { if let t = source.nextTime { push((t, index)) } }
        while let item = popMin() {
            if let frame = sources[item.source].pop() { writer.write(frame) }
            if let t = sources[item.source].nextTime { push((t, item.source)) }
        }
        writer.close()
        return writer.data
    }

    func backgroundFrames() -> [TimedFrame] {
        var frames: [TimedFrame] = []
        var rng = SeededRandom(seed: 4242)
        if let keepAlive {
            let callID = "keepalive-\(keepAlive.from.ip)"
            var t = 1.0
            var cseq = 1
            while t < keepAlive.duration {
                let branch = String(rng.next() % 1_000_000)
                let request = "OPTIONS sip:\(keepAlive.to.ip):\(keepAlive.to.port) SIP/2.0\r\nVia: SIP/2.0/UDP \(keepAlive.from.ip):\(keepAlive.from.port);branch=z9hG4bK-ka\(branch)\r\nMax-Forwards: 70\r\nFrom: <sip:pbx@\(keepAlive.from.ip)>;tag=ka1\r\nTo: <sip:\(keepAlive.to.ip)>\r\nCall-ID: \(callID)\r\nCSeq: \(cseq) OPTIONS\r\nUser-Agent: \(keepAlive.from.userAgent)\r\nContent-Length: 0\r\n\r\n"
                let response = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP \(keepAlive.from.ip):\(keepAlive.from.port);branch=z9hG4bK-ka\(branch)\r\nFrom: <sip:pbx@\(keepAlive.from.ip)>;tag=ka1\r\nTo: <sip:\(keepAlive.to.ip)>;tag=tr\(cseq)\r\nCall-ID: \(callID)\r\nCSeq: \(cseq) OPTIONS\r\nServer: \(keepAlive.to.userAgent)\r\nContent-Length: 0\r\n\r\n"
                frames.append(TimedFrame(time: t, bytes: FrameBuilder.udpFrame(source: keepAlive.from.ip, sourcePort: keepAlive.from.port, destination: keepAlive.to.ip, destinationPort: keepAlive.to.port, payload: Array(request.utf8), identification: UInt16(cseq))))
                frames.append(TimedFrame(time: t + 0.018, bytes: FrameBuilder.udpFrame(source: keepAlive.to.ip, sourcePort: keepAlive.to.port, destination: keepAlive.from.ip, destinationPort: keepAlive.from.port, payload: Array(response.utf8), identification: UInt16(cseq))))
                t += keepAlive.interval
                cseq += 1
            }
        }
        if let registration {
            let phone = registration.phone
            let server = registration.server
            let callID = "reg-\(phone.user)@\(phone.host.ip)"
            let request = "REGISTER sip:\(phone.domain) SIP/2.0\r\nVia: SIP/2.0/UDP \(phone.host.ip):\(phone.host.port);branch=z9hG4bK-reg1\r\nMax-Forwards: 70\r\nFrom: <sip:\(phone.user)@\(phone.domain)>;tag=r1\r\nTo: <sip:\(phone.user)@\(phone.domain)>\r\nCall-ID: \(callID)\r\nCSeq: 1 REGISTER\r\nContact: <sip:\(phone.user)@\(phone.host.ip):\(phone.host.port)>\r\nExpires: 3600\r\nUser-Agent: \(phone.host.userAgent)\r\nContent-Length: 0\r\n\r\n"
            let response = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP \(phone.host.ip):\(phone.host.port);branch=z9hG4bK-reg1\r\nFrom: <sip:\(phone.user)@\(phone.domain)>;tag=r1\r\nTo: <sip:\(phone.user)@\(phone.domain)>;tag=s1\r\nCall-ID: \(callID)\r\nCSeq: 1 REGISTER\r\nContact: <sip:\(phone.user)@\(phone.host.ip):\(phone.host.port)>;expires=3600\r\nServer: \(server.userAgent)\r\nContent-Length: 0\r\n\r\n"
            frames.append(TimedFrame(time: registration.at, bytes: FrameBuilder.udpFrame(source: phone.host.ip, sourcePort: phone.host.port, destination: server.ip, destinationPort: server.port, payload: Array(request.utf8), identification: 7)))
            frames.append(TimedFrame(time: registration.at + 0.011, bytes: FrameBuilder.udpFrame(source: server.ip, sourcePort: server.port, destination: phone.host.ip, destinationPort: phone.host.port, payload: Array(response.utf8), identification: 8)))
        }
        if let noise = backgroundNoise {
            var t = 0.5
            var id: UInt16 = 1
            while t < noise.duration {
                let host = noise.hosts[Int(rng.next() % UInt64(noise.hosts.count))]
                let port = UInt16(49152 + rng.next() % 10000)
                let name = ["pbx.office.lan", "time.apple.com", "updates.vendor.com", "provisioning.office.lan"][Int(rng.next() % 4)]
                var query: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
                for label in name.split(separator: ".") { query.append(UInt8(label.count)); query += Array(label.utf8) }
                query += [0, 0, 1, 0, 1]
                frames.append(TimedFrame(time: t, bytes: FrameBuilder.udpFrame(source: host, sourcePort: port, destination: noise.dnsServer, destinationPort: 53, payload: query, identification: id)))
                var answer = query
                answer[2] = 0x81; answer[3] = 0x80; answer[7] = 1
                answer += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 10, 20, 0, 5]
                frames.append(TimedFrame(time: t + 0.0012, bytes: FrameBuilder.udpFrame(source: noise.dnsServer, sourcePort: 53, destination: host, destinationPort: port, payload: answer, identification: id)))
                t += 5 + Double(rng.next() % 2000) / 100
                id &+= 1
            }
        }
        return frames
    }
}
