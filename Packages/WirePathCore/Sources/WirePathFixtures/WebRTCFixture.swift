import Foundation

extension FixtureCatalog {
    /// `webrtc-session.pcap`, captured on peer A (192.168.1.10) behind a NAT (203.0.113.10).
    ///
    /// Session 1 (SIP-signalled, ICE ufrags aF1x/bY7q): candidate gathering against a STUN server and a TURN server
    /// (Allocate challenged with 401, then allocated), an offer/answer carrying ICE candidates, connectivity checks
    /// where the host→host pair times out, a relayed check through a TURN channel succeeds and the host→srflx pair is
    /// nominated, then a DTLS-SRTP handshake, 3 s of Opus SRTP each way, a consent check and the relay released.
    ///
    /// Session 2 (ufrags cQ3z/dR8w, signalled out of band): the STUN server does not answer, TURN rejects the
    /// credentials and no candidate pair answers, so ICE fails.
    ///
    /// MESSAGE-INTEGRITY values are placeholders — the fixture holds no real credentials.
    static func webrtcSession() throws -> Data {
        typealias P = ProtocolBuilders
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        var frames: [TimedFrame] = []
        var id: UInt16 = 1
        func udp(_ time: Double, _ from: String, _ fromPort: UInt16, _ to: String, _ toPort: UInt16, _ payload: [UInt8]) {
            id &+= 1
            frames.append(TimedFrame(time: time, bytes: FrameBuilder.udpFrame(source: from, sourcePort: fromPort, destination: to,
                                                                              destinationPort: toPort, payload: payload, identification: id)))
        }
        var random = SeededRandom(seed: 0x57EB_4C00)
        func bytes(_ count: Int) -> [UInt8] { (0..<count).map { _ in UInt8(truncatingIfNeeded: random.next()) } }
        var transactionCounter: UInt32 = 0
        func transactionID() -> [UInt8] {
            transactionCounter += 1
            return Array("wpice".utf8) + [0x2D, 0x2D, 0x2D] + P.be32(transactionCounter)
        }

        let a = "192.168.1.10", aPort: UInt16 = 50_000, aPort2: UInt16 = 50_100
        let aNAT = "203.0.113.10", aNATPort: UInt16 = 62_000
        let bHost = "10.0.0.20", bHostPort: UInt16 = 40_000
        let b = "192.0.2.20", bPort: UInt16 = 55_000
        let stunServer = "198.51.100.40", deadSTUN = "198.51.100.41", stunPort: UInt16 = 3478
        let turn = "198.51.100.50", badTURN = "198.51.100.51", relayPort: UInt16 = 49_152
        let proxy = "198.51.100.5"
        let integrity = [UInt8](repeating: 0xA5, count: 20)
        let realm = Array("wirepath.test".utf8), nonce = Array("6f1d2c3b4a5e".utf8)

        func errorCode(_ code: Int, _ reason: String) -> [UInt8] { [0, 0, UInt8(code / 100), UInt8(code % 100)] + Array(reason.utf8) }
        func check(username: String, priority: UInt32, controlling: Bool, useCandidate: Bool = false) -> [(UInt16, [UInt8])] {
            var attributes: [(UInt16, [UInt8])] = [(0x0006, Array(username.utf8)), (0x0024, P.be32(priority)),
                                                   (controlling ? 0x802A : 0x8029, [0x1C, 0x2B, 0x3A, 0x49, 0x58, 0x67, 0x76, 0x85])]
            if useCandidate { attributes.append((0x0025, [])) }
            attributes.append((0x0008, integrity))
            return attributes
        }
        func mapped(_ ip: String, _ port: UInt16) -> [(UInt16, [UInt8])] { [(0x0020, P.xorAddress(ip, port: port)), (0x0008, integrity)] }

        // MARK: Session 1 — gathering
        // Server-reflexive candidate from the STUN server.
        var tx = transactionID()
        udp(0.100, a, aPort, stunServer, stunPort, P.stun(type: 0x0001, transactionID: tx, attributes: [(0x8022, Array("WirePath".utf8))]))
        udp(0.142, stunServer, stunPort, a, aPort, P.stun(type: 0x0101, transactionID: tx,
                                                          attributes: [(0x0020, P.xorAddress(aNAT, port: aNATPort))]))
        // TURN: unauthenticated Allocate challenged, then allocated with credentials.
        tx = transactionID()
        udp(0.150, a, aPort, turn, stunPort, P.stun(type: 0x0003, transactionID: tx, attributes: [(0x0019, [17, 0, 0, 0])]))
        udp(0.188, turn, stunPort, a, aPort, P.stun(type: 0x0113, transactionID: tx, attributes: [
            (0x0009, errorCode(401, "Unauthorized")), (0x0014, realm), (0x0015, nonce)]))
        tx = transactionID()
        udp(0.200, a, aPort, turn, stunPort, P.stun(type: 0x0003, transactionID: tx, attributes: [
            (0x0019, [17, 0, 0, 0]), (0x0006, Array("peer-a".utf8)), (0x0014, realm), (0x0015, nonce), (0x0008, integrity)]))
        udp(0.238, turn, stunPort, a, aPort, P.stun(type: 0x0103, transactionID: tx, attributes: [
            (0x0016, P.xorAddress(turn, port: relayPort)), (0x0020, P.xorAddress(aNAT, port: aNATPort)), (0x000D, P.be32(600)),
            (0x0008, integrity)]))

        // MARK: Session 1 — offer/answer over SIP
        let offer = """
        v=0\r
        o=- 4611731400430051336 2 IN IP4 \(aNAT)\r
        s=-\r
        t=0 0\r
        a=group:BUNDLE 0\r
        a=ice-ufrag:aF1x\r
        a=ice-pwd:fixture-placeholder-pwd-a\r
        a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3E:4F:3E:F3:D0:0F:DC:5E:87:4F:14:7E\r
        a=setup:actpass\r
        m=audio \(aNATPort) UDP/TLS/RTP/SAVPF 111\r
        c=IN IP4 \(aNAT)\r
        a=mid:0\r
        a=rtcp-mux\r
        a=rtpmap:111 opus/48000/2\r
        a=candidate:1 1 udp 2122260223 \(a) \(aPort) typ host generation 0\r
        a=candidate:2 1 udp 1686052607 \(aNAT) \(aNATPort) typ srflx raddr \(a) rport \(aPort) generation 0\r
        a=candidate:3 1 udp 41885439 \(turn) \(relayPort) typ relay raddr \(aNAT) rport \(aNATPort) generation 0\r

        """
        let answer = """
        v=0\r
        o=- 7304829101298374651 2 IN IP4 \(b)\r
        s=-\r
        t=0 0\r
        a=group:BUNDLE 0\r
        a=ice-ufrag:bY7q\r
        a=ice-pwd:fixture-placeholder-pwd-b\r
        a=fingerprint:sha-256 9C:1E:22:F0:73:4B:A8:6D:0E:55:91:C3:7A:2F:B4:68:DE:03:5A:17:C9:84:E2:6B:30:FA:4D:99:12:7E:B5:C0\r
        a=setup:active\r
        m=audio \(bPort) UDP/TLS/RTP/SAVPF 111\r
        c=IN IP4 \(b)\r
        a=mid:0\r
        a=rtcp-mux\r
        a=rtpmap:111 opus/48000/2\r
        a=candidate:1 1 udp 2122260223 \(bHost) \(bHostPort) typ host generation 0\r
        a=candidate:2 1 udp 1686052607 \(b) \(bPort) typ srflx raddr \(bHost) rport \(bHostPort) generation 0\r

        """
        let callID = "webrtc-7f3a91@\(a)"
        func sip(_ time: Double, fromA: Bool, _ startLine: String, cseq: String, toTag: Bool, body: String = "") {
            var text = "\(startLine)\r\nVia: SIP/2.0/UDP \(a):5060;branch=z9hG4bKw\(cseq.filter { $0 != " " })\r\n"
            text += "Max-Forwards: 70\r\nFrom: <sip:alice@\(proxy)>;tag=a71\r\nTo: <sip:bob@\(proxy)>\(toTag ? ";tag=b42" : "")\r\n"
            text += "Call-ID: \(callID)\r\nCSeq: \(cseq)\r\nContact: <sip:alice@\(a):5060>\r\nUser-Agent: WirePath-Fixture\r\n"
            if !body.isEmpty { text += "Content-Type: application/sdp\r\n" }
            text += "Content-Length: \(body.utf8.count)\r\n\r\n\(body)"
            udp(time, fromA ? a : proxy, 5060, fromA ? proxy : a, 5060, Array(text.utf8))
        }
        sip(0.300, fromA: true, "INVITE sip:bob@\(proxy) SIP/2.0", cseq: "1 INVITE", toTag: false, body: offer)
        sip(0.330, fromA: false, "SIP/2.0 100 Trying", cseq: "1 INVITE", toTag: false)
        sip(0.900, fromA: false, "SIP/2.0 180 Ringing", cseq: "1 INVITE", toTag: true)
        sip(2.000, fromA: false, "SIP/2.0 200 OK", cseq: "1 INVITE", toTag: true, body: answer)
        sip(2.010, fromA: true, "ACK sip:bob@\(proxy) SIP/2.0", cseq: "1 ACK", toTag: true)

        // MARK: Session 1 — connectivity checks (A controlling)
        // host → host: B's private address is unreachable; retransmitted, never answered.
        tx = transactionID()
        for delay in [0.0, 0.1, 0.3, 0.7] {
            udp(2.050 + delay, a, aPort, bHost, bHostPort, P.stun(type: 0x0001, transactionID: tx,
                                                                attributes: check(username: "bY7q:aF1x", priority: 2_122_260_223, controlling: true)))
        }
        // host → srflx: answered.
        tx = transactionID()
        udp(2.060, a, aPort, b, bPort, P.stun(type: 0x0001, transactionID: tx,
                                             attributes: check(username: "bY7q:aF1x", priority: 1_845_501_695, controlling: true)))
        udp(2.102, b, bPort, a, aPort, P.stun(type: 0x0101, transactionID: tx, attributes: mapped(aNAT, aNATPort)))
        // B's triggered check towards A (B is controlled).
        tx = transactionID()
        udp(2.070, b, bPort, a, aPort, P.stun(type: 0x0001, transactionID: tx,
                                             attributes: check(username: "aF1x:bY7q", priority: 1_686_052_607, controlling: false)))
        udp(2.071, a, aPort, b, bPort, P.stun(type: 0x0101, transactionID: tx, attributes: mapped(b, bPort)))
        // relay → srflx through a TURN channel: permission, channel binding, then the check inside ChannelData.
        tx = transactionID()
        udp(2.080, a, aPort, turn, stunPort, P.stun(type: 0x0008, transactionID: tx, attributes: [
            (0x0012, P.xorAddress(b, port: bPort)), (0x0006, Array("peer-a".utf8)), (0x0014, realm), (0x0015, nonce), (0x0008, integrity)]))
        udp(2.118, turn, stunPort, a, aPort, P.stun(type: 0x0108, transactionID: tx, attributes: [(0x0008, integrity)]))
        tx = transactionID()
        udp(2.120, a, aPort, turn, stunPort, P.stun(type: 0x0009, transactionID: tx, attributes: [
            (0x000C, [0x40, 0x00, 0, 0]), (0x0012, P.xorAddress(b, port: bPort)), (0x0006, Array("peer-a".utf8)), (0x0014, realm),
            (0x0015, nonce), (0x0008, integrity)]))
        udp(2.158, turn, stunPort, a, aPort, P.stun(type: 0x0109, transactionID: tx, attributes: [(0x0008, integrity)]))
        tx = transactionID()
        let relayedCheck = P.stun(type: 0x0001, transactionID: tx,
                                  attributes: check(username: "bY7q:aF1x", priority: 41_885_439, controlling: true))
        udp(2.170, a, aPort, turn, stunPort, [0x40, 0x00] + P.be16(UInt16(relayedCheck.count)) + relayedCheck)
        let relayedAnswer = P.stun(type: 0x0101, transactionID: tx, attributes: mapped(turn, relayPort))
        udp(2.262, turn, stunPort, a, aPort, [0x40, 0x00] + P.be16(UInt16(relayedAnswer.count)) + relayedAnswer)
        // Nomination on the host → srflx pair.
        tx = transactionID()
        udp(2.300, a, aPort, b, bPort, P.stun(type: 0x0001, transactionID: tx, attributes: check(
            username: "bY7q:aF1x", priority: 1_845_501_695, controlling: true, useCandidate: true)))
        udp(2.341, b, bPort, a, aPort, P.stun(type: 0x0101, transactionID: tx, attributes: mapped(aNAT, aNATPort)))

        // MARK: Session 1 — DTLS 1.2 handshake (B is the DTLS client: a=setup:active)
        var dtlsSequence: [String: UInt64] = [:]
        func dtlsRecord(_ sender: String, type: UInt8, epoch: UInt16, _ body: [UInt8]) -> [UInt8] {
            let sequence = dtlsSequence[sender + "\(epoch)", default: 0]
            dtlsSequence[sender + "\(epoch)"] = sequence + 1
            let seq48 = Array(withUnsafeBytes(of: sequence.bigEndian, Array.init).suffix(6))
            return [type, 0xFE, 0xFD] + P.be16(epoch) + seq48 + P.be16(UInt16(body.count)) + body
        }
        func handshake(_ type: UInt8, messageSequence: UInt16, _ body: [UInt8]) -> [UInt8] {
            let length = Array(P.be32(UInt32(body.count)).suffix(3))
            return [type] + length + P.be16(messageSequence) + [0, 0, 0] + length + body
        }
        let useSRTP: [UInt8] = [0x00, 0x0E, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00]
        let clientHello = P.join([0xFE, 0xFD], bytes(32), [0], [0], P.be16(4), [0xC0, 0x2B, 0xC0, 0x2F], [1, 0],
                                 P.be16(UInt16(useSRTP.count)), useSRTP)
        udp(2.400, b, bPort, a, aPort, dtlsRecord("b", type: 22, epoch: 0, handshake(1, messageSequence: 0, clientHello)))
        let serverHello = P.join([0xFE, 0xFD], bytes(32), [0], [0xC0, 0x2B], [0], P.be16(UInt16(useSRTP.count)), useSRTP)
        udp(2.402, a, aPort, b, bPort, dtlsRecord("a", type: 22, epoch: 0, handshake(2, messageSequence: 0, serverHello))
            + dtlsRecord("a", type: 22, epoch: 0, handshake(14, messageSequence: 1, [])))
        udp(2.445, b, bPort, a, aPort, dtlsRecord("b", type: 22, epoch: 0, handshake(16, messageSequence: 1, [65, 0x04] + bytes(64)))
            + dtlsRecord("b", type: 20, epoch: 0, [1]) + dtlsRecord("b", type: 22, epoch: 1, bytes(40)))
        udp(2.447, a, aPort, b, bPort, dtlsRecord("a", type: 20, epoch: 0, [1]) + dtlsRecord("a", type: 22, epoch: 1, bytes(40)))

        // MARK: Session 1 — SRTP (Opus, 20 ms), both directions on the nominated pair
        let aSSRC: UInt32 = 0x5EB7_A001, bSSRC: UInt32 = 0x5EB7_B002
        for index in 0..<150 {
            let time = 2.500 + Double(index) * 0.020
            let sequence = UInt16(1_000 + index)
            let marker: UInt8 = index == 0 ? 0x80 : 0
            let aHeader: [UInt8] = [0x80, marker | 111] + P.be16(sequence) + P.be32(UInt32(index * 960)) + P.be32(aSSRC)
            udp(time, a, aPort, b, bPort, aHeader + bytes(72 + index % 9) + bytes(10))
            let bHeader: [UInt8] = [0x80, marker | 111] + P.be16(sequence &+ 20_000) + P.be32(UInt32(index * 960 + 12_345)) + P.be32(bSSRC)
            udp(time + 0.043, b, bPort, a, aPort, bHeader + bytes(70 + index % 7) + bytes(10))
        }
        // Consent freshness (RFC 7675) on the selected pair.
        tx = transactionID()
        udp(4.505, a, aPort, b, bPort, P.stun(type: 0x0001, transactionID: tx,
                                             attributes: check(username: "bY7q:aF1x", priority: 1_845_501_695, controlling: true)))
        udp(4.546, b, bPort, a, aPort, P.stun(type: 0x0101, transactionID: tx, attributes: mapped(aNAT, aNATPort)))

        // Hang-up and relay released (Refresh with lifetime 0).
        sip(5.600, fromA: true, "BYE sip:bob@\(proxy) SIP/2.0", cseq: "2 BYE", toTag: true)
        sip(5.640, fromA: false, "SIP/2.0 200 OK", cseq: "2 BYE", toTag: true)
        tx = transactionID()
        udp(5.700, a, aPort, turn, stunPort, P.stun(type: 0x0004, transactionID: tx, attributes: [
            (0x000D, P.be32(0)), (0x0006, Array("peer-a".utf8)), (0x0014, realm), (0x0015, nonce), (0x0008, integrity)]))
        udp(5.738, turn, stunPort, a, aPort, P.stun(type: 0x0104, transactionID: tx, attributes: [(0x000D, P.be32(0)), (0x0008, integrity)]))

        // MARK: Session 2 — everything fails
        // The STUN server never answers (RFC 8489 retransmissions: 0.5 s, then doubling).
        tx = transactionID()
        for delay in [0.0, 0.5, 1.5, 3.5, 7.5] {
            udp(8.000 + delay, a, aPort2, deadSTUN, stunPort, P.stun(type: 0x0001, transactionID: tx, attributes: []))
        }
        // TURN: challenged, then the credentials are rejected.
        tx = transactionID()
        udp(8.010, a, aPort2, badTURN, stunPort, P.stun(type: 0x0003, transactionID: tx, attributes: [(0x0019, [17, 0, 0, 0])]))
        udp(8.051, badTURN, stunPort, a, aPort2, P.stun(type: 0x0113, transactionID: tx, attributes: [
            (0x0009, errorCode(401, "Unauthorized")), (0x0014, realm), (0x0015, nonce)]))
        tx = transactionID()
        udp(8.060, a, aPort2, badTURN, stunPort, P.stun(type: 0x0003, transactionID: tx, attributes: [
            (0x0019, [17, 0, 0, 0]), (0x0006, Array("peer-a".utf8)), (0x0014, realm), (0x0015, nonce), (0x0008, integrity)]))
        udp(8.101, badTURN, stunPort, a, aPort2, P.stun(type: 0x0113, transactionID: tx, attributes: [
            (0x0009, errorCode(401, "Unauthorized")), (0x0014, realm), (0x0015, nonce)]))
        // Checks to both of the remote peer's candidates: no answer.
        for (remote, remotePort, start) in [("10.1.1.99", UInt16(40_100), 8.220), ("192.0.2.99", UInt16(56_000), 8.230)] {
            tx = transactionID()
            for delay in [0.0, 0.1, 0.3, 0.7, 1.5] {
                udp(start + delay, a, aPort2, remote, remotePort, P.stun(type: 0x0001, transactionID: tx,
                                                                      attributes: check(username: "dR8w:cQ3z", priority: 2_122_260_223,
                                                                                        controlling: true)))
            }
        }

        // Unrelated background traffic after the last retransmission, so the capture shows the requests went unanswered.
        udp(17.000, a, 123, "198.51.100.123", 123, [0x23] + [UInt8](repeating: 0, count: 47))

        for frame in frames.sorted(by: { $0.time < $1.time }) { writer.write(frame) }
        writer.close()
        return writer.data
    }
}
