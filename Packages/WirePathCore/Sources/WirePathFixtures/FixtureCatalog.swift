import Foundation

/// The small, purposeful captures kept in `Fixtures/` (regenerate with `wpsamplegen --fixtures Fixtures`).
///
/// Each one exercises a specific part of the engine and is fully deterministic. `sip-call.pcap` is a checked-in
/// simulator capture used by the UI tests and is not regenerated here.
public enum FixtureCatalog {
    public struct Fixture: Sendable {
        public var fileName: String
        public var summary: String
        public var make: @Sendable () throws -> Data
    }

    /// 2026-09-26 12:00:00 UTC.
    public static let baseTime: Double = 1_790_424_000

    public static let all: [Fixture] = [
        Fixture(fileName: "basic-ethernet.pcap",
                summary: "ARP request/reply, ICMP echo, an 802.1Q-tagged UDP datagram, IPv6/UDP and a non-IP (LLDP) frame.",
                make: basicEthernet),
        Fixture(fileName: "ipv4-tcp.pcap",
                summary: "One HTTP-like TCP connection: handshake, data, a segment missing from the capture, duplicate ACKs, "
                    + "a retransmission, an out-of-order segment and FIN teardown.",
                make: ipv4TCP),
        Fixture(fileName: "udp.pcap",
                summary: "DNS queries and answers, NTP, syslog, a plain UDP flow and an IPv4-fragmented datagram.",
                make: udp),
        Fixture(fileName: "application-protocols.pcap",
                summary: "DHCP DORA, DNS SRV/NAPTR, a TCP handshake with options, HTTP, TLS hellos, STUN/ICE binding, "
                    + "TURN allocation with ChannelData, NTP, ICMP port unreachable, ICMPv6 neighbor discovery and a compound RTCP SR.",
                make: applicationProtocols),
        Fixture(fileName: "sip-problems.pcap",
                summary: "SIP diagnostics: rejected credentials, a refused REGISTER, a 200 OK never ACKed, OPTIONS timing out, "
                    + "SUBSCRIBE/MESSAGE errors, a busy call and an unanswered SIP-over-TCP connection.",
                make: sipProblems),
        Fixture(fileName: "rtcp-call.pcap",
                summary: "One RTP stream (G.711 µ-law, 10 s, 5 packets lost) with Sender Reports, Receiver Reports acknowledging "
                    + "them (40 ms round trip), SDES CNAMEs and an RTCP XR VoIP-metrics block (MOS-LQ 3.4).",
                make: rtcpCall),
        Fixture(fileName: "webrtc-session.pcap",
                summary: "Two ICE sessions seen from peer A: one gathers STUN/TURN candidates, checks four candidate pairs (one "
                    + "through a TURN channel), nominates host→srflx, completes DTLS-SRTP and carries Opus both ways; the other "
                    + "fails (STUN server silent, TURN credentials rejected, no pair answers).",
                make: webrtcSession),
        Fixture(fileName: "audio-codecs.pcap",
                summary: "Five SIP calls for audio reconstruction: G.711 µ-law with DTMF keys (RFC 4733), a 100 ms loss and "
                    + "comfort noise (RFC 3389); G.722 carrying a sweep; L16 at 16 kHz; G.729 (licence-restricted, not decoded); "
                    + "and an SRTP call (RTP/SAVP, encrypted).",
                make: audioCodecs),
        Fixture(fileName: "rtp-call.pcap",
                summary: "One answered G.711 A-law call with a loss burst, jitter, reordering and duplicates on the caller's media.",
                make: rtpCall),
        Fixture(fileName: "corrupted-capture.pcap",
                summary: "A pcap whose only record claims more bytes than the file holds (rejected before any packet).",
                make: corruptedCapture),
        Fixture(fileName: "damaged-capture.pcapng",
                summary: "pcapng with capture metadata, two interfaces, sliced packets, truncated headers, a packet comment, "
                    + "interface drop statistics and a damaged final block — analyzable up to the damage.",
                make: damagedCapture),
    ]

    // MARK: basic-ethernet

    static func basicEthernet() throws -> Data {
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        var t = 0.0
        func add(_ bytes: [UInt8], after delay: Double = 0.01) {
            t += delay
            writer.write(TimedFrame(time: t, bytes: bytes))
        }
        add(FrameBuilder.arpFrame(reply: false, senderIP: "10.0.0.10", targetIP: "10.0.0.1"))
        add(FrameBuilder.arpFrame(reply: true, senderIP: "10.0.0.1", targetIP: "10.0.0.10"), after: 0.0004)
        for sequence in UInt16(1)...3 {
            add(FrameBuilder.icmpEchoFrame(source: "10.0.0.10", destination: "10.0.0.1", reply: false, identifier: 0x77, sequence: sequence),
                after: 1)
            add(FrameBuilder.icmpEchoFrame(source: "10.0.0.1", destination: "10.0.0.10", reply: true, identifier: 0x77, sequence: sequence),
                after: 0.0009)
        }
        add(FrameBuilder.udpFrame(source: "10.0.0.10", sourcePort: 5_000, destination: "10.0.0.20", destinationPort: 6_000,
                                  payload: Array("vlan 100 payload".utf8), identification: 40, vlan: 100))
        let v6Source: [UInt8] = [0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]
        let v6Destination: [UInt8] = [0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20]
        add(FrameBuilder.udp6Frame(source: v6Source, sourcePort: 5_001, destination: v6Destination, destinationPort: 6_001,
                                   payload: Array("ipv6 payload".utf8)))
        // LLDP (EtherType 0x88CC): chassis ID, port ID, TTL, end.
        let lldp: [UInt8] = [0x02, 0x07, 0x04, 0x00, 0x1B, 0x21, 0x0A, 0x00, 0x0A, 0x04, 0x03, 0x05, 0x65, 0x30,
                             0x06, 0x02, 0x00, 0x78, 0x00, 0x00]
        add([0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E] + FrameBuilder.mac(for: "10.0.0.10") + [0x88, 0xCC] + lldp
            + [UInt8](repeating: 0, count: 26))
        writer.close()
        return writer.data
    }

    // MARK: ipv4-tcp

    static func ipv4TCP() throws -> Data {
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        let client = "192.168.1.10", server = "192.168.1.20"
        let clientPort: UInt16 = 51_000, serverPort: UInt16 = 80
        var t = 0.0
        var id: UInt16 = 1
        func send(fromClient: Bool, seq: UInt32, ack: UInt32, flags: UInt8, payload: [UInt8] = [], after delay: Double = 0.002) {
            t += delay
            id &+= 1
            let frame = fromClient
                ? FrameBuilder.tcpFrame(source: client, sourcePort: clientPort, destination: server, destinationPort: serverPort,
                                        sequence: seq, acknowledgment: ack, flags: flags, payload: payload, identification: id)
                : FrameBuilder.tcpFrame(source: server, sourcePort: serverPort, destination: client, destinationPort: clientPort,
                                        sequence: seq, acknowledgment: ack, flags: flags, payload: payload, identification: id)
            writer.write(TimedFrame(time: t, bytes: frame))
        }
        let syn: UInt8 = 0x02, ackFlag: UInt8 = 0x10, psh: UInt8 = 0x08, fin: UInt8 = 0x01
        let request = Array("GET /status HTTP/1.1\r\nHost: 192.168.1.20\r\n\r\n".utf8)
        func body(_ index: Int) -> [UInt8] { [UInt8](repeating: UInt8(0x41 + index), count: 100) }

        send(fromClient: true, seq: 1_000, ack: 0, flags: syn)
        send(fromClient: false, seq: 5_000, ack: 1_001, flags: syn | ackFlag)
        send(fromClient: true, seq: 1_001, ack: 5_001, flags: ackFlag)
        let requestEnd = 1_001 + UInt32(request.count)
        send(fromClient: true, seq: 1_001, ack: 5_001, flags: psh | ackFlag, payload: request)
        send(fromClient: false, seq: 5_001, ack: requestEnd, flags: ackFlag)
        send(fromClient: false, seq: 5_001, ack: requestEnd, flags: ackFlag, payload: body(0))        // 5001–5100
        // 5101–5200 is lost before the capture point.
        send(fromClient: false, seq: 5_201, ack: requestEnd, flags: ackFlag, payload: body(2))        // 5201–5300
        send(fromClient: true, seq: requestEnd, ack: 5_101, flags: ackFlag)
        send(fromClient: true, seq: requestEnd, ack: 5_101, flags: ackFlag, after: 0.001)             // duplicate ACK
        send(fromClient: false, seq: 5_101, ack: requestEnd, flags: ackFlag, payload: body(1), after: 0.03)  // retransmission
        send(fromClient: true, seq: requestEnd, ack: 5_301, flags: ackFlag)
        send(fromClient: false, seq: 5_401, ack: requestEnd, flags: ackFlag, payload: body(4))        // arrives before 5301
        send(fromClient: false, seq: 5_301, ack: requestEnd, flags: ackFlag, payload: body(3), after: 0.0005)  // out of order
        send(fromClient: true, seq: requestEnd, ack: 5_501, flags: ackFlag)
        send(fromClient: true, seq: requestEnd, ack: 5_501, flags: fin | ackFlag, after: 0.2)
        send(fromClient: false, seq: 5_501, ack: requestEnd + 1, flags: fin | ackFlag)
        send(fromClient: true, seq: requestEnd + 1, ack: 5_502, flags: ackFlag)
        writer.close()
        return writer.data
    }

    // MARK: udp

    static func udp() throws -> Data {
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        var t = 0.0
        func add(_ bytes: [UInt8], after delay: Double) {
            t += delay
            writer.write(TimedFrame(time: t, bytes: bytes))
        }
        let host = "10.1.0.5", resolver = "10.1.0.53"
        for (index, name) in ["pbx.office.lan", "time.apple.com"].enumerated() {
            let id = UInt16(0x1200 + index)
            add(FrameBuilder.udpFrame(source: host, sourcePort: 53_000 + UInt16(index), destination: resolver, destinationPort: 53,
                                      payload: FrameBuilder.dnsMessage(id: id, name: name), identification: id), after: 0.5)
            add(FrameBuilder.udpFrame(source: resolver, sourcePort: 53, destination: host, destinationPort: 53_000 + UInt16(index),
                                      payload: FrameBuilder.dnsMessage(id: id, name: name, answer: "10.1.0.\(80 + index)"),
                                      identification: id), after: 0.0011)
        }
        // NTP v4 client request and server reply (48 bytes each).
        var ntpRequest = [UInt8](repeating: 0, count: 48)
        ntpRequest[0] = 0x23
        var ntpReply = ntpRequest
        ntpReply[0] = 0x24
        ntpReply[1] = 2
        add(FrameBuilder.udpFrame(source: host, sourcePort: 123, destination: "10.1.0.1", destinationPort: 123,
                                  payload: ntpRequest, identification: 300), after: 0.3)
        add(FrameBuilder.udpFrame(source: "10.1.0.1", sourcePort: 123, destination: host, destinationPort: 123,
                                  payload: ntpReply, identification: 301), after: 0.0008)
        add(FrameBuilder.udpFrame(source: host, sourcePort: 514, destination: "10.1.0.9", destinationPort: 514,
                                  payload: Array("<134>Sep 26 12:00:01 phone-1003 sipd: registered".utf8), identification: 302),
            after: 0.2)
        // A plain request/response UDP flow whose payload does not look like RTP (first byte 0x00).
        for index in 0..<10 {
            let payload = [UInt8(0)] + Array("sensor reading \(index)".utf8)
            add(FrameBuilder.udpFrame(source: host, sourcePort: 40_000, destination: "10.1.0.9", destinationPort: 9_999,
                                      payload: payload, identification: UInt16(400 + index)), after: 0.1)
            add(FrameBuilder.udpFrame(source: "10.1.0.9", sourcePort: 9_999, destination: host, destinationPort: 40_000,
                                      payload: [0, 0x4F, 0x4B], identification: UInt16(500 + index)), after: 0.0004)
        }
        // A 3,000-byte datagram split into IPv4 fragments.
        let big = (0..<3_000).map { UInt8(truncatingIfNeeded: $0 * 7) }
        for fragment in FrameBuilder.fragmentedUDPFrames(source: host, sourcePort: 41_000, destination: "10.1.0.9",
                                                         destinationPort: 9_000, payload: big, identification: 777) {
            add(fragment, after: 0.0001)
        }
        writer.close()
        return writer.data
    }

    // MARK: application-protocols

    static func applicationProtocols() throws -> Data {
        typealias P = ProtocolBuilders
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        var t = 0.0
        var id: UInt16 = 100
        func add(_ bytes: [UInt8], after delay: Double = 0.01) {
            t += delay
            writer.write(TimedFrame(time: t, bytes: bytes))
        }
        func udp(_ source: String, _ sourcePort: UInt16, _ destination: String, _ destinationPort: UInt16, _ payload: [UInt8]) {
            id &+= 1
            add(FrameBuilder.udpFrame(source: source, sourcePort: sourcePort, destination: destination, destinationPort: destinationPort,
                                      payload: payload, identification: id))
        }
        let phone = "10.50.1.30", phoneMAC = FrameBuilder.mac(for: phone), server = "10.50.0.1"

        // DHCP DORA for an IP phone, with the TFTP provisioning server (option 66) and SIP server (option 120).
        let xid: UInt32 = 0x3903_F326
        let request: [(UInt8, [UInt8])] = [(55, [1, 3, 6, 15, 42, 66, 120, 150]), (60, Array("Yealink SIP-T54W".utf8)),
                                            (12, Array("phone-2001".utf8))]
        let lease: [(UInt8, [UInt8])] = [(54, FrameBuilder.ipv4Bytes(server)), (51, P.be32(86_400)), (1, [255, 255, 255, 0]),
                                          (3, FrameBuilder.ipv4Bytes(server)), (6, FrameBuilder.ipv4Bytes("10.50.0.53")),
                                          (66, Array("tftp://10.50.0.10".utf8)), (120, [1] + FrameBuilder.ipv4Bytes("10.50.0.5"))]
        udp("0.0.0.0", 68, "255.255.255.255", 67, P.dhcp(op: 1, messageType: 1, transactionID: xid, clientMAC: phoneMAC, options: request))
        udp(server, 67, "255.255.255.255", 68, P.dhcp(op: 2, messageType: 2, transactionID: xid, clientMAC: phoneMAC, yourIP: phone, options: lease))
        udp("0.0.0.0", 68, "255.255.255.255", 67,
            P.dhcp(op: 1, messageType: 3, transactionID: xid, clientMAC: phoneMAC, options: request + [(50, FrameBuilder.ipv4Bytes(phone))]))
        udp(server, 67, "255.255.255.255", 68, P.dhcp(op: 2, messageType: 5, transactionID: xid, clientMAC: phoneMAC, yourIP: phone, options: lease))

        // DNS: SIP server discovery (NAPTR then SRV).
        udp(phone, 50_000, "10.50.0.53", 53, FrameBuilder.dnsMessage(id: 0x0A01, name: "voice.example.com", type: 35))
        udp(phone, 50_001, "10.50.0.53", 53, FrameBuilder.dnsMessage(id: 0x0A02, name: "_sip._udp.voice.example.com", type: 33))
        udp("10.50.0.53", 53, phone, 50_000, P.dnsResponse(id: 0x0A01, question: "voice.example.com", type: 35, answers: [
            (35, P.naptrData(order: 10, preference: 10, flags: "S", service: "SIP+D2U", replacement: "_sip._udp.voice.example.com")),
        ]))
        udp("10.50.0.53", 53, phone, 50_001, P.dnsResponse(id: 0x0A02, question: "_sip._udp.voice.example.com", type: 33, answers: [
            (33, P.srvData(priority: 10, weight: 60, port: 5060, target: "sbc1.voice.example.com")),
            (33, P.srvData(priority: 20, weight: 40, port: 5060, target: "sbc2.voice.example.com")),
        ]))

        // TCP handshake with options, then HTTP provisioning.
        let web = "10.50.0.10"
        id &+= 1
        add(P.tcpFrame(source: phone, sourcePort: 49_200, destination: web, destinationPort: 80, sequence: 7_000, acknowledgment: 0,
                       flags: 0x02, options: P.synOptions, identification: id))
        id &+= 1
        add(P.tcpFrame(source: web, sourcePort: 80, destination: phone, destinationPort: 49_200, sequence: 9_000, acknowledgment: 7_001,
                       flags: 0x12, options: [2, 4, 0x05, 0xB4, 4, 2, 1, 3, 3, 7], identification: id), after: 0.001)
        let get = Array("GET /cfg/001b2b3201e0.cfg HTTP/1.1\r\nHost: 10.50.0.10\r\nUser-Agent: Yealink SIP-T54W\r\nAccept: */*\r\n\r\n".utf8)
        id &+= 1
        add(FrameBuilder.tcpFrame(source: phone, sourcePort: 49_200, destination: web, destinationPort: 80, sequence: 7_001,
                                  acknowledgment: 9_001, flags: 0x18, payload: get, identification: id), after: 0.001)
        let body = "#!version:1.0.0.1\naccount.1.sip_server.1.address = voice.example.com\n"
        let ok = Array("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)".utf8)
        id &+= 1
        add(FrameBuilder.tcpFrame(source: web, sourcePort: 80, destination: phone, destinationPort: 49_200, sequence: 9_001,
                                  acknowledgment: 7_001 + UInt32(get.count), flags: 0x18, payload: ok, identification: id))

        // TLS to the SBC (SIP over TLS): Client Hello with SNI/ALPN, Server Hello choosing TLS 1.3.
        let sbc = "198.51.100.20"
        id &+= 1
        add(FrameBuilder.tcpFrame(source: phone, sourcePort: 49_300, destination: sbc, destinationPort: 5061, sequence: 1,
                                  acknowledgment: 1, flags: 0x18, payload: P.tlsClientHello(serverName: "sbc1.voice.example.com"),
                                  identification: id))
        id &+= 1
        add(FrameBuilder.tcpFrame(source: sbc, sourcePort: 5061, destination: phone, destinationPort: 49_300, sequence: 1,
                                  acknowledgment: 1, flags: 0x18, payload: P.tlsServerHello(), identification: id), after: 0.02)

        // ICE connectivity check (STUN Binding with ICE attributes) and its response.
        let transaction: [UInt8] = [0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE]
        udp(phone, 50_010, "203.0.113.7", 61_000, P.stun(type: 0x0001, transactionID: transaction, attributes: [
            (0x0006, Array("rT3f:9aJ1".utf8)), (0x0024, P.be32(1_853_817_087)), (0x802A, [0x93, 0x2F, 0xF9, 0xB1, 0x51, 0x26, 0x3B, 0x36]),
            (0x0025, []), (0x0008, [UInt8](repeating: 0xAB, count: 20)),
        ]))
        udp("203.0.113.7", 61_000, phone, 50_010, P.stun(type: 0x0101, transactionID: transaction, attributes: [
            (0x0020, P.xorAddress("192.0.2.44", port: 50_010)), (0x0008, [UInt8](repeating: 0xCD, count: 20)),
        ]))

        // TURN: Allocate challenged (401), authenticated Allocate succeeds, then relayed media via ChannelData.
        let turnServer = "198.51.100.3"
        let allocate: [UInt8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC]
        udp(phone, 50_020, turnServer, 3478, P.stun(type: 0x0003, transactionID: allocate, attributes: [(0x0019, [17, 0, 0, 0])]))
        udp(turnServer, 3478, phone, 50_020, P.stun(type: 0x0113, transactionID: allocate, attributes: [
            (0x0009, [0, 0, 4, 1] + Array("Unauthorized".utf8)), (0x0014, Array("voice.example.com".utf8)), (0x0015, Array("3a4f7c".utf8)),
        ]))
        var second = allocate
        second[11] = 0xCD
        udp(phone, 50_020, turnServer, 3478, P.stun(type: 0x0003, transactionID: second, attributes: [
            (0x0019, [17, 0, 0, 0]), (0x0006, Array("2001".utf8)), (0x0014, Array("voice.example.com".utf8)),
            (0x0015, Array("3a4f7c".utf8)), (0x0008, [UInt8](repeating: 0xEF, count: 20)),
        ]))
        udp(turnServer, 3478, phone, 50_020, P.stun(type: 0x0103, transactionID: second, attributes: [
            (0x0016, P.xorAddress(turnServer, port: 49_152)), (0x0020, P.xorAddress("192.0.2.44", port: 50_020)),
            (0x000D, P.be32(600)), (0x0008, [UInt8](repeating: 0x12, count: 20)),
        ]))
        let rtp: [UInt8] = [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 160, 0xDE, 0xAD, 0xBE, 0xEF] + [UInt8](repeating: 0xFF, count: 160)
        udp(phone, 50_020, turnServer, 3478, [0x40, 0x00] + P.be16(UInt16(rtp.count)) + rtp)

        // NTP, an ICMP port unreachable quoting a SIP datagram, IPv6 neighbor discovery, and a compound RTCP report.
        var ntp = [UInt8](repeating: 0, count: 48)
        ntp[0] = 0x23
        udp(phone, 123, "10.50.0.1", 123, ntp)
        let quoted = FrameBuilder.udpFrame(source: phone, sourcePort: 5060, destination: "10.50.0.99", destinationPort: 5060,
                                           payload: Array("OPTIONS sip:10.50.0.99 SIP/2.0\r\n".utf8), identification: 999)
        let original = Array(quoted[14..<(14 + 28)])
        var unreachable: [UInt8] = [3, 3, 0, 0, 0, 0, 0, 0] + original
        let sum = FrameBuilder.checksum(unreachable)
        unreachable[2] = UInt8(sum >> 8)
        unreachable[3] = UInt8(sum & 0xFF)
        let icmpIP = FrameBuilder.ipv4Header(source: "10.50.0.99", destination: phone, protocolNumber: 1,
                                             payloadLength: unreachable.count, identification: 5)
        add(FrameBuilder.ethernet(source: "10.50.0.99", destination: phone, etherType: 0x0800, payload: icmpIP + unreachable))
        let v6Phone: [UInt8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1B, 0x21, 0xFF, 0xFE, 0, 0, 0x10]
        let v6Gateway: [UInt8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1B, 0x21, 0xFF, 0xFE, 0, 0, 0x20]
        let solicited: [UInt8] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0, 0, 0x20]
        let ns: [UInt8] = [135, 0, 0, 0, 0, 0, 0, 0] + v6Gateway + [1, 1, 0x00, 0x1B, 0x21, 0, 0, 0x10]
        add(P.icmpv6Frame(source: v6Phone, destination: solicited, message: ns))
        let na: [UInt8] = [136, 0, 0, 0, 0x60, 0, 0, 0] + v6Gateway + [2, 1, 0x00, 0x1B, 0x21, 0, 0, 0x20]
        add(P.icmpv6Frame(source: v6Gateway, destination: v6Phone, message: na))
        udp(phone, 40_001, "10.50.0.5", 30_001, P.rtcpSenderReport(
            ssrc: 0x1A2B_3C4D, reportee: 0x5E6F_7081, cname: "2001@10.50.1.30", ntpSeconds: 3_968_000_000, rtpTimestamp: 160_000,
            packets: 1_000, octets: 160_000, fractionLost: 13, cumulativeLost: 52, highestSequence: 1_052, jitter: 88))
        writer.close()
        return writer.data
    }

    // MARK: sip-problems

    static func sipProblems() throws -> Data {
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        let phone = "10.60.1.40", pbx = "10.60.0.5", deadServer = "10.60.0.99", peer = "10.60.1.41"
        var id: UInt16 = 1
        func send(_ time: Double, _ from: String, _ to: String, _ text: String) {
            id &+= 1
            writer.write(TimedFrame(time: time, bytes: FrameBuilder.udpFrame(source: from, sourcePort: 5060, destination: to,
                                                                             destinationPort: 5060, payload: Array(text.utf8),
                                                                             identification: id)))
        }
        func request(_ method: String, uri: String, callID: String, cseq: Int, from: String, fromUser: String, to: String,
                     toUser: String, branch: String, extra: String = "") -> String {
            "\(method) \(uri) SIP/2.0\r\nVia: SIP/2.0/UDP \(from):5060;branch=z9hG4bK\(branch)\r\nMax-Forwards: 70\r\n"
                + "From: <sip:\(fromUser)@\(pbx)>;tag=f\(branch)\r\nTo: <sip:\(toUser)@\(pbx)>\r\nCall-ID: \(callID)\r\n"
                + "CSeq: \(cseq) \(method)\r\n\(extra)User-Agent: WirePath-Fixture\r\nContent-Length: 0\r\n\r\n"
        }
        func response(_ code: Int, _ reason: String, method: String, callID: String, cseq: Int, from: String, fromUser: String,
                      toUser: String, branch: String, toTag: String = "t1", extra: String = "") -> String {
            "SIP/2.0 \(code) \(reason)\r\nVia: SIP/2.0/UDP \(from):5060;branch=z9hG4bK\(branch)\r\n"
                + "From: <sip:\(fromUser)@\(pbx)>;tag=f\(branch)\r\nTo: <sip:\(toUser)@\(pbx)>;tag=\(toTag)\r\nCall-ID: \(callID)\r\n"
                + "CSeq: \(cseq) \(method)\r\n\(extra)Content-Length: 0\r\n\r\n"
        }
        let challenge = "WWW-Authenticate: Digest realm=\"pbx\", nonce=\"4f1b\", algorithm=MD5\r\n"
        let credentials = "Authorization: Digest username=\"2001\", realm=\"pbx\", nonce=\"4f1b\", uri=\"sip:\(pbx)\", response=\"00ff\"\r\n"

        // 1. REGISTER challenged, retried with credentials, rejected again (wrong password).
        send(0.10, phone, pbx, request("REGISTER", uri: "sip:\(pbx)", callID: "reg-2001", cseq: 1, from: phone, fromUser: "2001",
                                       to: pbx, toUser: "2001", branch: "r1"))
        send(0.12, pbx, phone, response(401, "Unauthorized", method: "REGISTER", callID: "reg-2001", cseq: 1, from: phone,
                                        fromUser: "2001", toUser: "2001", branch: "r1", extra: challenge))
        send(0.14, phone, pbx, request("REGISTER", uri: "sip:\(pbx)", callID: "reg-2001", cseq: 2, from: phone, fromUser: "2001",
                                       to: pbx, toUser: "2001", branch: "r2", extra: credentials))
        send(0.16, pbx, phone, response(401, "Unauthorized", method: "REGISTER", callID: "reg-2001", cseq: 2, from: phone,
                                        fromUser: "2001", toUser: "2001", branch: "r2", extra: challenge))
        // 2. REGISTER refused outright.
        send(0.30, peer, pbx, request("REGISTER", uri: "sip:\(pbx)", callID: "reg-2002", cseq: 1, from: peer, fromUser: "2002",
                                      to: pbx, toUser: "2002", branch: "r3"))
        send(0.32, pbx, peer, response(403, "Forbidden", method: "REGISTER", callID: "reg-2002", cseq: 1, from: peer,
                                       fromUser: "2002", toUser: "2002", branch: "r3"))
        // 3. INVITE answered, 200 OK retransmitted (T1 doubling), never ACKed.
        send(1.00, phone, pbx, request("INVITE", uri: "sip:2003@\(pbx)", callID: "call-noack", cseq: 1, from: phone, fromUser: "2001",
                                       to: pbx, toUser: "2003", branch: "i1", extra: "Contact: <sip:2001@\(phone)>\r\n"))
        send(1.02, pbx, phone, response(100, "Trying", method: "INVITE", callID: "call-noack", cseq: 1, from: phone, fromUser: "2001",
                                        toUser: "2003", branch: "i1"))
        for delay in [0.0, 0.5, 1.5, 3.5] {
            send(2.00 + delay, pbx, phone, response(200, "OK", method: "INVITE", callID: "call-noack", cseq: 1, from: phone,
                                                    fromUser: "2001", toUser: "2003", branch: "i1", toTag: "ok",
                                                    extra: "Contact: <sip:2003@\(pbx)>\r\n"))
        }
        // 4. OPTIONS to a server that never answers (the capture continues well past Timer F).
        for (index, time) in [5.0, 5.5, 6.5].enumerated() {
            send(time, pbx, deadServer, request("OPTIONS", uri: "sip:\(deadServer)", callID: "ka-99", cseq: index + 1, from: pbx,
                                                fromUser: "pbx", to: deadServer, toUser: "ping", branch: "o\(index)"))
        }
        // 5. SUBSCRIBE and MESSAGE errors.
        send(8.0, phone, pbx, request("SUBSCRIBE", uri: "sip:2003@\(pbx)", callID: "sub-1", cseq: 1, from: phone, fromUser: "2001",
                                      to: pbx, toUser: "2003", branch: "s1", extra: "Event: dialog-bogus\r\n"))
        send(8.02, pbx, phone, response(489, "Bad Event", method: "SUBSCRIBE", callID: "sub-1", cseq: 1, from: phone,
                                        fromUser: "2001", toUser: "2003", branch: "s1"))
        send(9.0, phone, pbx, request("MESSAGE", uri: "sip:2003@\(pbx)", callID: "msg-1", cseq: 1, from: phone, fromUser: "2001",
                                      to: pbx, toUser: "2003", branch: "m1"))
        send(9.03, pbx, phone, response(503, "Service Unavailable", method: "MESSAGE", callID: "msg-1", cseq: 1, from: phone,
                                        fromUser: "2001", toUser: "2003", branch: "m1"))
        // 6. A busy call, properly ACKed (a call outcome, not a signalling problem).
        send(10.0, phone, pbx, request("INVITE", uri: "sip:2004@\(pbx)", callID: "call-busy", cseq: 1, from: phone, fromUser: "2001",
                                       to: pbx, toUser: "2004", branch: "b1"))
        send(10.3, pbx, phone, response(486, "Busy Here", method: "INVITE", callID: "call-busy", cseq: 1, from: phone,
                                        fromUser: "2001", toUser: "2004", branch: "b1"))
        send(10.31, phone, pbx, request("ACK", uri: "sip:2004@\(pbx)", callID: "call-busy", cseq: 1, from: phone, fromUser: "2001",
                                        to: pbx, toUser: "2004", branch: "b1"))
        // 7. SIP over TCP to a server that does not answer the SYN (retried once).
        for (index, time) in [11.0, 12.0].enumerated() {
            id &+= 1
            writer.write(TimedFrame(time: time, bytes: ProtocolBuilders.tcpFrame(
                source: phone, sourcePort: 49_500, destination: "10.60.0.6", destinationPort: 5060, sequence: 77_000,
                acknowledgment: 0, flags: 0x02, options: ProtocolBuilders.synOptions, identification: id + UInt16(index))))
        }
        // Keep the capture running past Timer B/F for the OPTIONS and the unacknowledged 200 OK.
        send(45.0, pbx, phone, request("OPTIONS", uri: "sip:\(phone)", callID: "ka-40", cseq: 1, from: pbx, fromUser: "pbx",
                                       to: phone, toUser: "ping", branch: "k1"))
        send(45.01, phone, pbx, response(200, "OK", method: "OPTIONS", callID: "ka-40", cseq: 1, from: pbx, fromUser: "pbx",
                                         toUser: "ping", branch: "k1"))
        writer.close()
        return writer.data
    }

    // MARK: rtcp-call

    static func rtcpCall() throws -> Data {
        typealias P = ProtocolBuilders
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: baseTime)
        let sender = "10.70.1.10", receiver = "10.70.1.20"
        let senderSSRC: UInt32 = 0x1111_2222, receiverSSRC: UInt32 = 0x3333_4444
        let oneWay = 0.020  // capture point is at the sender; the receiver is 20 ms away
        var frames: [TimedFrame] = []
        var id: UInt16 = 1
        func udp(_ time: Double, _ from: String, _ fromPort: UInt16, _ to: String, _ toPort: UInt16, _ payload: [UInt8]) {
            id &+= 1
            frames.append(TimedFrame(time: time, bytes: FrameBuilder.udpFrame(source: from, sourcePort: fromPort, destination: to,
                                                                              destinationPort: toPort, payload: payload, identification: id)))
        }
        func ntp(_ time: Double) -> (seconds: UInt32, fraction: UInt32) {
            let absolute = baseTime + time + 2_208_988_800
            let seconds = floor(absolute)
            return (UInt32(seconds), UInt32((absolute - seconds) * 4_294_967_296))
        }
        let lostSequences = Set(100..<105)
        var sent = 0, octets = 0
        var lastSR: (time: Double, middle: UInt32)?
        var receivedTotal = 0, expectedAtLastReport = 0, receivedAtLastReport = 0
        for index in 0..<500 {
            let time = 1.0 + Double(index) * 0.020
            let sequence = UInt16(index + 1)
            sent += 1
            octets += 160
            if !lostSequences.contains(index) {
                let header: [UInt8] = [0x80, 0x00] + P.be16(sequence) + P.be32(UInt32(index * 160)) + P.be32(senderSSRC)
                udp(time, sender, 40_000, receiver, 40_002, header + [UInt8](repeating: 0xFF, count: 160))
                receivedTotal += 1
            }
            // Every 2 s: the sender's SR (+ CNAME), then 50 ms later the receiver's RR acknowledging it.
            if index % 100 == 99 {
                let srTime = time + 0.005
                let stamp = ntp(srTime)
                udp(srTime, sender, 40_001, receiver, 40_003, P.rtcpSenderReport(
                    ssrc: senderSSRC, reportee: receiverSSRC, cname: "sender@\(sender)", ntpSeconds: stamp.seconds,
                    ntpFraction: stamp.fraction, rtpTimestamp: UInt32(index * 160), packets: UInt32(sent), octets: UInt32(octets), fractionLost: 0,
                    cumulativeLost: 0, highestSequence: 0, jitter: 0))
                lastSR = (srTime, (stamp.seconds & 0xFFFF) << 16 | stamp.fraction >> 16)
                // The receiver holds the SR for 50 ms before its RR: DLSR = 50 ms, so round trip = 2 × 20 ms.
                let rrSent = srTime + oneWay + 0.050
                let expected = index + 1
                let intervalExpected = expected - expectedAtLastReport
                let intervalLost = intervalExpected - (receivedTotal - receivedAtLastReport)
                expectedAtLastReport = expected
                receivedAtLastReport = receivedTotal
                let fraction = UInt8(min(255, intervalLost * 256 / max(1, intervalExpected)))
                var block = P.be32(senderSSRC) + [fraction] + Array(P.be32(UInt32(expected - receivedTotal)).suffix(3))
                block += P.be32(UInt32(expected)) + P.be32(12) + P.be32(lastSR?.middle ?? 0) + P.be32(UInt32(0.050 * 65_536))
                var compound: [UInt8] = [0x81, 201] + P.be16(7) + P.be32(receiverSSRC) + block
                var chunk: [UInt8] = P.be32(receiverSSRC) + [1, UInt8("receiver@\(receiver)".utf8.count)] + Array("receiver@\(receiver)".utf8) + [0]
                while chunk.count % 4 != 0 { chunk.append(0) }
                compound += [0x81, 202] + P.be16(UInt16(chunk.count / 4)) + chunk
                if index == 499 {
                    // RFC 3611 VoIP metrics (block type 7): loss 1 %, R 65, MOS-LQ 3.4, MOS-CQ 3.5, JB 40/80 ms.
                    var metrics: [UInt8] = [7, 0] + P.be16(8) + P.be32(senderSSRC) + [3, 0, 0, 0] + P.be16(0) + P.be16(0)
                    metrics += P.be16(40) + P.be16(30) + [127, 127, 127, 127] + [65, 127, 34, 35] + [0, 0] + P.be16(40) + P.be16(80) + P.be16(120)
                    compound += [0x80, 207] + P.be16(UInt16((8 + metrics.count) / 4 - 1)) + P.be32(receiverSSRC) + metrics
                }
                udp(rrSent + oneWay, receiver, 40_003, sender, 40_001, compound)
            }
        }
        for frame in frames.sorted(by: { $0.time < $1.time }) { writer.write(frame) }
        writer.close()
        return writer.data
    }

    // MARK: rtp-call

    static func rtpCall() throws -> Data {
        let server = SimHost("10.30.0.5", userAgent: "WirePath-PBX/3.2")
        let caller = SimParty("2001", "Mesa de ayuda", host: SimHost("10.30.1.21", userAgent: "Yealink SIP-T54W 96.86.0.70"))
        let callee = SimParty("2002", "Operaciones", host: SimHost("10.30.1.22", userAgent: "Poly VVX 450 6.4.3"))
        let impaired = SimImpairment(baseDelayMs: 12, jitterMs: 6, randomLoss: 0.01,
                                     lossWindows: [SimLossWindow(start: 6, end: 7.5, probability: 0.45)],
                                     spikes: [SimSpike(time: 10, amplitudeMs: 80, width: 0.6)],
                                     reorderProbability: 0.005, duplicateProbability: 0.002)
        let call = SimCall(start: 1, caller: caller, callee: callee, topology: .proxy(server),
                           outcome: .answered(talk: 16, hangupByCaller: true), codec: .pcma,
                           forward: impaired, reverse: SimImpairment(jitterMs: 1.2), seed: 2_002)
        return try SimCapture(baseTime: baseTime, calls: [call]).write()
    }

    // MARK: corrupted-capture

    static func corruptedCapture() throws -> Data {
        var data = Data()
        func le32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
        func le16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
        le32(0xA1B2_C3D4); le16(2); le16(4); le32(0); le32(0); le32(262_144); le32(1)
        le32(1_790_437_335); le32(0); le32(713); le32(713)
        data.append(contentsOf: Array("garbage-after-header".utf8))
        return data
    }

    // MARK: damaged-capture

    static func damagedCapture() throws -> Data {
        typealias W = PCAPNGBlockWriter
        var w = W()
        w.sectionHeader(options: W.option(2, "MacBook Pro (Mac16,8)") + W.option(3, "macOS 27.0") + W.option(4, "tcpdump 4.99.5")
                        + W.option(1, "Lab capture: branch office uplink, snap length 96") + W.endOfOptions)
        w.interface(linkType: 1, snapLength: 96, options: W.option(2, "en0") + W.option(3, "Ethernet uplink")
                    + W.option(9, [6]) + W.endOfOptions)
        w.interface(linkType: 101, snapLength: 65_535, options: W.option(2, "utun3") + W.option(9, [9]) + W.endOfOptions)

        let base = UInt64(baseTime * 1_000_000)
        let options = Array("OPTIONS sip:10.40.0.5 SIP/2.0\r\nVia: SIP/2.0/UDP 10.40.1.10:5060;branch=z9hG4bK-1\r\nFrom: <sip:probe@10.40.1.10>;tag=1\r\nTo: <sip:10.40.0.5>\r\nCall-ID: probe-1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n".utf8)
        let sipFrame = FrameBuilder.udpFrame(source: "10.40.1.10", sourcePort: 5_060, destination: "10.40.0.5", destinationPort: 5_060,
                                             payload: options, identification: 1)
        // 1. Sliced to the 96-byte snapshot length.
        w.enhancedPacket(interface: 0, timestamp: base, packet: Array(sipFrame.prefix(96)), originalLength: sipFrame.count)
        // 2. A TCP segment cut inside its header.
        let tcp = FrameBuilder.tcpFrame(source: "10.40.1.10", sourcePort: 51_500, destination: "10.40.0.5", destinationPort: 5_061,
                                        sequence: 1, flags: 0x02, payload: [], identification: 2)
        var cutTCP = Array(tcp.prefix(14 + 20 + 8))
        cutTCP[16] = 0; cutTCP[17] = 28  // IPv4 total length matches what was captured
        w.enhancedPacket(interface: 0, timestamp: base + 10_000, packet: cutTCP)
        // 3. A runt frame shorter than an Ethernet header.
        w.enhancedPacket(interface: 0, timestamp: base + 20_000, packet: [0x00, 0x1B, 0x21, 0x0A, 0x28, 0x00])
        // 4. A DNS query with a comment from the analyst.
        let dns = FrameBuilder.udpFrame(source: "10.40.1.10", sourcePort: 53_531, destination: "10.40.0.53", destinationPort: 53,
                                        payload: FrameBuilder.dnsMessage(id: 9, name: "pbx.branch.lan"), identification: 3)
        w.enhancedPacket(interface: 0, timestamp: base + 30_000, packet: dns,
                         options: W.option(1, "Resolver answered only after 2 s") + W.endOfOptions)
        // 5. Raw IPv4 on the tunnel interface (nanosecond timestamps).
        let ping = FrameBuilder.icmpEchoFrame(source: "10.99.0.2", destination: "10.99.0.1", reply: false, identifier: 1, sequence: 1)
        w.enhancedPacket(interface: 1, timestamp: UInt64(baseTime * 1e9) + 40_000_000, packet: Array(ping.dropFirst(14)))
        // 6. Statistics: the capture tool dropped packets on en0.
        w.interfaceStatistics(interface: 0, options: W.option(4, W.le64(412)) + W.option(5, W.le64(12)) + W.option(7, W.le64(3))
                              + W.endOfOptions)
        // 7. A final block whose trailing length disagrees with its header.
        w.block(6, [UInt8](repeating: 0x5A, count: 40), trailingLength: 7)
        return w.data
    }
}
