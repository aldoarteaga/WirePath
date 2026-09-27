import Foundation

/// Streams a large, realistic capture straight to disk for benchmarks: concurrent SIP calls with G.711 RTP both ways
/// (RTCP every 5 s), short TCP connections (HTTP-like request/response with handshake and teardown), DNS lookups
/// and one-off UDP datagrams (many small flows). Deterministic for a given configuration. Memory use is constant:
/// frames are written as they are generated.
public struct LargeCaptureGenerator: Sendable {
    public struct Configuration: Sendable {
        /// Stop once this many packets were written.
        public var packets: Int
        /// Calls in progress at any time (each is two 50 packet/s RTP streams).
        public var concurrentCalls: Int
        public var callSeconds: Double
        /// New TCP connections per second (each ~10 packets).
        public var tcpConnectionsPerSecond: Int
        /// DNS queries (and answers) per second.
        public var dnsPerSecond: Int
        /// One-off UDP datagrams per second, each on a new flow.
        public var udpFlowsPerSecond: Int
        /// Probability that an RTP packet is lost (5-tuple and sequence gaps for the analyzers).
        public var rtpLoss: Double
        public var seed: UInt64

        public init(packets: Int, concurrentCalls: Int = 200, callSeconds: Double = 90, tcpConnectionsPerSecond: Int = 40,
                    dnsPerSecond: Int = 30, udpFlowsPerSecond: Int = 20, rtpLoss: Double = 0.002, seed: UInt64 = 1) {
            self.packets = packets
            self.concurrentCalls = concurrentCalls
            self.callSeconds = callSeconds
            self.tcpConnectionsPerSecond = tcpConnectionsPerSecond
            self.dnsPerSecond = dnsPerSecond
            self.udpFlowsPerSecond = udpFlowsPerSecond
            self.rtpLoss = rtpLoss
            self.seed = seed
        }
    }

    public struct Summary: Sendable {
        public var packets = 0
        public var bytes: Int64 = 0
        public var calls = 0
        public var rtpPackets = 0
        public var tcpConnections = 0
        public var seconds = 0.0
    }

    public var configuration: Configuration

    public init(_ configuration: Configuration) {
        self.configuration = configuration
    }

    private struct Call {
        var number: Int
        var caller: String, callee: String
        var callerPort: UInt16, calleePort: UInt16
        var start: Double
        var end: Double
        var ssrc: (UInt32, UInt32)
        var sequence: (UInt16, UInt16)
        var timestamp: (UInt32, UInt32)
        var established = false
        var nextRTCP: Double
    }

    /// Writes the capture to `url`. `progress` receives the packets written so far.
    @discardableResult
    public func write(to url: URL, progress: ((Int) -> Void)? = nil) throws -> Summary {
        let config = configuration
        let writer = try CaptureWriter(format: .pcap(nanosecond: false, bigEndian: false), baseTime: FixtureCatalog.baseTime, url: url)
        var random = SeededRandom(seed: config.seed)
        var summary = Summary()
        let pbx = "10.100.0.5"
        let silence = [UInt8](repeating: 0xFF, count: 160)
        var ipID: UInt16 = 0

        let tickSeconds = 0.02
        // Frames are generated up to a second ahead; they wait in per-tick buckets so the file is in time order.
        var buckets: [Int: [TimedFrame]] = [:]
        func emit(_ time: Double, _ frame: [UInt8]) {
            buckets[Int(time / tickSeconds), default: []].append(TimedFrame(time: time, bytes: frame))
        }
        func flush(through tick: Int) {
            for key in buckets.keys.filter({ $0 <= tick }).sorted() {
                for frame in (buckets.removeValue(forKey: key) ?? []).sorted(by: { $0.time < $1.time }) {
                    writer.write(frame)
                    summary.packets += 1
                    summary.bytes += Int64(frame.bytes.count)
                    if summary.packets % 100_000 == 0 { progress?(summary.packets) }
                }
            }
        }
        func udp(_ time: Double, _ from: String, _ fromPort: UInt16, _ to: String, _ toPort: UInt16, _ payload: [UInt8]) {
            ipID &+= 1
            emit(time, FrameBuilder.udpFrame(source: from, sourcePort: fromPort, destination: to, destinationPort: toPort,
                                             payload: payload, identification: ipID))
        }
        func host(_ index: Int, net: Int = 1) -> String { "10.100.\(net + (index / 250) % 50).\(1 + index % 250)" }

        func sip(_ time: Double, _ call: Call, _ first: String, cseq: String, fromCaller: Bool, sdp: Bool) {
            let callID = "bench-\(call.number)@\(pbx)"
            var body = ""
            if sdp {
                let address = fromCaller ? call.caller : call.callee
                let port = fromCaller ? call.callerPort : call.calleePort
                body = "v=0\r\no=- \(call.number) 1 IN IP4 \(address)\r\ns=-\r\nc=IN IP4 \(address)\r\nt=0 0\r\n"
                    + "m=audio \(port) RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n"
            }
            var text = "\(first)\r\nVia: SIP/2.0/UDP \(fromCaller ? call.caller : call.callee):5060;branch=z9hG4bK\(call.number)\(cseq.filter(\.isNumber))\r\n"
            text += "From: <sip:\(1000 + call.number % 9000)@\(pbx)>;tag=a\(call.number)\r\nTo: <sip:\(2000 + call.number % 7000)@\(pbx)>"
            text += first.hasPrefix("INVITE") ? "\r\n" : ";tag=b\(call.number)\r\n"
            text += "Call-ID: \(callID)\r\nCSeq: \(cseq)\r\nMax-Forwards: 70\r\nUser-Agent: WirePath-Bench\r\n"
            if sdp { text += "Content-Type: application/sdp\r\n" }
            text += "Content-Length: \(body.utf8.count)\r\n\r\n" + body
            let endpoint = fromCaller ? call.caller : call.callee
            udp(time, fromCaller ? endpoint : pbx, 5060, fromCaller ? pbx : endpoint, 5060, Array(text.utf8))
        }

        var calls: [Call] = []
        var callCounter = 0
        func newCall(at time: Double) -> Call {
            callCounter += 1
            let n = callCounter
            let duration = config.callSeconds * (0.5 + random.uniform())
            return Call(number: n, caller: host(2 * n), callee: host(2 * n + 1), callerPort: UInt16(20_000 + (2 * n) % 20_000 & ~1),
                        calleePort: UInt16(20_000 + (2 * n + 1) % 20_000 & ~1), start: time, end: time + duration,
                        ssrc: (UInt32(truncatingIfNeeded: random.next()), UInt32(truncatingIfNeeded: random.next())),
                        sequence: (UInt16(truncatingIfNeeded: random.next()), UInt16(truncatingIfNeeded: random.next())),
                        timestamp: (UInt32(truncatingIfNeeded: random.next()), UInt32(truncatingIfNeeded: random.next())),
                        nextRTCP: time + 5)
        }
        // Stagger the initial calls over the first seconds.
        for index in 0..<config.concurrentCalls { calls.append(newCall(at: Double(index) * 2.0 / Double(max(1, config.concurrentCalls)))) }
        summary.calls = calls.count

        var tcpCounter = 0, dnsCounter = 0, udpCounter = 0
        var tick = 0
        while summary.packets < config.packets {
            let now = Double(tick) * tickSeconds
            tick += 1
            for index in calls.indices {
                var call = calls[index]
                if !call.established, now >= call.start {
                    call.start = now
                    sip(call.start, call, "INVITE sip:\(call.callee) SIP/2.0", cseq: "1 INVITE", fromCaller: true, sdp: true)
                    sip(call.start + 0.003, call, "SIP/2.0 100 Trying", cseq: "1 INVITE", fromCaller: false, sdp: false)
                    sip(call.start + 0.010, call, "SIP/2.0 200 OK", cseq: "1 INVITE", fromCaller: false, sdp: true)
                    sip(call.start + 0.012, call, "ACK sip:\(call.callee) SIP/2.0", cseq: "1 ACK", fromCaller: true, sdp: false)
                    call.established = true
                }
                guard call.established else { continue }
                if now >= call.end {
                    sip(now, call, "BYE sip:\(call.callee) SIP/2.0", cseq: "2 BYE", fromCaller: true, sdp: false)
                    sip(now + 0.004, call, "SIP/2.0 200 OK", cseq: "2 BYE", fromCaller: false, sdp: false)
                    call = newCall(at: now + 0.05)
                    summary.calls += 1
                    calls[index] = call
                    continue
                }
                let jitter = random.uniform() * 0.002
                for direction in 0..<2 {
                    let sequence = direction == 0 ? call.sequence.0 : call.sequence.1
                    let timestamp = direction == 0 ? call.timestamp.0 : call.timestamp.1
                    let ssrc = direction == 0 ? call.ssrc.0 : call.ssrc.1
                    if !random.chance(config.rtpLoss) {
                        let header: [UInt8] = [0x80, 0, UInt8(sequence >> 8), UInt8(sequence & 0xFF),
                                               UInt8(timestamp >> 24), UInt8((timestamp >> 16) & 0xFF), UInt8((timestamp >> 8) & 0xFF),
                                               UInt8(timestamp & 0xFF), UInt8(ssrc >> 24), UInt8((ssrc >> 16) & 0xFF),
                                               UInt8((ssrc >> 8) & 0xFF), UInt8(ssrc & 0xFF)]
                        let (from, fromPort, to, toPort) = direction == 0 ? (call.caller, call.callerPort, call.callee, call.calleePort)
                            : (call.callee, call.calleePort, call.caller, call.callerPort)
                        udp(now + jitter + Double(direction) * 0.0005, from, fromPort, to, toPort, header + silence)
                        summary.rtpPackets += 1
                    }
                    if direction == 0 {
                        call.sequence.0 &+= 1; call.timestamp.0 &+= 160
                    } else {
                        call.sequence.1 &+= 1; call.timestamp.1 &+= 160
                    }
                }
                if now >= call.nextRTCP {
                    call.nextRTCP = now + 5
                    let report = ProtocolBuilders.rtcpSenderReport(ssrc: call.ssrc.0, reportee: call.ssrc.1, cname: "bench@\(call.caller)",
                                                                   ntpSeconds: UInt32(3_999_000_000 + UInt32(now)), rtpTimestamp: call.timestamp.0,
                                                                   packets: 250, octets: 40_000, fractionLost: 0, cumulativeLost: 0,
                                                                   highestSequence: UInt32(call.sequence.1), jitter: 8)
                    udp(now + 0.001, call.caller, call.callerPort + 1, call.callee, call.calleePort + 1, report)
                }
                calls[index] = call
            }

            // Background traffic, spread over the second.
            if tick % 50 == 0 {
                for _ in 0..<config.tcpConnectionsPerSecond {
                    tcpCounter += 1
                    let client = host(tcpCounter % 5000, net: 60), server = "10.200.\(tcpCounter % 7).\(10 + tcpCounter % 40)"
                    let port = UInt16(30_000 + tcpCounter % 30_000)
                    let t = now + random.uniform()
                    let request = Array("GET /api/v1/items/\(tcpCounter) HTTP/1.1\r\nHost: \(server)\r\n\r\n".utf8)
                    let response = Array("HTTP/1.1 200 OK\r\nContent-Length: 600\r\n\r\n".utf8) + [UInt8](repeating: 0x41, count: 600)
                    let isn: UInt32 = UInt32(truncatingIfNeeded: random.next()), isr: UInt32 = UInt32(truncatingIfNeeded: random.next())
                    let steps: [(Double, Bool, UInt32, UInt32, UInt8, [UInt8])] = [
                        (0, true, isn, 0, 0x02, []), (0.0010, false, isr, isn &+ 1, 0x12, []), (0.0012, true, isn &+ 1, isr &+ 1, 0x10, []),
                        (0.0014, true, isn &+ 1, isr &+ 1, 0x18, request),
                        (0.0030, false, isr &+ 1, isn &+ 1 &+ UInt32(request.count), 0x18, response),
                        (0.0032, true, isn &+ 1 &+ UInt32(request.count), isr &+ 1 &+ UInt32(response.count), 0x10, []),
                        (0.0100, true, isn &+ 1 &+ UInt32(request.count), isr &+ 1 &+ UInt32(response.count), 0x11, []),
                        (0.0110, false, isr &+ 1 &+ UInt32(response.count), isn &+ 2 &+ UInt32(request.count), 0x11, []),
                        (0.0112, true, isn &+ 2 &+ UInt32(request.count), isr &+ 2 &+ UInt32(response.count), 0x10, []),
                    ]
                    for (delay, fromClient, sequence, ack, flags, payload) in steps {
                        ipID &+= 1
                        emit(t + delay, FrameBuilder.tcpFrame(source: fromClient ? client : server, sourcePort: fromClient ? port : 80,
                                                              destination: fromClient ? server : client, destinationPort: fromClient ? 80 : port,
                                                              sequence: sequence, acknowledgment: ack, flags: flags, payload: payload,
                                                              identification: ipID))
                    }
                    summary.tcpConnections += 1
                }
                for _ in 0..<config.dnsPerSecond {
                    dnsCounter += 1
                    let client = host(dnsCounter % 3000, net: 60), t = now + random.uniform()
                    let name = "host\(dnsCounter % 997).example.lan"
                    let port = UInt16(40_000 + dnsCounter % 20_000)
                    udp(t, client, port, "10.100.0.53", 53, FrameBuilder.dnsMessage(id: UInt16(truncatingIfNeeded: dnsCounter), name: name))
                    udp(t + 0.0008, "10.100.0.53", 53, client, port,
                        FrameBuilder.dnsMessage(id: UInt16(truncatingIfNeeded: dnsCounter), name: name, answer: "10.200.1.\(dnsCounter % 250)"))
                }
                for _ in 0..<config.udpFlowsPerSecond {
                    udpCounter += 1
                    udp(now + random.uniform(), host(udpCounter % 20_000, net: 60), UInt16(10_000 + udpCounter % 50_000),
                        "10.250.\(udpCounter % 200).\(udpCounter % 250)", 9_999, [UInt8](repeating: 0x5A, count: 40 + udpCounter % 200))
                }
            }
            flush(through: tick - 1)
        }
        flush(through: Int.max)
        writer.close()
        summary.seconds = Double(tick) * tickSeconds
        progress?(summary.packets)
        return summary
    }
}
