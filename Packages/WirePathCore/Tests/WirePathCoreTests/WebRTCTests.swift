@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// WebRTC on `webrtc-session.pcap`. tshark agrees on every STUN/TURN message, the SDP candidates, the DTLS
/// handshake and (with the rtp_udp heuristic) the 300 SRTP packets; transaction outcomes and pair states follow
/// from the fixture's construction.
@Suite("WebRTC")
struct WebRTCTests {
    static func endpoint(_ ip: String, _ port: UInt16) throws -> Endpoint {
        Endpoint(address: try #require(IPAddress(ip)), port: port)
    }

    @Test func connectedSessionIsReconstructed() async throws {
        let result = try await FixtureTests.analyze("webrtc-session.pcap").result
        #expect(result.webrtc.sessions.count == 2)
        let session = try #require(result.webrtc.sessions.first)
        #expect(session.ufrags == ["aF1x", "bY7q"])
        #expect(session.state == .connected)
        #expect(session.controllingPeer == 0)
        #expect(session.callID == "webrtc-7f3a91@192.168.1.10")
        #expect(!session.usesRelay)

        let a = try Self.endpoint("192.168.1.10", 50_000), b = try Self.endpoint("192.0.2.20", 55_000)
        let relay = try Self.endpoint("198.51.100.50", 49_152)
        #expect(session.pairs.count == 4)
        let selected = try #require(session.selected)
        #expect(selected.local == a && selected.remote == b)
        #expect(selected.localKind == .host && selected.remoteKind == .srflx)
        #expect(selected.nominated && selected.successes == 3 && selected.state == .succeeded)
        #expect(abs((selected.meanRTTMs ?? 0) - 124.0 / 3) < 0.01)  // 42, 41 and 41 ms

        let hostPair = try #require(session.pairs.first { $0.remote.port == 40_000 })
        #expect(hostPair.state == .failed && hostPair.timeouts == 1 && hostPair.remoteKind == .host)
        let relayed = try #require(session.pairs.first { $0.relayed })
        #expect(relayed.local == relay && relayed.remote == b && relayed.localKind == .relay && relayed.state == .succeeded)
        #expect(abs((relayed.meanRTTMs ?? 0) - 92) < 0.01)
        let triggered = try #require(session.pairs.first { $0.checkingPeer == 1 })
        #expect(triggered.local == b && triggered.remote == a && triggered.state == .succeeded && !triggered.nominated)

        #expect(session.candidates.contains { $0.endpoint == relay && $0.kind == .relay && $0.peer == 0 })
        #expect(session.candidates.contains { $0.kind == .srflx && $0.peer == 0 && $0.endpoint.port == 62_000 })
        #expect(session.candidates.filter { $0.peer == 1 }.map(\.kind).sorted { $0.rawValue < $1.rawValue } == [.host, .srflx])

        let dtls = try #require(session.dtls)
        #expect(dtls.established && dtls.alerts == 0)
        #expect(dtls.clientHelloFrame == 27 && dtls.serverHelloFrame == 28)

        #expect(session.streamIndices == [0, 1])
        #expect(result.streams.count == 2)
        #expect(result.streams.allSatisfy { $0.packetCount == 150 && $0.lostPackets == 0 && $0.codec?.encodingName.lowercased() == "opus" })
        #expect(session.turnAllocations == [0])
        #expect(session.serverBindingIndices.count == 1)
        #expect(result.webrtc.serverBindings.isEmpty)
        #expect(result.headline.text == "ICE failed · 1 session")
    }

    @Test func turnAllocations() async throws {
        let result = try await FixtureTests.analyze("webrtc-session.pcap").result
        #expect(result.webrtc.allocations.count == 2)
        let allocation = try #require(result.webrtc.allocations.first)
        #expect(allocation.succeeded && allocation.challenges == 1 && allocation.errorCodes.isEmpty)
        #expect(allocation.relayedAddress == (try Self.endpoint("198.51.100.50", 49_152)))
        #expect(allocation.mappedAddress == (try Self.endpoint("203.0.113.10", 62_000)))
        #expect(allocation.permissions == [try #require(IPAddress("192.0.2.20"))])
        #expect(allocation.channels == [.init(number: 0x4000, peer: try Self.endpoint("192.0.2.20", 55_000))])
        #expect(allocation.channelDataPackets == 2 && allocation.relayedPackets == 2)
        #expect(allocation.released && allocation.lifetime == 0)

        let rejected = result.webrtc.allocations[1]
        #expect(!rejected.succeeded && rejected.challenges == 1 && rejected.errorCodes == [401])
    }

    @Test func failuresAreDiagnosed() async throws {
        let result = try await FixtureTests.analyze("webrtc-session.pcap").result
        let failed = result.webrtc.sessions[1]
        #expect(failed.state == .failed && failed.selectedPair == nil)
        #expect(failed.pairs.allSatisfy { $0.state == .failed && $0.checks == 1 && $0.timeouts == 1 })
        #expect(failed.turnAllocations == [1])

        let webrtcFindings = result.findings.filter { ["WebRTC", "STUN", "TURN"].contains($0.protocolName) }
        #expect(webrtcFindings.map(\.kind) == [.iceFailure, .stunTimeout, .turnAllocationFailure])
        let ice = webrtcFindings[0]
        #expect(ice.severity == .error && ice.webrtcSessionIndex == 1)
        #expect(ice.packetReferences == Array(343...346) + Array(348...351) + [353, 354])
        #expect(webrtcFindings[1].packetReferences == [338, 347, 352, 355, 356])
        // The STUN server and TURN failures were gathering for session 2, and link to it.
        #expect(webrtcFindings[1].webrtcSessionIndex == 1 && webrtcFindings[2].webrtcSessionIndex == 1)
        #expect(webrtcFindings[2].detail.contains("credentials rejected"))
        #expect(webrtcFindings[2].packetReferences == [339, 340, 341, 342])
        // Every STUN transaction was answered in session 1 except the unreachable host candidate.
        let unanswered = result.webrtc.transactions.filter { $0.outcome == .noResponse }
        #expect(unanswered.count == 4)
        #expect(result.isStructurallyValid)
    }

    @Test func filterKeywords() async throws {
        let analysis = try await FixtureTests.analyze("webrtc-session.pcap")
        let store = try analysis.store()
        func count(_ expression: String) async throws -> Int {
            let filter = try DisplayFilter(expression, context: store.filterContext)
            return await store.filter(filter, scope: .all, callIndex: nil)?.count ?? store.count
        }
        #expect(try await count("webrtc") == 349)  // everything but SIP and the NTP packet
        #expect(try await count("webrtc.session == 1") == 330)
        #expect(try await count("webrtc.session == 2") == 19)
        #expect(try await count("stun") == 45)  // as tshark
        #expect(try await count("turn") == 16)  // as tshark: stun.type.method >= 3 or ChannelData
        #expect(try await count("dtls") == 4)
        #expect(try await count("webrtc and rtp") == 300)
    }

    @Test func icePasswordsAreNotKept() async throws {
        let result = try await FixtureTests.analyze("webrtc-session.pcap").result
        let json = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
        #expect(!json.contains("placeholder-pwd"))
        #expect(!json.contains("ice-pwd"))
        #expect(!json.contains("peer-a"))  // the TURN USERNAME
        #expect(!json.contains("6f1d2c3b4a5e"))  // the TURN NONCE
    }

    // MARK: Tracker and parser units

    static func ingest(_ tracker: inout WebRTCTracker, _ bytes: [UInt8], frame: Int, time: Double, _ source: Endpoint,
                       _ destination: Endpoint) {
        bytes.withUnsafeBytes {
            tracker.ingestSTUN($0, frame: frame, time: Timestamp(seconds: time), source: source, destination: destination)
        }
    }

    @Test func checksRelayedInSendAndDataIndications() throws {
        typealias P = ProtocolBuilders
        var tracker = WebRTCTracker()
        let client = try Self.endpoint("10.0.0.1", 5_000), server = try Self.endpoint("10.0.0.2", 3_478)
        let peer = try Self.endpoint("10.0.0.3", 6_000), relay = try Self.endpoint("10.0.0.2", 49_000)
        let t1 = [UInt8](repeating: 1, count: 12), t2 = [UInt8](repeating: 2, count: 12)
        Self.ingest(&tracker, P.stun(type: 0x0003, transactionID: t1, attributes: [(0x0019, [17, 0, 0, 0])]), frame: 1, time: 0,
                    client, server)
        Self.ingest(&tracker, P.stun(type: 0x0103, transactionID: t1, attributes: [(0x0016, P.xorAddress("10.0.0.2", port: 49_000))]),
                    frame: 2, time: 0.01, server, client)
        let check = P.stun(type: 0x0001, transactionID: t2, attributes: [(0x0006, Array("r:l".utf8)), (0x802A, [UInt8](repeating: 0, count: 8))])
        Self.ingest(&tracker, P.stun(type: 0x0016, transactionID: [UInt8](repeating: 3, count: 12), attributes: [
            (0x0012, P.xorAddress("10.0.0.3", port: 6_000)), (0x0013, check)]), frame: 3, time: 0.02, client, server)
        let answer = P.stun(type: 0x0101, transactionID: t2, attributes: [(0x0020, P.xorAddress("10.0.0.2", port: 49_000))])
        Self.ingest(&tracker, P.stun(type: 0x0017, transactionID: [UInt8](repeating: 4, count: 12), attributes: [
            (0x0012, P.xorAddress("10.0.0.3", port: 6_000)), (0x0013, answer)]), frame: 4, time: 0.05, server, client)

        let analysis = tracker.finish(streams: [], sipMessages: [], flowTable: FlowTable(), captureEnd: Timestamp(seconds: 1))
        let session = try #require(analysis.sessions.first)
        let pair = try #require(session.selected)
        #expect(pair.local == relay && pair.remote == peer && pair.relayed && pair.localKind == .relay)
        #expect(session.usesRelay && session.state == .connected)
        #expect(analysis.allocations.first?.sendIndications == 1 && analysis.allocations.first?.dataIndications == 1)
        #expect(WebRTCDiagnostics.findings(analysis, firstID: 0).contains { $0.kind == .turnRelay })
    }

    @Test func stateIsBounded() throws {
        typealias P = ProtocolBuilders
        var tracker = WebRTCTracker()
        let local = try Self.endpoint("10.0.0.1", 5_000)
        for index in 0..<200 {
            let remote = Endpoint(address: .v4(0x0A01_0000 + UInt32(index)), port: 7_000)
            let id = [UInt8](repeating: 0, count: 10) + [UInt8(index >> 8), UInt8(index & 0xFF)]
            Self.ingest(&tracker, P.stun(type: 0x0001, transactionID: id, attributes: [(0x0006, Array("r:l".utf8))]),
                        frame: index + 1, time: Double(index) * 0.001, local, remote)
        }
        let analysis = tracker.finish(streams: [], sipMessages: [], flowTable: FlowTable(), captureEnd: Timestamp(seconds: 10))
        #expect(analysis.sessions.count == 1)
        #expect(analysis.sessions[0].pairs.count == WebRTCTracker.maxPairsPerSession)
        #expect(analysis.sessions[0].state == .failed)
    }

    @Test func malformedSTUNIsRejected() {
        typealias P = ProtocolBuilders
        let valid = P.stun(type: 0x0001, transactionID: [UInt8](repeating: 9, count: 12), attributes: [(0x0006, Array("a:b".utf8))])
        // Declared length beyond the datagram, a length that is not a multiple of 4, an attribute overrunning the
        // message, and XOR addresses too short for their family.
        var tooLong = valid
        tooLong[3] = 0xF0
        var unaligned = valid
        unaligned[3] = 0x05
        var overrun = valid
        overrun[22] = 0xFF
        overrun[23] = 0xFF
        let shortAddress = P.stun(type: 0x0101, transactionID: [UInt8](repeating: 9, count: 12),
                                  attributes: [(0x0020, [0, 2, 0, 0, 1, 2, 3, 4])], fingerprint: false)
        #expect(valid.withUnsafeBytes { STUNParser.parse($0) }?.username == "a:b")
        #expect(tooLong.withUnsafeBytes { STUNParser.parse($0) } == nil)
        #expect(unaligned.withUnsafeBytes { STUNParser.parse($0) } == nil)
        #expect(overrun.withUnsafeBytes { STUNParser.parse($0) }.map { $0.username?.count ?? 0 <= 512 } == true)
        #expect(shortAddress.withUnsafeBytes { STUNParser.parse($0) }.map { $0.xorMappedAddress == nil } == true)
        let truncatedChannelData: [UInt8] = [0x40, 0x00, 0xFF, 0xFF, 1, 2]
        var tracker = WebRTCTracker()
        truncatedChannelData.withUnsafeBytes {
            tracker.ingestChannelData($0, frame: 1, time: Timestamp(nanoseconds: 0), source: Endpoint(address: .v4(1), port: 1),
                                      destination: Endpoint(address: .v4(2), port: 3478))
        }
        let truncatedDTLS: [UInt8] = [22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1]
        truncatedDTLS.withUnsafeBytes {
            tracker.ingestDTLS($0, frame: 2, time: Timestamp(nanoseconds: 0), source: Endpoint(address: .v4(1), port: 1),
                               destination: Endpoint(address: .v4(2), port: 2))
        }
        #expect(tracker.finish(streams: [], sipMessages: [], flowTable: FlowTable(), captureEnd: nil).isEmpty)
    }
}
