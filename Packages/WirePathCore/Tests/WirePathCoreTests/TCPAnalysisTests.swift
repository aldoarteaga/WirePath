@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// TCP stream analysis on `ipv4-tcp.pcap`. tshark flags the same packets: 7 and 12 "Previous segment not captured",
/// 9 "Dup ACK", 10 "Retransmission", 13 "Out-Of-Order".
@Suite("TCP analysis")
struct TCPAnalysisTests {
    @Test func flagsMatchTshark() async throws {
        let analysis = try await FixtureTests.analyze("ipv4-tcp.pcap")
        let store = try analysis.store()
        let flagged = (0..<store.count).compactMap { position -> (Int, PacketAnalysisFlags)? in
            let flags = store.record(at: position).analysisFlags
            return flags.isEmpty ? nil : (position + 1, flags)
        }
        #expect(flagged.map(\.0) == [7, 9, 10, 12, 13])
        #expect(flagged.map(\.1) == [.previousSegmentNotCaptured, .duplicateACK, .retransmission, .previousSegmentNotCaptured, .outOfOrder])
        #expect(store.row(at: 9).info.hasPrefix("[TCP Retransmission] 80 → 51000"))
        #expect(store.row(at: 12).info.hasPrefix("[TCP Out-Of-Order]"))

        let tcp = try #require(store.flows().first?.tcp)
        #expect(tcp.handshake == .complete)
        #expect(tcp.termination == .graceful)
        #expect(tcp.retransmissions == 1)
        #expect(tcp.outOfOrder == 1)
        #expect(tcp.segmentsNotCaptured == 2)
        #expect(tcp.duplicateACKs == 1)
        #expect(abs((tcp.initialRTTMs ?? 0) - 4) < 0.01)  // SYN at 2 ms, handshake ACK at 6 ms
        #expect(tcp.initiatorISN == 1_000 && tcp.responderISN == 5_000)
        #expect(tcp.payloadBytesFromResponder == 500)       // five 100-byte segments, one of them the retransmission

        // Relative numbers and the analysis appear in the packet details.
        let details = store.dissect(at: 9).layer("tcp")?.fields ?? []
        #expect(details.first { $0.name == "Relative Sequence" }?.value == "101")
        #expect(details.first { $0.name == "SEQ/ACK Analysis" }?.value == "TCP Retransmission")
        #expect(details.first { $0.name == "Stream" }?.value == "Flow #1")
    }

    @Test func tcpFiltersAndIssuesScope() async throws {
        let analysis = try await FixtureTests.analyze("ipv4-tcp.pcap")
        let store = try analysis.store()
        func count(_ text: String) async throws -> Int {
            await store.filter(try DisplayFilter(text, context: store.filterContext), scope: .all, callIndex: nil)?.count ?? store.count
        }
        #expect(try await count("tcp.analysis.retransmission") == 1)
        #expect(try await count("tcp.analysis.flags") == 5)
        #expect(try await count("tcp.analysis.lost_segment or tcp.analysis.out_of_order") == 3)
        #expect(try await count("tcp.flags.syn") == 2)
        #expect(try await count("tcp.flags.fin") == 2)
        #expect(try await count("tcp.stream == 0") == 17)
        #expect(try await count("flow == 1") == 17)
        #expect(try await count("issues") == 5)
        #expect(await store.filter(nil, scope: .issues, callIndex: nil)?.count == 5)
    }

    @Test func udpStreamsAreNumberedPerTransport() async throws {
        let analysis = try await FixtureTests.analyze("udp.pcap")
        let store = try analysis.store()
        let filter = try DisplayFilter("udp.stream == 4", context: store.filterContext)
        #expect(await store.filter(filter, scope: .all, callIndex: nil)?.count == 20)
        #expect(store.flows().allSatisfy { $0.tcp == nil })
    }

    @Test func handshakeAndResetVariants() {
        var analyzer = TCPAnalyzer()
        // Unanswered SYN, retried once.
        _ = analyzer.analyze(flow: 0, fromInitiator: true, sequence: 10, acknowledgment: 0, flags: 0x02, window: 1_000,
                             payloadLength: 0, timeNanos: 0)
        let retry = analyzer.analyze(flow: 0, fromInitiator: true, sequence: 10, acknowledgment: 0, flags: 0x02, window: 1_000,
                                     payloadLength: 0, timeNanos: 1_000_000_000)
        #expect(retry.contains(.retransmission))
        #expect(analyzer.stats(for: 0)?.handshake == .unanswered)
        // Mid-stream start, then reset by the responder with a zero window before it.
        _ = analyzer.analyze(flow: 1, fromInitiator: true, sequence: 500, acknowledgment: 900, flags: 0x18, window: 100,
                             payloadLength: 10, timeNanos: 0)
        let zero = analyzer.analyze(flow: 1, fromInitiator: false, sequence: 900, acknowledgment: 510, flags: 0x10, window: 0,
                                    payloadLength: 0, timeNanos: 1)
        #expect(zero.contains(.zeroWindow))
        let reset = analyzer.analyze(flow: 1, fromInitiator: false, sequence: 900, acknowledgment: 510, flags: 0x14, window: 0,
                                     payloadLength: 0, timeNanos: 2)
        #expect(reset.contains(.reset))
        let stats = analyzer.stats(for: 1)
        #expect(stats?.handshake == .notCaptured)
        #expect(stats?.termination == .resetByResponder)
        // Timestamps at the Int64 limits do not trap.
        _ = analyzer.analyze(flow: 2, fromInitiator: true, sequence: 0, acknowledgment: 0, flags: 0x18, window: 1, payloadLength: 5,
                             timeNanos: .max)
        _ = analyzer.analyze(flow: 2, fromInitiator: true, sequence: 100, acknowledgment: 0, flags: 0x18, window: 1, payloadLength: 5,
                             timeNanos: .min)
        _ = analyzer.analyze(flow: 2, fromInitiator: true, sequence: 50, acknowledgment: 0, flags: 0x18, window: 1, payloadLength: 5,
                             timeNanos: .max)
    }
}
