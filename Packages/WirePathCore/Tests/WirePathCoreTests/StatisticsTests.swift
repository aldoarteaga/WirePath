@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// Capture statistics for `rtp-call.pcap`, matching `tshark -z io,stat,1` and `tshark -z plen,tree` on the same file.
@Suite("Statistics")
struct StatisticsTests {
    @Test func trafficAndPacketSizesMatchTshark() async throws {
        let result = try await FixtureTests.analyze("rtp-call.pcap").result
        let statistics = try #require(result.statistics)
        #expect(statistics.traffic.binSeconds == 1)
        #expect(Array(statistics.traffic.packets.prefix(5)) == [6, 0, 0, 40, 100])
        #expect(statistics.traffic.bytes[3] == 10_019)
        #expect(statistics.traffic.packets[14] == 102)
        #expect(statistics.traffic.packets.reduce(0, +) == 1_563)
        #expect(statistics.peakPacketsPerSecond == 102)
        #expect(statistics.peakBitsPerSecond == 21_828 * 8)
        let sizes = Dictionary(uniqueKeysWithValues: statistics.packetSizes.map { ($0.label, $0.packets) })
        #expect(sizes["160–319"] == 1_549)
        #expect(sizes["320–639"] == 10)
        #expect(sizes["640–1279"] == 4)
        #expect(sizes["5120+"] == 0)
        #expect(statistics.traffic.protocolPackets.first?.protocolKind == .rtp)
        #expect(statistics.traffic.protocolPackets.first?.packets.reduce(0, +) == result.capture.rtpPackets)
        let mean = try #require(statistics.meanPacketsPerSecond)
        #expect(abs(mean - 1_563 / 19.673) < 0.01)  // tshark: 19.673 s duration
    }

    @Test func longSpansUseWiderBinsAndBoundedState() {
        var collector = StatisticsCollector()
        collector.add(timeNanos: 0, length: 60, protocolKind: .udp)
        collector.add(timeNanos: 10_000 * 1_000_000_000, length: 60, protocolKind: .udp)   // 10,000 s later
        collector.add(timeNanos: .max, length: 60, protocolKind: .udp)                     // absurd timestamp
        collector.add(timeNanos: .min, length: 60, protocolKind: .udp)
        let statistics = collector.finish(protocolTotals: [.udp: 4])
        #expect(statistics.traffic.packets.count <= StatisticsCollector.maxSeriesBins)
        #expect(statistics.traffic.binSeconds > 1)
        #expect(statistics.traffic.packets.reduce(0, +) == 4)
    }

    @Test func transportSummaries() async throws {
        let analysis = try await FixtureTests.analyze("application-protocols.pcap")
        let flows = try analysis.store().flows()
        let tcp = TransportSummary.of(flows, transport: .tcp)
        let udp = TransportSummary.of(flows, transport: .udp)
        #expect(tcp.flows == 2 && tcp.packets == 6)
        #expect(udp.flows == 8 && udp.packets == 17)
    }
}
