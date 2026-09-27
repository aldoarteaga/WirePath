@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// RTCP on `rtcp-call.pcap`. tshark agrees on the reported loss (fraction 12/256, cumulative 5) and the XR metrics
/// (MOS-LQ 3.4, R 65); the round trip is 40 ms by construction (2 × 20 ms one-way, 50 ms DLSR accounted for).
@Suite("RTCP")
struct RTCPTests {
    @Test func reportsAreLinkedToTheirStream() async throws {
        let result = try await FixtureTests.analyze("rtcp-call.pcap").result
        #expect(result.rtcpReports.count == 11)  // 5 SR, 5 RR, 1 XR
        #expect(result.rtcpReports.filter { $0.kind == .senderReport }.last?.senderPacketCount == 500)
        let stream = try #require(result.streams.first)
        #expect(result.streams.count == 1)
        #expect(stream.lostPackets == 5)

        let rtcp = try #require(stream.rtcp)
        #expect(rtcp.senderReports == 5)
        #expect(rtcp.receiverReports == 5)
        #expect(rtcp.lastSenderPacketCount == 500)
        #expect(rtcp.cname == "sender@10.70.1.10")
        #expect(abs((rtcp.maxFractionLostPercent ?? 0) - 12.0 / 256 * 100) < 1e-9)
        #expect(rtcp.lastCumulativeLost == 5)
        #expect(abs((rtcp.maxReportedJitterMs ?? 0) - 1.5) < 1e-9)  // 12 timestamp units at 8 kHz
        let rtt = try #require(rtcp.roundTripMs)
        #expect(rtt.samples == 5)
        // DLSR has 1/65,536 s resolution (50 ms is sent as 3,276 units = 49.988 ms), so expect 40 ms ± 0.05.
        #expect(abs(rtt.min - 40) < 0.05, "min \(rtt.min)")
        #expect(abs(rtt.max - 40) < 0.05, "max \(rtt.max)")
        #expect(rtcp.voipMetrics?.mosLQ == 3.4)
        #expect(rtcp.voipMetrics?.rFactor == 65)
        #expect(rtcp.voipMetrics?.jitterBufferNominalMs == 40)

        let reported = result.findings.filter { $0.kind == .reportedQuality }
        #expect(reported.count == 1)
        #expect(reported.first?.severity == .error)
        #expect(reported.first?.protocolName == "RTCP")
    }

    @Test func streamRates() async throws {
        let stream = try #require(try await FixtureTests.analyze("rtcp-call.pcap").result.streams.first)
        let pps = try #require(stream.packetsPerSecond)
        #expect(abs(pps - 494 / 9.98) < 0.01)
        let payload = try #require(stream.payloadBitrate)
        #expect(abs(payload - Double(495 * 160 * 8) * 494 / 495 / 9.98) < 1)
        let wire = try #require(stream.wireBitrate)
        #expect(abs(wire - Double(495 * 214 * 8) * 494 / 495 / 9.98) < 1)  // 214-byte frames
    }

    @Test func malformedRTCPIsBounded() {
        var tracker = RTCPTracker()
        let endpoint = Endpoint(address: .v4(1), port: 1)
        // Report count 31 in a packet too short for any block; a zero-length chain; a lone XR header.
        let packets: [[UInt8]] = [[0x9F, 201, 0, 1, 0, 0, 0, 1], [0x80, 200, 0, 0, 0, 0, 0, 1, 0x80, 201, 0, 0],
                                  [0x80, 207, 0, 2, 0, 0, 0, 1, 7, 0, 0, 8]]
        for bytes in packets {
            bytes.withUnsafeBytes { tracker.ingest($0, frameNumber: 1, time: Timestamp(nanoseconds: 0), source: endpoint, destination: endpoint) }
        }
        #expect(tracker.reports.allSatisfy { $0.blocks.isEmpty && $0.voipMetrics.isEmpty })
    }
}
