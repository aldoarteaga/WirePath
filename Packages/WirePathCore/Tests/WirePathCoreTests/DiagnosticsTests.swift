@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// SIP and TCP diagnostics on `sip-problems.pcap` (frame numbers as tshark lists them).
@Suite("Diagnostics")
struct DiagnosticsTests {
    static func findings(_ kind: FindingKind, in result: AnalysisResult) -> [Finding] { result.findings.filter { $0.kind == kind } }

    @Test func sipProblemsAreDiagnosedWithTheirPackets() async throws {
        let analysis = try await FixtureTests.analyze("sip-problems.pcap")
        let result = analysis.result

        let auth = Self.findings(.authenticationFailure, in: result)
        #expect(auth.count == 1)
        #expect(auth.first?.severity == .error)
        #expect(auth.first?.packetReferences == [3, 4])
        #expect(auth.first?.detail.hasPrefix("REGISTER 2001 → 10.60.0.5") == true)

        let registration = Self.findings(.registrationFailure, in: result)
        #expect(registration.map(\.packetReferences) == [[5, 6]])

        let missingACK = Self.findings(.missingACK, in: result)
        #expect(missingACK.count == 1)
        #expect(missingACK.first?.packetReferences == [7, 9, 10, 11, 12])
        #expect(missingACK.first?.callIndex != nil)
        #expect(missingACK.first?.detail.contains("4 times") == true)

        let timeouts = Self.findings(.sipTimeout, in: result)
        #expect(timeouts.count == 1)
        #expect(timeouts.first?.packetReferences == [13, 14, 15])
        #expect(timeouts.first?.detail.hasPrefix("OPTIONS → 10.60.0.99: 3 requests got no final response") == true)

        let errors = Self.findings(.sipErrorResponses, in: result)
        #expect(errors.map(\.title) == ["SIP 489 Bad Event", "SIP 503 Service Unavailable"])
        #expect(errors.map(\.severity) == [.warning, .error])
        #expect(errors.map(\.packetReferences) == [[17], [19]])

        // The busy call is a call outcome (reported with the call), not a signalling problem.
        let busy = Self.findings(.sipFailure, in: result)
        #expect(busy.count == 1)
        #expect(busy.first?.packetReferences == [21])
        #expect(!missingACK.contains { $0.detail.contains("call-busy") })

        let tcp = Self.findings(.tcpUnanswered, in: result)
        #expect(tcp.count == 1)
        #expect(tcp.first?.packetFilter?.hasPrefix("flow == ") == true)

        #expect(result.headline.text == "Registration failed")
        // The answered but never ACKed call has no media either, which is reported with the call (RTP).
        #expect(Set(result.findings.map(\.protocolName)).isSubset(of: ["SIP", "TCP", "RTP"]))
        #expect(Self.findings(.noMedia, in: result).first?.callIndex == missingACK.first?.callIndex)
    }

    @Test func diagnosticFiltersSelectTheirPackets() async throws {
        let analysis = try await FixtureTests.analyze("sip-problems.pcap")
        let store = try analysis.store()
        for finding in analysis.result.findings {
            let text = try #require(finding.displayFilter, "\(finding.title) has no packet evidence")
            let filter = try DisplayFilter(text, context: store.filterContext)
            let matches = await store.filter(filter, scope: .all, callIndex: nil) ?? []
            #expect(!matches.isEmpty, "\(finding.title): \(text)")
            if !finding.packetReferences.isEmpty {
                #expect(matches.map { Int($0) + 1 } == finding.packetReferences)
            }
        }
    }

    @Test func setMembershipFilters() throws {
        let context = PacketFilterContext(addresses: [nil], captureStartNanos: 0, streamSSRCs: [], streamPayloadTypes: [], sipCallIDs: [])
        let filter = try DisplayFilter("frame.number in {2, 4 6}", context: context)
        #expect((1...7).filter { filter.matches(PacketIndexRecord(), frameNumber: $0) } == [2, 4, 6])
        #expect(throws: DisplayFilterError.self) { try DisplayFilter("frame.number in {}", context: context) }
        #expect(throws: DisplayFilterError.self) { try DisplayFilter("frame.number in {1 2", context: context) }
        #expect(throws: DisplayFilterError.self) { try DisplayFilter("frame.number in 1", context: context) }
    }
}
