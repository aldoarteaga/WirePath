@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

@Suite("Search & conversations")
struct SearchTests {
    @Test func interpretsQueries() {
        #expect(PacketSearch.criteria(for: "5060") == [.packetNumber(5060), .port(5060)])
        #expect(PacketSearch.criteria(for: "#12") == [.packetNumber(12)])
        #expect(PacketSearch.criteria(for: "0xDEADBEEF").contains(.ssrc(0xDEAD_BEEF)))
        #expect(PacketSearch.criteria(for: "10.20.1.23").first == .address(.v4(0x0A14_0117)))
        #expect(PacketSearch.criteria(for: "rtcp").first == .protocolName(.rtcp))
        #expect(PacketSearch.criteria(for: "sip:1008@pbx").contains(.sipText("sip:1008@pbx")))
        #expect(PacketSearch.criteria(for: "Yealink").contains(.payloadText("Yealink")))
        #expect(PacketSearch.criteria(for: "   ").isEmpty)
    }

    @Test func findsPacketsByEveryKindOfQuery() async throws {
        let analysis = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()]))
        let store = try analysis.store()
        let result = analysis.result
        func search(_ text: String) async -> SearchResults { await PacketSearch.run(text, in: store, result: result) }

        let callID = try #require(result.sipMessages.first?.callID)
        let byCallID = await search(callID)
        #expect(byCallID.hits.count == result.sipMessages.count)
        #expect(byCallID.hits.allSatisfy { store.record(at: $0.position).protocolKind.isSIP })

        let ssrc = try #require(result.streams.first?.ssrc)
        let bySSRC = await search(String(format: "0x%08X", ssrc))
        #expect(bySSRC.hits.count == result.streams[0].packetCount)

        let byNumber = await search("#3")
        #expect(byNumber.hits.map(\.position) == [2])

        // A protocol name also matches payload text (SDP bodies mention "RTP/AVP"); each hit says why it matched.
        let byProtocol = await search("rtp")
        let protocolLabel = SearchCriterion.protocolName(.rtp).label
        #expect(byProtocol.hits.filter { $0.reason == protocolLabel }.count == result.capture.rtpPackets)
        #expect(byProtocol.hits.filter { $0.reason != protocolLabel }.allSatisfy { store.record(at: $0.position).protocolKind == .sipSDP })

        let caller = result.calls[0].caller.signalling.address.description
        let byAddress = await search(caller)
        let addressHits = byAddress.hits.filter { $0.reason == SearchCriterion.address(.v4(0)).label }
        #expect(!addressHits.isEmpty)
        #expect(addressHits.allSatisfy { store.packet(at: $0.position).metadata.source?.description == caller
                                         || store.packet(at: $0.position).metadata.destination?.description == caller })

        // Payload text: the SIP User-Agent header appears in the INVITE bytes.
        let agent = try #require(result.sipMessages.first?.userAgent?.split(separator: " ").first.map(String.init))
        let byText = await search(agent)
        #expect(!byText.hits.isEmpty)
        #expect(byText.hits.contains { $0.reason == SearchCriterion.payloadText(agent).label })
    }

    @Test func searchIsCancellable() async throws {
        let calls = (0..<3).map { Fixtures.call(outcome: .answered(talk: 30, hangupByCaller: true), start: Double($0) * 2, seed: UInt64($0)) }
        let analysis = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: calls))
        let store = try analysis.store()
        let task = Task { await PacketSearch.run("zzzz-not-there", in: store, result: analysis.result) }
        task.cancel()
        let results = await task.value
        #expect(results.cancelled || results.hits.isEmpty)
    }

    @Test func conversationsAndEndpoints() async throws {
        let analysis = try await FixtureTests.analyze("udp.pcap")
        let flows = try analysis.store().flows()
        let conversations = Conversations.ip(flows)
        // 10.1.0.5 talks to the resolver (2 DNS flows), the NTP server, and 10.1.0.9 (syslog, sensor, fragments).
        #expect(conversations.count == 3)
        let sensor = try #require(conversations.first { $0.addressB.description == "10.1.0.9" || $0.addressA.description == "10.1.0.9" })
        #expect(sensor.flows.count == 3)
        #expect(conversations.reduce(0) { $0 + $1.packets } == flows.reduce(0) { $0 + $1.packets })
        let endpoints = Conversations.endpoints(flows)
        #expect(endpoints.first?.address.description == "10.1.0.5")
        #expect(endpoints.first?.flows == flows.count)
    }
}
