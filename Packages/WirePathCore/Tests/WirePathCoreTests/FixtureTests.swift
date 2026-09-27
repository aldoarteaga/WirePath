@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// The fixture set in `Fixtures/`. Expected values were cross-checked against tshark 4.x on the same files.
@Suite("Fixtures")
struct FixtureTests {
    static var repositoryFixtures: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures")
    }

    static func analyze(_ name: String) async throws -> Fixtures.Analysis {
        let fixture = try #require(FixtureCatalog.all.first { $0.fileName == name })
        let directory = Fixtures.temporaryDirectory()
        let url = directory.appendingPathComponent(name)
        try fixture.make().write(to: url)
        return try await Fixtures.analyze(file: url, directory: directory)
    }

    static func count(_ result: AnalysisResult, _ kind: PacketProtocol) -> Int {
        result.capture.protocols.first { $0.name == kind.displayName }?.packets ?? 0
    }

    @Test func checkedInFixturesMatchTheCatalog() throws {
        for fixture in FixtureCatalog.all {
            let url = Self.repositoryFixtures.appendingPathComponent(fixture.fileName)
            guard FileManager.default.fileExists(atPath: url.path) else { continue }  // e.g. sandboxed test hosts
            #expect(try Data(contentsOf: url) == fixture.make(), "\(fixture.fileName) is stale: run wpsamplegen --fixtures Fixtures")
        }
    }

    @Test func basicEthernet() async throws {
        let analysis = try await Self.analyze("basic-ethernet.pcap")
        let result = analysis.result
        #expect(result.capture.packetCount == 11)
        #expect(Self.count(result, .arp) == 2)
        #expect(Self.count(result, .icmp) == 6)
        #expect(Self.count(result, .udp) == 2)
        #expect(result.capture.flowCount == 3)  // ICMP pair, UDP over VLAN, UDP over IPv6
        let store = try analysis.store()
        #expect(store.packet(at: 0).metadata.flowIndex == nil)  // ARP has no IP flow
        #expect(store.dissect(at: 8).layer("vlan")?.fields.contains { $0.name == "ID" && $0.value == "100" } == true)
        #expect(store.packet(at: 9).metadata.source?.isV4 == false)
    }

    @Test func ipv4TCP() async throws {
        let analysis = try await Self.analyze("ipv4-tcp.pcap")
        #expect(analysis.result.capture.packetCount == 17)
        let flows = try analysis.store().flows()
        #expect(flows.count == 1)
        let flow = try #require(flows.first)
        #expect(flow.transport == .tcp)
        #expect(flow.initiator == Endpoint(address: .v4(0xC0A8_010A), port: 51_000))
        #expect(flow.packetsFromInitiator == 9)
        #expect(flow.packetsFromResponder == 8)
    }

    @Test func udp() async throws {
        let analysis = try await Self.analyze("udp.pcap")
        let result = analysis.result
        #expect(result.capture.packetCount == 30)
        #expect(Self.count(result, .dns) == 4)
        let flows = try analysis.store().flows()
        // 2 DNS (different client ports), NTP, syslog, the request/response flow and the fragmented datagram.
        #expect(flows.count == 6)
        #expect(flows.first { $0.responder.port == 9_999 }?.packets == 20)
        // Non-first fragments carry no ports and are left out of flows.
        #expect(flows.reduce(0) { $0 + $1.packets } == result.capture.packetCount - 2)
    }

    @Test func rtpCall() async throws {
        let result = try await Self.analyze("rtp-call.pcap").result
        #expect(result.calls.count == 1)
        #expect(result.calls.first?.state == .completed)
        #expect(result.streams.count == 2)
        let lossy = try #require(result.streams.max { $0.lostPackets < $1.lostPackets })
        #expect(lossy.lostPackets > 20)
        #expect(lossy.codec?.displayName.contains("711") == true)
        #expect(!lossy.lossBursts.isEmpty)
    }

    @Test func corruptedCaptureIsRejected() async throws {
        await #expect(throws: (any Error).self) { _ = try await Self.analyze("corrupted-capture.pcap") }
    }

    @Test func damagedCaptureIsAnalyzedUpToTheDamage() async throws {
        let analysis = try await Self.analyze("damaged-capture.pcapng")
        let capture = analysis.result.capture
        #expect(capture.packetCount == 5)
        #expect(capture.truncatedAtEnd)
        #expect(capture.truncatedPackets == 3)
        #expect(capture.interfaces.map(\.name) == ["en0", "utun3"])
        #expect(capture.interfaces.first?.packetsDroppedByInterface == 12)
        #expect(capture.interfaces.first?.snapLength == 96)
        #expect(capture.section?.application == "tcpdump 4.99.5")
        #expect(capture.packetComments == [PacketComment(frameNumber: 4, text: "Resolver answered only after 2 s")])
        let store = try analysis.store()
        #expect(store.dissect(at: 0).problem == .ipv4Length)
        #expect(store.packet(at: 0).isSliced)
        #expect(store.dissect(at: 1).problem == .tcpHeader)
        #expect(store.dissect(at: 2).problem == .linkHeader)
        #expect(store.dissect(at: 3).problem == nil)
        #expect(store.packet(at: 4).linkType == .raw)
    }
}
