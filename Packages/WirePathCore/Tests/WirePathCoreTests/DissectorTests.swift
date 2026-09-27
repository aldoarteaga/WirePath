@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

/// The protocol registry against `application-protocols.pcap`; expected values match tshark's decode of the same file.
@Suite("Protocol dissectors")
struct DissectorTests {
    static func store() async throws -> (PacketStore, AnalysisResult) {
        let analysis = try await FixtureTests.analyze("application-protocols.pcap")
        return (try analysis.store(), analysis.result)
    }

    static func field(_ packet: DissectedPacket, _ layer: String, _ name: String) -> String? {
        packet.layer(layer)?.fields.first { $0.name == name }?.value
    }

    @Test func classifiesEveryPacket() async throws {
        let (store, _) = try await Self.store()
        let kinds = (0..<store.count).map { store.record(at: $0).protocolKind }
        let expected: [PacketProtocol] = [.dhcp, .dhcp, .dhcp, .dhcp, .dns, .dns, .dns, .dns, .tcp, .tcp, .http, .http, .tls, .tls,
                                          .stun, .stun, .turn, .turn, .turn, .turn, .turn, .ntp, .icmp, .icmpv6, .icmpv6, .rtcp]
        #expect(kinds == expected)
        #expect(store.record(at: 10).ipProtocolRaw == 6)
        #expect(store.record(at: 0).ipProtocolRaw == 17)
    }

    @Test func dhcpAndDNS() async throws {
        let (store, _) = try await Self.store()
        #expect(store.dissect(at: 0).summary == "DHCP Discover - Transaction ID 0x3903f326")
        let ack = store.dissect(at: 3)
        #expect(ack.summary == "DHCP ACK - Transaction ID 0x3903f326")
        #expect(Self.field(ack, "dhcp", "Your (client) IP") == "10.50.1.30")
        #expect(Self.field(ack, "dhcp", "Option (66) TFTP Server Name") == "tftp://10.50.0.10")
        #expect(Self.field(ack, "dhcp", "Option (120) SIP Servers") == "10.50.0.5")
        #expect(store.row(at: 0).info == "Discover - Transaction ID 0x3903f326")

        #expect(store.dissect(at: 4).summary == "DNS Standard query 0x0a01 NAPTR voice.example.com")
        let naptr = store.dissect(at: 6)
        #expect(naptr.summary.hasPrefix("DNS Standard query response 0x0a01 NAPTR voice.example.com NAPTR order 10"))
        #expect(naptr.layer("dns")?.fields.contains { $0.name == "Answer" && $0.value.contains("\"SIP+D2U\"") } == true)
        let srv = store.dissect(at: 7)
        let answers = srv.layer("dns")?.fields.filter { $0.name == "Answer" }.map(\.value) ?? []
        #expect(answers.count == 2)
        #expect(answers[0].contains("priority 10, weight 60, port 5060, sbc1.voice.example.com"))
    }

    @Test func tcpHTTPAndTLS() async throws {
        let (store, _) = try await Self.store()
        let syn = store.dissect(at: 8)
        #expect(Self.field(syn, "tcp", "Options") == "MSS=1460, SACK_PERM, TSval=12345 TSecr=0, WS=128")
        #expect(Self.field(syn, "ip", "Header Checksum")?.hasSuffix("(correct)") == true)
        #expect(store.dissect(at: 10).summary == "HTTP GET /cfg/001b2b3201e0.cfg HTTP/1.1")
        let ok = store.dissect(at: 11)
        #expect(Self.field(ok, "http", "Content-Type") == "text/plain")
        let hello = store.dissect(at: 12)
        #expect(hello.summary == "TLS Client Hello (SNI=sbc1.voice.example.com)")
        #expect(Self.field(hello, "tls", "ALPN") == "h2, http/1.1")
        #expect(Self.field(hello, "tls", "Supported Versions") == "TLS 1.3, TLS 1.2")
        let serverHello = store.dissect(at: 13)
        #expect(serverHello.summary == "TLS Server Hello (TLS_AES_128_GCM_SHA256, TLS 1.3), Change Cipher Spec, Application Data")
        #expect(store.row(at: 12).info == "Client Hello (SNI=sbc1.voice.example.com)")
    }

    @Test func stunTurnAndICE() async throws {
        let (store, _) = try await Self.store()
        let request = store.dissect(at: 14)
        #expect(request.summary == "STUN Binding Request")
        #expect(Self.field(request, "stun", "USERNAME") == "rT3f:9aJ1")
        #expect(Self.field(request, "stun", "PRIORITY") == "1853817087")
        #expect(Self.field(request, "stun", "USE-CANDIDATE") == "")
        #expect(request.layer("stun")?.fields.contains { $0.name == "ICE-CONTROLLING" } == true)
        #expect(store.dissect(at: 15).summary == "STUN Binding Success Response XOR-MAPPED-ADDRESS: 192.0.2.44:50010")
        let challenge = store.dissect(at: 17)
        #expect(challenge.layer("turn") != nil)
        #expect(Self.field(challenge, "turn", "ERROR-CODE") == "401 Unauthorized")
        #expect(Self.field(challenge, "turn", "REALM") == "voice.example.com")
        let allocated = store.dissect(at: 19)
        #expect(allocated.summary.contains("XOR-RELAYED-ADDRESS: 198.51.100.3:49152"))
        #expect(Self.field(allocated, "turn", "LIFETIME") == "600 s")
        let channel = store.dissect(at: 20)
        #expect(channel.summary == "TURN ChannelData 0x4000, 172 bytes")
        #expect(channel.layers.last?.name == "Data")
    }

    @Test func ntpICMPAndRTCP() async throws {
        let (store, _) = try await Self.store()
        #expect(store.dissect(at: 21).summary == "NTP Version 4, client")
        let unreachable = store.dissect(at: 22)
        #expect(unreachable.summary == "ICMP Destination unreachable (Port unreachable) (10.50.1.30 → 10.50.0.99 UDP 5060 → 5060)")
        #expect(store.dissect(at: 23).summary == "ICMPv6 Neighbor Solicitation for fe80::21b:21ff:fe00:20")
        let advertisement = store.dissect(at: 24)
        #expect(Self.field(advertisement, "icmpv6", "Flags") == "Solicited, Override")
        #expect(advertisement.layer("icmpv6")?.fields.contains { $0.name == "Target Link-Layer Address" && $0.value == "00:1b:21:00:00:20" } == true)
        let rtcp = store.dissect(at: 25)
        #expect(rtcp.summary == "RTCP Sender Report, Source description")
        let fields = rtcp.layers.filter { $0.protocolName == "rtcp" }.flatMap(\.fields)
        #expect(fields.first { $0.name == "Cumulative Lost" }?.value == "52")
        #expect(fields.first { $0.name == "Fraction Lost" }?.value == "5.1 %")
        #expect(fields.first { $0.name == "Interarrival Jitter" }?.value == "88 timestamp units")
        #expect(fields.first { $0.name == "CNAME" }?.value == "2001@10.50.1.30")
        #expect(fields.first { $0.name == "Sender's Packet Count" }?.value == "1000")
    }

    @Test func filtersUseTheNewClassifications() async throws {
        let (store, _) = try await Self.store()
        func count(_ text: String) async throws -> Int {
            let filter = try DisplayFilter(text, context: store.filterContext)
            return await store.filter(filter, scope: .all, callIndex: nil)?.count ?? store.count
        }
        #expect(try await count("http") == 2)
        #expect(try await count("tls") == 2)
        #expect(try await count("stun") == 7)  // STUN includes TURN
        #expect(try await count("turn") == 5)
        #expect(try await count("tcp") == 6)
        #expect(try await count("udp") == 17)
        #expect(try await count("tcp.port == 80") == 4)
        #expect(try await count("udp.port == 80") == 0)
    }

    @Test func registryIsExtensible() {
        struct Echo: ProtocolDissector {
            let name = "echo"
            func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool {
                layer == .transportPayload(.udp) && context.usesPort(7)
            }
            func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                         tree: inout ProtocolTreeBuilder) -> DissectionStep {
                tree.layer(name, "Echo Protocol", " \(range.count) bytes", range: range)
                context.summary = "ECHO"
                return .end
            }
        }
        let registry = DissectorRegistry(dissectors: DissectorRegistry.standard.dissectors + [Echo()])
        let frame = FrameBuilder.udpFrame(source: "10.0.0.1", sourcePort: 7, destination: "10.0.0.2", destinationPort: 7,
                                          payload: Array("ping".utf8), identification: 1)
        let context = DissectionContext(frameNumber: 1, timestampNanos: 0, captureStartNanos: 0, linkType: .ethernet, interfaceID: 0,
                                        originalLength: frame.count, codecForPayloadType: { _ in nil })
        let packet = frame.withUnsafeBytes { PacketDissector.dissect($0, context: context, registry: registry) }
        #expect(packet.layers.map(\.protocolName) == ["frame", "eth", "ip", "udp", "echo"], "\(packet.layers.map(\.protocolName))")
        #expect(packet.summary == "ECHO")
    }
}
