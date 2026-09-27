import Foundation
import WirePathFixtures

// wpsamplegen — writes simulated VoIP captures for manual testing and demos.
//
//   wpsamplegen <output-directory> [--scale 0.1]
//   wpsamplegen --fixtures <directory>     regenerates the small test fixtures (FixtureCatalog)
//
// Every metric WirePath shows for these files is computed from the generated packets; the
// simulator only decides what the network does (delay, jitter, loss, failures).

let arguments = Array(CommandLine.arguments.dropFirst())
if let flag = arguments.firstIndex(of: "--fixtures") {
    guard flag + 1 < arguments.count else {
        print("usage: wpsamplegen --fixtures <directory>")
        exit(2)
    }
    let directory = URL(fileURLWithPath: arguments[flag + 1], isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    for fixture in FixtureCatalog.all {
        let data = try fixture.make()
        try data.write(to: directory.appendingPathComponent(fixture.fileName))
        print("\(fixture.fileName)  \(data.count.formatted()) bytes — \(fixture.summary)")
    }
    exit(0)
}
guard let outputPath = arguments.first(where: { !$0.hasPrefix("--") }) else {
    print("usage: wpsamplegen <output-directory> [--scale <factor>] [--only <name>]")
    exit(2)
}
let scale: Double = arguments.firstIndex(of: "--scale").flatMap { Double(arguments[$0 + 1]) } ?? 1
let only: String? = arguments.firstIndex(of: "--only").map { arguments[$0 + 1] }
let output = URL(fileURLWithPath: outputPath, isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

/// Local wall-clock time on 2026-09-26 as a Unix timestamp.
func localTime(_ hour: Int, _ minute: Int, _ second: Int, day: Int = 26) -> Double {
    var components = DateComponents(year: 2026, month: 9, day: day, hour: hour, minute: minute, second: second)
    components.timeZone = .current
    return Calendar.current.date(from: components)!.timeIntervalSince1970
}

func seconds(_ mmss: String) -> Double {
    let parts = mmss.split(separator: ":").compactMap { Double($0) }
    return parts.count == 2 ? parts[0] * 60 + parts[1] : 0
}

// MARK: Office network

let pbx = SimHost("10.20.0.5", userAgent: "WirePath-PBX/3.2")
let trunkHost = SimHost("200.31.4.10", userAgent: "Carrier SBC")
let names = ["1001": "Recepción", "1002": "Ventas", "1003": "Soporte N1", "1004": "Contabilidad", "1005": "Gerencia",
             "1006": "RR. HH.", "1007": "Bodega", "1008": "Soporte N2", "1009": "Compras", "1010": "IT"]
func phone(_ ext: String) -> SimParty {
    let last = Int(ext.suffix(2))!
    let models = ["Yealink SIP-T54W 96.86.0.70", "Poly VVX 450 6.4.3", "Grandstream GRP2614 1.0.9"]
    return SimParty(ext, names[ext], host: SimHost("10.20.1.\(20 + last)", userAgent: models[last % 3]))
}
func trunk(_ number: String) -> SimParty {
    SimParty(number, "Trunk", host: trunkHost, domain: "sip.carrier.net")
}

nonisolated(unsafe) var seedCounter: UInt64 = 100
func nextSeed() -> UInt64 { seedCounter += 1; return seedCounter }

func answered(_ start: Double, _ from: SimParty, _ to: SimParty, _ talk: String, _ codec: SimCodec,
              forward: SimImpairment = SimImpairment(jitterMs: 1.8), reverse: SimImpairment = SimImpairment(jitterMs: 1.6),
              byCaller: Bool = true, ring: Double = 3.6) -> SimCall {
    SimCall(start: start, caller: from, callee: to, topology: .proxy(pbx),
            outcome: .answered(talk: seconds(talk) * scale, hangupByCaller: byCaller), ringDuration: ring, codec: codec,
            forward: forward, reverse: reverse, seed: nextSeed())
}

func failed(_ start: Double, _ from: SimParty, _ to: SimParty, _ outcome: SimOutcome) -> SimCall {
    SimCall(start: start, caller: from, callee: to, topology: .proxy(pbx), outcome: outcome, ringDuration: 5.2,
            seed: nextSeed())
}

func officeTraffic() throws {
    let base = localTime(9, 14, 2)
    func at(_ h: Int, _ m: Int, _ s: Int) -> Double { (localTime(h, m, s) - base) * max(scale, 0.02) }

    // The 09:42 call: jitter spike at +31 s, loss burst +52.4–55.1 s both ways, SSRC change at +44.2 s.
    let mediaOffset = 3.64   // media starts ~3.64 s after the INVITE
    let investigated = answered(at(9, 42, 15), phone("1003"), phone("1008"), "01:17", .g729,
        forward: SimImpairment(baseDelayMs: 4, jitterMs: 9, randomLoss: 0.006,
                               lossWindows: [SimLossWindow(start: 52.4 - mediaOffset, end: 55.1 - mediaOffset, probability: 0.13)],
                               spikes: [SimSpike(time: 31.2 - mediaOffset, amplitudeMs: 170, width: 0.35)], reorderProbability: 0.001),
        reverse: SimImpairment(baseDelayMs: 4, jitterMs: 7, randomLoss: 0.005,
                               lossWindows: [SimLossWindow(start: 52.4 - mediaOffset, end: 55.1 - mediaOffset, probability: 0.1)],
                               spikes: [SimSpike(time: 53.4 - mediaOffset, amplitudeMs: 60, width: 0.4)],
                               ssrcChangeAt: 44.21 - mediaOffset))

    let calls: [SimCall] = [
        answered(at(9, 14, 7), phone("1001"), phone("1002"), "03:12", .pcmu),
        answered(at(9, 18, 30), phone("1005"), phone("1003"), "04:05", .pcmu),
        failed(at(9, 22, 41), phone("1004"), trunk("+50322607788"), .rejected(code: 486, reason: "Busy Here", fromServer: false)),
        answered(at(9, 26, 10), phone("1002"), phone("1007"), "05:40", .g729, forward: SimImpairment(jitterMs: 2.5, randomLoss: 0.0015)),
        answered(at(9, 31, 22), phone("1001"), phone("1002"), "04:32", .pcmu, forward: SimImpairment(jitterMs: 2.4, randomLoss: 0.0012)),
        answered(at(9, 37, 40), phone("1009"), trunk("+50322419000"), "06:15", .pcma),
        investigated,
        answered(at(9, 55, 5), phone("1006"), phone("1001"), "03:30", .opus),
        answered(at(10, 2, 43), phone("1005"), phone("1001"), "07:12", .opus),
        answered(at(10, 6, 30), phone("1008"), phone("1004"), "08:10", .pcmu, byCaller: false),
        answered(at(10, 11, 9), phone("1002"), trunk("+50321234500"), "12:48", .pcma, forward: SimImpairment(baseDelayMs: 18, jitterMs: 3.5, randomLoss: 0.0018)),
        answered(at(10, 15, 20), phone("1010"), phone("1003"), "04:44", .g729),
        failed(at(10, 19, 55), phone("1007"), phone("1003"), .timeout),
        answered(at(10, 27, 30), phone("1006"), phone("1010"), "02:05", .g729, forward: SimImpairment(jitterMs: 7, randomLoss: 0.004), reverse: SimImpairment(jitterMs: 6, randomLoss: 0.004)),
        answered(at(10, 35, 12), phone("1008"), trunk("+50378991020"), "05:51", .pcmu, forward: SimImpairment(baseDelayMs: 16, jitterMs: 3)),
        answered(at(10, 41, 0), phone("1003"), phone("1005"), "06:20", .pcmu),
        failed(at(10, 48, 3), phone("1009"), phone("1004"), .rejected(code: 503, reason: "Service Unavailable", fromServer: true)),
        answered(at(10, 52, 47), phone("1010"), phone("1005"), "09:26", .opus),
        answered(at(10, 58, 10), phone("1004"), phone("1009"), "05:05", .opus),
        answered(at(11, 3, 18), phone("1001"), phone("1006"), "03:40", .pcmu),
        answered(at(11, 9, 40), phone("1007"), phone("1002"), "07:35", .pcmu),
        answered(at(11, 15, 26), phone("1004"), phone("1002"), "06:02", .g729,
                 forward: SimImpairment(baseDelayMs: 5, jitterMs: 24, randomLoss: 0.024,
                                        lossWindows: [SimLossWindow(start: 120, end: 124, probability: 0.3)]),
                 reverse: SimImpairment(baseDelayMs: 5, jitterMs: 20, randomLoss: 0.022)),
        answered(at(11, 24, 51), phone("1003"), phone("1009"), "01:54", .pcmu),
        answered(at(11, 32, 0), phone("1002"), phone("1008"), "10:05", .pcmu, byCaller: false),
    ]
    var capture = SimCapture(baseTime: base, calls: calls)
    let duration = (localTime(11, 48, 20) - base) * max(scale, 0.02)
    capture.keepAlive = (from: pbx, to: trunkHost, interval: 30, duration: duration)
    capture.registration = (phone: phone("1007"), server: pbx, at: 12)
    capture.backgroundNoise = (hosts: (21...30).map { "10.20.1.\($0)" }, dnsServer: "10.20.0.2", duration: duration)
    try capture.write(to: output.appendingPathComponent("office-traffic.pcap"))
}

func customerCall() throws {
    let base = localTime(16, 40, 5, day: 25)
    let agent = SimParty("2001", "Atención al Cliente", host: SimHost("10.20.2.31", userAgent: "Poly CCX 500"))
    let call = SimCall(start: 0.5, caller: trunk("+50377123456"), callee: agent, topology: .proxy(pbx),
                       outcome: .answered(talk: 372 * scale, hangupByCaller: true), ringDuration: 6.1, codec: .pcma,
                       forward: SimImpairment(baseDelayMs: 22, jitterMs: 6, randomLoss: 0.021,
                                              lossWindows: [SimLossWindow(start: 95, end: 99, probability: 0.35),
                                                            SimLossWindow(start: 240, end: 242, probability: 0.4)]),
                       reverse: SimImpairment(baseDelayMs: 22, jitterMs: 4, randomLoss: 0.012), seed: 900)
    try SimCapture(baseTime: base, calls: [call]).write(to: output.appendingPathComponent("customer-call.pcap"))
}

func branch03() throws {
    let base = localTime(10, 5, 0, day: 24)
    let branchPBX = SimHost("10.30.0.5", userAgent: "WirePath-PBX/3.2")
    func branchPhone(_ ext: String, _ name: String) -> SimParty {
        SimParty(ext, name, host: SimHost("10.30.1.\(Int(ext.suffix(2))! + 10)", userAgent: "Yealink SIP-T46U"), domain: "branch03.lan")
    }
    let people = [("3001", "Caja 1"), ("3002", "Caja 2"), ("3003", "Supervisor"), ("3004", "Bodega"), ("3005", "Gerencia")]
    var calls: [SimCall] = []
    for i in 0..<8 {
        let a = people[i % 5], b = people[(i + 2) % 5]
        calls.append(SimCall(start: Double(i) * 190 * scale + 1, caller: branchPhone(a.0, a.1), callee: branchPhone(b.0, b.1),
                             topology: .proxy(branchPBX), outcome: .answered(talk: Double(60 + i * 17) * scale, hangupByCaller: i % 3 != 0),
                             ringDuration: 2.5 + Double(i % 3), codec: .pcmu, forward: SimImpairment(jitterMs: 1.2),
                             reverse: SimImpairment(jitterMs: 1.1), seed: 300 + UInt64(i)))
    }
    try SimCapture(baseTime: base, calls: calls).write(to: output.appendingPathComponent("branch-03.pcap"))
}

func troubleshooting() throws {
    let base = localTime(14, 20, 0, day: 22)
    var calls: [SimCall] = []
    let extensions = ["1001", "1002", "1003", "1004", "1005", "1006", "1008", "1009", "1010"]
    for i in 0..<12 {
        let a = phone(extensions[i % extensions.count]), b = phone(extensions[(i + 4) % extensions.count])
        var reverse = SimImpairment(jitterMs: 1.5)
        if i == 3 || i == 8 { reverse.silent = true }  // NAT problem: no audio back to the caller
        calls.append(SimCall(start: Double(i) * 75 * scale + 1, caller: a, callee: b, topology: .proxy(pbx),
                             outcome: .answered(talk: Double(35 + i * 9) * scale, hangupByCaller: true),
                             codec: i % 4 == 0 ? .g729 : .pcmu, forward: SimImpairment(jitterMs: 1.7), reverse: reverse,
                             seed: 500 + UInt64(i)))
    }
    try SimCapture(baseTime: base, calls: calls).write(to: output.appendingPathComponent("troubleshooting.pcap"))
}

func trunkFailover() throws {
    let base = localTime(8, 0, 0)
    let sbc = SimHost("10.20.0.10", userAgent: "WirePath-SBC/1.4")
    let primary = SimHost("200.31.4.10", userAgent: "Carrier A SBC")
    let secondary = SimHost("190.86.2.20", userAgent: "Carrier B SBC")
    var calls: [SimCall] = []
    for i in 0..<30 {
        let caller = phone(["1001", "1002", "1004", "1005", "1008", "1009"][i % 6])
        let start = Double(i) * 55 * scale + 1
        if i >= 6 && i < 12 {
            // Primary carrier fails: 503 from the SBC, then retried through the secondary.
            calls.append(SimCall(start: start, caller: caller, callee: SimParty("+50322\(600000 + i)", "Carrier A", host: primary),
                                 topology: .b2bua(sbc, anchorMedia: true),
                                 outcome: .rejected(code: 503, reason: "Service Unavailable", fromServer: false), seed: 700 + UInt64(i)))
            calls.append(SimCall(start: start + 1.2, caller: caller, callee: SimParty("+50322\(600000 + i)", "Carrier B", host: secondary),
                                 topology: .b2bua(sbc, anchorMedia: true), outcome: .answered(talk: Double(40 + i * 3) * scale, hangupByCaller: true),
                                 codec: .pcma, forward: SimImpairment(baseDelayMs: 35, jitterMs: 5, randomLoss: 0.004),
                                 reverse: SimImpairment(baseDelayMs: 35, jitterMs: 5, randomLoss: 0.003), seed: 800 + UInt64(i)))
        } else {
            calls.append(SimCall(start: start, caller: caller, callee: SimParty("+50322\(600000 + i)", "Carrier A", host: primary),
                                 topology: .b2bua(sbc, anchorMedia: true), outcome: .answered(talk: Double(50 + i * 4) * scale, hangupByCaller: i % 2 == 0),
                                 codec: .pcma, forward: SimImpairment(baseDelayMs: 20, jitterMs: 2.5), reverse: SimImpairment(baseDelayMs: 20, jitterMs: 2.2),
                                 seed: 600 + UInt64(i)))
        }
    }
    try SimCapture(baseTime: base, calls: calls).write(to: output.appendingPathComponent("trunk-failover.pcapng"), format: .pcapng)
}

func single() throws {
    let call = SimCall(start: 1, caller: SimParty("1003", "Soporte N1", host: SimHost("10.20.1.23")),
                       callee: SimParty("1008", "Soporte N2", host: SimHost("10.20.1.28")), topology: .proxy(pbx),
                       outcome: .answered(talk: 10, hangupByCaller: true), codec: .pcmu, forward: .perfect, reverse: .perfect, seed: 7)
    try SimCapture(baseTime: localTime(9, 42, 14), calls: [call]).write(to: output.appendingPathComponent("single-call.pcap"))
}

let generators: [(String, () throws -> Void)] = [
    ("office-traffic", officeTraffic), ("customer-call", customerCall), ("branch-03", branch03),
    ("troubleshooting", troubleshooting), ("trunk-failover", trunkFailover), ("single-call", single),
]
for (name, generate) in generators where only == nil || only == name {
    let started = Date()
    try generate()
    print("wrote \(name) in \(String(format: "%.1f", Date().timeIntervalSince(started))) s")
}
