@testable import WirePathCore
import Foundation
import Testing
import WirePathFixtures

@Suite("End-to-end analysis")
struct EngineTests {
    @Test func answeredProxyCallOnPerfectNetwork() async throws {
        let capture = SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()])
        let analysis = try await Fixtures.analyze(capture)
        let result = analysis.result

        #expect(result.calls.count == 1)
        let call = try #require(result.calls.first)
        #expect(call.state == .completed)
        #expect(call.caller.user == "1003")
        #expect(call.caller.displayName == "Soporte N1")
        #expect(call.callee.user == "1008")
        #expect(call.endReason == .byeFromCaller)
        #expect(call.mediaPath == .direct)
        #expect(call.messageIndices.count == 14)               // INVITE…200 OK through both legs
        #expect(call.participants.count == 3)
        #expect(call.participants.map(\.label) == ["1003 · Caller", "SIP Server", "1008 · Callee"])
        #expect(abs((call.setupSeconds ?? 0) - 3.602) < 0.005)  // INVITE → 200 OK toward the caller
        #expect(call.codec?.kind == .pcmu)
        #expect(call.ptimeMs == 20)
        #expect(result.topology.sipServer == IPAddress("10.20.0.5"))

        // Media: two streams, one per direction, no impairments.
        #expect(result.streams.count == 2)
        for stream in result.streams {
            #expect(stream.lostPackets == 0)
            #expect(stream.duplicatePackets == 0)
            #expect(stream.outOfOrderPackets == 0)
            #expect(stream.negotiatedInSDP)
            #expect((stream.maxJitterMs ?? 99) < 0.001)
            #expect(stream.packetCount >= 495 && stream.packetCount <= 500)  // ~10 s at 50 pps
        }
        let quality = try #require(call.quality)
        #expect(quality.forward != nil && quality.reverse != nil)
        let expectedMOS = EModel.mos(fromR: 93.2)
        #expect(abs((quality.mos ?? 0) - expectedMOS) < 1e-9)
        #expect(result.findings.isEmpty)
        #expect(result.headline.text == "No issues")
        #expect(call.severity == .ok)
    }

    @Test func exactPacketLossIsMeasured() async throws {
        // Drop 25 of 500 forward packets (5 %), in two groups.
        let drops = Set((100..<110).map { $0 } + (300..<315).map { $0 })
        var forward = SimImpairment.perfect
        forward.dropIndices = drops
        let capture = SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call(forward: forward)])
        let result = try await Fixtures.analyze(capture).result
        let call = try #require(result.calls.first)
        let forwardStream = try #require(result.streams.first { $0.source.address == IPAddress("10.20.1.23") })
        #expect(forwardStream.lostPackets == 25)
        #expect(forwardStream.sequenceGaps == 2)
        #expect(abs(forwardStream.lossPercent - 25.0 / Double(forwardStream.expectedPackets) * 100) < 1e-9)
        #expect(forwardStream.burstRatio > 1)  // loss arrived in bursts
        // Bursts: both groups exceed 3 packets and 5 % of their second.
        #expect(forwardStream.lossBursts.count == 2)
        #expect(forwardStream.lossBursts.map(\.lostPackets).reduce(0, +) == 25)
        #expect(call.quality?.forward?.lost == 25)
        #expect(call.quality?.reverse?.lost == 0)
        #expect(result.findings.contains { $0.kind == .poorQuality })
        #expect(result.findings.contains { $0.kind == .lossBurst })
        #expect(call.severity == .error)  // 5 % loss exceeds the 2 % error threshold
    }

    @Test(arguments: [(486, "Busy Here", CallState.rejected), (404, "Not Found", .failed)])
    func rejectedByCallee(code: Int, reason: String, state: CallState) async throws {
        let call = Fixtures.call(outcome: .rejected(code: code, reason: reason, fromServer: false))
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [call])).result
        let record = try #require(result.calls.first)
        #expect(record.state == state)
        #expect(record.finalStatusCode == code)
        #expect(record.statusLabel == "\(code) \(reason)")
        #expect(record.streamIndices.isEmpty)
        #expect(record.severity == .error)
        #expect(result.voip.sipErrorResponses == [code])
        #expect(result.headline.text == "1 SIP error")
        #expect(result.findings.contains { $0.kind == .sipFailure })
    }

    @Test func serverUnavailable() async throws {
        let call = Fixtures.call(outcome: .rejected(code: 503, reason: "Service Unavailable", fromServer: true))
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [call])).result
        #expect(result.calls.first?.state == .failed)
        #expect(result.calls.first?.finalStatusCode == 503)
        #expect(result.calls.first?.messageIndices.count == 4)
    }

    @Test func timeoutWithRetransmissions() async throws {
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call(outcome: .timeout)])).result
        let call = try #require(result.calls.first)
        #expect(call.finalStatusCode == 408)
        #expect(call.state == .failed)
        let retransmitted = call.messageIndices.filter { result.sipMessages[$0].isRetransmission }
        #expect(retransmitted.count == 4)  // Timer A: 0.5, 1, 2 and 4 s intervals before the 8 s timeout
        #expect(result.sipTransactions.contains { $0.retransmissions == 4 })
    }

    @Test func cancelledCall() async throws {
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call(outcome: .cancelled(after: 2))])).result
        let call = try #require(result.calls.first)
        #expect(call.state == .cancelled)
        #expect(call.endReason == .cancel)
        #expect(result.voip.cancelledCalls == 1)
        #expect(!result.findings.contains { $0.kind == .sipFailure })
    }

    @Test func oneWayAudioIsFlagged() async throws {
        var reverse = SimImpairment.perfect
        reverse.silent = true
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call(reverse: reverse)])).result
        let call = try #require(result.calls.first)
        #expect(result.streams.count == 1)
        #expect(result.findings.contains { $0.kind == .oneWayAudio && $0.severity == .error })
        #expect(call.severity == .error)
        #expect(result.headline.text == "One-way audio · 1 call")
    }

    @Test func ssrcChangeWithoutReinvite() async throws {
        var reverse = SimImpairment.perfect
        reverse.ssrcChangeAt = 4
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call(reverse: reverse)])).result
        #expect(result.streams.count == 3)
        let changed = try #require(result.streams.first { $0.replacesSSRC != nil })
        #expect(changed.callIndex == 0)
        let finding = try #require(result.findings.first { $0.kind == .ssrcChange })
        #expect(finding.detail.contains("no re-INVITE"))
    }

    @Test func b2buaLegsAreMergedAndRelayedMediaDetected() async throws {
        let call = Fixtures.call(topology: .b2bua(Fixtures.server, anchorMedia: true))
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [call])).result
        #expect(result.sipSessions.count == 2)
        #expect(result.calls.count == 1)
        let record = try #require(result.calls.first)
        #expect(record.mergedLegs)
        #expect(record.callIDs.count == 2)
        #expect(record.streamIndices.count == 4)
        #expect(record.mediaPath == .relayed(IPAddress("10.20.0.5")!))
        #expect(record.quality?.forward?.streamIndices.count == 2)
    }

    @Test func b2buaRetryAfterFailureIsNotMergedIntoFailedCall() async throws {
        let sbc = SimHost("10.20.0.10", userAgent: "SBC")
        let carrierA = SimParty("+50322600006", "Carrier A", host: SimHost("200.31.4.10"))
        let carrierB = SimParty("+50322600006", "Carrier B", host: SimHost("190.86.2.20"))
        let failed = SimCall(start: 1, caller: Fixtures.caller, callee: carrierA, topology: .b2bua(sbc, anchorMedia: true),
                             outcome: .rejected(code: 503, reason: "Service Unavailable", fromServer: false), seed: 11)
        let retry = SimCall(start: 2.2, caller: Fixtures.caller, callee: carrierB, topology: .b2bua(sbc, anchorMedia: true),
                            outcome: .answered(talk: 8, hangupByCaller: true), codec: .pcma, forward: .perfect, reverse: .perfect, seed: 12)
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [failed, retry])).result
        #expect(result.sipSessions.count == 4)
        #expect(result.calls.count == 2)
        #expect(result.calls[0].state == .failed)
        #expect(result.calls[0].callIDs.count == 2)
        #expect(result.calls[0].streamIndices.isEmpty)
        #expect(result.calls[1].state == .completed)
        #expect(result.calls[1].callIDs.count == 2)
        #expect(result.calls[1].streamIndices.count == 4)
        #expect(result.calls[1].callee.signalling.address == IPAddress("190.86.2.20"))
    }

    @Test func lossBurstsNeedConcentratedLoss() async throws {
        // 1 % random loss: no bursts. A 3 s window at 40 % loss: exactly one burst covering it.
        let random = Fixtures.call(outcome: .answered(talk: 60, hangupByCaller: true), forward: SimImpairment(jitterMs: 0.5, randomLoss: 0.01))
        let randomResult = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [random])).result
        #expect(randomResult.streams.allSatisfy { $0.lossBursts.isEmpty })
        #expect(!randomResult.findings.contains { $0.kind == .lossBurst })

        let windowed = Fixtures.call(outcome: .answered(talk: 60, hangupByCaller: true),
                                     forward: SimImpairment(jitterMs: 0.5, lossWindows: [SimLossWindow(start: 20, end: 23, probability: 0.4)]))
        let windowedResult = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [windowed])).result
        let stream = try #require(windowedResult.streams.first { $0.source.address == IPAddress("10.20.1.23") })
        #expect(stream.lossBursts.count == 1)
        let burst = try #require(stream.lossBursts.first)
        #expect(burst.lostPackets == stream.lostPackets)
        let offset = burst.start.seconds(since: stream.firstTime)
        #expect(offset >= 19.9 && offset <= 21)
        #expect(stream.firstSequence != nil && stream.lastSequence != nil)
    }

    @Test func directCallWithoutServer() async throws {
        let call = Fixtures.call(topology: .direct, forward: SimImpairment(), reverse: SimImpairment())
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [call])).result
        #expect(result.calls.first?.messageIndices.count == 7)
        #expect(result.calls.first?.participants.count == 2)
        #expect(result.calls.first?.state == .completed)
        #expect((result.streams.first?.meanJitterMs ?? 0) > 0)  // SimImpairment() has some delay variation
    }

    @Test func calleeHangsUp() async throws {
        let call = Fixtures.call(outcome: .answered(talk: 5, hangupByCaller: false))
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [call])).result
        #expect(result.calls.first?.endReason == .byeFromCallee)
    }

    @Test func sipOverTCPWithSegmentedMessages() async throws {
        var call = Fixtures.call()
        call.sipOverTCP = true
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [call])).result
        #expect(result.calls.first?.state == .completed)
        #expect(result.calls.first?.messageIndices.count == 14)
        #expect(result.sipMessages.allSatisfy { $0.transport == .tcp })
        #expect(result.streams.count == 2)
    }

    @Test func fragmentedInviteIsReassembled() async throws {
        var call = Fixtures.call()
        call.fragmentMTU = 400
        let result = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [call])).result
        #expect(result.calls.first?.state == .completed)
        #expect(result.calls.first?.messageIndices.count == 14)
        #expect(result.streams.count == 2)
    }

    @Test func pcapngAndGzipGiveIdenticalResults() async throws {
        let capture = SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call(forward: SimImpairment(randomLoss: 0.02))])
        let plain = try await Fixtures.analyze(capture).result
        let ng = try await Fixtures.analyze(capture, format: .pcapng, fileName: "capture.pcapng").result
        #expect(ng.capture.format == .pcapng)
        #expect(ng.streams.map(\.lostPackets) == plain.streams.map(\.lostPackets))
        #expect(ng.capture.packetCount == plain.capture.packetCount)

        let directory = Fixtures.temporaryDirectory()
        let url = directory.appendingPathComponent("capture.pcap")
        try capture.write(to: url)
        try GzipWriter.gzipFile(at: url, to: url.appendingPathExtension("gz"))
        let gz = try await Fixtures.analyze(file: url.appendingPathExtension("gz"), directory: directory)
        #expect(gz.output.usedDecompressedCopy)
        #expect(gz.result.capture.compressed)
        #expect(gz.result.streams.map(\.lostPackets) == plain.streams.map(\.lostPackets))
        #expect(gz.result.capture.packetCount == plain.capture.packetCount)
    }

    @Test func capturesCanBeCopiedBeforeAnalysis() async throws {
        let directory = Fixtures.temporaryDirectory()
        let url = directory.appendingPathComponent("usb.pcap")
        try SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()]).write(to: url)
        #expect(!LocalCopy.isNeeded(for: url))  // temporary directory: internal storage
        let analysisDirectory = directory.appendingPathComponent("analysis", isDirectory: true)
        try FileManager.default.createDirectory(at: analysisDirectory, withIntermediateDirectories: true)
        let artifacts = AnalysisArtifactLocations(directory: analysisDirectory)
        let output = try await AnalysisEngine.analyze(capture: url, artifacts: artifacts, localCopy: .always)
        #expect(output.usedDecompressedCopy)
        #expect(output.analyzedCaptureURL.standardizedFileURL == artifacts.decompressedCapture.standardizedFileURL)
        #expect(try Data(contentsOf: artifacts.decompressedCapture) == Data(contentsOf: url))
        #expect(output.result.calls.count == 1)
        #expect(!FileManager.default.fileExists(atPath: artifacts.decompressedCapture.appendingPathExtension("source").path))

        // gzip input on "removable" storage: copied, then expanded.
        try GzipWriter.gzipFile(at: url, to: url.appendingPathExtension("gz"))
        let gzipDirectory = directory.appendingPathComponent("gz", isDirectory: true)
        try FileManager.default.createDirectory(at: gzipDirectory, withIntermediateDirectories: true)
        let gzipped = try await AnalysisEngine.analyze(capture: url.appendingPathExtension("gz"),
                                                       artifacts: AnalysisArtifactLocations(directory: gzipDirectory), localCopy: .always)
        #expect(gzipped.result.capture.compressed)
        #expect(gzipped.result.capture.packetCount == output.result.capture.packetCount)
    }

    @Test func corruptFileThrows() async throws {
        let directory = Fixtures.temporaryDirectory()
        let url = directory.appendingPathComponent("broken.pcap")
        try Data([0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4]).write(to: url)
        await #expect(throws: (any Error).self) {
            _ = try await Fixtures.analyze(file: url, directory: directory)
        }
    }

    @Test func analysisCanBeCancelled() async throws {
        let calls = (0..<4).map { Fixtures.call(outcome: .answered(talk: 120, hangupByCaller: true), start: Double($0) * 2, seed: UInt64($0)) }
        let directory = Fixtures.temporaryDirectory()
        let url = directory.appendingPathComponent("big.pcap")
        try SimCapture(baseTime: Fixtures.baseTime, calls: calls).write(to: url)
        let task = Task { try await Fixtures.analyze(file: url, directory: directory) }
        task.cancel()
        await #expect(throws: CancellationError.self) { _ = try await task.value }
    }
}

@Suite("Packet store & display filters")
struct PacketStoreTests {
    @Test func indexMatchesCaptureAndFiltersWork() async throws {
        var forward = SimImpairment.perfect
        forward.dropIndices = [50, 51, 52]
        let calls = [Fixtures.call(forward: forward),
                     Fixtures.call(outcome: .rejected(code: 486, reason: "Busy Here", fromServer: false), start: 20, seed: 9)]
        let analysis = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: calls))
        let store = try analysis.store()
        #expect(store.count == analysis.result.capture.packetCount)
        #expect(MemoryLayout<PacketIndexRecord>.stride == 64)

        let context = store.filterContext
        let gaps = try #require(await store.filter(try DisplayFilter("rtp.seq_gap", context: context), scope: .all, callIndex: nil))
        #expect(gaps.count == 1)
        let gapRow = store.row(at: Int(gaps[0]))
        #expect(gapRow.info.hasPrefix("Sequence gap: expected Seq="))
        #expect(gapRow.info.contains("3 packets lost"))

        let errors = try #require(await store.filter(try DisplayFilter("sip.status >= 400", context: context), scope: .all, callIndex: nil))
        #expect(errors.count == 2)  // 486 on both legs
        let combined = try #require(await store.filter(try DisplayFilter("rtp.seq_gap or sip.status >= 400", context: context), scope: .all, callIndex: nil))
        #expect(combined.count == 3)

        let callOne = try #require(await store.filter(nil, scope: .sipRTP, callIndex: 0))
        let sipAndRTP = analysis.result.calls[0].messageIndices.count + analysis.result.streams.reduce(0) { $0 + $1.packetCount }
        #expect(callOne.count == sipAndRTP)

        let byAddress = try #require(await store.filter(try DisplayFilter("ip.src == 10.20.1.23 && udp.port == 5060", context: context), scope: .all, callIndex: nil))
        #expect(!byAddress.isEmpty)
        #expect(byAddress.allSatisfy { store.row(at: Int($0)).source == "10.20.1.23" })

        let invite = try #require(await store.filter(try DisplayFilter("sip.method == INVITE", context: context), scope: .all, callIndex: nil))
        let dissected = store.dissect(at: Int(invite[0]))
        #expect(dissected.layers.map(\.name).contains("Session Initiation Protocol"))
        #expect(dissected.layers.map(\.name).contains("Session Description Protocol"))
        let callIDField = try #require(dissected.layers.flatMap(\.fields).first { $0.name == "Call-ID" })
        let range = try #require(callIDField.range)
        let text = String(decoding: dissected.bytes[range], as: UTF8.self)
        #expect(text.hasPrefix("Call-ID: "))
    }

    @Test func invalidFiltersReportErrors() {
        let context = PacketFilterContext(addresses: [nil], captureStartNanos: 0, streamSSRCs: [], streamPayloadTypes: [], sipCallIDs: [])
        #expect(throws: DisplayFilterError.self) { try DisplayFilter("sip.status >=", context: context) }
        #expect(throws: DisplayFilterError.self) { try DisplayFilter("nonsense.field == 1", context: context) }
        #expect(throws: DisplayFilterError.self) { try DisplayFilter("(sip or rtp", context: context) }
        #expect(throws: DisplayFilterError.self) { try DisplayFilter("ip.addr == 999.1.1.1", context: context) }
        #expect((try? DisplayFilter("not (sip || rtp) and frame.len > 100", context: context)) != nil)
        #expect((try? DisplayFilter("ip.addr == 10.0.0.0/8", context: context)) != nil)
    }
}

@Suite("Persistence")
struct PersistenceTests {
    @Test func roundTripsManifestAndResult() async throws {
        let analysis = try await Fixtures.analyze(SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()]))
        let library = AnalysisLibrary(rootURL: Fixtures.temporaryDirectory())
        var manifest = AnalysisManifest(displayName: "office.pcap", originalFileName: "office.pcap",
                                        originalPath: analysis.captureURL.path,
                                        bookmark: AnalysisLibrary.bookmark(for: analysis.captureURL),
                                        fileSize: 1, state: .analyzing, engineVersion: AnalysisEngine.version)
        try library.save(manifest)
        #expect(library.loadManifests().first?.state == .cancelled)  // interrupted analyses are not "running" after relaunch
        manifest.state = .ready
        manifest.summary = AnalysisSummaryInfo(result: analysis.result)
        try library.save(manifest)
        try library.saveResult(analysis.result, for: manifest.id)
        let loaded = try library.loadResult(for: manifest.id)
        #expect(loaded.calls.count == 1)
        #expect(loaded.calls[0].caller.user == "1003")
        #expect(loaded.streams.map(\.ssrc) == analysis.result.streams.map(\.ssrc))
        #expect(library.loadManifests().first?.summary?.callCount == 1)
        #expect(library.captureURL(for: manifest)?.resolvingSymlinksInPath().path
                == analysis.captureURL.resolvingSymlinksInPath().path)

        let copy = try library.duplicate(manifest, newName: "office copy.pcap")
        #expect(library.loadManifests().count == 2)
        try library.delete(copy.id)
        #expect(library.loadManifests().count == 1)
    }

    @Test func bookmarkFollowsAMovedCapture() throws {
        let directory = Fixtures.temporaryDirectory()
        let original = directory.appendingPathComponent("office.pcap")
        try SimCapture(baseTime: Fixtures.baseTime, calls: [Fixtures.call()]).write(to: original)
        let bookmark = try #require(CaptureBookmark.make(for: original))
        let moved = directory.appendingPathComponent("renamed.pcap")
        try FileManager.default.moveItem(at: original, to: moved)

        #expect(CaptureBookmark.resolve(bookmark)?.lastPathComponent == "renamed.pcap")
        let library = AnalysisLibrary(rootURL: directory.appendingPathComponent("Library"))
        let manifest = AnalysisManifest(displayName: "office.pcap", originalFileName: "office.pcap", originalPath: original.path,
                                        bookmark: bookmark, fileSize: 1, state: .ready, engineVersion: AnalysisEngine.version)
        #expect(library.originalURL(for: manifest)?.lastPathComponent == "renamed.pcap")

        try FileManager.default.removeItem(at: moved)
        #expect(library.originalURL(for: manifest) == nil)
        #expect(CaptureBookmark.resolve(Data([1, 2, 3])) == nil)
    }
}

@Suite("E-model")
struct EModelTests {
    @Test func referenceValues() {
        #expect(abs(EModel.mos(fromR: 93.2) - 4.41) < 0.01)
        #expect(EModel.mos(fromR: 0) == 1)
        #expect(EModel.mos(fromR: 100) == 4.5)
        // G.729A: Ie = 11 → R = 82.2 at zero loss.
        #expect(abs((EModel.rFactor(codec: .g729, packetLossPercent: 0) ?? 0) - 82.2) < 1e-9)
        // G.711 with PLC, 2 % random loss: Ie,eff = 95 * 2 / (2 + 25.1).
        let expected = 93.2 - 95 * 2 / (2 + 25.1)
        #expect(abs((EModel.rFactor(codec: .pcmu, packetLossPercent: 2) ?? 0) - expected) < 1e-9)
        // Bursty loss is worse than random loss.
        #expect(EModel.rFactor(codec: .pcmu, packetLossPercent: 2, burstRatio: 2)! < EModel.rFactor(codec: .pcmu, packetLossPercent: 2)!)
        // No invented values for codecs without parameters.
        #expect(EModel.mos(codec: .opus, packetLossPercent: 0) == nil)
        #expect(EModel.delayImpairment(oneWayDelayMs: 80) == 0)
        #expect(EModel.delayImpairment(oneWayDelayMs: 300) > 10)
    }
}
