import WirePathCore
import SwiftUI

/// RTP Streams: per-SSRC statistics for every stream in the capture.
struct RTPStreamsScreen: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    @State private var search = ""
    @State private var onlyIssues = false
    @State private var player = AudioPlaybackModel()

    private var result: AnalysisResult { document.result }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "RTP Streams"),
                      subtitle: String(localized: "\(document.manifest.displayName) · \(result.streams.count) streams · \(result.capture.rtpPackets) packets")) {
                SearchField(placeholder: String(localized: "Search SSRC, IP, codec"), text: $search,
                            width: layoutWidth == .wide ? 250 : 170, focusRequest: window.searchFocusRequest)
            }
            VStack(spacing: 14) {
                HStack(alignment: .bottom, spacing: 16) {
                    ScreenTitle(title: String(localized: "RTP Streams"), subtitle: subtitle)
                    Spacer(minLength: 8)
                    SegmentedControl(items: [.init(value: false, title: String(localized: "All \(result.streams.count)")),
                                             .init(value: true, title: String(localized: "With Issues \(issueStreams.count)"))],
                                     selection: $onlyIssues)
                }
                MetricStrip(items: metrics)
                DataTable(columns: columns, ids: visible, selection: $document.selectedStream,
                          emptyText: result.streams.isEmpty ? String(localized: "No RTP streams in this capture") : String(localized: "No streams match"),
                          cells: cells, onOpen: open, menu: { id in AnyView(menu(id)) })
                if let selected = document.selectedStream, selected < result.streams.count {
                    StreamDetailCard(stream: result.streams[selected], result: result, player: player, document: document)
                }
            }
            .padding(EdgeInsets(top: 18, leading: 22, bottom: 16, trailing: 22))
            FooterBar(leading: String(localized: "\(visible.count) of \(result.streams.count) streams"),
                      trailing: document.selectedStream.map { String(localized: "Selected \(result.streams[$0].ssrcHex)") } ?? String(localized: "No selection"))
        }
        .onAppear { if document.selectedStream == nil { document.selectedStream = issueStreams.first ?? result.streams.indices.first } }
        .onChange(of: document.selectedStream, initial: true) { _, selected in
            if let selected, selected < result.streams.count {
                player.offer(stream: result.streams[selected])
                player.preload(document: document, callIndex: nil)
            }
        }
        .onDisappear { player.stop() }
    }

    private var subtitle: String {
        let negotiated = result.streams.filter(\.negotiatedInSDP).count
        return String(localized: "\(negotiated) negotiated in SDP · \(result.streams.count - negotiated) detected heuristically · \(Set(result.streams.compactMap(\.callIndex)).count) calls")
    }

    private func severity(_ s: RTPStreamRecord) -> Severity {
        max(QualityThresholds.severity(mos: s.mos), QualityThresholds.severity(jitterMs: s.meanJitterMs),
            QualityThresholds.severity(lossPercent: s.lossPercent))
    }

    private var issueStreams: [Int] { result.streams.indices.filter { severity(result.streams[$0]) >= .warning } }

    private var visible: [Int] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        let base = onlyIssues ? issueStreams : Array(result.streams.indices)
        guard !query.isEmpty else { return base }
        return base.filter { index in
            let s = result.streams[index]
            return [s.ssrcHex, s.source.description, s.destination.description, s.codecName].contains { $0.lowercased().contains(query) }
        }
    }

    private var metrics: [MetricStrip.Item] {
        let streams = result.streams
        let lost = streams.reduce(0) { $0 + max(0, $1.lostPackets) }
        let expected = streams.reduce(0) { $0 + $1.expectedPackets }
        let jitters = streams.compactMap(\.meanJitterMs)
        return [
            .init(label: String(localized: "Streams"), value: "\(streams.count)", caption: String(localized: "\(Set(streams.map(\.ssrc)).count) SSRCs")),
            .init(label: String(localized: "RTP Packets"), value: Formatters.count(streams.reduce(0) { $0 + $1.packetCount }),
                  caption: Formatters.bytes(streams.reduce(0) { $0 + $1.payloadBytes }) + String(localized: " payload")),
            .init(label: String(localized: "Lost"), value: Formatters.count(lost),
                  caption: expected > 0 ? String(format: "%.2f%% of %@ expected", Double(lost) / Double(expected) * 100, Formatters.count(expected)) : nil,
                  color: lost > 0 ? Theme.warn : Theme.fg),
            .init(label: String(localized: "Mean Jitter"), value: jitters.isEmpty ? "—" : String(format: "%.1f", jitters.reduce(0, +) / Double(jitters.count)),
                  unit: jitters.isEmpty ? nil : "ms", caption: streams.compactMap(\.maxJitterMs).max().map { String(format: "max %.1f ms", $0) }),
            .init(label: String(localized: "Out-of-order"), value: Formatters.count(streams.reduce(0) { $0 + $1.outOfOrderPackets })),
            .init(label: String(localized: "Duplicates"), value: Formatters.count(streams.reduce(0) { $0 + $1.duplicatePackets })),
        ]
    }

    private var columns: [ColumnSpec] {
        [.fixed("", 30, .center), .fixed(String(localized: "SSRC"), 104), .flexible(String(localized: "Source"), from: .regular),
         .flexible(String(localized: "Destination"), from: .regular), .fixed(String(localized: "Codec"), 90), .fixed(String(localized: "Packets"), 70, .trailing, from: .regular),
         .fixed(String(localized: "Lost"), 90, .trailing), .fixed(String(localized: "OOO"), 50, .trailing, from: .wide), .fixed(String(localized: "Jitter"), 72, .trailing),
         .fixed(String(localized: "Max Jitter"), 80, .trailing, from: .wide), .fixed(String(localized: "Rate"), 84, .trailing, from: .wide),
         .fixed(String(localized: "Duration"), 70, .trailing, from: .wide),
         .fixed(String(localized: "MOS"), 50, .trailing), .fixed("", 12, from: .wide), .fixed(String(localized: "Call"), 64, from: .regular)]
    }

    private func cells(_ index: Int) -> [CellValue] {
        let s = result.streams[index]
        func color(_ severity: Severity) -> Color? { severity == .error ? Theme.err : severity == .warning ? Theme.warn : nil }
        return [.status(severity(s)), .mono(s.ssrcHex), .mono(s.source.description), .mono(s.destination.description),
                .text(s.codecName), .text(Formatters.count(s.packetCount)),
                .text("\(max(0, s.lostPackets)) · \(String(format: "%.2f%%", s.lossPercent))", color: color(QualityThresholds.severity(lossPercent: s.lossPercent))),
                .text("\(s.outOfOrderPackets)"),
                .text(Formatters.ms(s.meanJitterMs), color: color(QualityThresholds.severity(jitterMs: s.meanJitterMs))),
                .text(Formatters.ms(s.maxJitterMs), color: (s.maxJitterMs ?? 0) > QualityThresholds.jitterSpikeMs ? Theme.warn : nil),
                .text(s.wireBitrate.map { Formatters.bits($0) } ?? "—", color: Theme.fg2),
                .text(String(format: "%.1f s", s.durationSeconds)),
                .text(Formatters.mos(s.mos), color: color(QualityThresholds.severity(mos: s.mos)), weight: .medium), .text(""),
                .text(s.callIndex.map { Formatters.clock(result.calls[$0].startTime) } ?? "—", color: Theme.fg2)]
    }

    private func open(_ index: Int) {
        if let call = result.streams[index].callIndex { window.investigate(call) }
    }

    @ViewBuilder private func menu(_ index: Int) -> some View {
        let stream = result.streams[index]
        if let call = stream.callIndex {
            Button("Investigate Call") { window.investigate(call) }
            Button("Show Packets") { window.showPackets(forCall: call) }
        }
        Button("Copy SSRC") {
            Clipboard.copy(stream.ssrcHex)
        }
    }
}

/// Details of the selected stream (sequence numbers, timing, E-model inputs).
struct StreamDetailCard: View {
    @Environment(WindowModel.self) private var window
    var stream: RTPStreamRecord
    var result: AnalysisResult
    var player: AudioPlaybackModel
    var document: AnalysisDocument

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Stream \(stream.ssrcHex)"), subtitle: "\(stream.source) → \(stream.destination)") {
                Text(stream.negotiatedInSDP ? String(localized: "Negotiated in SDP") : String(localized: "Detected heuristically (no SDP)"))
                    .font(.wp(11)).foregroundStyle(stream.negotiatedInSDP ? Theme.fg3 : Theme.warn)
                PillButton(icon: player.isPlaying ? Icons.pause : Icons.play,
                           title: player.isPlaying ? String(localized: "Pause") : String(localized: "Play"),
                           help: player.canPlay ? String(localized: "Play the stream's audio")
                               : AudioPlaybackModel.reason(player.tracks.first?.playability),
                           isEnabled: player.canPlay) {
                    player.togglePlayback(document: document, callIndex: nil)
                }
                .accessibilityIdentifier("stream.play")
                IconButton(icon: Icons.export, iconSize: 16, help: String(localized: "Export the stream's audio as WAV"),
                           isEnabled: player.canPlay) {
                    player.exportWAV(document: document, callIndex: nil, name: String(localized: "Stream \(stream.ssrcHex)"), into: window)
                }
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 24, alignment: .topLeading)], alignment: .leading, spacing: 10) {
                item("Payload", "\(stream.codecName) · PT \(stream.payloadType)")
                item("Clock / Sample rate", [stream.codec?.clockRate.map { String(localized: "\($0) Hz") }, stream.codec?.sampleRate.map { String(localized: "\($0) Hz") }]
                    .compactMap { $0 }.joined(separator: " / ").nilIfEmpty ?? String(localized: "Unknown"))
                item("Packetization", stream.ptimeMs.map { String(localized: "\(Int($0.rounded())) ms") } ?? "—")
                item("Sequence", sequenceText)
                item("Expected / Received", "\(Formatters.count(stream.expectedPackets)) / \(Formatters.count(stream.packetCount))")
                item("Sequence gaps", "\(stream.sequenceGaps)")
                item("Inter-arrival", String(format: "mean %.1f ms · max %.1f ms", stream.meanDeltaMs, stream.maxDeltaMs))
                item("Markers · PT changes", "\(stream.markerPackets) · \(stream.payloadTypeChanges)")
                item("Loss bursts", stream.lossBursts.isEmpty ? String(localized: "None") : stream.lossBursts.map { String(localized: "\($0.lostPackets) pkts") }.joined(separator: ", "))
                item("E-model", stream.rFactor.map { String(format: "R %.1f · BurstR %.2f", $0, stream.burstRatio) } ?? String(localized: "No parameters for \(stream.codecName)"))
                item("Packet rate", stream.packetsPerSecond.map { String(format: "%.1f pkt/s", $0) } ?? "—")
                item("Audio", audioText)
                item("Bitrate (payload · wire)", [stream.payloadBitrate, stream.wireBitrate].map { $0.map { Formatters.bits($0) + "/s" } ?? "—" }
                    .joined(separator: " · "))
                if let rtcp = stream.rtcp {
                    item("RTCP", String(localized: "\(rtcp.senderReports) SR · \(rtcp.receiverReports) RR") + (rtcp.cname.map { " · \($0)" } ?? ""))
                    item("Receiver-reported loss", rtcp.maxFractionLostPercent.map { String(format: "max %.1f%% · cumulative %d", $0, rtcp.lastCumulativeLost ?? 0) } ?? "—")
                    item("Receiver-reported jitter", rtcp.maxReportedJitterMs.map { String(format: "max %.1f ms", $0) } ?? "—")
                    item("Round trip (RTCP)", rtcp.roundTripMs.map { String(format: "%.1f ms mean · %.1f–%.1f ms", $0.mean, $0.min, $0.max) } ?? "—")
                    if let metrics = rtcp.voipMetrics {
                        item("Endpoint-reported (XR)", [metrics.mosLQ.map { String(format: "MOS-LQ %.1f", $0) }, metrics.rFactor.map { "R \($0)" },
                                                        String(format: "loss %.1f%%", metrics.lossRate * 100)].compactMap { $0 }.joined(separator: " · "))
                    }
                }
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 14, trailing: 14))
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .card()
    }

    private var audioText: String {
        if player.isPlaying || player.currentTime > 0 {
            return "\(AudioCard.clock(player.currentTime)) / \(AudioCard.clock(player.duration))"
        }
        switch player.state {
        case .preparing: return String(localized: "Decoding…")
        case .unavailable(let message): return message
        default:
            guard let track = player.tracks.first else { return "—" }
            if let audio = track.audio {
                return String(format: "%.1f s", audio.durationSeconds) + (audio.dtmf.isEmpty ? "" : " · DTMF " + audio.dtmf.map(\.key).joined(separator: " "))
            }
            if case .playable(let decoder) = track.playability { return decoder }
            return AudioPlaybackModel.reason(track.playability)
        }
    }

    private var sequenceText: String {
        guard let first = stream.firstSequence, let last = stream.lastSequence else { return "—" }
        let cycles = stream.sequenceCycles ?? 0
        return cycles > 0 ? String(localized: "\(first) → \(last) (\(cycles) wraps)") : "\(first) → \(last)"
    }

    private func item(_ label: LocalizedStringKey, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
            Text(value).font(.wp(12.5)).foregroundStyle(Theme.fg).lineLimit(1).monospacedDigit().textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
