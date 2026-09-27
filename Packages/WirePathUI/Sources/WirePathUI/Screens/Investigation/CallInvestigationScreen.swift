import WirePathCore
import SwiftUI

/// Call Investigation (design board "Call Investigation — Dark/Light").
struct CallInvestigationScreen: View {
    @Environment(WindowModel.self) private var window
    @Environment(LibraryModel.self) private var library
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    let callIndex: Int

    enum Section: String, CaseIterable, Hashable {
        case summary, sipFlow, rtp, timeline

        var localizedTitle: String {
            switch self {
            case .summary: return String(localized: "Summary")
            case .sipFlow: return String(localized: "SIP Flow")
            case .rtp: return String(localized: "RTP")
            case .timeline: return String(localized: "Timeline")
            }
        }
    }

    @State private var section: Section = .summary
    @State private var search = ""
    @State private var selectedMessage: Int?
    @State private var showSDP = true
    @State private var player = AudioPlaybackModel()
    @FocusState private var focused: Bool

    private var call: CallRecord { document.result.calls[callIndex] }
    private var result: AnalysisResult { document.result }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "Call \(Formatters.clock(call.startTime))"),
                      subtitle: String(localized: "\(document.manifest.displayName) · Call \(callIndex + 1) of \(result.calls.count)"),
                      backHelp: String(localized: "Back to Calls (⌘[)")) {
                headerControls
            }
            ScrollViewReader { proxy in
                ScrollView(.vertical) {
                    VStack(spacing: 14) {
                        titleRow
                        CallSummaryCard(call: call, result: result).id(Section.summary)
                        if layoutWidth == .wide {
                            HStack(alignment: .top, spacing: 14) {
                                ladder.frame(width: 620)
                                RTPAnalysisCard(call: call, result: result).id(Section.rtp)
                            }
                            .frame(height: 540)
                        } else {
                            ladder.frame(height: 540)
                            RTPAnalysisCard(call: call, result: result).id(Section.rtp).frame(height: 560)
                        }
                        if layoutWidth >= .regular {
                            HStack(spacing: 14) {
                                JitterChartCard(call: call, result: result)
                                LossChartCard(call: call, result: result)
                            }
                            .frame(height: 214)
                        } else {
                            JitterChartCard(call: call, result: result).frame(height: 214)
                            LossChartCard(call: call, result: result).frame(height: 214)
                        }
                        AudioCard(model: player, document: document, callIndex: callIndex,
                                  exportName: String(localized: "Call \(Formatters.clock(call.startTime).replacingOccurrences(of: ":", with: "-"))"),
                                  subtitle: String(localized: "Reconstructed from RTP · caller left, callee right"))
                        CallTimelineCard(call: call, result: result).id(Section.timeline)
                    }
                    .padding(EdgeInsets(top: 18, leading: layoutWidth == .compact ? 14 : 22, bottom: 16,
                                        trailing: layoutWidth == .compact ? 14 : 22))
                }
                .onChange(of: section) { _, target in
                    withAnimationIfAllowed(.easeInOut(duration: 0.25)) { proxy.scrollTo(target, anchor: .top) }
                }
            }
        }
        .focusable()
        .focusEffectDisabled()
        .focused($focused)
        .onAppear {
            document.selectedCall = callIndex
            focused = true
            player.offer(call: call, result: result)
            player.preload(document: document, callIndex: callIndex)
        }
        .onChange(of: callIndex) { _, _ in
            player.offer(call: call, result: result)
            player.preload(document: document, callIndex: callIndex)
        }
        .onDisappear { player.stop() }
        .onKeyPress(.space) {
            togglePlayback()
            return .handled
        }
    }

    private var ladder: some View {
        SIPLadderCard(document: document, call: call, selectedMessage: $selectedMessage, showSDP: $showSDP, search: search)
            .id(Section.sipFlow)
    }

    // MARK: Header

    @ViewBuilder private var headerControls: some View {
        HStack(spacing: 0) {
            IconButton(icon: Icons.up, iconSize: 14, width: 32, height: 28, help: String(localized: "Previous Call (⌘↑)")) { window.stepCall(-1) }
            Rectangle().fill(Theme.line2).frame(width: 1, height: 16)
            IconButton(icon: Icons.down, iconSize: 14, width: 32, height: 28, help: String(localized: "Next Call (⌘↓)")) { window.stepCall(1) }
        }
        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.ctrl))
        let playHelp = player.canPlay ? String(localized: "Play / pause call audio (Space)")
            : AudioPlaybackModel.reason(player.tracks.first?.playability)
        if layoutWidth == .wide {
            PillButton(icon: player.isPlaying ? Icons.pause : Icons.play,
                       title: player.isPlaying ? String(localized: "Pause Audio") : String(localized: "Play Audio"),
                       help: playHelp, isEnabled: player.canPlay) { togglePlayback() }
            PillButton(icon: Icons.packets, iconSize: 14, title: String(localized: "Show Packets"), help: String(localized: "Show Packets (⇧⌘P)")) {
                window.showPackets(forCall: callIndex)
            }
        } else {
            IconButton(icon: player.isPlaying ? Icons.pause : Icons.play, iconSize: 13, help: playHelp,
                       isEnabled: player.canPlay) { togglePlayback() }
            IconButton(icon: Icons.packets, iconSize: 15, help: String(localized: "Show Packets (⇧⌘P)")) {
                window.showPackets(forCall: callIndex)
            }
        }
        IconButton(icon: Icons.export, iconSize: 17, help: String(localized: "Export Call Report (⇧⌘E)")) {
            window.exportReport()
        }
        if layoutWidth > .compact {
            SearchField(placeholder: String(localized: "Search in call"), text: $search, width: layoutWidth == .wide ? 220 : 160,
                        focusRequest: window.searchFocusRequest)
        }
    }

    private func togglePlayback() {
        guard player.canPlay else { return }
        player.togglePlayback(document: document, callIndex: callIndex)
    }

    // MARK: Title

    @ViewBuilder private var titleRow: some View {
        let parties = HStack(spacing: 10) {
            partyTitle(call.caller.user, call.caller.displayName)
            Icon(Icons.arrowRight, size: 16).foregroundStyle(Theme.fg3).accessibilityLabel("to")
            partyTitle(call.callee.user, call.callee.displayName)
        }
        let jump = SegmentedControl(items: Section.allCases.map { .init(value: $0, title: $0.localizedTitle) }, selection: $section,
                                    horizontalPadding: 12)
            .accessibilityLabel("Jump to section")
        if layoutWidth == .wide {
            HStack(alignment: .bottom, spacing: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    parties
                    HStack(spacing: 6) { chips }
                }
                Spacer(minLength: 8)
                jump
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                parties
                FlowLayout(spacing: 6) { chips }
                jump
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func partyTitle(_ user: String, _ name: String?) -> some View {
        HStack(spacing: 6) {
            Text(user).font(.wp(20, .bold))
            if let name { Text(name).font(.wp(20)).foregroundStyle(Theme.fg2) }
        }
        .tracking(-0.2)
        .foregroundStyle(Theme.fg)
        .lineLimit(1)
    }

    @ViewBuilder private var chips: some View {
        if let mos = call.quality?.mos {
            let severity = QualityThresholds.severity(mos: mos)
            HStack(spacing: 5) {
                if severity != .ok { StatusIcon(severity: severity, size: 11, plain: true) } else { StatusIcon(severity: .ok, size: 11, plain: true) }
                Text(verbatim: "\(QualityRating(mos: mos).localizedName) · MOS \(String(format: "%.2f", mos))")
            }
            .font(.wp(11.5, .semibold))
            .foregroundStyle(severity == .ok ? Theme.ok : severity.color)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 6).fill(severity == .ok ? Theme.okBg : severity.background))
        } else if call.state.isFailure {
            HStack(spacing: 5) {
                StatusIcon(severity: .error, size: 11, plain: true)
                Text("Failed")
            }
            .font(.wp(11.5, .semibold)).foregroundStyle(Theme.err)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 6).fill(Theme.errBg))
        }
        tag(call.state.wasAnswered ? "\(call.statusLabel) · \(call.endReason.label)" : call.statusLabel)
        if let codec = call.codec {
            Chip(text: codec.displayName + (call.ptimeMs.map { " · \($0) ms" } ?? ""), fontSize: 11, foreground: Theme.fg2)
        }
        if call.state.wasAnswered { tag(call.mediaPath.label) }
        if call.mergedLegs { tag(String(localized: "\(call.callIDs.count) legs · B2BUA")) }
    }

    private func tag(_ text: String) -> some View {
        Text(text).font(.wp(11.5)).foregroundStyle(Theme.fg2)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 6).fill(Theme.ctrl))
    }
}

// MARK: - Summary card

struct CallSummaryCard: View {
    @Environment(\.layoutWidth) private var layoutWidth
    var call: CallRecord
    var result: AnalysisResult

    var body: some View {
        Group {
            if layoutWidth == .wide { wideGrid } else { compactGrid }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 14)
        .card()
    }

    /// Narrower widths: Call-ID on its own row, the other fields in an adaptive grid.
    private var compactGrid: some View {
        VStack(alignment: .leading, spacing: 14) {
            callIDField
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 20, alignment: .topLeading)], alignment: .leading, spacing: 14) {
                field("Caller") { value("\(call.caller.user)\(call.caller.displayName.map { " · \($0)" } ?? "")") }
                field("Callee") { value("\(call.callee.user)\(call.callee.displayName.map { " · \($0)" } ?? "")") }
                field("Codec") { codecValue }
                field("Start") { value(Formatters.clockMillis(call.startTime)) }
                field("End") { value(Formatters.clockMillis(call.endTime)) }
                field("Duration") { durationValue }
                field("Source IP") { Text(call.caller.signalling.description).font(.wpMono(12.5)).textSelection(.enabled) }
                field("Destination IP") { Text(call.callee.signalling.description).font(.wpMono(12.5)).textSelection(.enabled) }
            }
        }
    }

    private var callIDField: some View {
        field("Call-ID") {
            HStack(spacing: 8) {
                Text(call.callIDs.first ?? "").font(.wpMono(12.5)).lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
                Button { Clipboard.copy(call.callIDs.joined(separator: "\n")) } label: {
                    Icon(Icons.copy, size: 14).foregroundStyle(Theme.fg3)
                }
                .buttonStyle(.plain)
                .help("Copy Call-ID")
                .accessibilityLabel("Copy Call-ID")
            }
        }
    }

    @ViewBuilder private var codecValue: some View {
        if let codec = call.codec {
            (Text(codec.displayName) + Text(codecDetail(codec)).foregroundColor(Theme.fg3)).font(.wp(13)).lineLimit(1)
        } else {
            value("—")
        }
    }

    private var durationValue: some View {
        (Text(Formatters.durationMillis(call.talkDurationSeconds ?? call.totalDurationSeconds))
         + Text(call.setupSeconds.map { String(localized: " · setup \(String(format: "%.2f", $0)) s") } ?? "").foregroundColor(Theme.fg3))
            .font(.wp(13)).lineLimit(1)
    }

    private var wideGrid: some View {
        Grid(alignment: .topLeading, horizontalSpacing: 20, verticalSpacing: 14) {
            GridRow {
                field("Call-ID") {
                    HStack(spacing: 8) {
                        Text(call.callIDs.first ?? "").font(.wpMono(12.5)).lineLimit(1).truncationMode(.middle)
                            .textSelection(.enabled)
                        Button {
                            Clipboard.copy(call.callIDs.joined(separator: "\n"))
                        } label: { Icon(Icons.copy, size: 14).foregroundStyle(Theme.fg3) }
                            .buttonStyle(.plain)
                            .help("Copy Call-ID")
                            .accessibilityLabel("Copy Call-ID")
                    }
                }
                .gridCellColumns(2)
                field("Caller") { value("\(call.caller.user)\(call.caller.displayName.map { " · \($0)" } ?? "")") }
                field("Callee") { value("\(call.callee.user)\(call.callee.displayName.map { " · \($0)" } ?? "")") }
                field("Codec") {
                    if let codec = call.codec {
                        (Text(codec.displayName) + Text(codecDetail(codec)).foregroundColor(Theme.fg3)).font(.wp(13)).lineLimit(1)
                    } else {
                        value("—")
                    }
                }
            }
            GridRow {
                field("Start") { value(Formatters.clockMillis(call.startTime)) }
                field("End") { value(Formatters.clockMillis(call.endTime)) }
                field("Duration") {
                    (Text(Formatters.durationMillis(call.talkDurationSeconds ?? call.totalDurationSeconds))
                     + Text(call.setupSeconds.map { String(localized: " · setup \(String(format: "%.2f", $0)) s") } ?? "").foregroundColor(Theme.fg3))
                        .font(.wp(13)).lineLimit(1)
                }
                field("Source IP") { Text(call.caller.signalling.description).font(.wpMono(12.5)).textSelection(.enabled) }
                field("Destination IP") { Text(call.callee.signalling.description).font(.wpMono(12.5)).textSelection(.enabled) }
            }
        }
    }

    private func codecDetail(_ codec: CodecDescriptor) -> String {
        var parts = ["PT \(codec.payloadType)"]
        if let rate = codec.sampleRate { parts.append(rate % 1000 == 0 ? String(localized: "\(rate / 1000) kHz") : String(format: String(localized: "%.1f kHz"), Double(rate) / 1000)) }
        return " · " + parts.joined(separator: " · ")
    }

    private func field<Content: View>(_ label: LocalizedStringKey, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
            content().foregroundStyle(Theme.fg)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func value(_ text: String) -> some View {
        Text(text).font(.wp(13)).lineLimit(1).monospacedDigit()
    }
}

// MARK: - RTP analysis card

struct RTPAnalysisCard: View {
    var call: CallRecord
    var result: AnalysisResult

    var body: some View {
        let quality = call.quality
        let directions = [quality?.forward, quality?.reverse]
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "RTP Analysis"), subtitle: subtitle)
            if quality == nil {
                Text(call.state.wasAnswered ? String(localized: "No RTP was captured for this call.") : String(localized: "The call was not answered, so no media was exchanged."))
                    .font(.wp(12)).foregroundStyle(Theme.fg3)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 0) {
                        Text("Field").frame(width: 148, alignment: .leading)
                        directionHeader(Theme.m1, "\(call.caller.user) → \(call.callee.user)")
                        directionHeader(Theme.m2, "\(call.callee.user) → \(call.caller.user)")
                    }
                    .font(.wp(11.5, .semibold))
                    .foregroundStyle(Theme.fg2)
                    .padding(.horizontal, 14)
                    .frame(height: 30)
                    .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
                    let rows = makeRows(directions)
                    ForEach(Array(rows.enumerated()), id: \.offset) { offset, row in
                        HStack(spacing: 0) {
                            Text(row.label).foregroundStyle(Theme.fg2).frame(width: 148, alignment: .leading)
                            cell(row.a, mono: row.mono, emphasis: row.aEmphasis)
                            cell(row.b, mono: row.mono, emphasis: row.bEmphasis)
                        }
                        .font(.wp(12))
                        .monospacedDigit()
                        .padding(.horizontal, 14)
                        .frame(height: 25)
                        .background(offset % 2 == 1 ? Theme.stripe : .clear)
                    }
                }
                .padding(.vertical, 4)
            }
            Spacer(minLength: 0)
            notes
        }
        .card()
    }

    private var subtitle: String {
        let count = call.streamIndices.count
        return String(localized: "\(count) streams · \(call.mediaPath.label.lowercased())")
    }

    private func directionHeader(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 6) {
            RoundedRectangle(cornerRadius: 2).fill(color).frame(width: 10, height: 3)
            Text(text).foregroundStyle(Theme.fg)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func cell(_ text: String, mono: Bool, emphasis: Color?) -> some View {
        Text(text)
            .font(mono ? .wpMono(11.5) : .wp(12))
            .fontWeight(emphasis == nil ? .regular : .semibold)
            .foregroundStyle(emphasis ?? Theme.fg)
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
    }

    struct Row {
        var label: String
        var a: String
        var b: String
        var mono = false
        var aEmphasis: Color?
        var bEmphasis: Color?
    }

    private func makeRows(_ directions: [DirectionQuality?]) -> [Row] {
        func streams(_ d: DirectionQuality?) -> [RTPStreamRecord] { d?.streamIndices.map { result.streams[$0] } ?? [] }
        let a = streams(directions[0]), b = streams(directions[1])
        func first(_ s: [RTPStreamRecord], _ f: (RTPStreamRecord) -> String) -> String {
            let values = s.map(f)
            var unique: [String] = []
            for v in values where !unique.contains(v) { unique.append(v) }
            return unique.isEmpty ? "—" : unique.joined(separator: " / ")
        }
        func color(_ severity: Severity) -> Color? { severity == .ok || severity == .info ? nil : severity.color }
        let da = directions[0], db = directions[1]
        func codecText(_ s: [RTPStreamRecord]) -> String {
            guard let stream = s.max(by: { $0.packetCount < $1.packetCount }) else { return "—" }
            var parts = [stream.codecName]
            if let rate = stream.codec?.sampleRate { parts.append(String(localized: "\(rate / 1000) kHz")) }
            if let ptime = stream.ptimeMs { parts.append(String(localized: "\(Int(ptime.rounded())) ms")) }
            return parts.joined(separator: " · ")
        }
        func duration(_ s: [RTPStreamRecord]) -> String {
            guard let start = s.map(\.firstTime).min(), let end = s.map(\.lastTime).max() else { return "—" }
            return String(format: "%.2f s", end.seconds(since: start))
        }
        let ssrcChangedA = a.count > 1, ssrcChangedB = b.count > 1
        return [
            Row(label: String(localized: "Source IP"), a: first(a) { "\($0.source.address)" }, b: first(b) { "\($0.source.address)" }, mono: true),
            Row(label: String(localized: "Source Port"), a: first(a) { "\($0.source.port)" }, b: first(b) { "\($0.source.port)" }, mono: true),
            Row(label: String(localized: "Destination IP"), a: first(a) { "\($0.destination.address)" }, b: first(b) { "\($0.destination.address)" }, mono: true),
            Row(label: String(localized: "Destination Port"), a: first(a) { "\($0.destination.port)" }, b: first(b) { "\($0.destination.port)" }, mono: true),
            Row(label: String(localized: "SSRC"), a: a.isEmpty ? "—" : a.map(\.ssrcHex).joined(separator: " → "),
                b: b.isEmpty ? "—" : b.map(\.ssrcHex).joined(separator: " → "), mono: true,
                aEmphasis: ssrcChangedA ? Theme.acc : nil, bEmphasis: ssrcChangedB ? Theme.acc : nil),
            Row(label: String(localized: "Payload Type"), a: first(a) { "\($0.payloadType)" }, b: first(b) { "\($0.payloadType)" }),
            Row(label: String(localized: "Codec"), a: codecText(a), b: codecText(b)),
            Row(label: String(localized: "Packets"), a: da.map { Formatters.count($0.packets) } ?? "—", b: db.map { Formatters.count($0.packets) } ?? "—"),
            Row(label: String(localized: "Lost Packets"), a: da.map { "\(max(0, $0.lost))" } ?? "—", b: db.map { "\(max(0, $0.lost))" } ?? "—"),
            Row(label: String(localized: "Packet Loss"), a: da.map { String(format: "%.2f%%", $0.lossPercent) } ?? "—",
                b: db.map { String(format: "%.2f%%", $0.lossPercent) } ?? "—",
                aEmphasis: color(QualityThresholds.severity(lossPercent: da?.lossPercent)),
                bEmphasis: color(QualityThresholds.severity(lossPercent: db?.lossPercent))),
            Row(label: String(localized: "Average Jitter"), a: Formatters.ms(da?.meanJitterMs), b: Formatters.ms(db?.meanJitterMs),
                aEmphasis: color(QualityThresholds.severity(jitterMs: da?.meanJitterMs)),
                bEmphasis: color(QualityThresholds.severity(jitterMs: db?.meanJitterMs))),
            Row(label: String(localized: "Maximum Jitter"), a: Formatters.ms(da?.maxJitterMs), b: Formatters.ms(db?.maxJitterMs),
                aEmphasis: (da?.maxJitterMs ?? 0) > QualityThresholds.jitterSpikeMs ? Theme.warn : nil,
                bEmphasis: (db?.maxJitterMs ?? 0) > QualityThresholds.jitterSpikeMs ? Theme.warn : nil),
            Row(label: String(localized: "Max Delta"), a: a.isEmpty ? "—" : String(format: "%.1f ms", a.map(\.maxDeltaMs).max() ?? 0),
                b: b.isEmpty ? "—" : String(format: "%.1f ms", b.map(\.maxDeltaMs).max() ?? 0)),
            Row(label: String(localized: "Out-of-order"), a: da.map { "\($0.outOfOrder)" } ?? "—", b: db.map { "\($0.outOfOrder)" } ?? "—"),
            Row(label: String(localized: "Duplicates"), a: da.map { "\($0.duplicates)" } ?? "—", b: db.map { "\($0.duplicates)" } ?? "—"),
            Row(label: String(localized: "MOS (est.)"), a: Formatters.mos(da?.mos), b: Formatters.mos(db?.mos),
                aEmphasis: color(QualityThresholds.severity(mos: da?.mos)), bEmphasis: color(QualityThresholds.severity(mos: db?.mos))),
            Row(label: String(localized: "Duration"), a: duration(a), b: duration(b)),
        ]
    }

    @ViewBuilder private var notes: some View {
        let kinds: Set<FindingKind> = [.lossBurst, .ssrcChange, .oneWayAudio, .noMedia, .jitterSpike, .outOfOrder, .sipRetransmissions, .sipFailure, .noFinalResponse]
        let items = call.findingIndices.map { result.findings[$0] }.filter { kinds.contains($0.kind) }.prefix(4)
        if !items.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(items), id: \.id) { finding in
                    FindingLine(finding: finding)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
        }
    }
}

/// "⚠ Loss burst at +52.4 – 55.1 s · 31 packets, both directions" (primary text + secondary detail).
struct FindingLine: View {
    var finding: Finding

    var body: some View {
        let parts = finding.detail.components(separatedBy: " · ")
        HStack(spacing: 8) {
            StatusIcon(severity: finding.severity, size: 12)
            Text(parts.first ?? finding.detail).foregroundStyle(Theme.fg).lineLimit(1).layoutPriority(1)
            if parts.count > 1 {
                Text("· " + parts.dropFirst().joined(separator: " · ")).foregroundStyle(Theme.fg2).lineLimit(1)
            }
        }
        .font(.wp(12))
    }
}
