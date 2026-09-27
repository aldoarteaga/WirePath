import WirePathCore
import SwiftUI

/// Overview (design board "Overview — Dark/Light").
struct OverviewScreen: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument

    private var result: AnalysisResult { document.result }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: document.manifest.displayName,
                      subtitle: "\(Formatters.bytes(document.manifest.fileSize)) · \(Formatters.range(result.capture.firstPacketTime, result.capture.lastPacketTime))") {
                OverviewHeaderControls(document: document)
            }
            HStack(spacing: 0) {
                // Measured on its own: with the inspector open the cards get less room than the window suggests.
                OverviewContent(document: document)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .adaptiveLayoutWidth()
                if window.inspectorVisible && layoutWidth != .compact {
                    CaptureInspector(result: result, manifest: document.manifest)
                        .transition(.move(edge: .trailing))
                }
            }
            .sheet(isPresented: Binding(get: { window.inspectorVisible && layoutWidth == .compact },
                                        set: { window.inspectorVisible = $0 })) {
                CaptureInspector(result: result, manifest: document.manifest).presentationDetents([.medium, .large])
            }
            FooterBar(leading: footerLeading, trailing: footerTrailing)
        }
    }

    private var footerLeading: String {
        let v = result.voip
        return String(localized: "\(v.totalCalls) calls · \(v.answeredCalls) answered · \(v.unansweredFailures) failed · \(document.issueCalls.count) with quality issues")
    }

    private var footerTrailing: String {
        guard let index = document.selectedCall, index < result.calls.count else { return String(localized: "No selection") }
        let call = result.calls[index]
        return String(localized: "1 selected · \(Formatters.clock(call.startTime)) · \(call.caller.user) → \(call.callee.user)")
    }
}

/// The Overview's cards and calls table, laid out for the width they actually get.
private struct OverviewContent: View {
    @Environment(\.layoutWidth) private var layoutWidth
    var document: AnalysisDocument
    private var result: AnalysisResult { document.result }

    var body: some View {
        if layoutWidth == .wide {
            content.padding(EdgeInsets(top: 18, leading: 22, bottom: 16, trailing: 22))
        } else {
            // Narrower areas (iPad portrait, Split View, inspector open): stack the cards and scroll.
            ScrollView(.vertical) {
                content.padding(EdgeInsets(top: 16, leading: layoutWidth == .compact ? 14 : 20, bottom: 16,
                                           trailing: layoutWidth == .compact ? 14 : 20))
            }
        }
    }

    @ViewBuilder private var content: some View {
        let wide = layoutWidth == .wide
        VStack(spacing: 16) {
            HStack(alignment: .bottom, spacing: 16) {
                ScreenTitle(title: String(localized: "Overview"), subtitle: subtitle)
                Spacer(minLength: 8)
                if layoutWidth > .compact { SeverityLegend() }
            }
            if wide {
                WeightedHStack(weights: [1, 1.15], spacing: 12) {
                    TrafficCard(result: result)
                    QualityCard(result: result)
                }
                HStack(spacing: 12) {
                    NeedsAttentionCard(document: document)
                    MOSDistributionCard(voip: result.voip).frame(width: 360)
                }
                .frame(height: 148)
            } else {
                TrafficCard(result: result)
                QualityCard(result: result)
                NeedsAttentionCard(document: document).frame(height: 148)
                MOSDistributionCard(voip: result.voip).frame(height: 148)
            }
            CallsSectionHeader(document: document)
            if wide {
                CallsTable(document: document)
            } else {
                CallsTable(document: document)
                    .frame(height: min(640, max(240, CGFloat(document.visibleCalls.count) * 26 + 30)))
            }
        }
    }

    private var subtitle: String {
        var parts = [String(localized: "\(Formatters.spoken(result.capture.durationSeconds)) capture")]
        if let server = result.topology.sipServer { parts.append(String(localized: "SIP server \(server.description)")) }
        if !result.topology.endpoints.isEmpty {
            parts.append(String(localized: "\(result.topology.endpoints.count) endpoints"))
        }
        if !result.topology.trunks.isEmpty {
            parts.append(String(localized: "\(result.topology.trunks.count) SIP trunks"))
        }
        return parts.joined(separator: " · ")
    }

}

struct OverviewHeaderControls: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Environment(LibraryModel.self) private var library
    @Bindable var document: AnalysisDocument

    var body: some View {
        HStack(spacing: 2) {
            Menu {
                Picker("Show", selection: $document.callFilter) {
                    ForEach(CallFilter.allCases, id: \.self) { filter in
                        Text("\(filter.title) (\(document.count(for: filter)))").tag(filter)
                    }
                }
                .pickerStyle(.inline)
            } label: {
                Icon(Icons.filterLines, size: 17).foregroundStyle(document.callFilter == .all ? Theme.fg2 : Theme.acc)
                    .frame(width: 34, height: 28).contentShape(Rectangle())
            }
            .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()
            .help("Filter Calls")
            .accessibilityLabel("Filter Calls")
            IconButton(icon: Icons.export, iconSize: 17, help: String(localized: "Export Report (⇧⌘E)")) {
                window.exportReport()
            }
            IconButton(icon: Icons.inspector, iconSize: 18, tint: window.inspectorVisible ? Theme.acc : Theme.fg2,
                       help: window.inspectorVisible ? String(localized: "Hide Inspector (⌥⌘I)") : String(localized: "Show Inspector (⌥⌘I)")) {
                withAnimationIfAllowed { window.inspectorVisible.toggle() }
            }
        }
        SearchField(placeholder: String(localized: "Search number, IP, Call-ID"), text: $document.searchText,
                    width: layoutWidth == .wide ? 250 : layoutWidth == .regular ? 200 : 150,
                    focusRequest: window.searchFocusRequest)
    }
}

// MARK: - Metric cards

private struct MetricCell<Content: View>: View {
    var label: String
    var leadingRule: Bool
    var spacing: CGFloat = 4
    var background: Color = .clear
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: spacing) {
            Text(label).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
            content()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(background)
        .overlay(alignment: .leading) { if leadingRule { Rectangle().fill(Theme.line).frame(width: 1) } }
    }
}

private struct BigValue: View {
    var text: String
    var color: Color = Theme.fg

    var body: some View {
        Text(text).font(.wp(24, .semibold)).tracking(-0.3).monospacedDigit().foregroundStyle(color).lineLimit(1)
            .minimumScaleFactor(0.7)
    }
}

private struct Caption: View {
    var text: String
    var body: some View { Text(text).font(.wp(11)).foregroundStyle(Theme.fg3).lineLimit(2) }
}

struct TrafficCard: View {
    var result: AnalysisResult

    var body: some View {
        let v = result.voip
        let capture = result.capture
        HStack(spacing: 0) {
            MetricCell(label: String(localized: "Calls"), leadingRule: false) {
                BigValue(text: "\(v.totalCalls)")
                Caption(text: callsCaption)
            }
            MetricCell(label: String(localized: "Duration"), leadingRule: true) {
                BigValue(text: Formatters.hms(capture.durationSeconds))
                Caption(text: v.talkTime.map { String(localized: "Talk time \(Formatters.hms($0.total))") } ?? String(localized: "No answered calls"))
            }
            MetricCell(label: String(localized: "Packets"), leadingRule: true) {
                BigValue(text: Formatters.count(capture.packetCount))
                Caption(text: String(localized: "SIP \(capture.sipPackets) · RTP \(capture.rtpPackets)"))
            }
            MetricCell(label: String(localized: "Codecs"), leadingRule: true, spacing: 6) {
                if v.codecUsage.isEmpty {
                    Text("—").font(.wp(24, .semibold)).foregroundStyle(Theme.fg3)
                } else {
                    FlowLayout(spacing: 5) {
                        ForEach(v.codecUsage.prefix(4), id: \.name) { Chip(text: $0.name) }
                    }
                    .padding(.top, 2)
                    Caption(text: String(localized: "\(v.codecUsage.prefix(4).map { "\($0.calls)" }.joined(separator: " · ")) calls"))
                }
            }
        }
        .card()
    }

    private var callsCaption: String {
        let v = result.voip
        var parts = [String(localized: "\(v.answeredCalls) answered"), String(localized: "\(v.failedCalls) failed")]
        if v.rejectedCalls > 0 { parts.append(String(localized: "\(v.rejectedCalls) rejected")) }
        if v.cancelledCalls > 0 { parts.append(String(localized: "\(v.cancelledCalls) cancelled")) }
        return parts.joined(separator: " · ")
    }
}

struct QualityCard: View {
    var result: AnalysisResult

    private var answeredCalls: [CallRecord] { result.calls.filter { $0.state.wasAnswered } }

    var body: some View {
        let v = result.voip
        let errors = v.sipErrorResponses
        HStack(spacing: 0) {
            MetricCell(label: String(localized: "MOS"), leadingRule: false) {
                if let mos = v.meanMOS {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        BigValue(text: String(format: "%.2f", mos))
                        let rating = QualityRating(mos: mos)
                        Text(rating.localizedName).font(.wp(11, .semibold))
                            .foregroundStyle(QualityThresholds.severity(mos: mos).colorOrOK)
                    }
                    HStack(spacing: 6) {
                        LevelBar(fraction: (mos - 1) / 4, color: QualityThresholds.severity(mos: mos).colorOrOK)
                        if let min = v.minMOS { Text("min \(String(format: "%.2f", min))").font(.wp(11)).foregroundStyle(Theme.fg3) }
                    }
                } else {
                    BigValue(text: "—", color: Theme.fg3)
                    Caption(text: v.answeredCalls > 0 ? String(localized: "No E-model data for these codecs") : String(localized: "No answered calls"))
                }
            }
            .help("Estimated listening quality (ITU-T G.107 E-model) from codec and measured packet loss. Network delay cannot be measured from a single capture point.")
            MetricCell(label: String(localized: "Jitter"), leadingRule: true) {
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    BigValue(text: v.meanJitterMs.map { String(format: "%.1f", $0) } ?? "—", color: v.meanJitterMs == nil ? Theme.fg3 : Theme.fg)
                    if v.meanJitterMs != nil { Text("ms").font(.wp(13)).foregroundStyle(Theme.fg2) }
                }
                let series = answeredCalls.compactMap { $0.quality?.meanJitterMs }
                Sparkline(values: series, maxValue: max(20, (series.max() ?? 0) * 1.05))
                    .frame(width: 120, height: 16)
                    .accessibilityLabel("Jitter per call, max \(Formatters.ms(v.maxJitterMs))")
            }
            MetricCell(label: String(localized: "Packet Loss"), leadingRule: true) {
                BigValue(text: Formatters.percent(v.lossPercent), color: v.lossPercent == nil ? Theme.fg3 : Theme.fg)
                let series = answeredCalls.compactMap { $0.quality?.lossPercent }
                Sparkline(values: series, maxValue: max(3, (series.max() ?? 0) * 1.05))
                    .frame(width: 120, height: 16)
                    .accessibilityLabel("Packet loss per call")
            }
            MetricCell(label: String(localized: "SIP Errors"), leadingRule: true, background: errors.isEmpty ? .clear : Theme.warnBg) {
                HStack(spacing: 7) {
                    if !errors.isEmpty { Icon(Icons.statusWarning, size: 16, knockout: Theme.win).foregroundStyle(Theme.warn) }
                    BigValue(text: "\(errors.count)", color: errors.isEmpty ? Theme.fg : Theme.warn)
                }
                Text(errors.isEmpty ? String(localized: "No failed calls") : groupedCodes(errors))
                    .font(errors.isEmpty ? .wp(11) : .wpMono(11))
                    .foregroundStyle(errors.isEmpty ? Theme.fg3 : Theme.fg2)
                    .lineLimit(1)
            }
        }
        .card()
    }
}

/// "486 · 408 · 503", or "503 ×6" when a code repeats.
func groupedCodes(_ codes: [Int]) -> String {
    var order: [Int] = []
    var counts: [Int: Int] = [:]
    for code in codes {
        if counts[code] == nil { order.append(code) }
        counts[code, default: 0] += 1
    }
    return order.map { code in
        let count = counts[code, default: 1]
        return count > 1 ? "\(code) ×\(count)" : "\(code)"
    }.joined(separator: " · ")
}

extension Severity {
    /// Green for OK (used by MOS where "Good" is shown in the OK colour).
    var colorOrOK: Color { self == .info ? Theme.ok : color }
}

// MARK: - Needs Attention

struct NeedsAttentionCard: View {
    @Environment(WindowModel.self) private var window
    var document: AnalysisDocument

    struct Entry: Identifiable {
        var id: String
        var severity: Severity
        var title: String
        var detail: String
        var action: String
        var perform: () -> Void
    }

    var body: some View {
        let entries = makeEntries()
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Needs Attention"), badge: "\(entries.count)", height: 36)
            if entries.isEmpty {
                HStack(spacing: 8) {
                    StatusIcon(severity: .ok, size: 13)
                    Text("No problems detected in this capture").font(.wp(12.5)).foregroundStyle(Theme.fg2)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView(.vertical) {
                    VStack(spacing: 0) {
                        ForEach(Array(entries.enumerated()), id: \.element.id) { offset, entry in
                            Button(action: entry.perform) {
                                HStack(spacing: 10) {
                                    StatusIcon(severity: entry.severity, size: 13)
                                    Text(entry.title).font(.wp(12.5, .medium)).foregroundStyle(Theme.fg)
                                        .frame(width: 160, alignment: .leading)
                                    Text(entry.detail).font(.wp(12.5)).foregroundStyle(Theme.fg2)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                    HStack(spacing: 3) {
                                        Text(entry.action)
                                        Icon(Icons.chevronRight, size: 10)
                                    }
                                    .font(.wp(12)).foregroundStyle(Theme.acc)
                                }
                                .lineLimit(1)
                                .padding(.horizontal, 14)
                                .frame(height: 37)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .overlay(alignment: .bottom) {
                                if offset < entries.count - 1 { Rectangle().fill(Theme.line).frame(height: 1) }
                            }
                        }
                    }
                }
                .scrollIndicators(.automatic)
            }
        }
        .card()
    }

    private func makeEntries() -> [Entry] {
        let result = document.result
        var entries: [Entry] = []
        let priority: [FindingKind] = [.oneWayAudio, .noMedia, .poorQuality]
        let findings = result.findings.filter { priority.contains($0.kind) }.sorted { a, b in
            if a.severity != b.severity { return a.severity > b.severity }
            let pa = priority.firstIndex(of: a.kind) ?? 0, pb = priority.firstIndex(of: b.kind) ?? 0
            if pa != pb { return pa < pb }
            return (a.time ?? Timestamp(nanoseconds: 0)) < (b.time ?? Timestamp(nanoseconds: 0))
        }
        var seenCalls = Set<Int>()
        for finding in findings {
            guard let callIndex = finding.callIndex, !seenCalls.contains(callIndex) else { continue }
            seenCalls.insert(callIndex)
            let call = result.calls[callIndex]
            let detail = finding.kind == .poorQuality ? finding.detail : "\(finding.title) — \(finding.detail.components(separatedBy: " · ").dropFirst().joined(separator: " · "))"
            entries.append(Entry(id: "f\(finding.id)", severity: finding.severity,
                                 title: "\(Formatters.clock(call.startTime)) · \(call.caller.user) → \(call.callee.user)",
                                 detail: detail, action: String(localized: "Investigate")) { [window] in window.investigate(callIndex) })
        }
        let failed = result.calls.filter { $0.state.isFailure }
        if !failed.isEmpty {
            let reasons = failed.map(\.statusLabel)
            var unique: [String] = []
            for reason in reasons where !unique.contains(reason) { unique.append(reason) }
            entries.append(Entry(id: "failed", severity: .warning,
                                 title: String(localized: "\(failed.count) failed calls"),
                                 detail: unique.joined(separator: " · "), action: String(localized: "Show Calls")) { [window, document] in
                document.callFilter = .failed
                window.navigate(to: .section(.calls))
            })
        }
        // Signalling, transport and WebRTC diagnostics (registration, authentication, missing ACKs, timeouts, TCP, ICE,
        // STUN, TURN, DTLS).
        let signalling: [FindingKind] = [.registrationFailure, .authenticationFailure, .missingACK, .sipTimeout,
                                         .sipErrorResponses, .tcpUnanswered, .tcpRetransmissions, .tcpReset,
                                         .iceFailure, .noMediaAfterICE, .dtlsFailure, .turnAllocationFailure, .stunTimeout, .stunError]
        let diagnostics = result.findings.filter { signalling.contains($0.kind) && $0.severity >= .warning }
            .sorted { $0.severity != $1.severity ? $0.severity > $1.severity : $0.id < $1.id }
        for finding in diagnostics.prefix(4) {
            if let session = finding.webrtcSessionIndex, finding.kind == .iceFailure || finding.kind == .noMediaAfterICE {
                entries.append(Entry(id: "d\(finding.id)", severity: finding.severity, title: finding.title, detail: finding.detail,
                                     action: String(localized: "Session")) { [window] in window.showWebRTCSession(session) })
            } else {
                entries.append(Entry(id: "d\(finding.id)", severity: finding.severity, title: finding.title, detail: finding.detail,
                                     action: String(localized: "Details")) { [window] in window.showDiagnostic(finding.id) })
            }
        }
        if diagnostics.count > 4 {
            entries.append(Entry(id: "more", severity: .info, title: String(localized: "\(diagnostics.count - 4) more diagnostics"),
                                 detail: String(localized: "SIP, TCP and WebRTC problems in this capture"), action: String(localized: "Diagnostics")) {
                [window] in window.navigate(to: .section(.diagnostics))
            })
        }
        for finding in result.findings where finding.kind == .captureTruncated {
            entries.append(Entry(id: "t\(finding.id)", severity: .info, title: finding.title, detail: finding.detail,
                                 action: String(localized: "Packets")) { [window] in
                if let filter = finding.displayFilter { window.showPackets(matching: filter) } else { window.navigate(to: .section(.packets)) }
            })
        }
        // Most severe first; the order within a severity (calls, failures, diagnostics) is kept.
        return entries.enumerated().sorted { a, b in
            a.element.severity != b.element.severity ? a.element.severity > b.element.severity : a.offset < b.offset
        }.map(\.element)
    }
}

// MARK: - MOS distribution

struct MOSDistributionCard: View {
    var voip: VoIPSummary

    var body: some View {
        let counts = voip.mosHistogram
        let peak = max(1, counts.max() ?? 1)
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "MOS Distribution"), height: 36) {
                Text("\(voip.callsWithMOS) answered calls").font(.wp(11)).foregroundStyle(Theme.fg3)
            }
            HStack(alignment: .bottom, spacing: 10) {
                ForEach(0..<5, id: \.self) { bucket in
                    let value = bucket < counts.count ? counts[bucket] : 0
                    VStack(spacing: 4) {
                        Text("\(value)").font(.wp(11, .semibold)).foregroundStyle(Theme.fg2)
                        UnevenRoundedRectangle(topLeadingRadius: 3, bottomLeadingRadius: 1, bottomTrailingRadius: 1, topTrailingRadius: 3)
                            .fill(color(bucket: bucket, value: value))
                            .frame(height: max(2, (CGFloat(value) / CGFloat(peak) * 52).rounded()))
                        Text(QualityThresholds.histogramLabels[bucket]).font(.wp(10.5)).foregroundStyle(Theme.fg3)
                            .lineLimit(1).fixedSize()
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .padding(EdgeInsets(top: 10, leading: 16, bottom: 8, trailing: 16))
            .frame(maxHeight: .infinity, alignment: .bottom)
        }
        .card()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("MOS distribution: \(counts.map(String.init).joined(separator: ", "))")
    }

    private func color(bucket: Int, value: Int) -> Color {
        guard value > 0 else { return Theme.ctrl2 }
        switch bucket {
        case 0, 1: return Theme.err
        case 2: return Theme.warn
        default: return Theme.m1
        }
    }
}

// MARK: - Calls section header

struct CallsSectionHeader: View {
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    var title = String(localized: "Calls")

    var body: some View {
        HStack(spacing: 12) {
            if layoutWidth > .compact { Text(title).font(.wp(15, .semibold)).foregroundStyle(Theme.fg) }
            SegmentedControl(items: CallFilter.allCases.map { .init(value: $0, title: "\($0.title) \(document.count(for: $0))") },
                             selection: $document.callFilter)
            Spacer(minLength: 8)
            if layoutWidth == .wide {
            HStack(spacing: 12) {
                KeyHint(key: "↩", label: String(localized: "Investigate"))
                KeyHint(key: "↑↓", label: String(localized: "Move"))
                KeyHint(key: "⇧⌘P", label: String(localized: "Packets"))
            }
            .font(.wp(11))
            .foregroundStyle(Theme.fg3)
            }
        }
    }
}

/// Wrapping horizontal layout for chips.
struct FlowLayout: Layout {
    var spacing: CGFloat = 5

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, maxX: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width { x = 0; y += rowHeight + spacing; rowHeight = 0 }
            x += size.width + spacing
            maxX = max(maxX, x - spacing)
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: min(maxX, width), height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > bounds.minX && x + size.width > bounds.maxX { x = bounds.minX; y += rowHeight + spacing; rowHeight = 0 }
            subview.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

/// Horizontal layout distributing width by weight (CSS flex-grow with flex-basis 0); height = tallest child.
struct WeightedHStack: Layout {
    var weights: [CGFloat]
    var spacing: CGFloat

    private func widths(total: CGFloat, count: Int) -> [CGFloat] {
        let available = max(0, total - spacing * CGFloat(max(0, count - 1)))
        let w = (0..<count).map { $0 < weights.count ? weights[$0] : 1 }
        let sum = w.reduce(0, +)
        return w.map { available * $0 / sum }
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let total = proposal.width ?? 800
        let columnWidths = widths(total: total, count: subviews.count)
        let height = zip(subviews, columnWidths).map { $0.sizeThatFits(ProposedViewSize(width: $1, height: nil)).height }.max() ?? 0
        return CGSize(width: total, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let columnWidths = widths(total: bounds.width, count: subviews.count)
        var x = bounds.minX
        for (subview, width) in zip(subviews, columnWidths) {
            subview.place(at: CGPoint(x: x, y: bounds.minY), proposal: ProposedViewSize(width: width, height: bounds.height))
            x += width + spacing
        }
    }
}
