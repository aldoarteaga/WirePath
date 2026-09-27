import WirePathCore
import SwiftUI

/// Diagnostics: every problem the analysis found (SIP, RTP, TCP, capture), most severe first, each linked to the
/// packets that show it and to its call when there is one.
struct DiagnosticsScreen: View {
    enum Scope: Hashable { case all, errors, warnings, info }

    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    @State private var search = ""
    @State private var scope = Scope.all
    @State private var protocolFilter: String?

    private var findings: [Finding] { document.result.findings }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "Diagnostics"), subtitle: String(localized: "\(document.manifest.displayName) · \(findings.count) diagnostics")) {
                SearchField(placeholder: String(localized: "Search diagnostics"), text: $search,
                            width: layoutWidth == .wide ? 250 : 170, focusRequest: window.searchFocusRequest)
            }
            VStack(spacing: 14) {
                titleRow
                MetricStrip(items: metrics)
                DataTable(columns: columns, ids: visible.map(\.id), selection: $document.selectedFinding,
                          emptyText: findings.isEmpty ? String(localized: "No problems detected in this capture")
                              : String(localized: "No diagnostics match"),
                          cells: cells, onOpen: open, menu: { id in AnyView(menu(id)) })
                if let finding = selected {
                    DiagnosticDetailCard(finding: finding, document: document)
                }
            }
            .padding(EdgeInsets(top: 18, leading: layoutWidth == .compact ? 14 : 22, bottom: 16, trailing: layoutWidth == .compact ? 14 : 22))
            FooterBar(leading: String(localized: "\(visible.count) of \(findings.count) diagnostics"),
                      trailing: selected.map { "\($0.protocolName) · \($0.title)" } ?? String(localized: "No selection"))
        }
        .onAppear {
            if document.selectedFinding == nil { document.selectedFinding = visible.first?.id }
        }
    }

    @ViewBuilder private var titleRow: some View {
        let segmented = SegmentedControl(items: [.init(value: Scope.all, title: String(localized: "All \(findings.count)")),
                                                 .init(value: .errors, title: String(localized: "Errors \(count(.errors))")),
                                                 .init(value: .warnings, title: String(localized: "Warnings \(count(.warnings))")),
                                                 .init(value: .info, title: String(localized: "Info \(count(.info))"))],
                                         selection: $scope)
        let protocols = Array(Set(findings.map(\.protocolName))).sorted()
        let protocolMenu = Menu {
            Button("All Protocols") { protocolFilter = nil }
            Divider()
            ForEach(protocols, id: \.self) { name in Button(name) { protocolFilter = name } }
        } label: {
            Text(protocolFilter ?? String(localized: "All Protocols")).font(.wp(12.5)).foregroundStyle(Theme.fg)
                .padding(.horizontal, 10).frame(height: 28)
                .background(RoundedRectangle(cornerRadius: 7).fill(Theme.ctrl))
        }
        .menuStyle(.button).buttonStyle(.plain).fixedSize()
        if layoutWidth >= .regular {
            HStack(alignment: .bottom, spacing: 16) {
                ScreenTitle(title: String(localized: "Diagnostics"), subtitle: subtitle)
                Spacer(minLength: 8)
                protocolMenu
                segmented
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                ScreenTitle(title: String(localized: "Diagnostics"), subtitle: subtitle)
                HStack(spacing: 8) { segmented; protocolMenu }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var subtitle: String {
        let byProtocol = Dictionary(grouping: findings, by: \.protocolName).mapValues(\.count)
        guard !byProtocol.isEmpty else { return String(localized: "Nothing to report") }
        return byProtocol.sorted { $0.key < $1.key }.map { "\($0.value) \($0.key)" }.joined(separator: " · ")
    }

    private var selected: Finding? {
        document.selectedFinding.flatMap { id in findings.first { $0.id == id } }
    }

    private func matches(_ finding: Finding, _ scope: Scope) -> Bool {
        switch scope {
        case .all: return true
        case .errors: return finding.severity == .error
        case .warnings: return finding.severity == .warning
        case .info: return finding.severity <= .info
        }
    }

    private func count(_ scope: Scope) -> Int { findings.filter { matches($0, scope) }.count }

    private var visible: [Finding] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return findings.filter { finding in
            guard matches(finding, scope), protocolFilter.map({ $0 == finding.protocolName }) ?? true else { return false }
            guard !query.isEmpty else { return true }
            return [finding.title, finding.detail, finding.protocolName].contains { $0.lowercased().contains(query) }
        }
        .sorted { a, b in
            if a.severity != b.severity { return a.severity > b.severity }
            return (a.time ?? Timestamp(nanoseconds: .min)) < (b.time ?? Timestamp(nanoseconds: .min))
        }
    }

    private var metrics: [MetricStrip.Item] {
        [
            .init(label: String(localized: "Diagnostics"), value: "\(findings.count)",
                  caption: String(localized: "\(Set(findings.compactMap(\.callIndex)).count) calls affected")),
            .init(label: String(localized: "Errors"), value: "\(count(.errors))", color: count(.errors) > 0 ? Theme.err : Theme.fg),
            .init(label: String(localized: "Warnings"), value: "\(count(.warnings))", color: count(.warnings) > 0 ? Theme.warn : Theme.fg),
            .init(label: String(localized: "SIP"), value: "\(findings.filter { $0.protocolName == "SIP" }.count)"),
            .init(label: String(localized: "RTP"), value: "\(findings.filter { $0.protocolName == "RTP" }.count)"),
            .init(label: String(localized: "TCP"), value: "\(findings.filter { $0.protocolName == "TCP" }.count)"),
            .init(label: String(localized: "WebRTC"), value: "\(findings.filter { ["WebRTC", "STUN", "TURN"].contains($0.protocolName) }.count)"),
        ]
    }

    private var columns: [ColumnSpec] {
        [.fixed("", 30, .center), .fixed(String(localized: "Protocol"), 76), .fixed(String(localized: "Diagnostic"), 210), .flexible(String(localized: "Detail"), from: .regular),
         .fixed(String(localized: "Time"), 84, .trailing, from: .wide), .fixed(String(localized: "Packets"), 70, .trailing, from: .regular)]
    }

    private func cells(_ id: Int) -> [CellValue] {
        guard let finding = findings.first(where: { $0.id == id }) else { return [] }
        let packets = finding.packetReferences.isEmpty ? (finding.packetFilter == nil ? "—" : String(localized: "filter"))
            : "\(finding.packetReferences.count)"
        return [.status(finding.severity), .text(finding.protocolName, weight: .medium), .text(finding.title),
                .text(finding.detail, color: Theme.fg2), .text(finding.time.map(Formatters.clock) ?? "—", color: Theme.fg2),
                .text(packets, color: Theme.fg2)]
    }

    private func open(_ id: Int) {
        guard let finding = findings.first(where: { $0.id == id }) else { return }
        if let filter = finding.displayFilter {
            window.showPackets(matching: filter)
        } else if let call = finding.callIndex {
            window.investigate(call)
        } else if let session = finding.webrtcSessionIndex {
            window.showWebRTCSession(session)
        }
    }

    @ViewBuilder private func menu(_ id: Int) -> some View {
        if let finding = findings.first(where: { $0.id == id }) {
            if let filter = finding.displayFilter {
                Button("Show Packets") { window.showPackets(matching: filter) }
                Button("Copy Filter") { Clipboard.copy(filter) }
            }
            if let call = finding.callIndex { Button("Investigate Call") { window.investigate(call) } }
            if let session = finding.webrtcSessionIndex { Button("Show WebRTC Session") { window.showWebRTCSession(session) } }
            Button("Copy Diagnostic") { Clipboard.copy("\(finding.protocolName) · \(finding.title) — \(finding.detail)") }
        }
    }
}

/// The selected diagnostic: what was measured, when, and where to look.
struct DiagnosticDetailCard: View {
    @Environment(WindowModel.self) private var window
    var finding: Finding
    var document: AnalysisDocument

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            CardHeader(title: finding.title, subtitle: finding.protocolName) {
                HStack(spacing: 8) {
                    if let call = finding.callIndex {
                        PillButton(icon: Icons.phone, title: String(localized: "Investigate Call")) { window.investigate(call) }
                    }
                    if let session = finding.webrtcSessionIndex {
                        PillButton(icon: Icons.webrtc, title: String(localized: "Show Session")) { window.showWebRTCSession(session) }
                    }
                    if let filter = finding.displayFilter {
                        PillButton(icon: Icons.packets, title: String(localized: "Show Packets")) { window.showPackets(matching: filter) }
                    }
                    if let first = finding.packetReferences.first {
                        PillButton(icon: Icons.goToPacket, title: String(localized: "Go to #\(first)")) { window.showPacket(frame: first) }
                    }
                }
            }
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    StatusIcon(severity: finding.severity, size: 13)
                    Text(finding.detail).font(.wp(12.5)).foregroundStyle(Theme.fg).textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)
                HStack(spacing: 16) {
                    if let time = finding.time {
                        label(String(localized: "Time"), finding.endTime.map { "\(Formatters.clock(time)) → \(Formatters.clock($0))" }
                            ?? Formatters.clock(time))
                    }
                    if let call = finding.callIndex, call < document.result.calls.count {
                        label(String(localized: "Call"), document.callTitle(call))
                    }
                    if !finding.packetReferences.isEmpty {
                        label(String(localized: "Packets"), finding.packetReferences.prefix(12).map { "#\($0)" }.joined(separator: " ")
                              + (finding.packetReferences.count > 12 ? " …" : ""))
                    } else if let filter = finding.packetFilter {
                        label(String(localized: "Filter"), filter)
                    }
                }
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 14, trailing: 14))
        }
        .card()
    }

    private func label(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
            Text(value).font(.wp(12.5)).foregroundStyle(Theme.fg).lineLimit(1).monospacedDigit().textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }
}
