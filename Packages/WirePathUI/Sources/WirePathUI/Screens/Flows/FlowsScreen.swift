import WirePathCore
import SwiftUI

/// Flows: every bidirectional 5-tuple (TCP connection, UDP flow, ICMP pair) with its traffic and TCP analysis.
/// Selecting a flow shows its details; opening it shows its packets (`flow == N`).
struct FlowsScreen: View {
    enum Scope: Hashable { case all, tcp, udp, issues }

    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    @State private var search = ""
    @State private var scope = Scope.all

    private var flows: [FlowRecord] { document.flows }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "Flows"),
                      subtitle: String(localized: "\(document.manifest.displayName) · \(document.result.capture.flowCount) flows")) {
                SearchField(placeholder: String(localized: "Search IP, port, protocol"), text: $search,
                            width: layoutWidth == .wide ? 250 : 170, focusRequest: window.searchFocusRequest)
            }
            switch document.flowState {
            case .notLoaded, .loading:
                ProgressView().controlSize(.small).frame(maxWidth: .infinity, maxHeight: .infinity)
            case .failed(let message):
                Text(message).font(.wp(12)).foregroundStyle(Theme.fg3).frame(maxWidth: .infinity, maxHeight: .infinity)
            case .loaded:
                content
            }
            FooterBar(leading: String(localized: "\(visible.count) of \(flows.count) flows"),
                      trailing: selectedFlow.map { String(localized: "Selected flow #\($0.id + 1)") } ?? String(localized: "No selection"))
        }
        .onAppear { document.loadFlows() }
    }

    private var content: some View {
        VStack(spacing: 14) {
            if layoutWidth >= .regular {
                HStack(alignment: .bottom, spacing: 16) {
                    ScreenTitle(title: String(localized: "Flows"), subtitle: subtitle)
                    Spacer(minLength: 8)
                    scopeControl
                }
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    ScreenTitle(title: String(localized: "Flows"), subtitle: subtitle)
                    scopeControl
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            MetricStrip(items: metrics)
            DataTable(columns: columns, ids: visible, selection: $document.selectedFlow,
                      emptyText: flows.isEmpty ? String(localized: "No IP traffic in this capture") : String(localized: "No flows match"),
                      cells: cells, onOpen: { window.showPackets(forFlow: $0) }, menu: { id in AnyView(menu(id)) })
            if let flow = selectedFlow {
                FlowDetailCard(flow: flow, onShowPackets: { window.showPackets(forFlow: flow.id) })
            }
        }
        .padding(EdgeInsets(top: 18, leading: layoutWidth == .compact ? 14 : 22, bottom: 16, trailing: layoutWidth == .compact ? 14 : 22))
    }

    private var scopeControl: some View {
        SegmentedControl(items: [.init(value: Scope.all, title: String(localized: "All \(flows.count)")),
                                 .init(value: .tcp, title: String(localized: "TCP \(count(.tcp))")),
                                 .init(value: .udp, title: String(localized: "UDP \(count(.udp))")),
                                 .init(value: .issues, title: String(localized: "With Issues \(count(.issues))"))],
                         selection: $scope)
    }

    private var selectedFlow: FlowRecord? {
        document.selectedFlow.flatMap { $0 < flows.count ? flows[$0] : nil }
    }

    private var subtitle: String {
        let tcp = flows.filter { $0.transport == .tcp }
        let complete = tcp.filter { $0.tcp?.handshake == .complete }.count
        return String(localized: "\(tcp.count) TCP connections (\(complete) with a captured handshake) · \(flows.filter { $0.transport == .udp }.count) UDP flows")
    }

    private func matches(_ flow: FlowRecord, _ scope: Scope) -> Bool {
        switch scope {
        case .all: return true
        case .tcp: return flow.transport == .tcp
        case .udp: return flow.transport == .udp
        case .issues: return Self.severity(flow) >= .warning
        }
    }

    private func count(_ scope: Scope) -> Int { flows.filter { matches($0, scope) }.count }

    private var visible: [Int] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return flows.indices.filter { index in
            let flow = flows[index]
            guard matches(flow, scope) else { return false }
            guard !query.isEmpty else { return true }
            return [flow.initiator.description, flow.responder.description, flow.application.displayName,
                    Self.transportName(flow), "#\(flow.id + 1)"].contains { $0.lowercased().contains(query) }
        }
    }

    static func severity(_ flow: FlowRecord) -> Severity {
        guard let tcp = flow.tcp else { return .ok }
        if tcp.termination == .resetByInitiator || tcp.termination == .resetByResponder || tcp.handshake == .unanswered {
            return .warning
        }
        return tcp.retransmissions + tcp.segmentsNotCaptured + tcp.zeroWindows > 0 ? .warning : .ok
    }

    static func transportName(_ flow: FlowRecord) -> String {
        switch flow.transport {
        case .tcp: return "TCP"
        case .udp: return "UDP"
        case .sctp: return "SCTP"
        case .other: return PacketDissector.ipProtocolName(flow.ipProtocol)
        }
    }

    private var metrics: [MetricStrip.Item] {
        let tcp = flows.compactMap(\.tcp)
        let retransmissions = tcp.reduce(0) { $0 + $1.retransmissions }
        let missing = tcp.reduce(0) { $0 + $1.segmentsNotCaptured }
        let resets = tcp.filter { $0.termination == .resetByInitiator || $0.termination == .resetByResponder }.count
        let rtts = tcp.compactMap(\.initialRTTMs)
        return [
            .init(label: String(localized: "Flows"), value: Formatters.count(flows.count),
                  caption: Formatters.bytes(flows.reduce(0) { $0 + $1.bytes })),
            .init(label: String(localized: "TCP"), value: Formatters.count(tcp.count),
                  caption: String(localized: "\(tcp.filter { $0.handshake == .complete }.count) handshakes")),
            .init(label: String(localized: "Retransmissions"), value: Formatters.count(retransmissions), color: retransmissions > 0 ? Theme.warn : Theme.fg),
            .init(label: String(localized: "Not Captured"), value: Formatters.count(missing), caption: String(localized: "sequence gaps"),
                  color: missing > 0 ? Theme.warn : Theme.fg),
            .init(label: String(localized: "Resets"), value: Formatters.count(resets), color: resets > 0 ? Theme.warn : Theme.fg),
            .init(label: String(localized: "Median iRTT"), value: rtts.isEmpty ? "—" : String(format: "%.1f", rtts.sorted()[rtts.count / 2]),
                  unit: rtts.isEmpty ? nil : "ms"),
        ]
    }

    private var columns: [ColumnSpec] {
        [.fixed("", 30, .center), .fixed("#", 56), .fixed(String(localized: "Protocol"), 76), .flexible(String(localized: "Endpoint A")), .flexible(String(localized: "Endpoint B"), from: .regular),
         .fixed(String(localized: "Packets"), 76, .trailing), .fixed(String(localized: "Bytes"), 86, .trailing, from: .regular), .fixed(String(localized: "Duration"), 78, .trailing, from: .wide),
         .fixed(String(localized: "Start"), 80, .trailing, from: .wide), .fixed("", 14, from: .regular), .fixed(String(localized: "TCP"), 150, from: .regular)]
    }

    private func cells(_ index: Int) -> [CellValue] {
        let flow = flows[index]
        let application = flow.application == .udp || flow.application == .tcp ? Self.transportName(flow)
            : "\(flow.application.displayName)"
        return [.status(Self.severity(flow)), .mono("\(flow.id + 1)"), .text(application, weight: .medium),
                .mono(Self.endpoint(flow.initiator, flow)), .mono(Self.endpoint(flow.responder, flow)),
                .text("\(Formatters.count(flow.packetsFromInitiator)) · \(Formatters.count(flow.packetsFromResponder))"),
                .text(Formatters.bytes(flow.bytes)), .text(String(format: "%.1f s", max(0, flow.durationSeconds))),
                .text(Formatters.clock(flow.firstTime), color: Theme.fg2), .text(""),
                .text(flow.tcp.map(Self.tcpSummary) ?? "—", color: Self.severity(flow) >= .warning ? Theme.warn : Theme.fg2)]
    }

    /// Ports only mean something for TCP/UDP/SCTP; ICMP and other flows show the address alone.
    static func endpoint(_ endpoint: Endpoint, _ flow: FlowRecord) -> String {
        flow.transport == .other ? endpoint.address.description : endpoint.description
    }

    static func tcpSummary(_ tcp: TCPConnectionStats) -> String {
        var parts: [String] = []
        if tcp.retransmissions > 0 { parts.append(String(localized: "\(tcp.retransmissions) retrans.")) }
        if tcp.segmentsNotCaptured > 0 { parts.append(String(localized: "\(tcp.segmentsNotCaptured) gaps")) }
        if tcp.duplicateACKs > 0 { parts.append(String(localized: "\(tcp.duplicateACKs) dup ACK")) }
        switch tcp.termination {
        case .resetByInitiator, .resetByResponder: parts.append(String(localized: "reset"))
        default: break
        }
        if tcp.handshake == .unanswered { parts.append(String(localized: "no answer")) }
        return parts.isEmpty ? String(localized: "OK") : parts.joined(separator: ", ")
    }

    @ViewBuilder private func menu(_ index: Int) -> some View {
        let flow = flows[index]
        Button("Show Packets") { window.showPackets(forFlow: flow.id) }
        Button("Copy Filter") { Clipboard.copy("flow == \(flow.id + 1)") }
        Button("Copy Endpoints") { Clipboard.copy("\(flow.initiator) ↔ \(flow.responder)") }
    }
}

/// Details of the selected flow: both directions and, for TCP, the connection analysis.
struct FlowDetailCard: View {
    var flow: FlowRecord
    var onShowPackets: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Flow #\(flow.id + 1)"),
                       subtitle: "\(FlowsScreen.endpoint(flow.initiator, flow)) ↔ \(FlowsScreen.endpoint(flow.responder, flow))") {
                PillButton(icon: Icons.packets, title: String(localized: "Show Packets"), action: onShowPackets)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 24, alignment: .topLeading)], alignment: .leading, spacing: 10) {
                item(String(localized: "Protocol"), "\(FlowsScreen.transportName(flow)) · \(flow.application.displayName)")
                item(String(localized: "A → B"), String(localized: "\(flow.packetsFromInitiator) packets · \(Formatters.bytes(flow.bytesFromInitiator))"))
                item(String(localized: "B → A"), String(localized: "\(flow.packetsFromResponder) packets · \(Formatters.bytes(flow.bytesFromResponder))"))
                item(String(localized: "Time"), "\(Formatters.clock(flow.firstTime)) → \(Formatters.clock(flow.lastTime))")
                item(String(localized: "Rate"), rate)
                item(String(localized: "First packet"), "#\(flow.firstFrame)")
                if let tcp = flow.tcp {
                    item(String(localized: "Handshake"), handshake(tcp))
                    item(String(localized: "Termination"), termination(tcp))
                    item(String(localized: "Payload A → B · B → A"),
                         "\(Formatters.bytes(tcp.payloadBytesFromInitiator)) · \(Formatters.bytes(tcp.payloadBytesFromResponder))")
                    item(String(localized: "Retransmissions · Out-of-order"), "\(tcp.retransmissions) · \(tcp.outOfOrder)")
                    item(String(localized: "Not captured · Dup ACKs"), "\(tcp.segmentsNotCaptured) · \(tcp.duplicateACKs)")
                    item(String(localized: "Zero windows · Keep-alives"), "\(tcp.zeroWindows) · \(tcp.keepAlives)")
                }
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 14, trailing: 14))
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .card()
    }

    private var rate: String {
        let seconds = flow.durationSeconds
        guard seconds > 0 else { return "—" }
        let pps = Double(flow.packets) / seconds
        let bps = Double(flow.bytes) * 8 / seconds
        return String(format: "%.1f pkt/s · %@/s", pps, Formatters.bits(bps))
    }

    private func handshake(_ tcp: TCPConnectionStats) -> String {
        switch tcp.handshake {
        case .complete: return tcp.initialRTTMs.map { String(localized: "Complete · iRTT \(String(format: "%.1f", $0)) ms") } ?? String(localized: "Complete")
        case .synAckSeen: return String(localized: "SYN, SYN/ACK (no final ACK)")
        case .unanswered: return String(localized: "SYN not answered")
        case .notCaptured: return String(localized: "Before the capture started")
        }
    }

    private func termination(_ tcp: TCPConnectionStats) -> String {
        switch tcp.termination {
        case .graceful: return String(localized: "FIN both ways")
        case .halfClosed: return String(localized: "FIN one way")
        case .resetByInitiator: return String(localized: "Reset by A")
        case .resetByResponder: return String(localized: "Reset by B")
        case .open: return String(localized: "Open at end of capture")
        }
    }

    private func item(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
            Text(value).font(.wp(12.5)).foregroundStyle(Theme.fg).lineLimit(1).monospacedDigit().textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}
