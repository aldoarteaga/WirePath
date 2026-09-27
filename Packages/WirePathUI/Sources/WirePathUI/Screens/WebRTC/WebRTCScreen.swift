import WirePathCore
import SwiftUI

/// WebRTC: ICE sessions reconstructed from STUN connectivity checks, with the path Peer A → candidate pair → Peer B,
/// every pair checked, the candidates each peer used, TURN relays, STUN servers, DTLS and the media that followed.
struct WebRTCScreen: View {
    enum Scope: Hashable { case all, connected, failed }

    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    @State private var search = ""
    @State private var scope = Scope.all

    private var webrtc: WebRTCAnalysis { document.result.webrtc }
    private var sessions: [WebRTCSessionRecord] { webrtc.sessions }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "WebRTC"), subtitle: String(localized: "\(document.manifest.displayName) · \(sessions.count) ICE sessions")) {
                SearchField(placeholder: String(localized: "Search ufrag, IP, port"), text: $search,
                            width: layoutWidth == .wide ? 250 : 170, focusRequest: window.searchFocusRequest)
            }
            ScrollView(.vertical) {
                VStack(spacing: 14) {
                    titleRow
                    MetricStrip(items: metrics)
                    DataTable(columns: columns, ids: visible, selection: $document.selectedWebRTCSession,
                              emptyText: sessions.isEmpty ? String(localized: "No ICE connectivity checks in this capture") : String(localized: "No sessions match"),
                              cells: cells, onOpen: { window.showPackets(matching: Self.filter(for: $0)) }, menu: { id in AnyView(menu(id)) })
                        .frame(height: 30 + 26 * CGFloat(min(max(visible.count, 2), 8)))
                    if let session = selected {
                        WebRTCSessionDetail(session: session, document: document)
                    } else if sessions.isEmpty {
                        unattachedTraffic
                    }
                }
                .padding(EdgeInsets(top: 18, leading: layoutWidth == .compact ? 14 : 22, bottom: 16, trailing: layoutWidth == .compact ? 14 : 22))
            }
            FooterBar(leading: String(localized: "\(visible.count) of \(sessions.count) sessions"),
                      trailing: selected.map { String(localized: "Selected session \($0.id + 1) · \($0.ufrags.joined(separator: " ↔ "))") }
                          ?? String(localized: "No selection"))
        }
        .onAppear {
            if document.selectedWebRTCSession.map({ $0 >= sessions.count }) ?? true { document.selectedWebRTCSession = visible.first }
        }
    }

    static func filter(for session: Int) -> String { "webrtc.session == \(session + 1)" }

    @ViewBuilder private var titleRow: some View {
        let segmented = SegmentedControl(items: [.init(value: Scope.all, title: String(localized: "All \(sessions.count)")),
                                                 .init(value: .connected, title: String(localized: "Connected \(count(.connected))")),
                                                 .init(value: .failed, title: String(localized: "Failed \(count(.failed))"))],
                                         selection: $scope)
        if layoutWidth >= .regular {
            HStack(alignment: .bottom, spacing: 16) {
                ScreenTitle(title: String(localized: "WebRTC"), subtitle: subtitle)
                Spacer(minLength: 8)
                segmented
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                ScreenTitle(title: String(localized: "WebRTC"), subtitle: subtitle)
                segmented
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var subtitle: String {
        let checks = webrtc.transactions.filter { $0.kind == .iceCheck }.count
        return String(localized: "\(checks) connectivity checks · \(webrtc.allocations.count) TURN allocations · \(Set(webrtc.transactions.filter { $0.kind == .serverBinding }.map(\.server)).count) STUN servers")
    }

    private var selected: WebRTCSessionRecord? {
        document.selectedWebRTCSession.flatMap { $0 < sessions.count ? sessions[$0] : nil }
    }

    private func matches(_ session: WebRTCSessionRecord, _ scope: Scope) -> Bool {
        switch scope {
        case .all: return true
        case .connected: return session.state == .connected
        case .failed: return session.state == .failed
        }
    }

    private func count(_ scope: Scope) -> Int { sessions.filter { matches($0, scope) }.count }

    private var visible: [Int] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return sessions.indices.filter { index in
            let session = sessions[index]
            guard matches(session, scope) else { return false }
            guard !query.isEmpty else { return true }
            let text = session.ufrags + session.candidates.map(\.endpoint.description) + [session.callID ?? ""]
            return text.contains { $0.lowercased().contains(query) }
        }
    }

    static func severity(_ session: WebRTCSessionRecord, findings: [Finding]) -> Severity {
        switch session.state {
        case .failed: return .error
        case .checking: return .info
        case .connected:
            return findings.filter { $0.webrtcSessionIndex == session.id }.map(\.severity).max() ?? .ok
        }
    }

    private var metrics: [MetricStrip.Item] {
        let pairs = sessions.flatMap(\.pairs)
        let unanswered = webrtc.transactions.filter { $0.outcome == .noResponse }.count
        let rtts = sessions.compactMap { $0.selected?.meanRTTMs }.sorted()
        let relayed = webrtc.allocations.reduce(0) { $0 + $1.relayedPackets }
        let dtls = sessions.filter { $0.dtls?.established == true }.count
        return [
            .init(label: String(localized: "ICE Sessions"), value: "\(sessions.count)",
                  caption: String(localized: "\(count(.connected)) connected · \(count(.failed)) failed"),
                  color: count(.failed) > 0 ? Theme.err : Theme.fg),
            .init(label: String(localized: "Candidate Pairs"), value: "\(pairs.count)",
                  caption: String(localized: "\(pairs.filter { $0.state == .succeeded }.count) succeeded")),
            .init(label: String(localized: "STUN Transactions"), value: Formatters.count(webrtc.transactions.count),
                  caption: String(localized: "\(unanswered) unanswered"), color: unanswered > 0 ? Theme.warn : Theme.fg),
            .init(label: String(localized: "TURN"), value: "\(webrtc.allocations.count)", unit: String(localized: "allocations"),
                  caption: String(localized: "\(relayed) relayed packets")),
            .init(label: String(localized: "DTLS"), value: "\(dtls)", caption: String(localized: "handshakes completed")),
            .init(label: String(localized: "Median ICE RTT"), value: rtts.isEmpty ? "—" : String(format: "%.1f", rtts[rtts.count / 2]),
                  unit: rtts.isEmpty ? nil : "ms"),
        ]
    }

    private var columns: [ColumnSpec] {
        [.fixed("", 30, .center), .fixed("#", 40), .fixed(String(localized: "State"), 86), .flexible(String(localized: "Peer A")), .flexible(String(localized: "Peer B"), from: .regular),
         .fixed(String(localized: "Selected Pair"), 150, from: .regular), .fixed(String(localized: "Pairs"), 70, .trailing), .fixed(String(localized: "RTT"), 70, .trailing, from: .wide),
         .fixed("", 14, from: .wide), .fixed(String(localized: "DTLS"), 90, from: .wide), .fixed(String(localized: "Media"), 80, .trailing, from: .regular), .fixed(String(localized: "Start"), 80, .trailing, from: .wide)]
    }

    private func cells(_ index: Int) -> [CellValue] {
        let session = sessions[index]
        let succeeded = session.pairs.filter { $0.state == .succeeded }.count
        return [.status(Self.severity(session, findings: document.result.findings)), .mono("\(session.id + 1)"),
                .text(Self.stateName(session.state), color: session.state == .failed ? Theme.err : nil, weight: .medium),
                .party(session.ufrags.first ?? "—", Self.peerSummary(session, peer: 0)),
                .party(session.ufrags.count > 1 ? session.ufrags[1] : "—", Self.peerSummary(session, peer: 1)),
                .text(session.selected.map { "\($0.localKind.label) → \($0.remoteKind.label)" } ?? "—", color: Theme.fg2),
                .text("\(succeeded)/\(session.pairs.count)"),
                .text(Formatters.ms(session.selected?.meanRTTMs), color: Theme.fg2), .text(""),
                .text(Self.dtlsText(session.dtls), color: Theme.fg2),
                .text(session.streamIndices.isEmpty ? "—" : String(localized: "\(session.streamIndices.count) streams")),
                .text(Formatters.clock(session.firstTime), color: Theme.fg2)]
    }

    nonisolated static func stateName(_ state: WebRTCSessionRecord.State) -> String {
        switch state {
        // Keyed: an ICE session (Spanish "sesión", feminine).
        case .connected: return String(localized: "ice.session.connected", defaultValue: "Connected")
        case .failed: return String(localized: "ice.session.failed", defaultValue: "Failed")
        case .checking: return String(localized: "ice.session.checking", defaultValue: "Checking")
        }
    }

    static func peerSummary(_ session: WebRTCSessionRecord, peer: Int) -> String {
        guard peer < session.peerAddresses.count, let first = session.peerAddresses[peer].first else { return "" }
        let others = session.peerAddresses[peer].count - 1
        return others > 0 ? "\(first) +\(others)" : first.description
    }

    static func dtlsText(_ dtls: DTLSFlowSummary?) -> String {
        guard let dtls else { return "—" }
        if dtls.alerts > 0 { return String(localized: "Alert") }
        return dtls.established ? String(localized: "Established") : String(localized: "Incomplete")
    }

    @ViewBuilder private func menu(_ index: Int) -> some View {
        let session = sessions[index]
        Button("Show Packets") { window.showPackets(matching: Self.filter(for: index)) }
        Button("Copy Filter") { Clipboard.copy(Self.filter(for: index)) }
        if let call = WebRTCSessionDetail.callIndex(session, document.result) {
            Button("Investigate Call") { window.investigate(call) }
        }
    }

    /// STUN/TURN seen without any connectivity check (e.g. only candidate gathering was captured).
    @ViewBuilder private var unattachedTraffic: some View {
        if !webrtc.allocations.isEmpty || !webrtc.serverBindings.isEmpty {
            WebRTCGatheringCard(webrtc: webrtc, bindings: webrtc.serverBindings, allocations: webrtc.allocations.map(\.id))
        }
    }
}

/// Everything about the selected ICE session.
struct WebRTCSessionDetail: View {
    @Environment(WindowModel.self) private var window
    var session: WebRTCSessionRecord
    var document: AnalysisDocument

    private var result: AnalysisResult { document.result }

    static func callIndex(_ session: WebRTCSessionRecord, _ result: AnalysisResult) -> Int? {
        guard let callID = session.callID else { return nil }
        return result.calls.firstIndex { call in
            call.messageIndices.contains { $0 < result.sipMessages.count && result.sipMessages[$0].callID == callID }
        }
    }

    var body: some View {
        VStack(spacing: 14) {
            ICEPathCard(session: session, result: result, callIndex: Self.callIndex(session, result))
            CandidatePairsCard(session: session, transactions: result.webrtc.transactions)
            AdaptiveStack(threshold: .wide, spacing: 14) {
                CandidatesCard(session: session)
                WebRTCGatheringCard(webrtc: result.webrtc, bindings: session.serverBindingIndices, allocations: session.turnAllocations)
            }
            let findings = result.findings.filter { $0.webrtcSessionIndex == session.id }
            if !findings.isEmpty {
                SessionDiagnosticsCard(findings: findings)
            }
        }
        .id(session.id)
    }
}

/// Peer A → candidate pair → Peer B: who connected to whom, through which candidates (and relay), with what result.
struct ICEPathCard: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    var session: WebRTCSessionRecord
    var result: AnalysisResult
    var callIndex: Int?

    static let peerWidth: CGFloat = 244

    private var pair: ICECandidatePairRecord? {
        session.selected ?? session.pairs.max { ($0.successes, $0.checks) < ($1.successes, $1.checks) }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Compact widths drop the time range and shorten the buttons so nothing truncates.
            let compact = layoutWidth == .compact
            CardHeader(title: String(localized: "ICE Session \(session.id + 1)"),
                       subtitle: compact ? nil : "\(Formatters.clock(session.firstTime)) → \(Formatters.clock(session.lastTime))") {
                HStack(spacing: 8) {
                    if let callIndex {
                        PillButton(icon: Icons.phone, title: compact ? String(localized: "Call") : String(localized: "Investigate Call"),
                                   help: String(localized: "Investigate Call")) { window.investigate(callIndex) }
                    }
                    PillButton(icon: Icons.packets, title: compact ? String(localized: "Packets") : String(localized: "Show Packets"),
                               help: String(localized: "Show Packets")) {
                        window.showPackets(matching: WebRTCScreen.filter(for: session.id))
                    }
                    .accessibilityIdentifier("webrtc.showPackets")
                }
            }
            Group {
                if layoutWidth == .compact {
                    VStack(spacing: 10) {
                        peer(0)
                        connection(vertical: true)
                        peer(1)
                    }
                } else {
                    HStack(alignment: .center, spacing: 0) {
                        peer(0).frame(width: Self.peerWidth).frame(maxHeight: .infinity)
                        // The pair on one line between the peers when it fits, else stacked.
                        ViewThatFits(in: .horizontal) {
                            connection(vertical: false)
                            connection(vertical: true)
                        }
                        peer(1).frame(width: Self.peerWidth).frame(maxHeight: .infinity)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(EdgeInsets(top: 14, leading: 14, bottom: 14, trailing: 14))
            stages
        }
        .card()
    }

    private func peer(_ index: Int) -> some View {
        let ufrag = index < session.ufrags.count ? session.ufrags[index] : "—"
        let candidates = session.candidates.filter { $0.peer == index }
        let role = session.controllingPeer.map { $0 == index ? String(localized: "Controlling") : String(localized: "Controlled") }
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(index == 0 ? String(localized: "Peer A") : String(localized: "Peer B")).font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
                if let role { Text(role).font(.wp(11)).foregroundStyle(Theme.fg3) }
            }
            HStack(spacing: 6) {
                Text("ufrag").font(.wp(11)).foregroundStyle(Theme.fg2)
                Chip(text: ufrag)
            }
            ForEach(Array(candidates.prefix(4).enumerated()), id: \.offset) { _, candidate in
                HStack(spacing: 6) {
                    CandidateKindChip(kind: candidate.kind)
                    Text(candidate.endpoint.description).font(.wpMono(11.5)).foregroundStyle(Theme.fg).lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            if candidates.count > 4 {
                Text("+\(candidates.count - 4) more").font(.wp(11)).foregroundStyle(Theme.fg3)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.surf2))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Theme.line, lineWidth: 1))
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("webrtc.peer\(index)")
    }

    private var connectionColor: Color {
        switch session.state {
        case .connected: return Theme.ok
        case .failed: return Theme.err
        case .checking: return Theme.warn
        }
    }

    private func connection(vertical: Bool) -> some View {
        let color = connectionColor
        let dashed = session.selected == nil
        return VStack(spacing: 8) {
            Text(session.selected != nil ? String(localized: "Selected candidate pair")
                 : (session.state == .failed ? String(localized: "No pair succeeded") : String(localized: "Checking")))
                .font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
            if let pair {
                // Peer A's candidate on the left, Peer B's on the right, whichever side sent the checks.
                let a = pair.checkingPeer == 0 ? (pair.local, pair.localKind) : (pair.remote, pair.remoteKind)
                let b = pair.checkingPeer == 0 ? (pair.remote, pair.remoteKind) : (pair.local, pair.localKind)
                if vertical {
                    candidate(a.0, a.1)
                    line(color: color, vertical: true, dashed: dashed)
                    candidate(b.0, b.1)
                } else {
                    HStack(spacing: 0) {
                        line(color: color, vertical: false, dashed: dashed).frame(minWidth: 10, maxWidth: 28)
                        candidate(a.0, a.1).fixedSize()
                        line(color: color, vertical: false, dashed: dashed).frame(minWidth: 24)
                        candidate(b.0, b.1).fixedSize()
                        line(color: color, vertical: false, dashed: dashed).frame(minWidth: 10, maxWidth: 28)
                    }
                }
                if pair.relayed || pair.localKind == .relay || pair.remoteKind == .relay {
                    Text(relayText).font(.wp(11)).foregroundStyle(Theme.acc)
                }
                Text(pairSummary(pair)).font(.wp(11)).foregroundStyle(Theme.fg2).monospacedDigit()
            }
        }
        .padding(.horizontal, vertical ? 14 : 0)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("webrtc.path")
    }

    private func candidate(_ endpoint: Endpoint, _ kind: ICECandidate.Kind) -> some View {
        HStack(spacing: 6) {
            CandidateKindChip(kind: kind)
            Text(endpoint.description).font(.wpMono(11.5)).foregroundStyle(Theme.fg).lineLimit(1)
        }
        .padding(.horizontal, 6)
    }

    private var relayText: String {
        let servers = session.turnAllocations.compactMap { $0 < result.webrtc.allocations.count ? result.webrtc.allocations[$0] : nil }
            .filter(\.succeeded).map(\.server.description)
        return servers.isEmpty ? String(localized: "via TURN relay") : String(localized: "via TURN \(servers.joined(separator: ", "))")
    }

    private func pairSummary(_ pair: ICECandidatePairRecord) -> String {
        var parts = [String(localized: "\(pair.successes)/\(pair.checks) checks answered")]
        if let rtt = pair.meanRTTMs { parts.append(String(format: "RTT %.1f ms", rtt)) }
        if pair.nominated { parts.append(String(localized: "nominated")) }
        return parts.joined(separator: " · ")
    }

    private func line(color: Color, vertical: Bool, dashed: Bool) -> some View {
        let style = StrokeStyle(lineWidth: 2, lineCap: .round, dash: dashed ? [4, 4] : [])
        return Canvas { context, size in
            var path = Path()
            if vertical {
                path.move(to: CGPoint(x: size.width / 2, y: 2))
                path.addLine(to: CGPoint(x: size.width / 2, y: size.height - 2))
            } else {
                path.move(to: CGPoint(x: 2, y: size.height / 2))
                path.addLine(to: CGPoint(x: size.width - 2, y: size.height / 2))
            }
            context.stroke(path, with: .color(color), style: style)
        }
        .frame(height: vertical ? 22 : 8)
        .accessibilityHidden(true)
    }

    /// ICE → DTLS → SRTP, each with what the capture shows.
    private var stages: some View {
        let items = Group {
            stage(String(localized: "ICE"), Self.iceSeverity(session), iceText)
            stage(String(localized: "DTLS"), dtlsSeverity, dtlsText)
            stage(String(localized: "Media"), mediaSeverity, mediaText)
        }
        return Group {
            if layoutWidth == .compact {
                VStack(spacing: 0) { items }.padding(.vertical, 4)
            } else {
                HStack(spacing: 0) { items }
            }
        }
        .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
    }

    static func iceSeverity(_ session: WebRTCSessionRecord) -> Severity {
        switch session.state {
        case .connected: return .ok
        case .failed: return .error
        case .checking: return .info
        }
    }

    private var iceText: String {
        let succeeded = session.pairs.filter { $0.state == .succeeded }.count
        return "\(WebRTCScreen.stateName(session.state)) · " + String(localized: "\(succeeded) of \(session.pairs.count) pairs")
    }

    private var dtlsSeverity: Severity {
        guard let dtls = session.dtls else { return session.selected == nil ? .info : .warning }
        return dtls.established && dtls.alerts == 0 ? .ok : .warning
    }

    private var dtlsText: String {
        guard let dtls = session.dtls else { return String(localized: "Not seen") }
        return "\(WebRTCScreen.dtlsText(dtls)) · " + String(localized: "\(dtls.records) records")
    }

    private var mediaSeverity: Severity {
        guard session.selected != nil else { return .info }
        return session.streamIndices.isEmpty ? .warning : .ok
    }

    private var mediaText: String {
        let streams = session.streamIndices.filter { $0 < result.streams.count }.map { result.streams[$0] }
        guard !streams.isEmpty else { return String(localized: "No RTP on the pair") }
        let packets = streams.reduce(0) { $0 + $1.packetCount }
        let codecs = Array(Set(streams.map(\.codecName))).sorted().joined(separator: ", ")
        return String(localized: "\(streams.count) streams · \(packets) packets") + " · \(codecs)"
    }

    private func stage(_ title: String, _ severity: Severity, _ detail: String) -> some View {
        HStack(spacing: 8) {
            StatusIcon(severity: severity, size: 13)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
                Text(detail).font(.wp(12)).foregroundStyle(Theme.fg).lineLimit(1).monospacedDigit()
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .frame(maxWidth: .infinity, minHeight: layoutWidth == .compact ? 40 : 48)
        .accessibilityElement(children: .combine)
    }
}

/// Host / Server Reflexive / Peer Reflexive / Relay tag.
struct CandidateKindChip: View {
    var kind: ICECandidate.Kind

    var body: some View {
        Chip(text: Self.short(kind), mono: false, fontSize: 11, foreground: color, background: color.opacity(0.14))
            .help(kind.label)
    }

    static func short(_ kind: ICECandidate.Kind) -> String {
        switch kind {
        case .host: return "host"
        case .srflx: return "srflx"
        case .prflx: return "prflx"
        case .relay: return "relay"
        }
    }

    private var color: Color {
        switch kind {
        case .host: return Theme.acc
        case .srflx, .prflx: return Theme.m1
        case .relay: return Theme.m2
        }
    }
}

/// Every candidate pair ICE checked in the session.
struct CandidatePairsCard: View {
    @Environment(WindowModel.self) private var window
    var session: WebRTCSessionRecord
    var transactions: [STUNTransactionRecord]
    @State private var selection: Int?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text("Candidate Pairs").font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
                Text(String(localized: "\(session.pairs.filter { $0.state == .succeeded }.count) of \(session.pairs.count) succeeded"))
                    .font(.wp(11)).foregroundStyle(Theme.fg3)
            }
            DataTable(columns: [.fixed("", 30, .center), .fixed(String(localized: "From"), 50), .flexible(String(localized: "Local")), .fixed("", 58),
                                .flexible(String(localized: "Remote"), from: .regular), .fixed("", 58, from: .regular),
                                .fixed(String(localized: "Checks"), 64, .trailing), .fixed(String(localized: "Answered"), 76, .trailing, from: .regular),
                                .fixed(String(localized: "RTT"), 70, .trailing, from: .wide), .fixed("", 14), .fixed(String(localized: "State"), 110)],
                      ids: session.pairs.map(\.id), selection: $selection,
                      emptyText: String(localized: "No connectivity checks"),
                      cells: cells, onOpen: { showPackets($0) }, menu: { id in
                          AnyView(Button("Show Packets") { showPackets(id) })
                      })
                .frame(height: min(320, CGFloat(max(session.pairs.count, 2)) * 26 + 30))
        }
    }

    private func frames(_ id: Int) -> [Int] {
        guard id < session.pairs.count else { return [] }
        let pair = session.pairs[id]
        return session.transactionIndices.filter { $0 < transactions.count }.map { transactions[$0] }
            .filter { $0.client == pair.local && $0.server == pair.remote }
            .flatMap { $0.requestFrames + ($0.responseFrame.map { [$0] } ?? []) }.sorted()
    }

    private func showPackets(_ id: Int) {
        let frames = frames(id)
        guard !frames.isEmpty else { return }
        window.showPackets(matching: "frame.number in {" + frames.prefix(Finding.maxPacketReferences).map(String.init).joined(separator: " ") + "}")
    }

    private func cells(_ id: Int) -> [CellValue] {
        guard id < session.pairs.count else { return [] }
        let pair = session.pairs[id]
        let severity: Severity = pair.state == .succeeded ? .ok : (pair.state == .failed ? .warning : .info)
        let state: String
        switch pair.state {
        // Keyed: a candidate pair (Spanish "par", masculine).
        case .succeeded:
            state = session.selectedPair == id ? String(localized: "ice.pair.selected", defaultValue: "Selected")
                : (pair.nominated ? String(localized: "ice.pair.nominated", defaultValue: "Nominated")
                   : String(localized: "ice.pair.succeeded", defaultValue: "Succeeded"))
        case .failed:
            state = pair.timeouts > 0 && pair.errors == 0 ? String(localized: "ice.pair.timedOut", defaultValue: "Timed out")
                : String(localized: "ice.pair.failed", defaultValue: "Failed")
        case .inProgress: state = String(localized: "ice.pair.inProgress", defaultValue: "In progress")
        }
        return [.status(severity), .text(pair.checkingPeer == 0 ? "A" : "B", color: Theme.fg2),
                .mono(pair.local.description), .text(CandidateKindChip.short(pair.localKind), color: Theme.fg2),
                .mono(pair.remote.description), .text(CandidateKindChip.short(pair.remoteKind), color: Theme.fg2),
                .text("\(pair.checks)"), .text("\(pair.successes)" + (pair.errors > 0 ? String(localized: " · \(pair.errors) err") : "")),
                .text(Formatters.ms(pair.meanRTTMs), color: Theme.fg2), .text(""),
                .text(state, color: pair.state == .failed ? Theme.warn : (session.selectedPair == id ? Theme.ok : nil),
                      weight: session.selectedPair == id ? .semibold : .regular)]
    }
}

/// Candidates each peer used, by type, and where WirePath learned them.
struct CandidatesCard: View {
    var session: WebRTCSessionRecord

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Candidates"), subtitle: String(localized: "\(session.candidates.count) observed"))
            VStack(alignment: .leading, spacing: 12) {
                ForEach(0..<2, id: \.self) { peer in
                    let candidates = session.candidates.filter { $0.peer == peer }
                    VStack(alignment: .leading, spacing: 6) {
                        Text(peer == 0 ? String(localized: "Peer A") : String(localized: "Peer B"))
                            .font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
                        if candidates.isEmpty {
                            Text("None observed").font(.wp(12)).foregroundStyle(Theme.fg3)
                        }
                        ForEach(Array(candidates.enumerated()), id: \.offset) { _, candidate in
                            HStack(spacing: 8) {
                                CandidateKindChip(kind: candidate.kind).frame(width: 52, alignment: .leading)
                                Text(candidate.endpoint.description).font(.wpMono(11.5)).foregroundStyle(Theme.fg)
                                    .lineLimit(1).textSelection(.enabled)
                                Spacer(minLength: 8)
                                Text(Self.source(candidate.source)).font(.wp(11)).foregroundStyle(Theme.fg3)
                            }
                            .accessibilityElement(children: .combine)
                        }
                    }
                }
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 14, trailing: 14))
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .card()
    }

    static func source(_ source: ObservedCandidate.Source) -> String {
        switch source {
        case .sdp: return String(localized: "SDP")
        case .connectivityCheck: return String(localized: "Connectivity check")
        case .stunServer: return String(localized: "STUN server")
        case .turnServer: return String(localized: "TURN server")
        }
    }
}

/// Candidate gathering: STUN server bindings and TURN allocations.
struct WebRTCGatheringCard: View {
    @Environment(WindowModel.self) private var window
    var webrtc: WebRTCAnalysis
    var bindings: [Int]
    var allocations: [Int]

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "STUN & TURN Servers"),
                       subtitle: String(localized: "\(bindings.count) bindings · \(allocations.count) allocations"))
            VStack(alignment: .leading, spacing: 10) {
                if bindings.isEmpty && allocations.isEmpty {
                    Text("No STUN or TURN servers were contacted from this session's sockets")
                        .font(.wp(12)).foregroundStyle(Theme.fg3)
                }
                ForEach(bindings.filter { $0 < webrtc.transactions.count }, id: \.self) { index in
                    binding(webrtc.transactions[index])
                }
                ForEach(allocations.filter { $0 < webrtc.allocations.count }, id: \.self) { index in
                    allocation(webrtc.allocations[index])
                }
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 14, trailing: 14))
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .card()
    }

    private func binding(_ transaction: STUNTransactionRecord) -> some View {
        let severity: Severity
        let detail: String
        switch transaction.outcome {
        case .success:
            severity = .ok
            detail = String(localized: "mapped \(transaction.mappedAddress?.description ?? "—")") + (transaction.rttMs.map { String(format: " · %.0f ms", $0) } ?? "")
        case .error(let code, let reason):
            severity = .warning
            detail = "\(code) \(reason)"
        case .noResponse:
            severity = .warning
            detail = String(localized: "No response · \(transaction.requestFrames.count) requests")
        case .pending:
            severity = .info
            detail = String(localized: "Capture ended before a response")
        }
        return row(severity, String(localized: "STUN \(transaction.server.description)"), detail,
                   frames: transaction.requestFrames + (transaction.responseFrame.map { [$0] } ?? []))
    }

    private func allocation(_ allocation: TURNAllocationRecord) -> some View {
        let severity: Severity = allocation.succeeded ? .ok : (allocation.errorCodes.isEmpty ? .info : .error)
        var parts: [String] = []
        if allocation.succeeded, let relayed = allocation.relayedAddress {
            parts.append(String(localized: "relay \(relayed.description)"))
        } else if !allocation.errorCodes.isEmpty {
            parts.append(String(localized: "refused \(allocation.errorCodes.map(String.init).joined(separator: ", "))"))
        } else {
            parts.append(String(localized: "not allocated"))
        }
        if allocation.challenges > 0 { parts.append(String(localized: "\(allocation.challenges) auth challenges")) }
        if !allocation.permissions.isEmpty { parts.append(String(localized: "\(allocation.permissions.count) permissions")) }
        if !allocation.channels.isEmpty { parts.append(String(localized: "\(allocation.channels.count) channels")) }
        if allocation.relayedPackets > 0 { parts.append(String(localized: "\(allocation.relayedPackets) relayed packets")) }
        if allocation.released { parts.append(String(localized: "released")) }
        return row(severity, String(localized: "TURN \(allocation.server.description)"), parts.joined(separator: " · "), filter:
                    "turn and ip.addr == \(allocation.server.address) and udp.port == \(allocation.client.port)")
    }

    private func row(_ severity: Severity, _ title: String, _ detail: String, frames: [Int] = [], filter: String? = nil) -> some View {
        Button {
            if let filter {
                window.showPackets(matching: filter)
            } else if !frames.isEmpty {
                window.showPackets(matching: "frame.number in {" + frames.sorted().map(String.init).joined(separator: " ") + "}")
            }
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                StatusIcon(severity: severity, size: 12)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.wpMono(11.5)).foregroundStyle(Theme.fg).lineLimit(1)
                    Text(detail).font(.wp(11.5)).foregroundStyle(Theme.fg2).lineLimit(2).monospacedDigit()
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(String(localized: "Show the packets"))
        .accessibilityElement(children: .combine)
    }
}

/// Diagnostics about the session, each opening the Diagnostics screen.
struct SessionDiagnosticsCard: View {
    @Environment(WindowModel.self) private var window
    var findings: [Finding]

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Diagnostics"), badge: "\(findings.count)")
            VStack(alignment: .leading, spacing: 8) {
                ForEach(findings) { finding in
                    Button {
                        window.showDiagnostic(finding.id)
                    } label: {
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            StatusIcon(severity: finding.severity, size: 12)
                            Text(finding.title).font(.wp(12.5, .medium)).foregroundStyle(Theme.fg)
                            Text(finding.detail).font(.wp(12)).foregroundStyle(Theme.fg2).lineLimit(1)
                            Spacer(minLength: 0)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityElement(children: .combine)
                }
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 14, trailing: 14))
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .card()
    }
}
