import WirePathCore
import SwiftUI

/// SIP Dialogs: every Call-ID session, its messages, transactions, headers and SDP.
struct SIPDialogsScreen: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    @State private var search = ""

    private var result: AnalysisResult { document.result }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "SIP Dialogs"),
                      subtitle: String(localized: "\(document.manifest.displayName) · \(result.sipSessions.count) dialogs · \(result.sipMessages.count) messages")) {
                SearchField(placeholder: String(localized: "Search Call-ID, user, method"), text: $search,
                            width: layoutWidth == .wide ? 250 : 170,
                            focusRequest: window.searchFocusRequest)
            }
            VStack(spacing: 14) {
                HStack(alignment: .bottom, spacing: 16) {
                    ScreenTitle(title: String(localized: "SIP Dialogs"), subtitle: subtitle)
                    Spacer(minLength: 8)
                    if layoutWidth == .wide { responseCodes }
                }
                DataTable(columns: sessionColumns, ids: visibleSessions, selection: $document.selectedSession,
                          emptyText: search.isEmpty ? String(localized: "No SIP traffic in this capture") : String(localized: "No dialogs match “\(search)”"),
                          cells: sessionCells, onOpen: openSession, menu: { id in AnyView(sessionMenu(id)) })
                    .frame(maxHeight: .infinity)
                if let session = document.selectedSession, session < result.sipSessions.count {
                    if layoutWidth == .wide {
                        HStack(alignment: .top, spacing: 14) {
                            SessionMessagesCard(document: document, session: result.sipSessions[session])
                                .frame(width: 470)
                            SIPMessageDetailCard(document: document)
                        }
                        .frame(height: 330)
                    } else {
                        SessionMessagesCard(document: document, session: result.sipSessions[session]).frame(height: 240)
                        SIPMessageDetailCard(document: document).frame(height: 300)
                    }
                }
            }
            .padding(EdgeInsets(top: 18, leading: 22, bottom: 16, trailing: 22))
            FooterBar(leading: String(localized: "\(visibleSessions.count) of \(result.sipSessions.count) dialogs · \(result.sipTransactions.count) transactions"),
                      trailing: selectionSummary)
        }
        .onAppear {
            if document.selectedSession == nil { document.selectedSession = result.sipSessions.indices.first }
        }
        .onChange(of: document.selectedSession) { _, session in
            document.selectedSessionMessage = session.flatMap { result.sipSessions[$0].messageIndices.first }
        }
    }

    private var subtitle: String {
        let invites = result.sipSessions.filter { $0.initialMethod == "INVITE" }.count
        let retransmissions = result.sipMessages.filter(\.isRetransmission).count
        return String(localized: "\(invites) INVITE · \(result.sipSessions.count - invites) other · \(retransmissions) retransmissions")
    }

    /// Response-code distribution ("Códigos de respuesta").
    private var responseCodes: some View {
        var counts: [Int: Int] = [:]
        for message in result.sipMessages where !message.isRequest && !message.isRetransmission {
            if let code = message.statusCode { counts[code, default: 0] += 1 }
        }
        let sorted = counts.sorted { $0.key < $1.key }.prefix(8)
        return HStack(spacing: 5) {
            ForEach(sorted, id: \.key) { code, count in
                Chip(text: "\(code) ×\(count)", fontSize: 11,
                     foreground: code >= 400 ? Theme.err : code >= 200 && code < 300 ? Theme.ok : Theme.fg2)
                    .help(SIPStatus.reasonPhrase(for: code))
            }
        }
    }

    private var sessionColumns: [ColumnSpec] {
        [.fixed("", 30, .center), .fixed(String(localized: "Start"), 76), .fixed(String(localized: "Method"), 86), .flexible(String(localized: "From")), .flexible(String(localized: "To")),
         .fixed(String(localized: "Messages"), 74, .trailing, from: .regular), .fixed(String(localized: "Duration"), 76, .trailing, from: .regular),
         .fixed("", 16, from: .wide), .fixed(String(localized: "Result"), 170), .flexible(String(localized: "Call-ID"), from: .wide)]
    }

    private var visibleSessions: [Int] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return result.sipSessions.indices.filter { index in
            guard !query.isEmpty else { return true }
            let s = result.sipSessions[index]
            return [s.callID, s.initialMethod, s.from.shortIdentity, s.to.shortIdentity, s.from.displayName ?? "", s.to.displayName ?? ""]
                .contains { $0.lowercased().contains(query) }
        }
    }

    private func sessionCells(_ index: Int) -> [CellValue] {
        let s = result.sipSessions[index]
        let severity: Severity = s.state == .failed || s.state == .noResponse ? .error : .ok
        let resultText: String
        switch s.state {
        case .completed: resultText = String(localized: "Completed")
        case .established: resultText = String(localized: "Established")
        case .early: resultText = String(localized: "Early (no answer)")
        case .cancelled: resultText = String(localized: "Cancelled")
        case .noResponse: resultText = String(localized: "No response")
        case .succeeded, .failed:
            resultText = s.finalStatusCode.map { "\($0) \(SIPStatus.reasonPhrase(for: $0))" } ?? s.state.rawValue
        }
        return [.status(severity), .text(Formatters.clock(s.startTime)), .text(s.initialMethod, weight: .medium),
                .party(s.from.shortIdentity, s.from.displayName), .party(s.to.shortIdentity, s.to.displayName),
                .text("\(s.messageIndices.count)"), .text(Formatters.duration(s.durationSeconds)), .text(""),
                .text(resultText, color: severity == .error ? Theme.err : Theme.fg2), .mono(s.callID, color: Theme.fg2)]
    }

    private func openSession(_ index: Int) {
        if let call = result.sipSessions[index].callIndex { window.investigate(call) }
    }

    @ViewBuilder private func sessionMenu(_ index: Int) -> some View {
        let session = result.sipSessions[index]
        if let call = session.callIndex {
            Button("Investigate Call") { window.investigate(call) }
            Button("Show Packets") { window.showPackets(forCall: call) }
        }
        Button("Copy Call-ID") {
            Clipboard.copy(session.callID)
        }
    }

    private var selectionSummary: String {
        guard let index = document.selectedSession, index < result.sipSessions.count else { return String(localized: "No selection") }
        let s = result.sipSessions[index]
        return String(localized: "\(s.initialMethod) · \(s.messageIndices.count) messages · \(s.transactionIndices.count) transactions")
    }
}

/// Messages of one dialog with its transactions summary.
struct SessionMessagesCard: View {
    var document: AnalysisDocument
    var session: SIPSessionRecord

    var body: some View {
        let result = document.result
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Messages"), subtitle: String(localized: "\(session.messageIndices.count) · \(session.transactionIndices.count) transactions"))
            ScrollView(.vertical) {
                LazyVStack(spacing: 0) {
                    ForEach(Array(session.messageIndices.enumerated()), id: \.element) { offset, index in
                        let message = result.sipMessages[index]
                        let selected = document.selectedSessionMessage == index
                        HStack(spacing: 8) {
                            Text(String(format: "%.3f", message.time.seconds(since: session.startTime)))
                                .font(.wpMono(11)).foregroundStyle(selected ? Theme.onSelSub : Theme.fg3).frame(width: 64, alignment: .leading)
                            Text(message.label)
                                .font(.wp(12, message.isRequest || (message.statusCode ?? 0) >= 200 ? .semibold : .regular))
                                .foregroundStyle(selected ? Theme.onSel : color(message))
                                .frame(width: 150, alignment: .leading)
                            Text(verbatim: "\(message.source.address) → \(message.destination.address)")
                                .font(.wpMono(11)).foregroundStyle(selected ? Theme.onSel : Theme.fg2)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            if message.hasSDP { Text("SDP").font(.wp(10)).foregroundStyle(selected ? Theme.onSelSub : Theme.fg3) }
                            if message.isRetransmission { Text("↻").font(.wp(11)).foregroundStyle(selected ? Theme.onSelSub : Theme.warn).help("Retransmission").accessibilityLabel("Retransmission") }
                        }
                        .lineLimit(1)
                        .padding(.horizontal, 14)
                        .frame(height: 24)
                        .background(selected ? Theme.sel : (offset % 2 == 1 ? Theme.stripe : .clear))
                        .contentShape(Rectangle())
                        .onTapGesture { document.selectedSessionMessage = index }
                    }
                }
            }
            transactions(result)
        }
        .card()
    }

    private func color(_ message: SIPMessageRecord) -> Color {
        if message.isRequest { return Theme.fg }
        let code = message.statusCode ?? 0
        return code >= 400 ? Theme.err : code >= 200 ? Theme.ok : Theme.fg2
    }

    private func transactions(_ result: AnalysisResult) -> some View {
        let items = session.transactionIndices.map { result.sipTransactions[$0] }
        return ScrollView(.horizontal) {
            HStack(spacing: 6) {
                ForEach(items, id: \.id) { t in
                    let code = t.finalStatusCode
                    Text("\(t.method) \(t.cseq) · \(code.map(String.init) ?? "—") · \(String(format: "%.2f s", t.durationSeconds))\(t.retransmissions > 0 ? " · ↻\(t.retransmissions)" : "")")
                        .font(.wp(11))
                        .foregroundStyle(code.map { $0 >= 400 ? Theme.err : Theme.fg2 } ?? Theme.warn)
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(RoundedRectangle(cornerRadius: 5).fill(Theme.ctrl))
                }
            }
            .padding(.horizontal, 14)
        }
        .scrollIndicators(.never)
        .frame(height: 38)
        .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
    }
}

/// Full text of the selected SIP message: headers (name/value) and SDP body.
struct SIPMessageDetailCard: View {
    var document: AnalysisDocument

    var body: some View {
        let result = document.result
        VStack(spacing: 0) {
            if let index = document.selectedSessionMessage, index < result.sipMessages.count {
                let message = result.sipMessages[index]
                CardHeader(title: message.label,
                           subtitle: String(localized: "\(message.source.description) → \(message.destination.description) · frame \(message.frameNumber) · \(message.byteLength) bytes · \(message.transport.rawValue.uppercased())"))
                ScrollView(.vertical) {
                    Text(styled(document.sipText(index)))
                        .font(.wpMono(11.5))
                        .lineSpacing(3)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .padding(14)
                }
            } else {
                Text("Select a message").font(.wp(12)).foregroundStyle(Theme.fg3).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .card()
    }

    private func styled(_ text: String) -> AttributedString {
        var output = AttributedString()
        var inBody = false
        let lines = text.components(separatedBy: "\n").map { $0.hasSuffix("\r") ? String($0.dropLast()) : $0 }
        for (index, line) in lines.enumerated() {
            var piece: AttributedString
            if index == 0 {
                piece = AttributedString(line)
                piece.foregroundColor = Theme.fg
                piece.inlinePresentationIntent = .stronglyEmphasized
            } else if line.isEmpty {
                inBody = true
                piece = AttributedString("")
            } else if !inBody, let colon = line.firstIndex(of: ":") {
                var name = AttributedString(String(line[...colon]))
                name.foregroundColor = Theme.acc
                var value = AttributedString(String(line[line.index(after: colon)...]))
                value.foregroundColor = Theme.fg
                piece = name + value
            } else if inBody, line.count >= 2, line.dropFirst().first == "=" {
                var key = AttributedString(String(line.prefix(2)))
                key.foregroundColor = Theme.m2
                var value = AttributedString(String(line.dropFirst(2)))
                value.foregroundColor = Theme.fg
                piece = key + value
            } else {
                piece = AttributedString(line)
                piece.foregroundColor = Theme.fg2
            }
            output += piece
            if index < lines.count - 1 { output += AttributedString("\n") }
        }
        return output
    }
}
