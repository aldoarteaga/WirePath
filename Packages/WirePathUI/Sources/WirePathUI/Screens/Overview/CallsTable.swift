import WirePathCore
import SwiftUI

/// Column layout of the calls table (design: 30 76 70 1fr 1fr 112 112 150 78 58 70 74).
enum CallColumns {
    static let status: CGFloat = 30
    static let start: CGFloat = 76
    static let duration: CGFloat = 70
    static let sourceIP: CGFloat = 112
    static let destinationIP: CGFloat = 112
    static let sipStatus: CGFloat = 150
    static let codec: CGFloat = 78
    static let mos: CGFloat = 58
    static let jitter: CGFloat = 70
    static let loss: CGFloat = 74
}

/// The SIP calls table (Overview and Calls screens). Keyboard: ↑↓ move, ↩ investigate, ⇧⌘P packets.
struct CallsTable: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    @FocusState private var focused: Bool

    var body: some View {
        let rows = document.visibleCalls
        VStack(spacing: 0) {
            header
            if rows.isEmpty {
                Text(!document.searchText.isEmpty ? String(localized: "No calls match “\(document.searchText)”")
                     : document.result.calls.isEmpty ? String(localized: "No SIP calls in this capture")
                     : String(localized: "No calls in this category"))
                    .font(.wp(12)).foregroundStyle(Theme.fg3)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView(.vertical) {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(rows.enumerated()), id: \.element) { offset, index in
                                CallRow(call: document.result.calls[index], striped: offset % 2 == 1,
                                        selected: document.selectedCall == index, layoutWidth: layoutWidth)
                                    .id(index)
                                    .onTapGesture(count: 2) { window.investigate(index) }
                                    .onTapGesture { document.selectedCall = index; focused = true }
                                    .contextMenu { callMenu(index) }
                                    .accessibilityAddTraits(.isButton)
                                    .accessibilityAction { window.investigate(index) }
                                    .accessibilityAction(named: "Show Packets") { window.showPackets(forCall: index) }
                                    .accessibilityIdentifier("calls.row.\(index)")
                            }
                        }
                    }
                    .onChange(of: document.selectedCall) { _, selected in
                        if let selected { withAnimationIfAllowed(.linear(duration: 0.08)) { proxy.scrollTo(selected) } }
                    }
                }
            }
        }
        .card(radius: 8)
        .focusable()
        .focusEffectDisabled()
        .focused($focused)
        .onKeyPress(.downArrow) { move(1); return .handled }
        .onKeyPress(.upArrow) { move(-1); return .handled }
        .onKeyPress(.return) {
            if let selected = document.selectedCall { window.investigate(selected) }
            return .handled
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("SIP calls")
        .accessibilityIdentifier("calls.table")
    }

    private func move(_ delta: Int) {
        let rows = document.visibleCalls
        guard !rows.isEmpty else { return }
        let current = document.selectedCall.flatMap { rows.firstIndex(of: $0) } ?? (delta > 0 ? -1 : rows.count)
        document.selectedCall = rows[max(0, min(rows.count - 1, current + delta))]
    }

    @ViewBuilder private func callMenu(_ index: Int) -> some View {
        Button("Investigate") { window.investigate(index) }
        Button("Show Packets") { window.showPackets(forCall: index) }
        Divider()
        Button("Copy Call-ID") {
            Clipboard.copy(document.result.calls[index].callIDs.joined(separator: "\n"))
        }
    }

    private var header: some View {
        HStack(spacing: 0) {
            Color.clear.frame(width: CallColumns.status)
            Button { document.sortAscending.toggle() } label: {
                HStack(spacing: 4) {
                    Text("Start")
                    Icon(document.sortAscending ? Icons.sortUp : Icons.sortDown, size: 8)
                }
                .foregroundStyle(Theme.fg)
                .frame(width: CallColumns.start, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Text("Duration").frame(width: CallColumns.duration - 14, alignment: .trailing).padding(.trailing, 14)
            Text("Caller").frame(maxWidth: .infinity, alignment: .leading)
            Text("Callee").frame(maxWidth: .infinity, alignment: .leading)
            if layoutWidth == .wide {
                Text("Source IP").frame(width: CallColumns.sourceIP, alignment: .leading)
                Text("Destination IP").frame(width: CallColumns.destinationIP, alignment: .leading)
            }
            Text("SIP Status").frame(width: layoutWidth == .compact ? 118 : CallColumns.sipStatus, alignment: .leading)
            if layoutWidth > .compact {
                Text("Codec").frame(width: CallColumns.codec, alignment: .leading)
            }
            Text("MOS").frame(width: CallColumns.mos, alignment: .trailing)
            if layoutWidth > .compact {
                Text("Jitter").frame(width: CallColumns.jitter, alignment: .trailing)
            }
            Text("Loss").frame(width: CallColumns.loss, alignment: .trailing)
        }
        .font(.wp(11.5, .medium))
        .foregroundStyle(Theme.fg2)
        .lineLimit(1)
        .padding(.horizontal, 10)
        .frame(height: 28)
        .background(Theme.surf2)
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
    }
}

struct CallRow: View {
    var call: CallRecord
    var striped: Bool
    var selected: Bool
    var layoutWidth: LayoutWidth = .wide

    var body: some View {
        let q = call.quality
        let fg = selected ? Theme.onSel : Theme.fg
        let sub = selected ? Theme.onSelSub : Theme.fg3
        HStack(spacing: 0) {
            statusIcon.frame(width: CallColumns.status)
            Text(Formatters.clock(call.startTime)).frame(width: CallColumns.start, alignment: .leading)
            Text(call.talkDurationSeconds.map(Formatters.duration) ?? "—")
                .frame(width: CallColumns.duration - 14, alignment: .trailing).padding(.trailing, 14)
            party(call.caller.user, call.caller.displayName, sub: sub)
            party(call.callee.user, call.callee.displayName, sub: sub)
            if layoutWidth == .wide {
                Text(call.caller.signalling.address.description).font(.wpMono(11.5))
                    .frame(width: CallColumns.sourceIP, alignment: .leading)
                Text(call.callee.signalling.address.description).font(.wpMono(11.5))
                    .frame(width: CallColumns.destinationIP, alignment: .leading)
            }
            Text(call.statusLabel)
                .foregroundStyle(selected ? Theme.onSel : (call.state.isFailure ? Theme.err : Theme.fg2))
                .frame(width: layoutWidth == .compact ? 118 : CallColumns.sipStatus, alignment: .leading)
            if layoutWidth > .compact {
                Text(call.codec?.displayName ?? "—").frame(width: CallColumns.codec, alignment: .leading)
            }
            Text(Formatters.mos(q?.mos))
                .fontWeight(.medium)
                .foregroundStyle(levelColor(QualityThresholds.severity(mos: q?.mos)))
                .frame(width: CallColumns.mos, alignment: .trailing)
            if layoutWidth > .compact {
                Text(Formatters.ms(q?.meanJitterMs))
                    .foregroundStyle(levelColor(QualityThresholds.severity(jitterMs: q?.meanJitterMs)))
                    .frame(width: CallColumns.jitter, alignment: .trailing)
            }
            Text(Formatters.percent(q?.lossPercent))
                .foregroundStyle(levelColor(QualityThresholds.severity(lossPercent: q?.lossPercent)))
                .frame(width: CallColumns.loss, alignment: .trailing)
        }
        .font(.wp(12))
        .monospacedDigit()
        .foregroundStyle(fg)
        .lineLimit(1)
        .padding(.horizontal, 10)
        .frame(height: 26)
        .background(selected ? Theme.sel : (striped ? Theme.stripe : Color.clear))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }

    private func levelColor(_ level: Severity) -> Color {
        if selected { return Theme.onSel }
        switch level {
        case .error: return Theme.err
        case .warning: return Theme.warn
        default: return Theme.fg
        }
    }

    private func party(_ user: String, _ name: String?, sub: Color) -> some View {
        HStack(spacing: 6) {
            Text(user).layoutPriority(1)
            if let name { Text(name).foregroundStyle(sub).truncationMode(.tail) }
        }
        .padding(.trailing, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder private var statusIcon: some View {
        switch call.severity {
        case .ok, .info:
            Icon(Icons.dot, size: 8).foregroundStyle(Theme.ok).opacity(0.85)
        case .warning:
            Icon(Icons.statusWarning, size: 12, knockout: selected ? Theme.sel : Theme.win).foregroundStyle(selected ? Theme.onSel : Theme.warn)
        case .error:
            Icon(Icons.statusError, size: 12, knockout: selected ? Theme.sel : Theme.win).foregroundStyle(selected ? Theme.onSel : Theme.err)
        }
    }
}
