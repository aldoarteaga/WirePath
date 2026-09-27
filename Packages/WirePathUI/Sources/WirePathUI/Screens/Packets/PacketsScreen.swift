import SwiftUI
import UniformTypeIdentifiers
import WirePathCore

/// Packet Inspector (design board "Packet Inspector — Dark").
/// Wide: list 650 pt + details side by side. Regular: flexible split. Compact: list, details in a sheet.
struct PacketsScreen: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    var document: AnalysisDocument
    @Bindable var model: PacketInspectorModel
    @State private var showGoTo = false
    @State private var goToText = ""

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "Packets"),
                      subtitle: "\(document.manifest.displayName) · \(Formatters.count(model.totalCount)) \(String(localized: "packets"))") {
                headerControls
            }
            if let error = model.openError {
                VStack(spacing: 10) {
                    StatusIcon(severity: .warning, size: 28)
                    Text("Packets are not available").font(.wp(15, .semibold)).foregroundStyle(Theme.fg)
                    Text(error).font(.wp(12)).foregroundStyle(Theme.fg2).multilineTextAlignment(.center).frame(maxWidth: 480)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                PacketFilterBar(document: document, model: model)
                HStack(spacing: 0) {
                    list
                        .frame(width: listWidth)
                        .frame(maxWidth: listWidth == nil ? .infinity : nil)
                        .overlay(alignment: .trailing) { if showsInlineDetails { Rectangle().fill(Theme.line).frame(width: 1) } }
                    if showsInlineDetails {
                        PacketDetailsPane(document: document, model: model)
                    }
                }
            }
            FooterBar(leading: footerLeading, trailing: footerTrailing)
        }
        .sheet(isPresented: detailSheetBinding) {
            NavigationStack {
                PacketDetailsPane(document: document, model: model)
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Done") { model.detailRequested = false }
                        }
                    }
                    .navigationTitle(model.selectedPosition.map { String(localized: "Packet \($0 + 1)") } ?? "")
                    #if os(iOS)
                    .navigationBarTitleDisplayMode(.inline)
                    #endif
            }
            .presentationDetents([.medium, .large])
        }
        .alert("Go to Packet", isPresented: $showGoTo) {
            TextField("Packet number", text: $goToText)
            Button("Go") { goToPacket() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enter a packet number between 1 and \(model.totalCount).")
        }
    }

    private var list: some View {
        VStack(spacing: 0) {
            PacketListHeader(compact: layoutWidth == .compact)
            PacketListView(model: model, compact: layoutWidth == .compact)
                .overlay {
                    if model.isFiltering {
                        ProgressView().controlSize(.small).padding(10)
                            .background(RoundedRectangle(cornerRadius: 8).fill(Theme.surf2))
                    } else if model.displayedCount == 0 {
                        Text("No packets match").font(.wp(12)).foregroundStyle(Theme.fg3)
                    }
                }
        }
    }

    /// Details are inline on regular/wide layouts; compact layouts present them in a sheet.
    private var showsInlineDetails: Bool { model.showDetails && layoutWidth != .compact }

    private var listWidth: CGFloat? {
        guard showsInlineDetails else { return nil }
        return layoutWidth == .wide ? 650 : 440
    }

    private var detailSheetBinding: Binding<Bool> {
        Binding(get: { layoutWidth == .compact && model.detailRequested && model.selectedPosition != nil },
                set: { model.detailRequested = $0 })
    }

    @ViewBuilder private var headerControls: some View {
        let callIndex = selectedCall
        if layoutWidth > .compact {
            PillButton(icon: Icons.sipDialogs, iconSize: 14, title: String(localized: "Open in SIP Flow"),
                       help: callIndex == nil ? String(localized: "The selected packet does not belong to a call")
                           : String(localized: "Open the selected packet's call"),
                       isEnabled: callIndex != nil) {
                if let callIndex { window.investigate(callIndex) }
            }
        }
        PacketSearchControls(model: model, width: layoutWidth == .wide ? 230 : 150)
        HStack(spacing: 2) {
            IconButton(icon: Icons.goToPacket, iconSize: 16, help: String(localized: "Go to Packet (⌘G)")) {
                goToText = ""
                showGoTo = true
            }
            .macKeyboardShortcut("g", modifiers: .command)
            IconButton(icon: Icons.export, iconSize: 17, help: String(localized: "Export Displayed Packets (⇧⌘E)")) { exportPackets() }
            if layoutWidth > .compact {
                IconButton(icon: Icons.inspector, iconSize: 18, tint: model.showDetails ? Theme.acc : Theme.fg2,
                           help: model.showDetails ? String(localized: "Hide Packet Details (⌥⌘I)") : String(localized: "Show Packet Details (⌥⌘I)")) {
                    withAnimationIfAllowed { model.showDetails.toggle() }
                }
            }
        }
    }

    private var selectedCall: Int? {
        guard let store = model.store, let position = model.selectedPosition else { return nil }
        let record = store.record(at: position)
        return record.callIndex >= 0 ? Int(record.callIndex) : model.callIndex
    }

    private var footerLeading: String {
        var text = String(localized: "Displayed \(model.displayedCount) of \(model.totalCount)")
        let truncated = document.result.capture.truncatedPackets
        if truncated > 0 { text += " · " + String(localized: "Truncated \(truncated)") }
        return text
    }

    private var footerTrailing: String {
        guard let position = model.selectedPosition, let packet = model.dissection else { return String(localized: "No packet selected") }
        var parts = [String(localized: "Selected \(position + 1)"), packet.summary]
        if let call = selectedCall { parts.append(document.callTitle(call)) }
        return parts.joined(separator: " · ")
    }

    private func goToPacket() {
        guard let number = Int(goToText.filter(\.isNumber)) else { return }
        model.reveal(frame: number)
    }

    private func exportPackets() {
        guard let store = model.store else { return }
        let positions = (0..<model.displayedCount).compactMap { model.position(forRow: $0) }
        let name = ((document.manifest.displayName as NSString).deletingPathExtension) + " filtered.pcap"
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".pcap")
        let library = window.library
        Task {
            do {
                _ = try await Task.detached { try store.exportPCAP(positions: positions, to: temporary) }.value
                window.pendingExport = ExportFile(filename: name, contentType: CaptureTypes.pcap, url: temporary)
            } catch {
                library.lastError = String(localized: "The packets could not be exported: \(error.localizedDescription)")
            }
        }
    }
}

// MARK: - Filter bar

struct PacketFilterBar: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    var document: AnalysisDocument
    @Bindable var model: PacketInspectorModel
    @State private var liveError: DisplayFilterError?
    @FocusState private var focused: Bool

    var body: some View {
        Group {
            if layoutWidth == .compact {
                // Narrow widths: filter field on its own row, scopes and count below.
                VStack(spacing: 8) {
                    filterField
                    HStack(spacing: 10) {
                        ScrollView(.horizontal) { scopes }.scrollIndicators(.never)
                        count
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
            } else {
                HStack(spacing: 10) {
                    filterField
                    scopes
                    count
                }
                .padding(.horizontal, 14)
                .frame(height: 46)
            }
        }
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
        .onChange(of: window.displayFilterFocusRequest) { focused = true }
    }

    private var filterField: some View {
        let empty = model.filterText.trimmingCharacters(in: .whitespaces).isEmpty
        let error = liveError ?? model.filterError
        let ring: Color = empty ? .clear : (error == nil ? Theme.ok : Theme.err)
        return HStack(spacing: 6) {
            Icon(Icons.filterLines, size: 14).foregroundStyle(empty ? Theme.fg3 : (error == nil ? Theme.ok : Theme.err))
            if let call = model.callIndex, call < document.result.calls.count {
                token(String(localized: "Call · \(Formatters.clock(document.result.calls[call].startTime))"),
                      help: String(localized: "Remove call filter")) {
                    model.removeCallToken()
                }
            }
            if model.scope != .all && layoutWidth > .compact {
                token(String(localized: "Protocol · \(scopeLabel)"), help: String(localized: "Remove protocol filter")) { model.setScope(.all) }
            }
            TextField("", text: $model.filterText,
                      prompt: Text(layoutWidth == .compact ? String(localized: "Display filter") : String(localized: "Display filter, e.g. rtp.seq_gap or sip.status >= 400"))
                        .foregroundStyle(Theme.fg3))
                .textFieldStyle(.plain)
                .font(.wpMono(12))
                .foregroundStyle(Theme.fg)
                .focused($focused)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .submitLabel(.search)
                #endif
                .onSubmit { model.applyFilter() }
                .onChange(of: model.filterText) { _, text in liveError = model.validate(text) }
                .accessibilityLabel("Display filter")
                .accessibilityIdentifier("packets.filter")
            if !empty {
                Text(error.map { $0.message } ?? String(localized: "Valid filter"))
                    .font(.wp(11)).foregroundStyle(error == nil ? Theme.ok : Theme.err)
                    .lineLimit(1)
                    .help(error?.message ?? String(localized: "Press Return to apply"))
            }
        }
        .padding(.horizontal, 8)
        .frame(height: layoutWidth == .compact ? 34 : 28)
        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.ctrl))
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(ring, lineWidth: 1))
        .help(String(localized: "Fields: ") + DisplayFilter.knownFields.joined(separator: ", "))
    }

    private var scopes: some View {
        SegmentedControl(items: [
            .init(value: PacketScope.all, title: String(localized: "All")),
            .init(value: .sipRTP, title: String(localized: "SIP + RTP")),
            .init(value: .sdp, title: String(localized: "SDP")),
            .init(value: .rtcp, title: String(localized: "RTCP")),
            .init(value: .issues, title: String(localized: "Issues"), leadingIcon: Icons.statusWarningPlain, iconColor: Theme.warn),
        ], selection: Binding(get: { model.scope }, set: { model.setScope($0) }), horizontalPadding: 10)
    }

    private var count: some View {
        Text("\(model.displayedCount) of \(model.totalCount)")
            .font(.wp(11)).foregroundStyle(Theme.fg2).lineLimit(1).fixedSize()
    }

    private var scopeLabel: String {
        switch model.scope {
        case .all: return String(localized: "All")
        case .sipRTP: return "SIP, RTP"
        case .sdp: return "SDP"
        case .rtcp: return "RTCP"
        case .issues: return String(localized: "Issues")
        }
    }

    private func token(_ text: String, help: String, remove: @escaping () -> Void) -> some View {
        HStack(spacing: 5) {
            Text(text).font(.wp(12)).lineLimit(1).fixedSize()
            Button(action: remove) { Icon(Icons.close, size: 12).opacity(0.8) }
                .buttonStyle(.plain)
                .help(help)
                .accessibilityLabel(help)
        }
        .foregroundStyle(Theme.acc)
        .padding(.leading, 7).padding(.trailing, 4)
        .frame(height: 20)
        .background(RoundedRectangle(cornerRadius: 5).fill(Theme.selSoft))
    }
}

// MARK: - Details

struct PacketDetailsPane: View {
    @Environment(WindowModel.self) private var window
    var document: AnalysisDocument
    @Bindable var model: PacketInspectorModel

    var body: some View {
        VStack(spacing: 0) {
            if let packet = model.dissection, let position = model.selectedPosition, let store = model.store {
                let record = store.record(at: position)
                HStack(spacing: 10) {
                    Text("Packet \(position + 1)").font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
                    Text("\(String(format: "%.6f", record.timestamp.seconds(since: Timestamp(nanoseconds: model.referenceNanos)))) s · \(Int(record.originalLength)) bytes · \(packet.summary)")
                        .font(.wp(11)).foregroundStyle(Theme.fg3).lineLimit(1)
                    Spacer(minLength: 0)
                    if record.flowIndex >= 0 {
                        // Packet → Flow: show every packet of this conversation.
                        Button("Follow Flow") {
                            model.detailRequested = false
                            window.showPackets(forFlow: Int(record.flowIndex))
                        }
                        .buttonStyle(.plain).font(.wp(11.5)).foregroundStyle(Theme.acc)
                        .help(String(localized: "Show only the packets of flow #\(Int(record.flowIndex) + 1)"))
                    }
                    Button("Expand All") { model.expandAll() }
                        .buttonStyle(.plain).font(.wp(11.5)).foregroundStyle(Theme.acc)
                        .macKeyboardShortcut(.rightArrow, modifiers: .command)
                }
                .padding(.horizontal, 14)
                .frame(height: 38)
                .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }

                PacketNotes(frame: position + 1, problem: packet.problem, comments: document.packetComments(frame: position + 1))
                ProtocolTree(packet: packet, model: model)
                HexPane(packet: packet, model: model)
            } else {
                Text(model.store == nil ? "" : String(localized: "Select a packet to see its layers"))
                    .font(.wp(12)).foregroundStyle(Theme.fg3)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Theme.surf)
    }
}

/// Decode problems and capture-file comments for the selected packet, above its protocol tree.
struct PacketNotes: View {
    var frame: Int
    var problem: DecodeProblem?
    var comments: [String]

    var body: some View {
        if problem != nil || !comments.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                if let problem {
                    HStack(alignment: .top, spacing: 8) {
                        StatusIcon(severity: .warning, size: 12)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Packet #\(frame) could not be fully decoded.")
                                .font(.wp(12, .semibold)).foregroundStyle(Theme.fg)
                            Text("Reason: \(problem.message).").font(.wp(12)).foregroundStyle(Theme.fg2)
                            Text("The remaining capture can still be analyzed.").font(.wp(11.5)).foregroundStyle(Theme.fg3)
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
                ForEach(Array(comments.enumerated()), id: \.offset) { _, comment in
                    HStack(alignment: .top, spacing: 8) {
                        StatusIcon(severity: .info, size: 12)
                        Text(comment).font(.wp(12)).foregroundStyle(Theme.fg).textSelection(.enabled)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel(Text("Packet comment: \(comment)"))
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surf2)
            .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
        }
    }
}

/// Header search: IP, port, packet number, Call-ID, SIP URI, SSRC, protocol or payload text, with match navigation.
struct PacketSearchControls: View {
    @Environment(WindowModel.self) private var window
    @Bindable var model: PacketInspectorModel
    var width: CGFloat

    var body: some View {
        HStack(spacing: 4) {
            SearchField(placeholder: String(localized: "Find IP, port, Call-ID, SSRC, text"), text: $model.searchText,
                        width: width, focusRequest: window.searchFocusRequest) { model.runSearch() }
            if let summary = model.searchSummary {
                Text(summary).font(.wp(11)).foregroundStyle(Theme.fg3).lineLimit(1).monospacedDigit()
                    .accessibilityLabel(Text(summary))
                if (model.searchResults?.hits.count ?? 0) > 1 {
                    IconButton(icon: Icons.up, iconSize: 12, help: String(localized: "Previous Match")) { model.showMatch(offset: -1) }
                    IconButton(icon: Icons.down, iconSize: 12, help: String(localized: "Next Match")) { model.showMatch(offset: 1) }
                }
            }
        }
        .onChange(of: model.searchText) { _, text in if text.isEmpty { model.clearSearch() } }
    }
}

struct ProtocolTree: View {
    var packet: DissectedPacket
    @Bindable var model: PacketInspectorModel

    var body: some View {
        ScrollView(.vertical) {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(packet.layers) { layer in
                    let open = model.expandedLayers.contains(layer.id)
                    Button {
                        if open { model.expandedLayers.remove(layer.id) } else { model.expandedLayers.insert(layer.id) }
                    } label: {
                        HStack(spacing: 6) {
                            Icon(Icons.disclosure, size: 9).foregroundStyle(Theme.fg3).rotationEffect(.degrees(open ? 90 : 0))
                            Text(layer.name).font(.wp(12, .semibold)).foregroundStyle(Theme.fg)
                            Text(layer.summary).font(.wp(12)).foregroundStyle(Theme.fg2).truncationMode(.tail)
                        }
                        .lineLimit(1)
                        .padding(.horizontal, 14)
                        .frame(height: 22)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(open ? [.isSelected] : [])
                    if open {
                        ForEach(layer.fields) { field in
                            HStack(spacing: 0) {
                                // Nested fields (DNS records, TLS extensions, STUN attributes…) indent their name and keep values aligned.
                                Text(field.name).font(.wp(12)).foregroundStyle(Theme.fg2).lineLimit(1)
                                    .frame(width: 120 - CGFloat(min(field.level, 2)) * 16, alignment: .leading)
                                Text(field.value).font(.wpMono(11.5)).foregroundStyle(Theme.fg).lineLimit(1).truncationMode(.tail)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .padding(.leading, 40 + CGFloat(min(field.level, 2)) * 16).padding(.trailing, 14)
                            .frame(height: 22)
                            .background(model.selectedFieldID == field.id ? Theme.selSoft : .clear)
                            .contentShape(Rectangle())
                            .onTapGesture { model.selectedFieldID = field.id }
                            .contextMenu {
                                Button("Copy Value") { Clipboard.copy(field.value) }
                                Button("Copy Name and Value") { Clipboard.copy("\(field.name): \(field.value)") }
                            }
                            .help("\(field.name): \(field.value)")
                        }
                    }
                }
            }
            .padding(.vertical, 4)
            // Layer and field IDs restart for every packet: a new identity per packet keeps the lazy stack from
            // reusing rows of the previously selected packet.
            .id(packet.frameNumber)
        }
        .frame(maxHeight: .infinity)
    }
}

struct HexPane: View {
    var packet: DissectedPacket
    @Bindable var model: PacketInspectorModel

    var body: some View {
        let field = model.selectedField
        let range = field?.range ?? packet.layers.last?.range
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Text("Bytes").font(.wp(12, .semibold)).foregroundStyle(Theme.fg)
                if let range {
                    Text("\(field?.name ?? packet.layers.last?.name ?? "") · offset \(String(format: "0x%04x", range.lowerBound)) · \(range.count) bytes")
                        .font(.wp(11)).foregroundStyle(Theme.fg3).lineLimit(1)
                }
                Spacer(minLength: 0)
                SegmentedControl(items: [.init(value: false, title: String(localized: "Hex")), .init(value: true, title: String(localized: "Bits"))],
                                 selection: $model.showBits, fontSize: 11, horizontalPadding: 8, verticalPadding: 1,
                                 outerRadius: 6, innerRadius: 4)
            }
            .padding(.horizontal, 14)
            .frame(height: 30)
            ScrollViewReader { proxy in
                ScrollView(.vertical) {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        let bytes = [UInt8](packet.bytes)
                        let perLine = model.showBits ? 4 : 16
                        let lines = (bytes.count + perLine - 1) / perLine
                        ForEach(0..<lines, id: \.self) { line in
                            Text(lineText(bytes, line: line, perLine: perLine, highlight: range))
                                .font(.wpMono(11.5))
                                .frame(height: 19)
                                .id(line)
                        }
                    }
                    .padding(EdgeInsets(top: 2, leading: 14, bottom: 10, trailing: 14))
                    .textSelection(.enabled)
                }
                .onChange(of: range) { _, newRange in scroll(proxy, to: newRange) }
                .onAppear { scroll(proxy, to: range) }
            }
        }
        .frame(height: 196)
        .background(Theme.win)
        .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
    }

    private func scroll(_ proxy: ScrollViewProxy, to range: Range<Int>?) {
        guard let range else { return }
        let perLine = model.showBits ? 4 : 16
        proxy.scrollTo(max(0, range.lowerBound / perLine - 2), anchor: .top)
    }

    private func lineText(_ bytes: [UInt8], line: Int, perLine: Int, highlight: Range<Int>?) -> AttributedString {
        var result = AttributedString(String(format: "%04x", line * perLine))
        result.foregroundColor = Theme.fg3
        result += AttributedString("  ")
        var hex = AttributedString()
        var ascii = AttributedString()
        for k in 0..<perLine {
            let index = line * perLine + k
            let inRange = highlight?.contains(index) ?? false
            let nextInRange = highlight?.contains(index + 1) ?? false
            var cell: AttributedString
            if index < bytes.count {
                let b = bytes[index]
                cell = AttributedString(model.showBits ? String(b, radix: 2).leftPadded(to: 8) : String(format: "%02x", b))
                var char = AttributedString(b >= 32 && b < 127 ? String(UnicodeScalar(b)) : "·")
                char.foregroundColor = inRange ? Theme.fg : Theme.fg3
                if inRange { char.backgroundColor = Theme.highlight }
                ascii += char
            } else {
                cell = AttributedString(model.showBits ? "        " : "  ")
            }
            cell.foregroundColor = inRange ? Theme.fg : Theme.fg2
            if inRange { cell.backgroundColor = Theme.highlight }
            hex += cell
            if k < perLine - 1 {
                var gap = AttributedString(!model.showBits && k == 7 ? "  " : " ")
                if inRange && nextInRange { gap.backgroundColor = Theme.highlight }
                hex += gap
            }
        }
        result += hex
        result += AttributedString("  ")
        result += ascii
        return result
    }
}

private extension String {
    func leftPadded(to length: Int) -> String {
        count >= length ? self : String(repeating: "0", count: length - count) + self
    }
}
