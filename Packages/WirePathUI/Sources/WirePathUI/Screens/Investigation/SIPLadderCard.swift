import WirePathCore
import SwiftUI

/// SIP ladder diagram (design: "SIP Flow" card, 620 × 540, geometry copied from the SVG).
struct SIPLadderCard: View {
    @Environment(WindowModel.self) private var window
    var document: AnalysisDocument
    var call: CallRecord
    @Binding var selectedMessage: Int?
    @Binding var showSDP: Bool
    var search: String

    @State private var availableWidth: CGFloat = 588

    var body: some View {
        // The design's ladder is 588 pt wide; narrower cards tighten the columns (min 420 pt, then scroll).
        let layout = LadderLayout(call: call, result: document.result, width: max(420, min(588, availableWidth - 32)))
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "SIP Flow"),
                       subtitle: String(localized: "\(call.messageIndices.count) messages · \(call.participants.count) participants")) {
                Toggle(isOn: $showSDP) { Text("Show SDP").font(.wp(12)).foregroundStyle(Theme.fg2) }
                    #if os(macOS)
                    .toggleStyle(.checkbox)
                    #else
                    .toggleStyle(.button)
                    #endif
                    .controlSize(.small)
                IconButton(icon: Icons.export, iconSize: 15, width: 28, height: 24, help: String(localized: "Export Ladder Diagram")) {
                    exportLadder(layout)
                }
            }
            ScrollView([.vertical, .horizontal]) {
                ZStack(alignment: .topLeading) {
                    LadderCanvas(layout: layout, selected: selectedMessage, showSDP: showSDP, highlight: search)
                        .frame(width: layout.width, height: layout.height)
                    // Hit targets for selecting messages.
                    ForEach(layout.messageRows, id: \.messageIndex) { row in
                        Color.clear
                            .contentShape(Rectangle())
                            .frame(width: layout.width, height: 22)
                            .offset(y: row.y - 14)
                            .onTapGesture(count: 2) { openPacket(row.messageIndex) }
                            .onTapGesture { selectedMessage = row.messageIndex }
                            .help(tooltip(row.messageIndex))
                    }
                }
                .frame(width: layout.width, height: layout.height, alignment: .topLeading)
                .padding(EdgeInsets(top: 10, leading: 16, bottom: 10, trailing: 16))
                .containerRelativeFrame(.horizontal) { width, _ in max(width, layout.width + 32) }
            }
            .scrollIndicators(.automatic)
        }
        .card()
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { availableWidth = $0 }
        .onAppear { if selectedMessage == nil { selectedMessage = call.messageIndices.first } }
    }

    private func tooltip(_ index: Int) -> String {
        let message = document.result.sipMessages[index]
        return String(localized: "\(message.infoText)\n\(message.source.description) → \(message.destination.description)\nFrame \(message.frameNumber) · \(message.byteLength) bytes\(message.isRetransmission ? " · retransmission" : "")\nDouble-click to show the packet")
    }

    private func openPacket(_ index: Int) {
        let message = document.result.sipMessages[index]
        let model = document.packetModel(callIndex: call.id)
        model.selectedPosition = message.frameNumber - 1
        window.showPackets(forCall: call.id)
    }

    @MainActor private func exportLadder(_ layout: LadderLayout) {
        let renderer = ImageRenderer(content: LadderCanvas(layout: layout, selected: nil, showSDP: showSDP, highlight: "")
            .frame(width: layout.width, height: layout.height)
            .padding(16)
            .background(Theme.surf)
            .environment(\.colorScheme, .light))
        renderer.scale = 2
        guard let image = renderer.cgImage, let png = PNGEncoder.data(for: image) else { return }
        let name = String(localized: "SIP flow \(Formatters.clock(call.startTime).replacingOccurrences(of: ":", with: "-")).png")
        window.pendingExport = try? ExportFile.temporary(png, filename: name, contentType: .png)
    }
}

/// Geometry of the ladder, computed once per call.
struct LadderLayout {
    struct Column { var x: CGFloat; var label: String; var address: String }
    struct MessageRow {
        var messageIndex: Int
        var y: CGFloat
        var fromX: CGFloat
        var toX: CGFloat
        var label: String
        var kind: Kind
        var hasSDP: Bool
        var time: Double
        var retransmission: Bool
        enum Kind { case request, provisional, success, failure }
    }
    struct Band {
        var top: CGFloat
        var fromX: CGFloat
        var toX: CGFloat
        var label: String
        var startTime: Double
        var endTime: Double
    }

    var width: CGFloat
    var height: CGFloat = 0
    var columns: [Column] = []
    var boxWidth: CGFloat = 116
    var messageRows: [MessageRow] = []
    var band: Band?

    static let firstRowY: CGFloat = 82
    static let rowStep: CGFloat = 24
    static let bandHeight: CGFloat = 32

    init(call: CallRecord, result: AnalysisResult, width: CGFloat) {
        self.width = width
        let participants = call.participants
        let first: CGFloat = 150, last: CGFloat = width - 60
        let count = max(1, participants.count)
        let spacing = count > 1 ? (last - first) / CGFloat(count - 1) : 0
        boxWidth = count > 1 ? min(116, spacing - 8) : 116
        columns = participants.enumerated().map { index, participant in
            Column(x: count > 1 ? first + CGFloat(index) * spacing : (first + last) / 2, label: participant.label,
                   address: participant.address.description)
        }
        func columnX(_ address: IPAddress) -> CGFloat? {
            participants.firstIndex { $0.address == address }.map { columns[$0].x }
        }

        let messages = call.messageIndices.map { result.sipMessages[$0] }
        let origin = messages.first?.time ?? call.startTime
        let voice = call.streamIndices.map { result.streams[$0] }.filter { $0.codec?.kind.isVoice ?? true }
        let mediaStart = voice.map(\.firstTime).min()
        let mediaEnd = voice.map(\.lastTime).max()

        var y = Self.firstRowY
        var bandPlaced = false
        func placeBand() {
            guard !bandPlaced, let mediaStart, let mediaEnd else { return }
            bandPlaced = true
            // Span the media between the columns of the addresses carrying it (caller ↔ callee when unknown).
            let xs = voice.flatMap { [columnX($0.source.address), columnX($0.destination.address)] }.compactMap { $0 }
            let callerX = columnX(call.caller.signalling.address) ?? columns.first?.x ?? first
            let calleeX = columnX(call.callee.signalling.address) ?? columns.last?.x ?? last
            let lo = xs.min() ?? min(callerX, calleeX), hi = xs.max() ?? max(callerX, calleeX)
            let top = y - Self.rowStep + 18
            let packets = voice.reduce(0) { $0 + $1.packetCount }
            let duration = voice.map(\.durationSeconds).max() ?? 0
            let codec = call.codec?.displayName ?? voice.first?.codecName ?? "RTP"
            band = Band(top: top, fromX: min(lo, hi == lo ? calleeX : lo), toX: max(hi, lo == hi ? callerX : hi),
                        label: String(localized: "RTP · \(codec) · \(String(format: "%.1f", duration)) s · \(packets) pkts"),
                        startTime: mediaStart.seconds(since: origin), endTime: mediaEnd.seconds(since: origin))
            y = top + Self.bandHeight + 38
        }

        for (offset, message) in zip(call.messageIndices, messages) {
            if let mediaStart, message.time > mediaStart, !bandPlaced, message.method == "BYE" || message.time > mediaStart.adding(seconds: 0.5) {
                placeBand()
            }
            let fromX = columnX(message.source.address) ?? first
            let toX = columnX(message.destination.address) ?? last
            let kind: MessageRow.Kind
            if message.isRequest {
                kind = .request
            } else if let code = message.statusCode {
                kind = code < 200 ? .provisional : code < 300 ? .success : .failure
            } else {
                kind = .provisional
            }
            messageRows.append(MessageRow(messageIndex: offset, y: y, fromX: fromX, toX: toX, label: message.label, kind: kind,
                                          hasSDP: message.hasSDP, time: message.time.seconds(since: origin),
                                          retransmission: message.isRetransmission))
            y += Self.rowStep
        }
        placeBand()
        height = max(y, 120) - Self.rowStep + 18
    }
}

/// Draws the ladder with SwiftUI Canvas (text, lifelines, arrows, RTP band).
struct LadderCanvas: View {
    var layout: LadderLayout
    var selected: Int?
    var showSDP: Bool
    var highlight: String

    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Canvas { context, size in
            let fg = Theme.fg, fg2 = Theme.fg2, fg3 = Theme.fg3
            // Time column header
            context.draw(Text("Time (s)").font(.wp(10.5, .medium)).foregroundColor(fg3), at: CGPoint(x: 6, y: 30), anchor: .leading)

            // Selected row highlight
            if let selected, let row = layout.messageRows.first(where: { $0.messageIndex == selected }) {
                context.fill(Path(roundedRect: CGRect(x: 0, y: row.y - 14, width: size.width, height: 22), cornerRadius: 5),
                             with: .color(Theme.selSoft))
            }
            let query = highlight.trimmingCharacters(in: .whitespaces).lowercased()
            if !query.isEmpty {
                for row in layout.messageRows where row.label.lowercased().contains(query) {
                    context.stroke(Path(roundedRect: CGRect(x: 0.5, y: row.y - 13.5, width: size.width - 1, height: 21), cornerRadius: 5),
                                   with: .color(Theme.acc), lineWidth: 1)
                }
            }

            // Lifelines (dashed where they cross the RTP band without taking part in it)
            let bottom = size.height - 4
            for column in layout.columns {
                var path = Path()
                if let band = layout.band, column.x > band.fromX + 1, column.x < band.toX - 1 {
                    path.move(to: CGPoint(x: column.x, y: 46)); path.addLine(to: CGPoint(x: column.x, y: band.top - 4))
                    path.move(to: CGPoint(x: column.x, y: band.top + LadderLayout.bandHeight + 4)); path.addLine(to: CGPoint(x: column.x, y: bottom))
                    var dashed = Path()
                    dashed.move(to: CGPoint(x: column.x, y: band.top - 4)); dashed.addLine(to: CGPoint(x: column.x, y: band.top + LadderLayout.bandHeight + 4))
                    context.stroke(dashed, with: .color(Theme.line2), style: StrokeStyle(lineWidth: 1, dash: [2, 3]))
                } else {
                    path.move(to: CGPoint(x: column.x, y: 46)); path.addLine(to: CGPoint(x: column.x, y: bottom))
                }
                context.stroke(path, with: .color(Theme.line2), lineWidth: 1)
            }

            // Participant boxes
            for column in layout.columns {
                let rect = CGRect(x: column.x - layout.boxWidth / 2, y: 6, width: layout.boxWidth, height: 40)
                let box = Path(roundedRect: rect, cornerRadius: 8)
                context.fill(box, with: .color(Theme.surf2))
                context.stroke(box, with: .color(Theme.line2), lineWidth: 1)
                context.draw(Text(column.label).font(.wp(12, .semibold)).foregroundColor(fg), at: CGPoint(x: column.x, y: 19))
                context.draw(Text(column.address).font(.wpMono(10.5)).foregroundColor(fg3), at: CGPoint(x: column.x, y: 34.5))
            }

            // Messages
            for row in layout.messageRows {
                context.draw(Text(String(format: "%.3f", row.time)).font(.wpMono(10.5)).foregroundColor(fg3),
                             at: CGPoint(x: 6, y: row.y), anchor: .leading)
                let isRequest = row.kind == .request
                let lineColor = isRequest ? fg2 : fg3
                let direction: CGFloat = row.toX >= row.fromX ? 1 : -1
                let tip = CGPoint(x: row.toX, y: row.y)
                var line = Path()
                line.move(to: CGPoint(x: row.fromX + direction, y: row.y))
                line.addLine(to: CGPoint(x: row.toX - direction * 7, y: row.y))
                context.stroke(line, with: .color(lineColor),
                               style: isRequest ? StrokeStyle(lineWidth: 1.2) : StrokeStyle(lineWidth: 1.1, dash: [4, 3]))
                var head = Path()
                head.move(to: tip)
                head.addLine(to: CGPoint(x: tip.x - direction * 7, y: tip.y - 3.5))
                head.addLine(to: CGPoint(x: tip.x - direction * 7, y: tip.y + 3.5))
                head.closeSubpath()
                context.fill(head, with: .color(lineColor))

                let labelColor: Color
                let weight: Font.Weight
                switch row.kind {
                case .request: labelColor = fg; weight = .semibold
                case .provisional: labelColor = fg2; weight = .regular
                case .success: labelColor = Theme.ok; weight = .semibold
                case .failure: labelColor = Theme.err; weight = .semibold
                }
                var text = Text(row.label).font(.wp(11, weight)).foregroundColor(row.retransmission ? fg3 : labelColor)
                if showSDP && row.hasSDP { text = text + Text(" SDP").font(.wp(10)).foregroundColor(fg3) }
                if row.retransmission { text = text + Text(" ↻").font(.wp(10)).foregroundColor(fg3) }
                context.draw(text, at: CGPoint(x: (row.fromX + row.toX) / 2, y: row.y - 9))
            }

            // RTP band
            if let band = layout.band {
                let rect = CGRect(x: band.fromX, y: band.top, width: band.toX - band.fromX, height: LadderLayout.bandHeight)
                context.fill(Path(roundedRect: rect, cornerRadius: 5), with: .color(Theme.m1Bg))
                var forward = Path()
                forward.move(to: CGPoint(x: band.fromX + 2, y: band.top + 7)); forward.addLine(to: CGPoint(x: band.toX - 8, y: band.top + 7))
                context.stroke(forward, with: .color(Theme.m1), lineWidth: 2)
                var forwardHead = Path()
                forwardHead.move(to: CGPoint(x: band.toX, y: band.top + 7))
                forwardHead.addLine(to: CGPoint(x: band.toX - 8, y: band.top + 3)); forwardHead.addLine(to: CGPoint(x: band.toX - 8, y: band.top + 11))
                forwardHead.closeSubpath()
                context.fill(forwardHead, with: .color(Theme.m1))
                var reverse = Path()
                reverse.move(to: CGPoint(x: band.toX - 2, y: band.top + 25)); reverse.addLine(to: CGPoint(x: band.fromX + 8, y: band.top + 25))
                context.stroke(reverse, with: .color(Theme.m2), lineWidth: 2)
                var reverseHead = Path()
                reverseHead.move(to: CGPoint(x: band.fromX, y: band.top + 25))
                reverseHead.addLine(to: CGPoint(x: band.fromX + 8, y: band.top + 21)); reverseHead.addLine(to: CGPoint(x: band.fromX + 8, y: band.top + 29))
                reverseHead.closeSubpath()
                context.fill(reverseHead, with: .color(Theme.m2))
                let label = context.resolve(Text(band.label).font(.wp(10.5, .semibold)).foregroundColor(fg))
                let labelSize = label.measure(in: CGSize(width: 400, height: 20))
                let center = CGPoint(x: (band.fromX + band.toX) / 2, y: band.top + 16)
                context.fill(Path(roundedRect: CGRect(x: center.x - labelSize.width / 2 - 6, y: center.y - 6, width: labelSize.width + 12, height: 12), cornerRadius: 3),
                             with: .color(Theme.surf))
                context.draw(label, at: center)
                context.draw(Text(String(format: "%.3f", band.startTime)).font(.wpMono(10.5)).foregroundColor(fg3),
                             at: CGPoint(x: 6, y: band.top + 10), anchor: .leading)
                context.draw(Text(String(format: "%.3f", band.endTime)).font(.wpMono(10.5)).foregroundColor(fg3),
                             at: CGPoint(x: 6, y: band.top + 26), anchor: .leading)
            }
        }
        .accessibilityLabel("SIP ladder diagram: " + layout.messageRows.map(\.label).joined(separator: ", "))
    }
}
