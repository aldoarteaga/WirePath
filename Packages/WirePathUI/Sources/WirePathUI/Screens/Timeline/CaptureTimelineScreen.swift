import WirePathCore
import SwiftUI

/// Capture timeline: every call on a shared time axis (ringing, talk, failures, quality events)
/// plus a concurrent-calls lane. Same visual language as the investigation timeline.
///
/// Rows are lazy (a capture can hold tens of thousands of calls): each call row draws its own lane, and zooming
/// shows a window of the capture that is panned with the slider or by dragging, so labels stay in place.
struct CaptureTimelineScreen: View {
    @Environment(WindowModel.self) private var window
    @Bindable var document: AnalysisDocument
    @State private var zoom: Double = 1
    /// Start of the visible window as a fraction of the part of the capture outside it (0 = start, 1 = end).
    @State private var pan: Double = 0
    @State private var dragOrigin: Double?
    @State private var concurrency = TimelineConcurrency()

    private var result: AnalysisResult { document.result }
    static let rowHeight: CGFloat = 26
    static let labelWidth: CGFloat = 230
    static let headerHeight: CGFloat = 70

    var body: some View {
        let start = result.capture.firstPacketTime ?? result.calls.first?.startTime ?? Timestamp(nanoseconds: 0)
        let span = max(1, result.capture.durationSeconds)
        let visible = span / zoom
        let window = TimelineWindow(start: start.adding(seconds: pan * (span - visible)), span: visible)
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "Timeline"), subtitle: "\(document.manifest.displayName) · \(Formatters.range(result.capture.firstPacketTime, result.capture.lastPacketTime))") {
                HStack(spacing: 6) {
                    IconButton(icon: Icons.minus, iconSize: 12, width: 24, height: 22, help: String(localized: "Zoom Out (⌘−)")) { zoom = max(1, zoom / 1.5) }
                        .macKeyboardShortcut("-", modifiers: .command)
                    Slider(value: $zoom, in: 1...40).frame(width: 140).controlSize(.small).accessibilityLabel("Timeline zoom")
                    IconButton(icon: Icons.plusSmall, iconSize: 12, width: 24, height: 22, help: String(localized: "Zoom In (⌘+)")) { zoom = min(40, zoom * 1.5) }
                        .macKeyboardShortcut("=", modifiers: .command)
                    Button { zoom = 1; pan = 0 } label: {
                        Text("Fit").font(.wp(11.5)).foregroundStyle(Theme.fg)
                            .padding(.horizontal, 9).frame(height: 22)
                            .background(RoundedRectangle(cornerRadius: 5).fill(Theme.ctrl))
                    }
                    .buttonStyle(.plain)
                }
            }
            VStack(spacing: 14) {
                HStack(alignment: .bottom, spacing: 16) {
                    ScreenTitle(title: String(localized: "Timeline"), subtitle: String(localized: "\(result.calls.count) calls over \(Formatters.spoken(span)) · peak \(concurrency.peak) concurrent"))
                    Spacer(minLength: 8)
                    legend
                }
                GeometryReader { proxy in
                    let trackWidth = max(200, proxy.size.width - Self.labelWidth - 32)
                    ScrollView(.vertical) {
                        LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                            Section {
                                ForEach(result.calls.indices, id: \.self) { index in
                                    row(index, window: window, trackWidth: trackWidth)
                                }
                            } header: {
                                header(window: window, trackWidth: trackWidth)
                            }
                        }
                        .padding(EdgeInsets(top: 10, leading: 16, bottom: 14, trailing: 16))
                    }
                    .card()
                    .simultaneousGesture(panGesture(trackWidth: trackWidth))
                }
                if zoom > 1 {
                    HStack(spacing: 10) {
                        Text(Formatters.clock(window.start)).font(.wpMono(11)).foregroundStyle(Theme.fg2)
                        Slider(value: $pan, in: 0...1).controlSize(.small).accessibilityLabel("Visible part of the capture")
                        Text(Formatters.clock(window.start.adding(seconds: window.span))).font(.wpMono(11)).foregroundStyle(Theme.fg2)
                    }
                    .padding(.horizontal, 4)
                }
            }
            .padding(EdgeInsets(top: 18, leading: 22, bottom: 16, trailing: 22))
            FooterBar(leading: String(localized: "\(result.calls.count) calls · double-click a call to investigate"),
                      trailing: document.selectedCall.map { String(localized: "Selected \(document.callTitle($0))") } ?? String(localized: "No selection"))
        }
        .task(id: document.manifest.id) { concurrency = TimelineConcurrency(calls: result.calls) }
    }

    /// Dragging the lanes pans the zoomed window.
    private func panGesture(trackWidth: CGFloat) -> some Gesture {
        DragGesture(minimumDistance: 4)
            .onChanged { value in
                // Horizontal drags only: vertical ones scroll the rows.
                guard zoom > 1, abs(value.translation.width) > abs(value.translation.height) else { return }
                let origin = dragOrigin ?? pan
                if dragOrigin == nil { dragOrigin = pan }
                // One track width of drag moves the window by its own width.
                let delta = -Double(value.translation.width / trackWidth) / (zoom - 1)
                pan = min(1, max(0, origin + delta))
            }
            .onEnded { _ in dragOrigin = nil }
    }

    private func header(window: TimelineWindow, trackWidth: CGFloat) -> some View {
        HStack(alignment: .top, spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                Color.clear.frame(height: 22)
                Text("Concurrent calls").font(.wp(11, .semibold)).foregroundStyle(Theme.fg).frame(height: 48)
            }
            .frame(width: Self.labelWidth, alignment: .leading)
            TimelineHeaderTrack(concurrency: concurrency, window: window)
                .frame(width: trackWidth, height: Self.headerHeight)
        }
        .background(Theme.surf)
    }

    private func row(_ index: Int, window: TimelineWindow, trackWidth: CGFloat) -> some View {
        HStack(spacing: 0) {
            callLabel(index)
                .frame(width: Self.labelWidth, height: Self.rowHeight)
            TimelineCallLane(call: result.calls[index], findings: result.findings, window: window,
                             selected: document.selectedCall == index)
                .frame(width: trackWidth, height: Self.rowHeight)
        }
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { self.window.investigate(index) }
        .onTapGesture { document.selectedCall = index }
        .accessibilityElement(children: .combine)
    }

    private var legend: some View {
        HStack(spacing: 14) {
            swatch(Theme.ctrl2, "Ringing")
            swatch(Theme.m1, "Talk")
            swatch(Theme.warn, "Warning")
            swatch(Theme.err, "Error / failed")
        }
        .font(.wp(11)).foregroundStyle(Theme.fg2)
    }

    private func swatch(_ color: Color, _ label: LocalizedStringKey) -> some View {
        HStack(spacing: 5) {
            RoundedRectangle(cornerRadius: 2).fill(color).frame(width: 12, height: 8)
            Text(label)
        }
    }

    private func callLabel(_ index: Int) -> some View {
        let call = result.calls[index]
        let selected = document.selectedCall == index
        return HStack(spacing: 6) {
            StatusIcon(severity: call.severity == .info ? .ok : call.severity, size: 10, plain: true)
            Text(Formatters.clock(call.startTime)).font(.wpMono(11)).foregroundStyle(selected ? Theme.onSel : Theme.fg2)
            Text("\(call.caller.user) → \(call.callee.user)").font(.wp(11.5)).foregroundStyle(selected ? Theme.onSel : Theme.fg)
                .lineLimit(1).truncationMode(.tail)
        }
        .padding(.horizontal, 6)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 5).fill(selected ? Theme.sel : .clear))
    }
}

/// The part of the capture on screen.
struct TimelineWindow: Equatable {
    var start: Timestamp
    var span: Double

    func x(_ time: Timestamp, width: CGFloat) -> CGFloat {
        CGFloat(time.seconds(since: start) / span) * (width - 2) + 1
    }

    /// Tick times and labels for the axis.
    func ticks(width: CGFloat) -> [(Timestamp, String)] {
        let step = niceStep(span: span, target: max(4, Double(width) / 110))
        let first = (start.seconds / step).rounded(.up) * step - start.seconds
        var ticks: [(Timestamp, String)] = []
        var t = max(0, first)
        while t <= span, ticks.count < 200 {
            let time = start.adding(seconds: t)
            ticks.append((time, step >= 60 ? String(Formatters.clock(time).prefix(5)) : Formatters.clock(time)))
            t += step
        }
        return ticks
    }
}

/// Call starts and ends, sorted once per result (for the concurrent-calls lane).
struct TimelineConcurrency: Equatable {
    var events: [Timestamp] = []
    var deltas: [Int] = []
    var peak = 0

    init() {}

    init(calls: [CallRecord]) {
        var pairs: [(Timestamp, Int)] = []
        pairs.reserveCapacity(calls.count * 2)
        for call in calls {
            pairs.append((call.startTime, 1))
            pairs.append((call.endTime, -1))
        }
        pairs.sort { $0.0 != $1.0 ? $0.0 < $1.0 : $0.1 < $1.1 }
        events = pairs.map(\.0)
        deltas = pairs.map(\.1)
        var current = 0
        for delta in deltas {
            current += delta
            peak = max(peak, current)
        }
    }
}

/// Axis ticks and the concurrent-calls step area for the visible window.
struct TimelineHeaderTrack: View {
    var concurrency: TimelineConcurrency
    var window: TimelineWindow

    var body: some View {
        Canvas { context, size in
            let laneTop: CGFloat = 22, laneHeight: CGFloat = 40
            var grid = Path()
            for (index, (time, label)) in window.ticks(width: size.width).enumerated() {
                let px = window.x(time, width: size.width)
                grid.move(to: CGPoint(x: px, y: 18))
                grid.addLine(to: CGPoint(x: px, y: size.height))
                context.draw(Text(label).font(.wpMono(10.5)).foregroundColor(Theme.fg3), at: CGPoint(x: px, y: 7),
                             anchor: index == 0 && px < 20 ? .leading : .center)
            }
            context.stroke(grid, with: .color(Theme.grid), lineWidth: 1)
            guard concurrency.peak > 0 else { return }
            var area = Path()
            area.move(to: CGPoint(x: 1, y: laneTop + laneHeight))
            var current = 0
            var lastY = laneTop + laneHeight
            let end = window.start.adding(seconds: window.span)
            for (time, delta) in zip(concurrency.events, concurrency.deltas) {
                if time > end { break }
                let px = max(1, window.x(time, width: size.width))
                area.addLine(to: CGPoint(x: px, y: lastY))
                current += delta
                lastY = laneTop + laneHeight - CGFloat(current) / CGFloat(concurrency.peak) * (laneHeight - 4)
                area.addLine(to: CGPoint(x: px, y: lastY))
            }
            area.addLine(to: CGPoint(x: size.width - 1, y: lastY))
            area.addLine(to: CGPoint(x: size.width - 1, y: laneTop + laneHeight))
            area.closeSubpath()
            context.clip(to: Path(CGRect(origin: .zero, size: size)))
            context.fill(area, with: .color(Theme.m1Bg))
            context.stroke(area, with: .color(Theme.m1), lineWidth: 1)
            context.draw(Text("\(concurrency.peak)").font(.wp(10, .semibold)).foregroundColor(Theme.fg3),
                         at: CGPoint(x: size.width - 4, y: laneTop + 6), anchor: .trailing)
        }
        .accessibilityLabel("Concurrent calls, peak \(concurrency.peak)")
    }
}

/// One call's lane: ringing, talk and quality events inside the visible window.
struct TimelineCallLane: View {
    var call: CallRecord
    var findings: [Finding]
    var window: TimelineWindow
    var selected: Bool

    var body: some View {
        Canvas { context, size in
            let rowHeight = size.height
            context.clip(to: Path(CGRect(origin: .zero, size: size)))
            if selected {
                context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(Theme.selSoft))
            }
            var grid = Path()
            for (time, _) in window.ticks(width: size.width) {
                let px = window.x(time, width: size.width)
                grid.move(to: CGPoint(x: px, y: 0))
                grid.addLine(to: CGPoint(x: px, y: rowHeight))
            }
            context.stroke(grid, with: .color(Theme.grid), lineWidth: 1)
            func x(_ t: Timestamp) -> CGFloat { window.x(t, width: size.width) }
            let barY = (rowHeight - 10) / 2
            let x0 = x(call.startTime)
            if let answer = call.answerTime {
                let xa = x(answer)
                context.fill(Path(roundedRect: CGRect(x: x0, y: barY + 2, width: max(1, xa - x0), height: 6), cornerRadius: 2), with: .color(Theme.ctrl2))
                let color: Color = call.severity == .error ? Theme.err : call.severity == .warning ? Theme.warn : Theme.m1
                context.fill(Path(roundedRect: CGRect(x: xa, y: barY, width: max(2, x(call.endTime) - xa), height: 10), cornerRadius: 3),
                             with: .color(color.opacity(0.85)))
            } else {
                let color: Color = call.state.isFailure ? Theme.err : Theme.fg3
                context.fill(Path(roundedRect: CGRect(x: x0, y: barY + 2, width: max(3, x(call.endTime) - x0), height: 6), cornerRadius: 2),
                             with: .color(color.opacity(0.7)))
                context.draw(Text(call.statusLabel).font(.wp(10)).foregroundColor(color),
                             at: CGPoint(x: max(x0, x(call.endTime)) + 6, y: rowHeight / 2), anchor: .leading)
            }
            for findingIndex in call.findingIndices where findingIndex < findings.count {
                let finding = findings[findingIndex]
                guard let time = finding.time else { continue }
                let px = x(time)
                switch finding.kind {
                case .lossBurst:
                    var diamond = Path()
                    diamond.move(to: CGPoint(x: px, y: 4)); diamond.addLine(to: CGPoint(x: px + 5, y: rowHeight / 2))
                    diamond.addLine(to: CGPoint(x: px, y: rowHeight - 4)); diamond.addLine(to: CGPoint(x: px - 5, y: rowHeight / 2))
                    diamond.closeSubpath()
                    context.fill(diamond, with: .color(Theme.err))
                case .jitterSpike, .ssrcChange:
                    var line = Path()
                    line.move(to: CGPoint(x: px, y: 3)); line.addLine(to: CGPoint(x: px, y: rowHeight - 3))
                    context.stroke(line, with: .color(finding.kind == .jitterSpike ? Theme.warn : Theme.acc), lineWidth: 2)
                default:
                    break
                }
            }
        }
    }
}
