import WirePathCore
import SwiftUI

/// Timeline card of the investigation (SIP / RTP lanes / events), with zoom (⌘− ⌘+) and Fit.
struct CallTimelineCard: View {
    var call: CallRecord
    var result: AnalysisResult
    @State private var zoom: Double = 1

    var body: some View {
        let media = CallMedia(call: call, result: result)
        let end = call.startTime.adding(seconds: media.span)
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Timeline")) {
                Text("\(Formatters.clockMillis(call.startTime)) – \(Formatters.clockMillis(end))")
                    .font(.wpMono(11)).foregroundStyle(Theme.fg3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.leading, 2)
                IconButton(icon: Icons.minus, iconSize: 12, width: 24, height: 22, help: String(localized: "Zoom Out (⌘−)")) { zoom = max(1, zoom / 1.5) }
                    .macKeyboardShortcut("-", modifiers: .command)
                Slider(value: $zoom, in: 1...10).frame(width: 110).controlSize(.small).accessibilityLabel("Timeline zoom")
                IconButton(icon: Icons.plusSmall, iconSize: 12, width: 24, height: 22, help: String(localized: "Zoom In (⌘+)")) { zoom = min(10, zoom * 1.5) }
                    .macKeyboardShortcut("=", modifiers: .command)
                Button { zoom = 1 } label: {
                    Text("Fit").font(.wp(11.5)).foregroundStyle(Theme.fg)
                        .padding(.horizontal, 9).frame(height: 22)
                        .background(RoundedRectangle(cornerRadius: 5).fill(Theme.ctrl))
                }
                .buttonStyle(.plain)
            }
            HStack(alignment: .top, spacing: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    Color.clear.frame(height: 20)
                    Text("SIP").font(.wp(11, .semibold)).foregroundStyle(Theme.fg).frame(height: 44)
                    laneLabel(Theme.m1, "RTP \(call.caller.user) → \(call.callee.user)")
                    laneLabel(Theme.m2, "RTP \(call.callee.user) → \(call.caller.user)")
                    Text("Events").font(.wp(11, .semibold)).foregroundStyle(Theme.fg).frame(height: 34)
                }
                .frame(width: 120, alignment: .leading)
                GeometryReader { proxy in
                    ScrollView(.horizontal) {
                        TimelineTrack(call: call, result: result, media: media)
                            .frame(width: max(proxy.size.width, proxy.size.width * zoom), height: 146)
                    }
                    .scrollIndicators(zoom > 1 ? .visible : .never)
                }
                .frame(height: 146)
            }
            .padding(EdgeInsets(top: 10, leading: 16, bottom: 14, trailing: 16))
        }
        .card()
    }

    private func laneLabel(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 6) {
            RoundedRectangle(cornerRadius: 2).fill(color).frame(width: 8, height: 8)
            Text(text).lineLimit(1)
        }
        .font(.wp(11)).foregroundStyle(Theme.fg2)
        .frame(height: 24)
    }
}

/// The drawn track: ticks, grid, SIP markers, RTP bars with loss ticks, event overlays and labels.
struct TimelineTrack: View {
    var call: CallRecord
    var result: AnalysisResult
    var media: CallMedia

    var body: some View {
        Canvas { context, size in
            let span = media.span
            func x(_ t: Double) -> CGFloat { CGFloat(t / span) * (size.width - 2) + 1 }
            func rel(_ ts: Timestamp) -> Double { ts.seconds(since: call.startTime) }

            // Ticks & grid
            let step = niceStep(span: span, target: max(4, Double(size.width) / 120))
            var grid = Path()
            var t = 0.0
            var previousMinute = -1
            while t <= span {
                let px = x(t)
                grid.move(to: CGPoint(x: px, y: 18)); grid.addLine(to: CGPoint(x: px, y: size.height))
                let date = call.startTime.adding(seconds: t).date
                let minute = Calendar.current.component(.minute, from: date)
                let label = t == 0 || minute != previousMinute ? Formatters.clock(call.startTime.adding(seconds: t))
                    : String(format: ":%02d", Calendar.current.component(.second, from: date))
                previousMinute = minute
                context.draw(Text(label).font(.wpMono(10.5)).foregroundColor(Theme.fg3), at: CGPoint(x: px, y: 7),
                             anchor: t == 0 ? .leading : .center)
                t += step
            }
            context.stroke(grid, with: .color(Theme.grid), lineWidth: 1)

            let findings = call.findingIndices.map { result.findings[$0] }
            // Overlays: loss bursts, jitter spikes, SSRC changes.
            for burst in findings where burst.kind == .lossBurst {
                guard let start = burst.time, let end = burst.endTime else { continue }
                let rect = CGRect(x: x(rel(start)), y: 18, width: max(2, x(rel(end)) - x(rel(start))), height: size.height - 18)
                context.fill(Path(rect), with: .color(Theme.errBg))
                var edges = Path()
                edges.move(to: CGPoint(x: rect.minX, y: rect.minY)); edges.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
                edges.move(to: CGPoint(x: rect.maxX, y: rect.minY)); edges.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
                context.stroke(edges, with: .color(Theme.err), lineWidth: 1)
            }
            for finding in findings where finding.kind == .jitterSpike || finding.kind == .ssrcChange {
                guard let time = finding.time else { continue }
                var line = Path()
                line.move(to: CGPoint(x: x(rel(time)), y: 18)); line.addLine(to: CGPoint(x: x(rel(time)), y: size.height))
                context.stroke(line, with: .color(finding.kind == .jitterSpike ? Theme.warn : Theme.acc),
                               style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
            }

            // SIP lane markers
            func marker(_ time: Timestamp, _ label: String, color: Color, background: Color, row: Int, trailing: Bool = false) {
                let px = x(rel(time))
                var line = Path()
                line.move(to: CGPoint(x: px, y: 24)); line.addLine(to: CGPoint(x: px, y: 60))
                context.stroke(line, with: .color(color), lineWidth: 2)
                let text = context.resolve(Text(label).font(.wp(10.5, .semibold)).foregroundColor(color == Theme.fg2 ? Theme.fg : color))
                let textSize = text.measure(in: CGSize(width: 300, height: 20))
                let y: CGFloat = row == 0 ? 24 : 42
                let originX = trailing ? min(px - 6 - textSize.width - 12, size.width - textSize.width - 12) : px + 6
                let rect = CGRect(x: max(0, originX), y: y, width: textSize.width + 12, height: 16)
                context.fill(Path(roundedRect: rect, cornerRadius: 4), with: .color(background))
                context.draw(text, at: CGPoint(x: rect.midX, y: rect.midY))
            }
            marker(call.startTime, "INVITE", color: Theme.fg2, background: Theme.ctrl2, row: 0)
            if let answer = call.answerTime {
                marker(answer, "200 OK · ACK", color: Theme.ok, background: Theme.okBg, row: 1)
            } else if call.state.isFailure || call.state == .cancelled {
                marker(call.endTime, call.statusLabel, color: Theme.err, background: Theme.errBg, row: 1, trailing: rel(call.endTime) > span * 0.6)
            }
            if call.endReason == .byeFromCaller || call.endReason == .byeFromCallee {
                marker(call.endTime, "BYE · 200 OK", color: Theme.fg2, background: Theme.ctrl2, row: 0, trailing: true)
            }

            // RTP lanes
            func lane(_ streams: [RTPStreamRecord], y: CGFloat, color: Color) {
                for stream in streams {
                    let x0 = x(rel(stream.firstTime)), x1 = x(rel(stream.lastTime))
                    context.fill(Path(roundedRect: CGRect(x: x0, y: y, width: max(2, x1 - x0), height: 10), cornerRadius: 3),
                                 with: .color(color.opacity(0.85)))
                    let offset = rel(stream.series.origin)
                    for (index, lost) in stream.series.lost.enumerated() where lost > 0 {
                        let px = x(offset + (Double(index) + 0.5) * stream.series.lossBinSeconds)
                        context.fill(Path(roundedRect: CGRect(x: px - 1, y: y - 2, width: 2, height: 14), cornerRadius: 1), with: .color(Theme.err))
                    }
                }
            }
            lane(media.forward, y: 71, color: Theme.m1)
            lane(media.reverse, y: 95, color: Theme.m2)

            // Event labels
            func event(_ time: Double, _ text: String, color: Color, icon: IconSpec?, bold: Bool = true, trailing: Bool = false) {
                var label = Text(text).font(.wp(10.5, bold ? .semibold : .regular)).foregroundColor(color)
                if let icon {
                    let glyph = Text(Image(systemName: icon == Icons.diamond ? "diamond.fill" : icon == Icons.statusWarningPlain ? "exclamationmark.triangle.fill"
                                           : icon == Icons.mediaStart ? "play.fill" : icon == Icons.mediaEnd ? "stop.fill" : "circle.fill"))
                        .font(.system(size: 8)).foregroundColor(icon == Icons.mediaStart || icon == Icons.mediaEnd ? Theme.m1 : color)
                    label = trailing ? label + Text(" ") + glyph : glyph + Text(" ") + label
                }
                context.draw(label, at: CGPoint(x: x(time) + (trailing ? -4 : 0), y: 126), anchor: trailing ? .trailing : .leading)
            }
            if let start = (media.forward + media.reverse).map(\.firstTime).min() {
                event(rel(start), String(localized: "RTP start"), color: Theme.fg2, icon: Icons.mediaStart, bold: false)
            }
            for finding in findings {
                guard let time = finding.time else { continue }
                switch finding.kind {
                case .jitterSpike: event(rel(time), finding.title, color: Theme.warn, icon: Icons.statusWarningPlain)
                case .ssrcChange: event(rel(time), String(localized: "SSRC change"), color: Theme.acc, icon: Icons.dot)
                case .lossBurst: event(rel(finding.endTime ?? time) + 0.3, finding.title, color: Theme.err, icon: Icons.diamond)
                default: break
                }
            }
            if let end = (media.forward + media.reverse).map(\.lastTime).max() {
                event(rel(end), String(localized: "RTP end"), color: Theme.fg2, icon: Icons.mediaEnd, bold: false, trailing: true)
            }
        }
        .accessibilityLabel("Call timeline")
    }
}
