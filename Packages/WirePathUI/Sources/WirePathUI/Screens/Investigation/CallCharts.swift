import WirePathCore
import SwiftUI

/// Media of a call split by direction, with helpers shared by the charts and the timeline.
struct CallMedia {
    var forward: [RTPStreamRecord]
    var reverse: [RTPStreamRecord]
    var origin: Timestamp
    var span: Double

    init(call: CallRecord, result: AnalysisResult) {
        func streams(_ d: DirectionQuality?) -> [RTPStreamRecord] {
            (d?.streamIndices.map { result.streams[$0] } ?? []).sorted { $0.firstTime < $1.firstTime }
        }
        forward = streams(call.quality?.forward)
        reverse = streams(call.quality?.reverse)
        origin = call.startTime
        let mediaEnd = (forward + reverse).map(\.lastTime).max() ?? call.endTime
        span = max(1, max(call.endTime, mediaEnd).seconds(since: origin))
    }

    var isEmpty: Bool { forward.isEmpty && reverse.isEmpty }

    /// (seconds since call start, jitter ms) samples for a direction.
    func jitterPoints(_ streams: [RTPStreamRecord]) -> [[(Double, Double)]] {
        streams.map { stream in
            let offset = stream.series.origin.seconds(since: origin)
            return stream.series.jitterMs.enumerated().compactMap { index, value in
                value.map { (offset + (Double(index) + 0.5) * stream.series.jitterBinSeconds, $0) }
            }
        }
    }

    /// Lost packets per whole second since call start.
    func lossPerSecond(_ streams: [RTPStreamRecord]) -> [Int: Int] {
        var result: [Int: Int] = [:]
        for stream in streams {
            let offset = stream.series.origin.seconds(since: origin)
            for (index, lost) in stream.series.lost.enumerated() where lost > 0 {
                let second = Int(offset + Double(index) * stream.series.lossBinSeconds)
                result[second, default: 0] += lost
            }
        }
        return result
    }
}

/// Picks a "nice" tick step so roughly `target` ticks fit in `span`.
func niceStep(span: Double, target: Double) -> Double {
    let steps: [Double] = [0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200]
    return steps.first { span / $0 <= target } ?? 7200
}

private struct ChartFrame {
    var size: CGSize
    var span: Double
    var maxY: Double
    let left: CGFloat = 30
    let top: CGFloat = 10
    var right: CGFloat { size.width - 6 }
    var bottom: CGFloat { size.height - 28 }

    func x(_ t: Double) -> CGFloat { left + CGFloat(t / span) * (right - left) }
    func y(_ v: Double) -> CGFloat { bottom - CGFloat(min(v, maxY) / maxY) * (bottom - top) }

    func drawAxes(_ context: GraphicsContext, unitSuffix: String = "") {
        var grid = Path()
        for i in 0...3 {
            let v = maxY * Double(3 - i) / 3
            let yy = y(v)
            grid.move(to: CGPoint(x: left, y: yy)); grid.addLine(to: CGPoint(x: right, y: yy))
            context.draw(Text(v.rounded() == v ? "\(Int(v))" : String(format: "%.1f", v)).font(.wp(10)).foregroundColor(Theme.fg3),
                         at: CGPoint(x: left - 6, y: yy), anchor: .trailing)
        }
        context.stroke(grid, with: .color(Theme.grid), lineWidth: 1)
        let step = niceStep(span: span, target: 6)
        var t = 0.0
        while t <= span + 0.001 {
            let label: String
            if t == 0 { label = step >= 60 ? "0 min" : "0 s" } else if step >= 60 { label = "\(Int(t / 60))" } else { label = "\(Int(t))" }
            let isLast = t + step > span + 0.001
            let text = isLast && t > 0 ? label + (step >= 60 ? " min" : " s") : label
            context.draw(Text(text).font(.wp(10)).foregroundColor(Theme.fg3), at: CGPoint(x: x(t), y: bottom + 14),
                         anchor: t == 0 ? .leading : .center)
            t += step
        }
    }
}

private func niceMax(_ value: Double, minimum: Double, step: Double) -> Double {
    max(minimum, (value / step).rounded(.up) * step)
}

struct JitterChartCard: View {
    var call: CallRecord
    var result: AnalysisResult

    var body: some View {
        let media = CallMedia(call: call, result: result)
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Text("Jitter").font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
                legend(Theme.m1, "\(call.caller.user) → \(call.callee.user)")
                legend(Theme.m2, "\(call.callee.user) → \(call.caller.user)")
                Spacer(minLength: 0)
                HStack(spacing: 6) {
                    Rectangle().stroke(Theme.warn, style: StrokeStyle(lineWidth: 1, dash: [3, 2])).frame(width: 12, height: 0.5)
                    Text("\(Int(QualityThresholds.jitterSpikeMs)) ms threshold")
                }
                .font(.wp(11)).foregroundStyle(Theme.fg3)
            }
            .padding(.horizontal, 14)
            .frame(height: 40)
            if media.isEmpty || (media.forward + media.reverse).allSatisfy({ $0.maxJitterMs == nil }) {
                placeholder(media.isEmpty ? "No RTP in this call" : "Jitter needs a known RTP clock rate")
            } else {
                Canvas { context, size in draw(context, size: size, media: media) }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 2)
                    .accessibilityLabel("Jitter over time, peak \(Formatters.ms(call.quality?.maxJitterMs))")
            }
        }
        .card()
    }

    private func draw(_ context: GraphicsContext, size: CGSize, media: CallMedia) {
        let forward = media.jitterPoints(media.forward), reverse = media.jitterPoints(media.reverse)
        let peakValue = (forward + reverse).flatMap { $0 }.map(\.1).max() ?? 0
        let frame = ChartFrame(size: size, span: media.span, maxY: niceMax(peakValue * 1.1, minimum: 60, step: 30))
        frame.drawAxes(context)
        var threshold = Path()
        threshold.move(to: CGPoint(x: frame.left, y: frame.y(QualityThresholds.jitterSpikeMs)))
        threshold.addLine(to: CGPoint(x: frame.right, y: frame.y(QualityThresholds.jitterSpikeMs)))
        context.stroke(threshold, with: .color(Theme.warn), style: StrokeStyle(lineWidth: 1, dash: [3, 3]))
        func plot(_ segments: [[(Double, Double)]], color: Color, width: CGFloat) {
            for points in segments where !points.isEmpty {
                var path = Path()
                for (i, point) in points.enumerated() {
                    let p = CGPoint(x: frame.x(point.0), y: frame.y(point.1))
                    i == 0 ? path.move(to: p) : path.addLine(to: p)
                }
                context.stroke(path, with: .color(color), style: StrokeStyle(lineWidth: width, lineJoin: .round))
            }
        }
        plot(reverse, color: Theme.m2, width: 1.3)
        plot(forward, color: Theme.m1, width: 1.4)
        if let peak = (forward + reverse).flatMap({ $0 }).max(by: { $0.1 < $1.1 }) {
            let point = CGPoint(x: frame.x(peak.0), y: frame.y(peak.1))
            let color = peak.1 > QualityThresholds.jitterSpikeMs ? Theme.warn : Theme.fg2
            context.fill(Path(ellipseIn: CGRect(x: point.x - 3, y: point.y - 3, width: 6, height: 6)), with: .color(color))
            let leftSide = point.x > size.width - 70
            context.draw(Text(String(format: "%.1f ms", peak.1)).font(.wp(10.5, .semibold)).foregroundColor(color),
                         at: CGPoint(x: point.x + (leftSide ? -6 : 6), y: point.y - 4), anchor: leftSide ? .trailing : .leading)
        }
    }
}

struct LossChartCard: View {
    var call: CallRecord
    var result: AnalysisResult

    var body: some View {
        let media = CallMedia(call: call, result: result)
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Text("Packet Loss").font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
                legend(Theme.m1, "\(call.caller.user) → \(call.callee.user) · \(max(0, call.quality?.forward?.lost ?? 0))", square: true)
                legend(Theme.m2, "\(call.callee.user) → \(call.caller.user) · \(max(0, call.quality?.reverse?.lost ?? 0))", square: true)
                Spacer(minLength: 0)
                Text("lost packets / second").font(.wp(11)).foregroundStyle(Theme.fg3)
            }
            .padding(.horizontal, 14)
            .frame(height: 40)
            if media.isEmpty {
                placeholder("No RTP in this call")
            } else {
                Canvas { context, size in draw(context, size: size, media: media) }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 2)
                    .accessibilityLabel("Packets lost per second")
            }
        }
        .card()
    }

    private func draw(_ context: GraphicsContext, size: CGSize, media: CallMedia) {
        let forward = media.lossPerSecond(media.forward), reverse = media.lossPerSecond(media.reverse)
        let seconds = Set(forward.keys).union(reverse.keys)
        let peak = seconds.map { (forward[$0] ?? 0) + (reverse[$0] ?? 0) }.max() ?? 0
        let frame = ChartFrame(size: size, span: media.span, maxY: niceMax(Double(peak) * 1.1, minimum: 15, step: 15))
        frame.drawAxes(context)
        let barWidth = max(1.5, min(8, (frame.right - frame.left) / CGFloat(media.span) * 0.75))
        for second in seconds {
            let a = forward[second] ?? 0, b = reverse[second] ?? 0
            let x = frame.x(Double(second) + 0.5) - barWidth / 2
            if a > 0 {
                context.fill(Path(CGRect(x: x, y: frame.y(Double(a)), width: barWidth, height: frame.bottom - frame.y(Double(a)))), with: .color(Theme.m1))
            }
            if b > 0 {
                context.fill(Path(CGRect(x: x, y: frame.y(Double(a + b)), width: barWidth, height: frame.y(Double(a)) - frame.y(Double(a + b)))), with: .color(Theme.m2))
            }
        }
        // Annotate the largest loss burst.
        let bursts = call.findingIndices.map { result.findings[$0] }.filter { $0.kind == .lossBurst }
        if let burst = bursts.max(by: { ($0.title.split(separator: " ").compactMap { Int($0) }.first ?? 0) < ($1.title.split(separator: " ").compactMap { Int($0) }.first ?? 0) }),
           let start = burst.time, let end = burst.endTime {
            let s = start.seconds(since: media.origin), e = end.seconds(since: media.origin)
            let x = frame.x(e) + 8
            let leftSide = x > size.width - 110
            let anchorX = leftSide ? frame.x(s) - 8 : x
            context.draw(Text(burst.title.replacingOccurrences(of: "Loss burst", with: "Burst")).font(.wp(10.5, .semibold)).foregroundColor(Theme.fg),
                         at: CGPoint(x: anchorX, y: 20), anchor: leftSide ? .trailing : .leading)
            context.draw(Text(String(format: "+%.1f – %.1f s", s, e)).font(.wp(10)).foregroundColor(Theme.fg3),
                         at: CGPoint(x: anchorX, y: 33), anchor: leftSide ? .trailing : .leading)
        }
    }
}

@ViewBuilder
private func legend(_ color: Color, _ text: String, square: Bool = false) -> some View {
    HStack(spacing: 6) {
        if square {
            RoundedRectangle(cornerRadius: 2).fill(color).frame(width: 8, height: 8)
        } else {
            Rectangle().fill(color).frame(width: 12, height: 2)
        }
        Text(text)
    }
    .font(.wp(11))
    .foregroundStyle(Theme.fg2)
    .lineLimit(1)
}

private func placeholder(_ text: LocalizedStringKey) -> some View {
    Text(text).font(.wp(12)).foregroundStyle(Theme.fg3).frame(maxWidth: .infinity, maxHeight: .infinity)
}
