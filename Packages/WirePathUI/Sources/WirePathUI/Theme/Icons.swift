import SwiftUI

/// Minimal SVG path-data parser (M L H V C S Q A Z, absolute and relative) producing a SwiftUI `Path`.
/// The design's icons are hand-drawn SVGs; rendering the same path data keeps them pixel-identical.
struct SVGPath {
    static func parse(_ data: String) -> Path {
        var path = Path()
        let tokens = tokenize(data)
        var index = 0
        var current = CGPoint.zero
        var start = CGPoint.zero
        var lastControl: CGPoint?
        var command: Character = "M"

        func number() -> CGFloat {
            guard index < tokens.count, case .number(let value) = tokens[index] else { return 0 }
            index += 1
            return value
        }
        func hasNumber() -> Bool {
            if index < tokens.count, case .number = tokens[index] { return true }
            return false
        }
        func flag() -> Bool { number() != 0 }

        while index < tokens.count {
            if case .command(let c) = tokens[index] {
                command = c
                index += 1
            } else if command == "Z" || command == "z" {
                command = "L"  // stray numbers after Z: treat as line-tos rather than looping
            }
            let relative = command.isLowercase
            let base = relative ? current : .zero
            switch command.uppercased().first ?? " " {
            case "M":
                let p = CGPoint(x: base.x + number(), y: base.y + number())
                path.move(to: p)
                current = p
                start = p
                lastControl = nil
                command = relative ? "l" : "L"  // subsequent pairs are implicit line-tos
            case "L":
                let p = CGPoint(x: base.x + number(), y: base.y + number())
                path.addLine(to: p)
                current = p
                lastControl = nil
            case "H":
                let x = (relative ? current.x : 0) + number()
                current = CGPoint(x: x, y: current.y)
                path.addLine(to: current)
                lastControl = nil
            case "V":
                let y = (relative ? current.y : 0) + number()
                current = CGPoint(x: current.x, y: y)
                path.addLine(to: current)
                lastControl = nil
            case "C":
                let c1 = CGPoint(x: base.x + number(), y: base.y + number())
                let c2 = CGPoint(x: base.x + number(), y: base.y + number())
                let p = CGPoint(x: base.x + number(), y: base.y + number())
                path.addCurve(to: p, control1: c1, control2: c2)
                current = p
                lastControl = c2
            case "S":
                let c1 = lastControl.map { CGPoint(x: 2 * current.x - $0.x, y: 2 * current.y - $0.y) } ?? current
                let c2 = CGPoint(x: base.x + number(), y: base.y + number())
                let p = CGPoint(x: base.x + number(), y: base.y + number())
                path.addCurve(to: p, control1: c1, control2: c2)
                current = p
                lastControl = c2
            case "Q":
                let c = CGPoint(x: base.x + number(), y: base.y + number())
                let p = CGPoint(x: base.x + number(), y: base.y + number())
                path.addQuadCurve(to: p, control: c)
                current = p
                lastControl = nil
            case "A":
                let rx = number(), ry = number(), rotation = number()
                let large = flag(), sweep = flag()
                let p = CGPoint(x: base.x + number(), y: base.y + number())
                addArc(to: &path, from: current, to: p, rx: rx, ry: ry, rotation: rotation, large: large, sweep: sweep)
                current = p
                lastControl = nil
            case "Z":
                path.closeSubpath()
                current = start
                lastControl = nil
            default:
                // Unsupported command: skip its numbers.
                while hasNumber() { index += 1 }
            }
        }
        return path
    }

    private enum Token { case command(Character), number(CGFloat) }

    private static func tokenize(_ data: String) -> [Token] {
        var tokens: [Token] = []
        var buffer = ""
        func flush() {
            if !buffer.isEmpty, let value = Double(buffer) { tokens.append(.number(CGFloat(value))) }
            buffer = ""
        }
        for ch in data {
            if ch.isLetter && ch != "e" && ch != "E" {
                flush()
                tokens.append(.command(ch))
            } else if ch == "," || ch.isWhitespace {
                flush()
            } else if ch == "-" {
                if let last = buffer.last, last == "e" || last == "E" { buffer.append(ch) } else { flush(); buffer.append(ch) }
            } else if ch == "." {
                if buffer.contains(".") && !buffer.contains("e") { flush() }
                buffer.append(ch)
            } else {
                buffer.append(ch)
            }
        }
        flush()
        return tokens
    }

    /// SVG elliptical arc → cubic Béziers (SVG implementation notes F.6).
    private static func addArc(to path: inout Path, from p0: CGPoint, to p1: CGPoint, rx rxIn: CGFloat, ry ryIn: CGFloat,
                               rotation: CGFloat, large: Bool, sweep: Bool) {
        var rx = abs(rxIn), ry = abs(ryIn)
        guard rx > 0, ry > 0, p0 != p1 else { path.addLine(to: p1); return }
        let phi = rotation * .pi / 180
        let cosPhi = cos(phi), sinPhi = sin(phi)
        let dx = (p0.x - p1.x) / 2, dy = (p0.y - p1.y) / 2
        let x1 = cosPhi * dx + sinPhi * dy
        let y1 = -sinPhi * dx + cosPhi * dy
        let lambda = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry)
        if lambda > 1 { rx *= sqrt(lambda); ry *= sqrt(lambda) }
        let numerator = rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1
        let denominator = rx * rx * y1 * y1 + ry * ry * x1 * x1
        var factor = sqrt(max(0, numerator / denominator))
        if large == sweep { factor = -factor }
        let cxp = factor * rx * y1 / ry
        let cyp = -factor * ry * x1 / rx
        let cx = cosPhi * cxp - sinPhi * cyp + (p0.x + p1.x) / 2
        let cy = sinPhi * cxp + cosPhi * cyp + (p0.y + p1.y) / 2
        func angle(_ ux: CGFloat, _ uy: CGFloat, _ vx: CGFloat, _ vy: CGFloat) -> CGFloat {
            let dot = ux * vx + uy * vy
            let length = sqrt(ux * ux + uy * uy) * sqrt(vx * vx + vy * vy)
            var a = acos(max(-1, min(1, dot / length)))
            if ux * vy - uy * vx < 0 { a = -a }
            return a
        }
        let theta1 = angle(1, 0, (x1 - cxp) / rx, (y1 - cyp) / ry)
        var delta = angle((x1 - cxp) / rx, (y1 - cyp) / ry, (-x1 - cxp) / rx, (-y1 - cyp) / ry)
        if !sweep && delta > 0 { delta -= 2 * .pi }
        if sweep && delta < 0 { delta += 2 * .pi }
        let segments = max(1, Int(ceil(abs(delta) / (.pi / 2))))
        let step = delta / CGFloat(segments)
        let t = 4 / 3 * tan(step / 4)
        var theta = theta1
        for _ in 0..<segments {
            let cos1 = cos(theta), sin1 = sin(theta)
            let cos2 = cos(theta + step), sin2 = sin(theta + step)
            func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                CGPoint(x: cx + rx * x * cosPhi - ry * y * sinPhi, y: cy + rx * x * sinPhi + ry * y * cosPhi)
            }
            let c1 = point(cos1 - t * sin1, sin1 + t * cos1)
            let c2 = point(cos2 + t * sin2, sin2 - t * cos2)
            path.addCurve(to: point(cos2, sin2), control1: c1, control2: c2)
            theta += step
        }
    }
}

/// An icon from the design: stroked and/or filled SVG paths in a square view box.
struct IconSpec: Hashable, Sendable {
    enum Element: Hashable, Sendable {
        case path(String)
        case rect(x: CGFloat, y: CGFloat, width: CGFloat, height: CGFloat, radius: CGFloat)
        case circle(cx: CGFloat, cy: CGFloat, r: CGFloat)
    }

    var viewBox: CGFloat
    var stroke: [Element] = []
    var fill: [Element] = []
    var lineWidth: CGFloat = 1.3
    var roundCaps = false
    var roundJoins = false
    /// Details drawn in the window background colour (e.g. the "!" inside status glyphs).
    var knockout: [Element] = []
    var knockoutWidth: CGFloat = 1.4

    static func path(for elements: [Element]) -> Path {
        var path = Path()
        for element in elements {
            switch element {
            case .path(let data): path.addPath(SVGPath.parse(data))
            case .rect(let x, let y, let w, let h, let r):
                path.addRoundedRect(in: CGRect(x: x, y: y, width: w, height: h), cornerSize: CGSize(width: r, height: r))
            case .circle(let cx, let cy, let r):
                path.addEllipse(in: CGRect(x: cx - r, y: cy - r, width: 2 * r, height: 2 * r))
            }
        }
        return path
    }
}

/// Renders an `IconSpec` at a given point size using the current foreground style.
struct Icon: View {
    var spec: IconSpec
    var size: CGFloat
    var knockoutColor: Color = Theme.win

    init(_ spec: IconSpec, size: CGFloat, knockout: Color = Theme.win) {
        self.spec = spec
        self.size = size
        self.knockoutColor = knockout
    }

    var body: some View {
        Canvas { context, canvasSize in
            let scale = canvasSize.width / spec.viewBox
            let transform = CGAffineTransform(scaleX: scale, y: scale)
            let shading = GraphicsContext.Shading.foreground
            if !spec.fill.isEmpty {
                context.fill(IconSpec.path(for: spec.fill).applying(transform), with: shading)
            }
            if !spec.stroke.isEmpty {
                context.stroke(IconSpec.path(for: spec.stroke).applying(transform), with: shading,
                               style: StrokeStyle(lineWidth: spec.lineWidth * scale, lineCap: spec.roundCaps ? .round : .butt,
                                                  lineJoin: spec.roundJoins ? .round : .miter))
            }
            if !spec.knockout.isEmpty {
                context.stroke(IconSpec.path(for: spec.knockout).applying(transform), with: .color(knockoutColor),
                               style: StrokeStyle(lineWidth: spec.knockoutWidth * scale, lineCap: .round, lineJoin: .round))
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The icon set used by the design (paths copied from design/*.dc.html).
enum Icons {
    static let sidebar = IconSpec(viewBox: 18, stroke: [.rect(x: 2, y: 3.5, width: 14, height: 11, radius: 2.5), .path("M7 3.5v11")], lineWidth: 1.4)
    static let inspector = IconSpec(viewBox: 18, stroke: [.rect(x: 2, y: 3.5, width: 14, height: 11, radius: 2.5), .path("M11 3.5v11")], lineWidth: 1.4)
    static let chevronDown = IconSpec(viewBox: 10, stroke: [.path("M2 3.5 5 6.5 8 3.5")], lineWidth: 1.5, roundCaps: true, roundJoins: true)
    static let chevronRight = IconSpec(viewBox: 10, stroke: [.path("M3.5 2 6.5 5 3.5 8")], lineWidth: 1.5, roundCaps: true, roundJoins: true)
    static let captureFile = IconSpec(viewBox: 16, stroke: [.path("M3.5 1.8h5.8l3.2 3.2v9.2h-9z"), .path("M9.3 1.8V5h3.2"),
                                                        .path("M5.6 10.5V9.5M7.4 12V8M9.2 11V9.2M11 10.4v-.6")], lineWidth: 1.3, roundCaps: true, roundJoins: true)
    static let overview = IconSpec(viewBox: 16, stroke: [.rect(x: 2, y: 2, width: 5, height: 5, radius: 1.3), .rect(x: 9, y: 2, width: 5, height: 5, radius: 1.3),
                                                     .rect(x: 2, y: 9, width: 5, height: 5, radius: 1.3), .rect(x: 9, y: 9, width: 5, height: 5, radius: 1.3)])
    static let phone = IconSpec(viewBox: 16, stroke: [.path("M4.6 2.2 6.3 2.7l.8 2.5-1.2 1.1a7 7 0 0 0 3.8 3.8l1.1-1.2 2.5.8.5 1.7c-.2.9-1 1.6-1.9 1.6C6.7 13 3 9.3 3 4.1c0-.9.7-1.7 1.6-1.9Z")], roundJoins: true)
    static let sipDialogs = IconSpec(viewBox: 16, stroke: [.path("M2.5 5.5h10M10 3l2.5 2.5L10 8M13.5 10.5h-10M6 8l-2.5 2.5L6 13")], roundCaps: true, roundJoins: true)
    static let rtp = IconSpec(viewBox: 16, stroke: [.path("M2 8h1M4.7 5.5v5M7.2 2.8v10.4M9.7 5v6M12.2 6.5v3M14 8h0")], lineWidth: 1.4, roundCaps: true)
    static let timeline = IconSpec(viewBox: 16, stroke: [.path("M2 13.5h12"), .path("M3 4h4.5M5 7.2h6.5M8 10.4h5")], roundCaps: true)
    /// Two endpoints joined by a two-way link (flows / conversations), in the sidebar icons' style.
    static let flows = IconSpec(viewBox: 16, stroke: [.path("M4.5 5.5h7M4.5 10.5h7"), .path("M9.5 3.5l2 2-2 2M6.5 8.5l-2 2 2 2")],
                                roundCaps: true, roundJoins: true)
    /// Two peers joined through a candidate pair (WebRTC / ICE), in the sidebar icons' style.
    static let webrtc = IconSpec(viewBox: 16, stroke: [.circle(cx: 3.2, cy: 8, r: 1.9), .circle(cx: 12.8, cy: 8, r: 1.9),
                                                       .path("M5.1 8h1.3M9.6 8h1.3"), .path("M8 6.2 9.8 8 8 9.8 6.2 8Z")],
                                 roundCaps: true, roundJoins: true)
    /// Warning triangle outline (diagnostics), drawn like the other sidebar icons.
    static let diagnostics = IconSpec(viewBox: 16, stroke: [.path("M8 2.3 14.2 13.2H1.8Z"), .path("M8 6.6v3.1M8 11.4v.05")],
                                      roundCaps: true, roundJoins: true)
    /// Vertical bars (traffic statistics).
    static let statistics = IconSpec(viewBox: 16, stroke: [.path("M2.5 13.5h11"), .path("M4 11V8M7 11V4.5M10 11V7M13 11V5.5")],
                                     lineWidth: 1.4, roundCaps: true)
    static let packets = IconSpec(viewBox: 16, stroke: [.rect(x: 2, y: 2.5, width: 12, height: 11, radius: 2), .path("M4.8 6h6.4M4.8 8.3h6.4M4.8 10.6h3.6")], roundCaps: true)
    static let plus = IconSpec(viewBox: 14, stroke: [.path("M7 2v10M2 7h10")], lineWidth: 1.5, roundCaps: true)
    static let search = IconSpec(viewBox: 16, stroke: [.circle(cx: 7, cy: 7, r: 4.6), .path("m10.5 10.5 3.3 3.3")], lineWidth: 1.7, roundCaps: true)
    static let back = IconSpec(viewBox: 14, stroke: [.path("M8.8 2.5 4.3 7l4.5 4.5")], lineWidth: 1.7, roundCaps: true, roundJoins: true)
    static let forward = IconSpec(viewBox: 14, stroke: [.path("M5.2 2.5 9.7 7l-4.5 4.5")], lineWidth: 1.7, roundCaps: true, roundJoins: true)
    static let up = IconSpec(viewBox: 14, stroke: [.path("M2.5 8.8 7 4.3l4.5 4.5")], lineWidth: 1.7, roundCaps: true, roundJoins: true)
    static let down = IconSpec(viewBox: 14, stroke: [.path("M2.5 5.2 7 9.7l4.5-4.5")], lineWidth: 1.7, roundCaps: true, roundJoins: true)
    static let filterLines = IconSpec(viewBox: 18, stroke: [.path("M3 5h12M5.5 9h7M8 13h2")], lineWidth: 1.5, roundCaps: true)
    static let export = IconSpec(viewBox: 18, stroke: [.path("M9 2.5v9M6 5.3 9 2.5l3 2.8"), .path("M6 7.5H4.5v8h9v-8H12")], lineWidth: 1.4, roundCaps: true, roundJoins: true)
    static let play = IconSpec(viewBox: 14, fill: [.path("M4 2.5v9l7.5-4.5z")])
    /// Loudspeaker (unmuted track) and the same with a cross (muted), in the toolbar icons' style.
    static let speaker = IconSpec(viewBox: 16, stroke: [.path("M2.5 6.2h2.4L8.3 3.4v9.2L4.9 9.8H2.5Z"),
                                                        .path("M10.6 5.6A3.4 3.4 0 0 1 10.6 10.4"), .path("M12.4 3.9A5.8 5.8 0 0 1 12.4 12.1")],
                                  lineWidth: 1.3, roundCaps: true, roundJoins: true)
    static let speakerMuted = IconSpec(viewBox: 16, stroke: [.path("M2.5 6.2h2.4L8.3 3.4v9.2L4.9 9.8H2.5Z"),
                                                             .path("M10.8 6.2l3.4 3.6M14.2 6.2l-3.4 3.6")],
                                       lineWidth: 1.3, roundCaps: true, roundJoins: true)
    static let pause = IconSpec(viewBox: 14, fill: [.rect(x: 3.5, y: 2.5, width: 2.6, height: 9, radius: 0.6), .rect(x: 7.9, y: 2.5, width: 2.6, height: 9, radius: 0.6)])
    static let copy = IconSpec(viewBox: 14, stroke: [.rect(x: 4.5, y: 4.5, width: 7.5, height: 7.5, radius: 1.5),
                                                 .path("M9.5 4.5V3.2c0-.8-.6-1.4-1.4-1.4H3.2c-.8 0-1.4.6-1.4 1.4v4.9c0 .8.6 1.4 1.4 1.4h1.3")])
    static let arrowRight = IconSpec(viewBox: 16, stroke: [.path("M2.5 8h11M9.5 4l4 4-4 4")], lineWidth: 1.6, roundCaps: true, roundJoins: true)
    static let goToPacket = IconSpec(viewBox: 16, stroke: [.path("M3 8h9M8.5 4.5 12 8l-3.5 3.5"), .path("M14 3v10")], lineWidth: 1.4, roundCaps: true, roundJoins: true)
    static let close = IconSpec(viewBox: 12, stroke: [.path("M3.5 3.5l5 5M8.5 3.5l-5 5")], lineWidth: 1.4, roundCaps: true)
    static let sortUp = IconSpec(viewBox: 8, stroke: [.path("M1.5 5.5 4 3l2.5 2.5")], lineWidth: 1.4, roundCaps: true)
    static let sortDown = IconSpec(viewBox: 8, stroke: [.path("M1.5 2.5 4 5l2.5-2.5")], lineWidth: 1.4, roundCaps: true)
    static let disclosure = IconSpec(viewBox: 10, fill: [.path("M3 1.5 7.5 5 3 8.5Z")])
    static let minus = IconSpec(viewBox: 12, stroke: [.path("M2 6h8")], lineWidth: 1.5, roundCaps: true)
    static let plusSmall = IconSpec(viewBox: 12, stroke: [.path("M2 6h8M6 2v8")], lineWidth: 1.5, roundCaps: true)
    static let mediaStart = IconSpec(viewBox: 10, fill: [.path("M1 0 9 5 1 10Z")])
    static let mediaEnd = IconSpec(viewBox: 10, fill: [.path("M1 0H9V10H1Z")])
    static let diamond = IconSpec(viewBox: 12, fill: [.path("M6 .8 11.2 6 6 11.2.8 6Z")])
    static let dot = IconSpec(viewBox: 8, fill: [.circle(cx: 4, cy: 4, r: 3.5)])
    static let dropFile = IconSpec(viewBox: 44, stroke: [.path("M11 5h15l8 8v26H11z"), .path("M26 5v8h8"), .path("M22.5 19v12M17.5 26l5 5 5-5")],
                                   lineWidth: 2, roundCaps: true, roundJoins: true)

    // Status glyphs (12 × 12)
    static let statusOK = IconSpec(viewBox: 12, fill: [.circle(cx: 6, cy: 6, r: 5.2)], knockout: [.path("m3.6 6.1 1.7 1.7 3.2-3.4")])
    static let statusGood = IconSpec(viewBox: 12, fill: [.circle(cx: 6, cy: 6, r: 5.2)])
    static let statusWarning = IconSpec(viewBox: 12, fill: [.path("M6 1 11.3 10.6H.7Z")], knockout: [.path("M6 4.3v3.1M6 8.9v.05")])
    static let statusWarningPlain = IconSpec(viewBox: 12, fill: [.path("M6 1 11.3 10.6H.7Z")])
    static let statusError = IconSpec(viewBox: 12, fill: [.path("M4 .8h4L11.2 4v4L8 11.2H4L.8 8V4Z")], knockout: [.path("M6 3.4v3.2M6 8.5v.05")])
    static let statusErrorPlain = IconSpec(viewBox: 12, fill: [.path("M4 .8h4L11.2 4v4L8 11.2H4L.8 8V4Z")])
    static let statusInfo = IconSpec(viewBox: 12, fill: [.circle(cx: 6, cy: 6, r: 5.2)], knockout: [.path("M6 5.4v3M6 3.6v.05")])
}
