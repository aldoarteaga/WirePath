import WirePathCore
import SwiftUI

/// Borderless icon button used in the header and sidebar (hover/pressed states follow macOS toolbars).
struct IconButton: View {
    var icon: IconSpec
    var iconSize: CGFloat
    var width: CGFloat = 34
    var height: CGFloat = 28
    var tint: Color = Theme.fg2
    var help: String
    var isEnabled = true
    var action: () -> Void

    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Icon(icon, size: iconSize)
                .foregroundStyle(tint)
                .frame(width: width, height: height)
                .background(RoundedRectangle(cornerRadius: 6).fill(hovering && isEnabled ? Theme.ctrl : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(PressedStyle(radius: 6))
        .opacity(isEnabled ? 1 : 0.5)
        .disabled(!isEnabled)
        .onHover { hovering = $0 }
        .help(help)
        .accessibilityLabel(Text(help))
    }
}

/// Darkens the control slightly while pressed.
struct PressedStyle: ButtonStyle {
    var radius: CGFloat

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .overlay(RoundedRectangle(cornerRadius: radius).fill(configuration.isPressed ? Theme.ctrl : .clear))
    }
}

/// Text button with a leading icon ("Play Audio", "Show Packets", "Open in SIP Flow").
struct PillButton: View {
    var icon: IconSpec
    var iconSize: CGFloat = 13
    var title: String
    var help: String?
    var isEnabled = true
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Icon(icon, size: iconSize).foregroundStyle(Theme.fg2)
                Text(title).font(.wp(12.5)).foregroundStyle(Theme.fg)
            }
            .padding(.horizontal, 10)
            .frame(height: 28)
            .background(RoundedRectangle(cornerRadius: 7).fill(Theme.ctrl))
            .contentShape(Rectangle())
        }
        .buttonStyle(PressedStyle(radius: 7))
        .opacity(isEnabled ? 1 : 0.45)
        .disabled(!isEnabled)
        .help(help ?? title)
    }
}

/// Rounded search field (header: 28 pt, sidebar filter: 24 pt).
struct SearchField: View {
    var placeholder: String
    @Binding var text: String
    var width: CGFloat?
    var height: CGFloat = 28
    var fontSize: CGFloat = 13
    var iconSize: CGFloat = 13
    var radius: CGFloat = 7
    var focusRequest: Int = 0
    var onSubmit: () -> Void = {}

    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: fontSize >= 13 ? 7 : 6) {
            Icon(Icons.search, size: iconSize).foregroundStyle(Theme.fg3)
            TextField("", text: $text, prompt: Text(placeholder).foregroundStyle(Theme.fg3))
                .textFieldStyle(.plain)
                .font(.wp(fontSize))
                .foregroundStyle(Theme.fg)
                .focused($focused)
                .onSubmit(onSubmit)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: fontSize - 1)).foregroundStyle(Theme.fg3)
                }
                .buttonStyle(.plain)
                .help("Clear")
                .accessibilityLabel("Clear")
            }
        }
        .padding(.horizontal, fontSize >= 13 ? 9 : 8)
        .frame(width: width, height: height)
        .background(RoundedRectangle(cornerRadius: radius).fill(Theme.ctrl))
        .onChange(of: focusRequest) { focused = true }
        .accessibilityLabel(Text(placeholder))
    }
}

/// The design's segmented control (radiogroup with a raised thumb).
struct SegmentedControl<Value: Hashable>: View {
    struct Item {
        var value: Value
        var title: String
        var leadingIcon: IconSpec?
        var iconColor: Color?
    }

    var items: [Item]
    @Binding var selection: Value
    var fontSize: CGFloat = 12
    var horizontalPadding: CGFloat = 11
    var verticalPadding: CGFloat = 3
    var outerRadius: CGFloat = 7
    var innerRadius: CGFloat = 5

    var body: some View {
        HStack(spacing: 0) {
            ForEach(items.indices, id: \.self) { index in
                let item = items[index]
                let selected = item.value == selection
                Button {
                    selection = item.value
                } label: {
                    HStack(spacing: 5) {
                        if let icon = item.leadingIcon {
                            Icon(icon, size: 10).foregroundStyle(item.iconColor ?? Theme.fg2)
                        }
                        Text(item.title).font(.wp(fontSize)).lineLimit(1)
                    }
                    .foregroundStyle(selected ? Theme.fg : Theme.fg2)
                    .padding(.horizontal, horizontalPadding)
                    .padding(.vertical, verticalPadding)
                    .background {
                        if selected {
                            RoundedRectangle(cornerRadius: innerRadius).fill(Theme.ctrl2)
                                .shadow(color: Theme.thumbShadow, radius: 1, y: 1)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selected ? [.isSelected] : [])
            }
        }
        .padding(2)
        .background(RoundedRectangle(cornerRadius: outerRadius).fill(Theme.ctrl))
    }
}

/// Keyboard hint (`↩ Investigate`).
struct KeyHint: View {
    var key: String
    var label: String

    var body: some View {
        HStack(spacing: 5) {
            Text(key)
                .font(.wp(10.5))
                .foregroundStyle(Theme.fg2)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(Theme.line2, lineWidth: 1))
            Text(label)
        }
    }
}

/// Mono tag ("G.711", "G.729 · 20 ms").
struct Chip: View {
    var text: String
    var mono = true
    var fontSize: CGFloat = 11.5
    var foreground: Color = Theme.fg
    var background: Color = Theme.ctrl

    var body: some View {
        Text(text)
            .font(mono ? .wpMono(fontSize) : .wp(fontSize))
            .foregroundStyle(foreground)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 5).fill(background))
    }
}

/// Status glyph matching the design's Good / Warning / Error / Info icons.
struct StatusIcon: View {
    var severity: Severity
    var size: CGFloat = 12
    var plain = false

    var body: some View {
        switch severity {
        case .ok: Icon(plain ? Icons.statusGood : Icons.statusOK, size: size).foregroundStyle(Theme.ok)
        case .info: Icon(Icons.statusInfo, size: size).foregroundStyle(Theme.acc)
        case .warning: Icon(plain ? Icons.statusWarningPlain : Icons.statusWarning, size: size).foregroundStyle(Theme.warn)
        case .error: Icon(plain ? Icons.statusErrorPlain : Icons.statusError, size: size).foregroundStyle(Theme.err)
        }
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .ok: return Theme.ok
        case .info: return Theme.acc
        case .warning: return Theme.warn
        case .error: return Theme.err
        }
    }

    var background: Color {
        switch self {
        case .ok: return Theme.okBg
        case .info: return Theme.selSoft
        case .warning: return Theme.warnBg
        case .error: return Theme.errBg
        }
    }
}

/// 4 pt progress / level bar.
struct LevelBar: View {
    var fraction: Double
    var color: Color = Theme.acc
    var height: CGFloat = 4

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: height / 2).fill(Theme.ctrl2)
                RoundedRectangle(cornerRadius: height / 2).fill(color)
                    .frame(width: max(0, min(1, fraction)) * proxy.size.width)
            }
        }
        .frame(height: height)
    }
}

/// Card surface used for every panel.
struct CardBackground: ViewModifier {
    var radius: CGFloat = 10

    func body(content: Content) -> some View {
        content
            .background(RoundedRectangle(cornerRadius: radius).fill(Theme.surf))
            .clipShape(RoundedRectangle(cornerRadius: radius))
            .overlay(RoundedRectangle(cornerRadius: radius).strokeBorder(Theme.line, lineWidth: 1))
    }
}

extension View {
    func card(radius: CGFloat = 10) -> some View { modifier(CardBackground(radius: radius)) }
}

/// Section header inside a card (36–40 pt, bottom rule).
struct CardHeader<Trailing: View>: View {
    var title: String
    var subtitle: String?
    var badge: String?
    var height: CGFloat = 40
    var showsRule = true
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack(spacing: 8) {
            Text(title).font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
            if let badge {
                Text(badge)
                    .font(.wp(11, .semibold))
                    .foregroundStyle(Theme.fg2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Theme.ctrl2))
            }
            if let subtitle { Text(subtitle).font(.wp(11)).foregroundStyle(Theme.fg3) }
            Spacer(minLength: 0)
            trailing()
        }
        .padding(.horizontal, 14)
        .frame(height: height)
        .overlay(alignment: .bottom) { if showsRule { Rectangle().fill(Theme.line).frame(height: 1) } }
    }
}

extension CardHeader where Trailing == EmptyView {
    init(title: String, subtitle: String? = nil, badge: String? = nil, height: CGFloat = 40, showsRule: Bool = true) {
        self.init(title: title, subtitle: subtitle, badge: badge, height: height, showsRule: showsRule) { EmptyView() }
    }
}

/// Status bar at the bottom of the main area (28 pt).
struct FooterBar: View {
    var leading: String
    var trailing: String

    var body: some View {
        HStack(spacing: 10) {
            Text(leading)
            Spacer(minLength: 0)
            Text(trailing)
        }
        .font(.wp(11))
        .foregroundStyle(Theme.fg2)
        .lineLimit(1)
        .padding(.horizontal, 16)
        .frame(height: 28)
        .background(Theme.bar)
        .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
    }
}

/// Simple polyline sparkline (0 = bottom).
struct Sparkline: View {
    var values: [Double]
    var maxValue: Double
    var color: Color = Theme.m1

    var body: some View {
        Canvas { context, size in
            guard values.count > 1, maxValue > 0 else { return }
            var path = Path()
            for (i, value) in values.enumerated() {
                let x = CGFloat(i) * size.width / CGFloat(values.count - 1)
                let y = size.height - CGFloat(min(value, maxValue) / maxValue) * size.height
                i == 0 ? path.move(to: CGPoint(x: x, y: y)) : path.addLine(to: CGPoint(x: x, y: y))
            }
            context.stroke(path, with: .color(color), style: StrokeStyle(lineWidth: 1.3, lineJoin: .round))
        }
    }
}
