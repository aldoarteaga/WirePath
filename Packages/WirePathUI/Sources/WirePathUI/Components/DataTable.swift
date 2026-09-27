import WirePathCore
import SwiftUI

/// Column of a `DataTable` (fixed width, or flexible when `width` is nil).
struct ColumnSpec: Identifiable {
    var title: String
    var width: CGFloat?
    var alignment: Alignment = .leading
    /// Narrowest layout on which the column is shown (secondary columns hide on compact widths).
    var minimum: LayoutWidth = .compact
    var id: String { title + "\(width ?? -1)" }

    static func fixed(_ title: String, _ width: CGFloat, _ alignment: Alignment = .leading,
                      from minimum: LayoutWidth = .compact) -> ColumnSpec {
        ColumnSpec(title: title, width: width, alignment: alignment, minimum: minimum)
    }

    static func flexible(_ title: String, _ alignment: Alignment = .leading, from minimum: LayoutWidth = .compact) -> ColumnSpec {
        ColumnSpec(title: title, width: nil, alignment: alignment, minimum: minimum)
    }
}

/// One cell's content; styling follows the calls table of the design.
struct CellValue {
    var text: String
    var secondary: String?
    var color: Color?
    var mono = false
    var weight: Font.Weight = .regular
    var status: Severity?

    static func text(_ text: String, color: Color? = nil, weight: Font.Weight = .regular) -> CellValue {
        CellValue(text: text, color: color, weight: weight)
    }

    static func mono(_ text: String, color: Color? = nil) -> CellValue { CellValue(text: text, color: color, mono: true) }
    static func status(_ severity: Severity) -> CellValue { CellValue(text: "", status: severity) }
    static func party(_ user: String, _ name: String?) -> CellValue { CellValue(text: user, secondary: name) }
}

/// Card table with a styled header, striped 26 pt rows, selection, ↑↓ / ↩ keyboard handling.
struct DataTable<ID: Hashable>: View {
    @Environment(\.layoutWidth) private var layoutWidth
    var columns: [ColumnSpec]
    var ids: [ID]
    @Binding var selection: ID?
    var emptyText = String(localized: "Nothing to show")
    var cells: (ID) -> [CellValue]
    var onOpen: ((ID) -> Void)?
    var menu: ((ID) -> AnyView)?
    @FocusState private var focused: Bool

    /// Indices of the columns shown at the current width.
    private var visible: [Int] { columns.indices.filter { columns[$0].minimum <= layoutWidth } }

    /// When narrow layouts hide every flexible column, the last leading-aligned visible column stretches instead, so the
    /// table always fills its card.
    private var stretchedColumn: Int? {
        let shown = visible
        guard !shown.contains(where: { columns[$0].width == nil }) else { return nil }
        return shown.last { columns[$0].alignment == .leading && !columns[$0].title.isEmpty } ?? shown.last
    }

    private func width(_ index: Int) -> CGFloat? {
        index == stretchedColumn ? nil : columns[index].width.map { max(0, $0) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                ForEach(visible, id: \.self) { index in
                    let column = columns[index]
                    // Same trailing inset as the cells, so right-aligned titles line up with their values and
                    // never touch the next column's title.
                    Text(column.title)
                        .padding(.trailing, column.title.isEmpty ? 0 : 8)
                        .frame(width: width(index), alignment: column.alignment)
                        .frame(maxWidth: width(index) == nil ? .infinity : nil, alignment: column.alignment)
                }
            }
            .font(.wp(11.5, .medium))
            .foregroundStyle(Theme.fg2)
            .lineLimit(1)
            .padding(.horizontal, 10)
            .frame(height: 28)
            .background(Theme.surf2)
            .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }

            if ids.isEmpty {
                Text(emptyText).font(.wp(12)).foregroundStyle(Theme.fg3).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView(.vertical) {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(ids.enumerated()), id: \.element) { offset, id in
                                row(id, striped: offset % 2 == 1)
                                    .id(id)
                                    .onTapGesture(count: 2) { onOpen?(id) }
                                    .onTapGesture { selection = id; focused = true }
                                    .contextMenu { if let menu { menu(id) } }
                            }
                        }
                    }
                    .onChange(of: selection) { _, value in
                        if let value { withAnimationIfAllowed(.linear(duration: 0.08)) { proxy.scrollTo(value) } }
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
            if let selection { onOpen?(selection) }
            return .handled
        }
        .modifier(CopyRow(text: selectionText))
    }

    /// The selected row as tab-separated text (Edit ▸ Copy), in the columns shown.
    private var selectionText: String? {
        guard let selection else { return nil }
        let values = cells(selection)
        return visible.compactMap { index -> String? in
            guard index < values.count, values[index].status == nil else { return nil }
            return [values[index].text, values[index].secondary].compactMap { $0 }.joined(separator: " ")
        }
        .joined(separator: "\t")
    }

    private func move(_ delta: Int) {
        guard !ids.isEmpty else { return }
        let current = selection.flatMap { ids.firstIndex(of: $0) } ?? (delta > 0 ? -1 : ids.count)
        selection = ids[max(0, min(ids.count - 1, current + delta))]
    }

    private func row(_ id: ID, striped: Bool) -> some View {
        let selected = selection == id
        let values = cells(id)
        return HStack(spacing: 0) {
            ForEach(visible, id: \.self) { index in
                let column = columns[index]
                cell(index < values.count ? values[index] : .text(""), selected: selected)
                    .frame(width: width(index), alignment: column.alignment)
                    .frame(maxWidth: width(index) == nil ? .infinity : nil, alignment: column.alignment)
            }
        }
        .font(.wp(12))
        .monospacedDigit()
        .foregroundStyle(selected ? Theme.onSel : Theme.fg)
        .lineLimit(1)
        .padding(.horizontal, 10)
        .frame(height: 26)
        .background(selected ? Theme.sel : (striped ? Theme.stripe : Color.clear))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }

    @ViewBuilder private func cell(_ value: CellValue, selected: Bool) -> some View {
        if let status = value.status {
            switch status {
            case .ok, .info: Icon(Icons.dot, size: 8).foregroundStyle(status == .ok ? Theme.ok : Theme.acc).opacity(0.85)
            case .warning: Icon(Icons.statusWarning, size: 12, knockout: selected ? Theme.sel : Theme.win).foregroundStyle(selected ? Theme.onSel : Theme.warn)
            case .error: Icon(Icons.statusError, size: 12, knockout: selected ? Theme.sel : Theme.win).foregroundStyle(selected ? Theme.onSel : Theme.err)
            }
        } else {
            HStack(spacing: 6) {
                Text(value.text)
                    .font(value.mono ? .wpMono(11.5) : .wp(12))
                    .fontWeight(value.weight)
                    .foregroundStyle(selected ? Theme.onSel : (value.color ?? Theme.fg))
                    .layoutPriority(1)
                if let secondary = value.secondary {
                    Text(secondary).foregroundStyle(selected ? Theme.onSelSub : Theme.fg3).truncationMode(.tail)
                }
            }
            .padding(.trailing, 8)
        }
    }
}

/// Edit ▸ Copy (⌘C) for a table's selected row.
private struct CopyRow: ViewModifier {
    var text: String?

    func body(content: Content) -> some View {
        #if os(macOS)
        content.onCopyCommand { text.map { [NSItemProvider(object: $0 as NSString)] } ?? [] }
        #else
        if #available(iOS 27.0, *) {
            content.copyable(text.map { [$0] } ?? [])
        } else {
            content
        }
        #endif
    }
}

/// A single-card row of metric cells (design: Traffic/Quality cards), reused by list screens.
struct MetricStrip: View {
    @Environment(\.layoutWidth) private var layoutWidth

    struct Item {
        var label: String
        var value: String
        var unit: String?
        var caption: String?
        var color: Color = Theme.fg
    }

    var items: [Item]

    var body: some View {
        if layoutWidth == .wide {
            strip
        } else {
            // Narrow widths: a wrapping grid of cells instead of a single row.
            LazyVGrid(columns: [GridItem(.adaptive(minimum: layoutWidth == .compact ? 150 : 170), spacing: 0)], spacing: 0) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in cellView(item) }
            }
            .card()
        }
    }

    private func cellView(_ item: Item) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(item.label).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(item.value).font(.wp(22, .semibold)).tracking(-0.3).monospacedDigit().foregroundStyle(item.color)
                    .lineLimit(1).minimumScaleFactor(0.6)
                if let unit = item.unit { Text(unit).font(.wp(13)).foregroundStyle(Theme.fg2) }
            }
            if let caption = item.caption { Text(caption).font(.wp(11)).foregroundStyle(Theme.fg3).lineLimit(1) }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var strip: some View {
        HStack(spacing: 0) {
            ForEach(Array(items.enumerated()), id: \.offset) { index, item in
                VStack(alignment: .leading, spacing: 4) {
                    Text(item.label).font(.wp(11, .medium)).foregroundStyle(Theme.fg2)
                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                        Text(item.value).font(.wp(24, .semibold)).tracking(-0.3).monospacedDigit().foregroundStyle(item.color)
                            .lineLimit(1).minimumScaleFactor(0.6)
                        if let unit = item.unit { Text(unit).font(.wp(13)).foregroundStyle(Theme.fg2) }
                    }
                    if let caption = item.caption {
                        Text(caption).font(.wp(11)).foregroundStyle(Theme.fg3).lineLimit(1)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .overlay(alignment: .leading) { if index > 0 { Rectangle().fill(Theme.line).frame(width: 1) } }
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .card()
    }
}
