import SwiftUI
import WirePathCore

#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Column geometry of the packet list (design: 70 80 92 92 58 50 1fr, padding 0 10).
enum PacketColumns {
    static let number: CGFloat = 70
    static let time: CGFloat = 80
    static let source: CGFloat = 92
    static let destination: CGFloat = 92
    static let proto: CGFloat = 58
    static let length: CGFloat = 50
    static let padding: CGFloat = 10
    static let rowHeight: CGFloat = 24
}

/// SwiftUI header row matching the design (sorted by number).
struct PacketListHeader: View {
    var compact = false

    var body: some View {
        HStack(spacing: 0) {
            HStack(spacing: 4) {
                Text("No.")
                Icon(Icons.sortUp, size: 8)
            }
            .foregroundStyle(Theme.fg)
            .frame(width: PacketColumns.number, alignment: .leading)
            Text("Time").frame(width: PacketColumns.time, alignment: .leading)
            if !compact {
                Text("Source").frame(width: PacketColumns.source, alignment: .leading)
                Text("Destination").frame(width: PacketColumns.destination, alignment: .leading)
            }
            Text("Protocol").frame(width: PacketColumns.proto, alignment: .leading)
            if !compact {
                Text("Length").frame(width: PacketColumns.length - 10, alignment: .trailing).padding(.trailing, 10)
            }
            Text("Info").frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.wp(11.5, .medium))
        .foregroundStyle(Theme.fg2)
        .lineLimit(1)
        .padding(.horizontal, PacketColumns.padding)
        .frame(height: 26)
        .background(Theme.surf2)
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.line).frame(height: 1) }
        .accessibilityHidden(true)
    }
}

/// Everything needed to draw one packet row.
struct PacketRowContent {
    var row: PacketRow
    var striped: Bool
    var referenceNanos: Int64
    var dotColor: PlatformColor
    var compact: Bool
}

/// Draws a packet row with Core Graphics — shared by the AppKit and UIKit list implementations so
/// both platforms render identical rows without creating per-cell view hierarchies.
enum PacketRowRenderer {
    static func drawBackground(_ content: PacketRowContent, selected: Bool, in rect: CGRect) {
        if selected {
            ThemeColors.sel.setFill()
        } else if content.row.flags.contains(.sequenceGap) {
            ThemeColors.warnBg.setFill()
        } else if content.striped {
            ThemeColors.stripe.setFill()
        } else {
            return
        }
        fill(rect)
    }

    static func drawContent(_ content: PacketRowContent, selected: Bool, in bounds: CGRect) {
        let row = content.row
        let fg = selected ? PlatformColor.white : ThemeColors.fg
        let sub = selected ? PlatformColor.white.withAlphaComponent(0.75) : ThemeColors.fg3
        let infoColor = selected ? PlatformColor.white : (row.flags.contains(.sequenceGap) ? ThemeColors.warn : ThemeColors.fg2)
        let mono = PlatformFont.wpMono(11.5)
        let body = PlatformFont.wp(12)
        let medium = PlatformFont.wp(12, .medium)
        var x = PacketColumns.padding
        let height = bounds.height

        func text(_ string: String, font: PlatformFont, color: PlatformColor, width: CGFloat, alignRight: Bool = false,
                  rightPadding: CGFloat = 0) {
            let style = NSMutableParagraphStyle()
            style.lineBreakMode = .byTruncatingTail
            style.alignment = alignRight ? .right : .left
            let attributes: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color, .paragraphStyle: style]
            let size = (string as NSString).size(withAttributes: attributes)
            let rect = CGRect(x: x, y: (height - size.height) / 2, width: max(0, width - rightPadding), height: size.height)
            (string as NSString).draw(with: rect, options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine],
                                      attributes: attributes, context: nil)
            x += width
        }

        let relative = Timestamp(nanoseconds: row.timestampNanos).seconds(since: Timestamp(nanoseconds: content.referenceNanos))
        text("\(row.frameNumber)", font: mono, color: fg, width: PacketColumns.number, rightPadding: 6)
        text(String(format: "%.6f", relative), font: mono, color: sub, width: PacketColumns.time, rightPadding: 6)
        if !content.compact {
            // A gap before the next column, so values that fill their column never run into the next one.
            text(row.source, font: mono, color: fg, width: PacketColumns.source, rightPadding: 8)
            text(row.destination, font: mono, color: fg, width: PacketColumns.destination, rightPadding: 8)
        }
        let dot = CGRect(x: x, y: (height - 6) / 2, width: 6, height: 6)
        (selected ? PlatformColor.white : content.dotColor).setFill()
        roundedFill(dot, radius: 2)
        x += 11
        text(row.protocolName, font: medium, color: fg, width: PacketColumns.proto - 11, rightPadding: 3)
        if !content.compact {
            text("\(row.length)", font: body, color: sub, width: PacketColumns.length, alignRight: true, rightPadding: 10)
        }
        text(row.info, font: body, color: infoColor, width: bounds.width - x - PacketColumns.padding)
    }

    private static func fill(_ rect: CGRect) {
        #if os(macOS)
        rect.fill()
        #else
        UIRectFill(rect)
        #endif
    }

    private static func roundedFill(_ rect: CGRect, radius: CGFloat) {
        #if os(macOS)
        NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius).fill()
        #else
        UIBezierPath(roundedRect: rect, cornerRadius: radius).fill()
        #endif
    }

    static func accessibilityLabel(_ row: PacketRow) -> String {
        String(localized: "Packet \(row.frameNumber), \(row.protocolName), \(row.source) to \(row.destination), \(row.info)")
    }
}

/// Shared data source logic for both list implementations.
@MainActor
final class PacketListSource {
    var model: PacketInspectorModel
    var generation = -1
    var compact = false

    init(model: PacketInspectorModel) { self.model = model }

    var count: Int { model.store == nil ? 0 : model.displayedCount }

    func content(forRow row: Int) -> PacketRowContent? {
        guard let store = model.store, let position = model.position(forRow: row) else { return nil }
        let packet = store.row(at: position)
        return PacketRowContent(row: packet, striped: row % 2 == 1, referenceNanos: model.referenceNanos,
                                dotColor: dotColor(for: packet), compact: compact)
    }

    private func dotColor(for row: PacketRow) -> PlatformColor {
        if row.flags.contains(.sequenceGap) { return ThemeColors.warn }
        switch row.protocolKind {
        case .sip, .sipSDP: return ThemeColors.acc
        case .rtp:
            let calls = model.document.result.calls
            if let stream = row.streamIndex, let call = row.callIndex, call < calls.count,
               calls[call].quality?.reverse?.streamIndices.contains(stream) == true {
                return ThemeColors.m2
            }
            return ThemeColors.m1
        case .rtcp: return ThemeColors.m2
        case .stun, .turn: return ThemeColors.warn
        default: return ThemeColors.fg3
        }
    }
}

#if os(macOS)

/// Virtualised packet list backed by NSTableView — only visible rows are decoded.
struct PacketListView: NSViewRepresentable {
    var model: PacketInspectorModel
    var compact = false

    func makeCoordinator() -> Coordinator { Coordinator(source: PacketListSource(model: model)) }

    func makeNSView(context: Context) -> NSScrollView {
        let table = NSTableView()
        table.headerView = nil
        table.style = .plain
        table.rowHeight = PacketColumns.rowHeight
        table.intercellSpacing = .zero
        table.backgroundColor = .clear
        table.gridStyleMask = []
        table.allowsMultipleSelection = false
        table.allowsEmptySelection = true
        table.selectionHighlightStyle = .regular
        table.focusRingType = .none
        let column = NSTableColumn(identifier: .init("packet"))
        column.resizingMask = .autoresizingMask
        table.addTableColumn(column)
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        table.dataSource = context.coordinator
        table.delegate = context.coordinator
        table.setAccessibilityLabel(String(localized: "Packets"))
        table.setAccessibilityIdentifier("packets.list")
        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.autohidesScrollers = true
        context.coordinator.table = table
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        let coordinator = context.coordinator
        coordinator.source.model = model
        let compactChanged = coordinator.source.compact != compact
        coordinator.source.compact = compact
        if coordinator.source.generation != model.generation || compactChanged {
            coordinator.source.generation = model.generation
            coordinator.table?.reloadData()
        }
        coordinator.syncSelection()
    }

    @MainActor
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        let source: PacketListSource
        weak var table: NSTableView?
        private var updatingSelection = false

        init(source: PacketListSource) { self.source = source }

        func numberOfRows(in tableView: NSTableView) -> Int { source.count }

        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? { nil }

        func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
            let view = (tableView.makeView(withIdentifier: PacketRowView.identifier, owner: nil) as? PacketRowView) ?? PacketRowView()
            view.identifier = PacketRowView.identifier
            view.content = source.content(forRow: row)
            return view
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !updatingSelection, let table else { return }
            source.model.selectedPosition = source.model.position(forRow: table.selectedRow)
        }

        func syncSelection() {
            guard let table else { return }
            let wanted = source.model.selectedPosition.flatMap { source.model.row(forPosition: $0) }
            guard wanted != (table.selectedRow >= 0 ? table.selectedRow : nil) else { return }
            updatingSelection = true
            if let wanted {
                table.selectRowIndexes(IndexSet(integer: wanted), byExtendingSelection: false)
                table.scrollRowToVisible(wanted)
            } else {
                table.deselectAll(nil)
            }
            updatingSelection = false
        }
    }
}

final class PacketRowView: NSTableRowView {
    static let identifier = NSUserInterfaceItemIdentifier("PacketRow")
    var content: PacketRowContent? {
        didSet {
            if let content { setAccessibilityLabel(PacketRowRenderer.accessibilityLabel(content.row)) }
            needsDisplay = true
        }
    }

    override var isEmphasized: Bool { get { true } set {} }

    override func drawBackground(in dirtyRect: NSRect) {
        guard let content else { return }
        PacketRowRenderer.drawBackground(content, selected: false, in: bounds)
    }

    override func drawSelection(in dirtyRect: NSRect) {
        guard let content else { return }
        PacketRowRenderer.drawBackground(content, selected: true, in: bounds)
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let content else { return }
        PacketRowRenderer.drawContent(content, selected: isSelected, in: bounds)
    }
}

#else

/// Virtualised packet list backed by UITableView (touch, pointer and keyboard), sharing the row renderer.
struct PacketListView: UIViewRepresentable {
    var model: PacketInspectorModel
    var compact = false

    func makeCoordinator() -> Coordinator { Coordinator(source: PacketListSource(model: model)) }

    func makeUIView(context: Context) -> UITableView {
        let table = UITableView(frame: .zero, style: .plain)
        table.register(PacketCell.self, forCellReuseIdentifier: PacketCell.identifier)
        table.rowHeight = PacketColumns.rowHeight + (compact ? 8 : 4)
        table.separatorStyle = .none
        table.backgroundColor = .clear
        table.dataSource = context.coordinator
        table.delegate = context.coordinator
        table.allowsFocus = true
        table.selectionFollowsFocus = true
        table.accessibilityLabel = String(localized: "Packets")
        table.accessibilityIdentifier = "packets.list"
        context.coordinator.table = table
        return table
    }

    func updateUIView(_ table: UITableView, context: Context) {
        let coordinator = context.coordinator
        coordinator.source.model = model
        let compactChanged = coordinator.source.compact != compact
        coordinator.source.compact = compact
        table.rowHeight = PacketColumns.rowHeight + (compact ? 8 : 4)
        if coordinator.source.generation != model.generation || compactChanged {
            coordinator.source.generation = model.generation
            table.reloadData()
        }
        coordinator.syncSelection()
    }

    @MainActor
    final class Coordinator: NSObject, UITableViewDataSource, UITableViewDelegate {
        let source: PacketListSource
        weak var table: UITableView?
        private var updatingSelection = false

        init(source: PacketListSource) { self.source = source }

        func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { source.count }

        func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
            let cell = tableView.dequeueReusableCell(withIdentifier: PacketCell.identifier, for: indexPath)
            (cell as? PacketCell)?.content = source.content(forRow: indexPath.row)
            return cell
        }

        func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
            guard !updatingSelection else { return }
            source.model.selectedPosition = source.model.position(forRow: indexPath.row)
            source.model.detailRequested = true
        }

        func syncSelection() {
            guard let table else { return }
            let wanted = source.model.selectedPosition.flatMap { source.model.row(forPosition: $0) }
            guard wanted != table.indexPathForSelectedRow?.row else { return }
            updatingSelection = true
            if let wanted, wanted < source.count {
                table.selectRow(at: IndexPath(row: wanted, section: 0), animated: false, scrollPosition: .middle)
            } else if let selected = table.indexPathForSelectedRow {
                table.deselectRow(at: selected, animated: false)
            }
            updatingSelection = false
        }
    }
}

final class PacketCell: UITableViewCell {
    static let identifier = "PacketCell"
    private let canvas = PacketCellCanvas()

    var content: PacketRowContent? {
        didSet {
            canvas.content = content
            accessibilityLabel = content.map { PacketRowRenderer.accessibilityLabel($0.row) }
        }
    }

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        backgroundColor = .clear
        selectionStyle = .none
        canvas.frame = contentView.bounds
        canvas.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        contentView.addSubview(canvas)
        isAccessibilityElement = true
    }

    required init?(coder: NSCoder) { nil }

    override func setSelected(_ selected: Bool, animated: Bool) {
        super.setSelected(selected, animated: animated)
        canvas.selected = selected
    }
}

final class PacketCellCanvas: UIView {
    var content: PacketRowContent? { didSet { setNeedsDisplay() } }
    var selected = false { didSet { setNeedsDisplay() } }

    override init(frame: CGRect) {
        super.init(frame: frame)
        isOpaque = false
        contentMode = .redraw
    }

    required init?(coder: NSCoder) { nil }

    override func draw(_ rect: CGRect) {
        guard let content else { return }
        PacketRowRenderer.drawBackground(content, selected: selected, in: bounds)
        PacketRowRenderer.drawContent(content, selected: selected, in: bounds)
    }
}

#endif
