import WirePathCore
import SwiftUI

/// Left column: analyses with their sections, import button and filter (design: nav, 256 pt).
public struct SidebarView: View {
    @Environment(WindowModel.self) private var window
    @Environment(LibraryModel.self) private var library
    @Environment(\.openWindow) private var openWindow
    @Environment(\.navigationCollapsed) private var collapsed

    public init() {}

    public var body: some View {
        @Bindable var window = window
        VStack(spacing: 0) {
            // Title-bar band: traffic lights live here (positioned by WindowConfigurator), toggle on the right.
            HStack(spacing: 8) {
                if !Platform.isMac {
                    Text("WirePath").font(.wp(17, .bold)).foregroundStyle(Theme.fg)
                }
                Spacer()
                if !collapsed {
                    IconButton(icon: Icons.sidebar, iconSize: 18, width: 30, height: 28, help: String(localized: "Hide Sidebar (⌃⌘S)")) {
                        withAnimationIfAllowed { window.sidebarVisible = false }
                    }
                }
            }
            .padding(.leading, 18)
            .padding(.trailing, 10)
            .frame(height: 52)
            .background(WindowDragArea())

            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text("Analyses").font(.wp(11, .semibold)).foregroundStyle(Theme.fg3)
                        Spacer()
                        Text("\(filteredItems.count)").font(.wp(11)).foregroundStyle(Theme.fg3)
                    }
                    .padding(EdgeInsets(top: 6, leading: 8, bottom: 4, trailing: 8))

                    ForEach(filteredItems) { item in
                        AnalysisRow(item: item)
                        if item.isExpanded && !item.isAnalyzing && item.manifest.state == .ready {
                            SectionList(item: item)
                        }
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 2)
            }
            .scrollIndicators(.never)
            .focusable()
            .focusEffectDisabled()
            .onKeyPress(.return) {
                guard window.renamingID == nil, let id = window.location?.analysisID else { return .ignored }
                window.renamingID = id
                return .handled
            }

            SidebarFooter()
        }
        .frame(width: Platform.isMac ? 256 : nil)
        .background(Theme.side.ignoresSafeArea())
        .overlay(alignment: .trailing) { Rectangle().fill(Theme.line).frame(width: 1) }
    }

    private var filteredItems: [AnalysisItem] {
        let query = window.sidebarFilter.trimmingCharacters(in: .whitespaces).lowercased()
        guard !query.isEmpty else { return library.items }
        return library.items.filter { $0.name.lowercased().contains(query) }
    }
}

/// One capture in the sidebar (expandable when analysed, progress bar while analysing).
struct AnalysisRow: View {
    @Environment(WindowModel.self) private var window
    @Environment(LibraryModel.self) private var library
    @Environment(\.openWindow) private var openWindow
    var item: AnalysisItem

    private var isCurrent: Bool { window.location?.analysisID == item.id }

    var body: some View {
        HStack(alignment: .top, spacing: 7) {
            Button {
                withAnimationIfAllowed(.easeInOut(duration: 0.15)) { item.isExpanded.toggle() }
            } label: {
                Icon(item.isExpanded ? Icons.chevronDown : Icons.chevronRight, size: 10)
                    .foregroundStyle(Theme.fg3)
                    .padding(.top, 4)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .opacity(item.manifest.state == .ready ? 1 : 0)
            .disabled(item.manifest.state != .ready)
            .accessibilityLabel(item.isExpanded ? String(localized: "Collapse") : String(localized: "Expand"))

            Icon(Icons.captureFile, size: 16)
                .foregroundStyle(item.isAnalyzing ? Theme.fg3 : Theme.acc)
                .padding(.top, 1)

            VStack(alignment: .leading, spacing: item.isAnalyzing ? 4 : 2) {
                if window.renamingID == item.id {
                    RenameField(item: item)
                } else {
                    Text(item.name)
                        .font(.wp(13, isCurrent ? .semibold : .regular))
                        .foregroundStyle(item.isAnalyzing ? Theme.fg2 : Theme.fg)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                content
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 7).fill(isCurrent ? Theme.ctrl : .clear))
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { window.renamingID = item.id }
        .onTapGesture { window.select(item) }
        .contextMenu { AnalysisContextMenu(item: item) }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
    }

    @ViewBuilder private var content: some View {
        switch item.manifest.state {
        case .analyzing:
            let progress = item.progress
            let percent = Int(((progress?.fraction ?? 0) * 100).rounded())
            let packets = progress.map { String(localized: " · \(Formatters.compact($0.packetsProcessed)) packets") } ?? ""
            Text("\(Formatters.phase(progress?.phase))… \(percent)%\(packets)")
                .font(.wp(11)).foregroundStyle(Theme.fg2).lineLimit(1)
            LevelBar(fraction: progress?.fraction ?? 0)
        case .ready:
            let summary = item.manifest.summary
            let calls = summary?.callCount ?? 0
            Text("\(calls) calls · \(Formatters.relativeDay(item.manifest.importedAt))")
                .font(.wp(11)).foregroundStyle(Theme.fg2).lineLimit(1)
            if let headline = summary?.headline {
                HStack(spacing: 5) {
                    StatusIcon(severity: headline.severity)
                    Text(headline.text).lineLimit(1)
                }
                .font(.wp(11))
                .foregroundStyle(headline.severity == .ok || headline.severity == .info ? Theme.fg2 : headline.severity.color)
            }
        case .failed(let message):
            HStack(alignment: .top, spacing: 5) {
                StatusIcon(severity: .error)
                Text(message).lineLimit(2)
            }
            .font(.wp(11)).foregroundStyle(Theme.err)
        case .cancelled:
            HStack(spacing: 5) {
                StatusIcon(severity: .info)
                Text("Analysis stopped · Re-analyze to continue").lineLimit(1)
            }
            .font(.wp(11)).foregroundStyle(Theme.fg2)
        }
    }
}

/// The analysis sections (Overview, Calls, … Diagnostics) under an expanded analysis.
struct SectionList: View {
    @Environment(WindowModel.self) private var window
    var item: AnalysisItem

    var body: some View {
        VStack(spacing: 1) {
            ForEach(AnalysisSection.allCases, id: \.self) { section in
                SectionRow(item: item, section: section)
            }
        }
        .padding(EdgeInsets(top: 2, leading: 22, bottom: 6, trailing: 0))
    }
}

struct SectionRow: View {
    @Environment(WindowModel.self) private var window
    var item: AnalysisItem
    var section: AnalysisSection

    private var isSelected: Bool {
        window.location?.analysisID == item.id && window.location?.route.section == section
    }

    private var trailing: String? {
        guard let summary = item.manifest.summary else { return nil }
        switch section {
        case .overview: return "⌘1"
        case .calls: return "\(summary.callCount)"
        case .sipDialogs: return "\(summary.sipSessionCount)"
        case .rtpStreams: return "\(summary.rtpStreamCount)"
        case .webrtc: return summary.webrtcSessionCount.map { "\($0)" }
        case .timeline: return nil
        case .packets: return Formatters.compact(summary.packetCount)
        case .flows: return summary.flowCount.map(Formatters.compact)
        case .statistics: return nil
        case .diagnostics: return nil
        }
    }

    var body: some View {
        Button {
            window.select(item, section: section)
        } label: {
            HStack(spacing: 8) {
                Icon(section.icon, size: 15).foregroundStyle(isSelected ? Theme.onSel : Theme.acc)
                Text(section.title).font(.wp(13)).frame(maxWidth: .infinity, alignment: .leading)
                if let trailing {
                    Text(trailing)
                        .font(.wp(11))
                        .foregroundStyle(isSelected ? Theme.onSel.opacity(0.7) : Theme.fg3)
                }
            }
            .foregroundStyle(isSelected ? Theme.onSel : Theme.fg)
            .padding(.horizontal, 8)
            .frame(height: 26)
            .background(RoundedRectangle(cornerRadius: 6).fill(isSelected ? Theme.sel : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? [.isSelected] : [])
        .accessibilityIdentifier("sidebar.\(section.identifier)")
    }
}

/// Inline rename (↩ saves, esc cancels); the base name is pre-selected like Finder.
struct RenameField: View {
    @Environment(WindowModel.self) private var window
    @Environment(LibraryModel.self) private var library
    var item: AnalysisItem
    @State private var text = ""
    @State private var selection: TextSelection?
    @FocusState private var focused: Bool

    var body: some View {
        TextField("Analysis name", text: $text, selection: $selection)
            .textFieldStyle(.plain)
            .font(.wp(13))
            .padding(.horizontal, 5)
            .frame(height: 22)
            .background(RoundedRectangle(cornerRadius: 4).fill(Theme.win))
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(Theme.sel, lineWidth: 1))
            .background(RoundedRectangle(cornerRadius: 6).stroke(Theme.selSoft, lineWidth: 3).padding(-1.5))
            .focused($focused)
            .onAppear {
                text = item.name
                let base = (text as NSString).deletingPathExtension
                selection = TextSelection(range: text.startIndex..<text.index(text.startIndex, offsetBy: base.count))
                focused = true
            }
            .onSubmit { commit() }
            .onKeyPress(.escape) {
                window.renamingID = nil
                return .handled
            }
            .onChange(of: focused) { _, isFocused in if !isFocused && window.renamingID == item.id { commit() } }
            .accessibilityLabel("Analysis name")
    }

    private func commit() {
        library.rename(item, to: text)
        window.renamingID = nil
    }
}

/// Right-click menu on an analysis (design: "Sidebar context menu").
struct AnalysisContextMenu: View {
    @Environment(WindowModel.self) private var window
    @Environment(LibraryModel.self) private var library
    @Environment(\.openWindow) private var openWindow
    var item: AnalysisItem

    var body: some View {
        Button("Open in New Window") { openWindow(value: item.id) }
            .macKeyboardShortcut("o", modifiers: [.option, .command])
        #if os(macOS)
        Button("Show in Finder") { library.showInFinder(item) }
            .macKeyboardShortcut("r", modifiers: [.shift, .command])
        #endif
        Divider()
        Button("Rename…") { window.renamingID = item.id }
        Button("Duplicate Analysis") { library.duplicate(item) }
            .disabled(item.isAnalyzing)
        Button("Export Report…") { window.select(item); window.exportReport() }
            .macKeyboardShortcut("e", modifiers: [.shift, .command])
            .disabled(item.manifest.state != .ready)
        Divider()
        if item.isAnalyzing {
            Button("Stop Analysis") { library.cancelAnalysis(item) }
                .macKeyboardShortcut(".", modifiers: .command)
        } else {
            Button("Re-analyze") { library.reanalyze(item) }
                .macKeyboardShortcut("r", modifiers: .command)
        }
        Divider()
        Button("Close Analysis") { window.forget(item.id); item.isExpanded = false }
        Button("Delete Analysis…", role: .destructive) { window.pendingDeletion = item }
            .macKeyboardShortcut(.delete, modifiers: .command)
    }
}

/// Bottom bar: import menu (+) and filter.
struct SidebarFooter: View {
    @Environment(WindowModel.self) private var window
    @Environment(LibraryModel.self) private var library

    var body: some View {
        @Bindable var window = window
        HStack(spacing: 8) {
            Menu {
                Button("Import PCAP…") { window.importFolders = false; window.showImporter = true }
                    .macKeyboardShortcut("i", modifiers: [.shift, .command])
                Button("Open PCAP…") { window.importFolders = false; window.showImporter = true }
                    .macKeyboardShortcut("o", modifiers: .command)
                Menu("Open Recent") {
                    ForEach(library.recentCaptures, id: \.self) { url in
                        Button(url.lastPathComponent) { open(library.importCaptures([url])) }
                    }
                    if library.recentCaptures.isEmpty {
                        Text("No Recent Captures")
                    } else {
                        Divider()
                        Button("Clear Menu") { library.clearRecentCaptures() }
                    }
                }
                Divider()
                Button("Import Folder of Captures…") { window.importFolders = true; window.showImporter = true }
            } label: {
                Icon(Icons.plus, size: 14).foregroundStyle(Theme.fg2)
                    .frame(width: 28, height: 24)
                    .contentShape(Rectangle())
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Import PCAP (⇧⌘I)")
            .accessibilityLabel("Import PCAP…")

            SearchField(placeholder: String(localized: "Filter"), text: $window.sidebarFilter, height: 24, fontSize: 12, iconSize: 12, radius: 6)
        }
        .padding(.horizontal, 10)
        .frame(height: 44)
        .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
    }

    private func open(_ items: [AnalysisItem]) {
        if let first = items.first { window.select(first) }
    }
}
