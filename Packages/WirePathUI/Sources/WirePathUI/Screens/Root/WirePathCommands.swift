import SwiftUI
import WirePathCore
#if os(macOS)
import AppKit
#endif

// MARK: - Menu bar

public struct WindowModelKey: FocusedValueKey {
    public typealias Value = WindowModel
}

extension FocusedValues {
    public var windowModel: WindowModel? {
        get { self[WindowModelKey.self] }
        set { self[WindowModelKey.self] = newValue }
    }
}

extension View {
    /// Applies a keyboard shortcut on macOS only. On iPadOS the same keys belong to system commands
    /// (Close Window ⌘W, Show Sidebar ⌃⌘S, Find ⌘F, Find and Replace ⌥⌘F, Show Inspector ⌥⌘I), which
    /// UIKit refuses to duplicate; the system versions drive the same native behaviour there.
    @ViewBuilder func macKeyboardShortcut(_ key: KeyEquivalent, modifiers: EventModifiers = .command) -> some View {
        #if os(macOS)
        keyboardShortcut(key, modifiers: modifiers)
        #else
        self
        #endif
    }
}

/// Menu commands and the keyboard shortcuts from the design's shortcut table.
public struct WirePathCommands: Commands {
    let library: LibraryModel
    @FocusedValue(\.windowModel) private var window

    public init(library: LibraryModel) { self.library = library }

    public var body: some Commands {
        CommandGroup(replacing: .newItem) {
            #if os(macOS)
            Button("Open PCAP…") { window?.importFolders = false; window?.showImporter = true }
                .keyboardShortcut("o", modifiers: .command)
            #endif
            Button("Import PCAP…") { window?.importFolders = false; window?.showImporter = true }
                .keyboardShortcut("i", modifiers: [.shift, .command])
            Button("Import Folder of Captures…") { window?.importFolders = true; window?.showImporter = true }
        }
        CommandGroup(replacing: .saveItem) {
            Button("Close Analysis") {
                guard let window, let item = window.selectedItem else { return }
                item.isExpanded = false
                window.forget(item.id)
            }
            .macKeyboardShortcut("w", modifiers: .command)
            .disabled(window?.selectedItem == nil)
            #if os(macOS)
            Button("Close Window") { NSApp.keyWindow?.performClose(nil) }
                .keyboardShortcut("w", modifiers: [.shift, .command])
            #endif
        }
        CommandGroup(after: .newItem) {
            Divider()
            Button("Export Report…") { window?.exportReport() }
            .keyboardShortcut("e", modifiers: [.shift, .command])
            .disabled(window?.document == nil)
            Button("Re-analyze") { if let item = window?.selectedItem { library.reanalyze(item) } }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(window?.selectedItem == nil || window?.selectedItem?.isAnalyzing == true)
            Button("Stop Analysis") { if let item = window?.selectedItem { library.cancelAnalysis(item) } }
                .keyboardShortcut(".", modifiers: .command)
                .disabled(window?.selectedItem?.isAnalyzing != true)
            #if os(macOS)
            Button("Show in Finder") { if let item = window?.selectedItem { library.showInFinder(item) } }
                .keyboardShortcut("r", modifiers: [.shift, .command])
                .disabled(window?.selectedItem == nil)
            #endif
            Divider()
            Button("Delete Analysis…") { window?.pendingDeletion = window?.selectedItem }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(window?.selectedItem == nil)
        }
        #if os(iOS)
        // iPadOS ships a text-editing Find (⌘F); WirePath's ⌘F searches calls, numbers and IPs instead.
        CommandGroup(replacing: .textEditing) {}
        #endif
        CommandGroup(after: .textEditing) {
            Button("Find Calls, Numbers, IPs…") { window?.searchFocusRequest += 1 }
                .macKeyboardShortcut("f", modifiers: .command)
            Button("Edit Display Filter") {
                guard let window else { return }
                if window.location?.route.section != .packets { window.navigate(to: .section(.packets)) }
                window.displayFilterFocusRequest += 1
            }
            .macKeyboardShortcut("f", modifiers: [.option, .command])
            .disabled(window?.document == nil)
        }
        CommandGroup(before: .sidebar) {
            Button(window?.sidebarVisible == false ? String(localized: "Show Sidebar") : String(localized: "Hide Sidebar")) {
                withAnimationIfAllowed { window?.sidebarVisible.toggle() }
            }
            .macKeyboardShortcut("s", modifiers: [.control, .command])
            Button(window?.inspectorVisible == true ? String(localized: "Hide Inspector") : String(localized: "Show Inspector")) {
                withAnimationIfAllowed { window?.inspectorVisible.toggle() }
            }
            .macKeyboardShortcut("i", modifiers: [.option, .command])
            Divider()
            ForEach(AnalysisSection.allCases, id: \.self) { section in
                Button(section.title) { window?.navigate(to: .section(section)) }
                    .keyboardShortcut(KeyEquivalent(section.shortcutDigit), modifiers: .command)
                    .disabled(window?.document == nil)
            }
            Divider()
        }
        CommandMenu("Go") {
            Button("Back") { window?.goBack() }
                .keyboardShortcut("[", modifiers: .command)
                .disabled(window?.canGoBack != true)
            Button("Forward") { window?.goForward() }
                .keyboardShortcut("]", modifiers: .command)
                .disabled(window?.canGoForward != true)
            Divider()
            Button("Previous Call") { window?.stepCall(-1) }
                .keyboardShortcut(.upArrow, modifiers: .command)
                .disabled(window?.document == nil)
            Button("Next Call") { window?.stepCall(1) }
                .keyboardShortcut(.downArrow, modifiers: .command)
                .disabled(window?.document == nil)
            Button("Investigate Selected Call") {
                if let call = window?.document?.selectedCall { window?.investigate(call) }
            }
            .disabled(window?.document?.selectedCall == nil)
            Button("Show Packets for Selected Call") {
                guard let window else { return }
                if case .call(let index)? = window.location?.route { window.showPackets(forCall: index) }
                else if let call = window.document?.selectedCall { window.showPackets(forCall: call) }
            }
            .keyboardShortcut("p", modifiers: [.shift, .command])
            .disabled(window?.document?.selectedCall == nil)
        }
    }
}
