import SwiftUI
import UniformTypeIdentifiers
import WirePathCore

/// Capture file types WirePath opens (registered by both apps' Info.plists).
public enum CaptureTypes {
    public static let pcap = UTType(importedAs: "com.tcpdump.pcap", conformingTo: .data)
    public static let pcapng = UTType(importedAs: "com.wireshark.pcapng", conformingTo: .data)

    /// Everything the importer accepts: pcap, pcapng and gzip-compressed captures.
    public static let all: [UTType] = [pcap, pcapng, .gzip, UTType(filenameExtension: "cap") ?? pcap].reduce(into: []) { list, type in
        if !list.contains(type) { list.append(type) }
    }
}

/// Chooses the screen for the window's current location.
public struct DetailView: View {
    @Environment(WindowModel.self) private var window
    @Environment(LibraryModel.self) private var library

    public init() {}

    public var body: some View {
        Group {
            if let item = window.selectedItem, let location = window.location {
                switch item.manifest.state {
                case .analyzing:
                    AnalyzingView(item: item)
                case .failed(let message):
                    ProblemView(item: item, title: String(localized: "The capture could not be analyzed"), message: message)
                case .cancelled:
                    ProblemView(item: item, title: String(localized: "Analysis stopped"),
                                message: String(localized: "The analysis was stopped before it finished. Re-analyze to see its results."))
                case .ready:
                    if let document = item.document {
                        screen(for: location.route, document: document)
                    } else if case .failed(let message) = item.loadState {
                        ProblemView(item: item, title: String(localized: "The saved results could not be opened"), message: message)
                    } else {
                        LoadingView(item: item).onAppear { library.loadDocument(item) }
                    }
                }
            } else {
                EmptyLibraryView()
            }
        }
        .adaptiveLayoutWidth()
    }

    @ViewBuilder private func screen(for route: Route, document: AnalysisDocument) -> some View {
        switch route {
        case .section(.overview): OverviewScreen(document: document)
        case .section(.calls): CallsScreen(document: document)
        case .call(let index) where index < document.result.calls.count:
            CallInvestigationScreen(document: document, callIndex: index).id(index)
        case .call: CallsScreen(document: document)
        case .section(.sipDialogs): SIPDialogsScreen(document: document)
        case .section(.rtpStreams): RTPStreamsScreen(document: document)
        case .section(.webrtc): WebRTCScreen(document: document)
        case .section(.timeline): CaptureTimelineScreen(document: document)
        case .section(.packets): PacketsScreen(document: document, model: document.packetModel(callIndex: nil))
        case .section(.flows): FlowsScreen(document: document)
        case .section(.statistics): StatisticsScreen(document: document)
        case .section(.diagnostics): DiagnosticsScreen(document: document)
        case .packets(let callIndex): PacketsScreen(document: document, model: document.packetModel(callIndex: callIndex))
        }
    }
}

/// Design: "Drag and drop · files dropped anywhere on the window".
struct DropOverlay: View {
    var names: [String]

    var body: some View {
        VStack(spacing: 10) {
            Icon(Icons.dropFile, size: 44).foregroundStyle(Theme.acc)
            Text("Drop to Analyze").font(.wp(16, .semibold)).foregroundStyle(Theme.fg)
            if !names.isEmpty {
                Text("\(names.count) captures · \(names.joined(separator: ", "))")
                    .font(.wp(12)).foregroundStyle(Theme.fg2).lineLimit(1).truncationMode(.middle)
            }
            Text("Each file opens as a new analysis").font(.wp(11)).foregroundStyle(Theme.fg3)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(RoundedRectangle(cornerRadius: 12).fill(Theme.selSoft))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.acc, style: StrokeStyle(lineWidth: 2, dash: [6, 4])))
        .background(RoundedRectangle(cornerRadius: 12).fill(Theme.win.opacity(0.85)))
        .accessibilityElement(children: .combine)
    }
}

extension View {
    /// Window-level services shared by both apps: import panel, drag & drop, export panel,
    /// delete confirmation and error alerts.
    public func wirePathWindowServices(window: WindowModel, library: LibraryModel) -> some View {
        modifier(WindowServices(window: window, library: library))
    }
}

private struct WindowServices: ViewModifier {
    @Bindable var window: WindowModel
    @Bindable var library: LibraryModel
    @State private var confirmDelete = false
    #if os(macOS)
    @Environment(\.appearsActive) private var isKeyWindow
    #else
    private let isKeyWindow = true
    #endif

    /// Shows a capture opened from Finder or the Dock in the key window (only one window takes it).
    private func showExternallyOpenedCapture() {
        guard isKeyWindow, library.pendingExternalSelection != nil, let item = library.takeExternalSelection() else { return }
        Log.ui.notice("Showing an externally opened capture in the key window")
        window.select(item)
    }

    func body(content: Content) -> some View {
        content
            .overlay {
                if window.dropCount > 0 { DropOverlay(names: window.dropNames).padding(14).allowsHitTesting(false) }
            }
            .onDrop(of: [.fileURL, .data], delegate: CaptureDropDelegate(window: window, library: library))
            .fileImporter(isPresented: $window.showImporter,
                          allowedContentTypes: window.importFolders ? [.folder] : CaptureTypes.all + [.data],
                          allowsMultipleSelection: true) { outcome in
                if case .success(let urls) = outcome {
                    let items = library.importCaptures(urls)
                    if let first = items.first { window.select(first) }
                }
            }
            .fileExporter(isPresented: Binding(get: { window.pendingExport != nil }, set: { if !$0 { window.pendingExport = nil } }),
                          document: window.pendingExport.map { ExportDocument(url: $0.url) },
                          contentType: window.pendingExport?.contentType ?? .data,
                          defaultFilename: window.pendingExport?.filename) { outcome in
                if case .failure(let error) = outcome {
                    library.lastError = String(localized: "The file could not be saved: \(error.localizedDescription)")
                }
                window.pendingExport = nil
            }
            .onChange(of: library.pendingExternalSelection) { showExternallyOpenedCapture() }
            .onChange(of: isKeyWindow) { showExternallyOpenedCapture() }
            .onAppear { showExternallyOpenedCapture() }
            .onChange(of: window.pendingDeletion?.id) { _, id in
                guard id != nil, let item = window.pendingDeletion else { return }
                #if os(macOS)
                MacDeleteAlert.present(item: item) { confirmed, moveToTrash in
                    if confirmed { delete(item, moveToTrash: moveToTrash) }
                    window.pendingDeletion = nil
                }
                #else
                confirmDelete = true
                #endif
            }
            .confirmationDialog(Text("Delete “\(window.pendingDeletion?.name ?? "")”?"), isPresented: $confirmDelete,
                                titleVisibility: .visible, presenting: window.pendingDeletion) { item in
                Button("Delete Analysis", role: .destructive) {
                    delete(item, moveToTrash: false)
                    window.pendingDeletion = nil
                }
                Button("Cancel", role: .cancel) { window.pendingDeletion = nil }
            } message: { _ in
                Text("The analysis and its cached results will be removed from WirePath. The original capture file stays where it is.")
            }
            .alert("WirePath", isPresented: Binding(get: { library.lastError != nil }, set: { if !$0 { library.lastError = nil } })) {
                Button("OK", role: .cancel) { library.lastError = nil }
            } message: {
                Text(library.lastError ?? "")
            }
    }

    private func delete(_ item: AnalysisItem, moveToTrash: Bool) {
        window.forget(item.id)
        library.delete(item, moveCaptureToTrash: moveToTrash)
    }
}

#if os(macOS)
import AppKit

/// Design: "Delete confirmation · alert sheet" — app icon, title, message, trash checkbox, Cancel / Delete.
@MainActor
enum MacDeleteAlert {
    static func present(item: AnalysisItem, completion: @escaping (Bool, Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = String(localized: "Delete “\(item.name)”?")
        alert.informativeText = String(localized: "The analysis and its cached results will be removed from WirePath. The original capture file stays on disk.")
        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = String(localized: "Also move the capture file to the Trash")
        alert.suppressionButton?.state = .off
        alert.addButton(withTitle: String(localized: "Cancel"))
        let delete = alert.addButton(withTitle: String(localized: "Delete"))
        delete.hasDestructiveAction = true
        let respond: (NSApplication.ModalResponse) -> Void = { response in
            completion(response == .alertSecondButtonReturn, alert.suppressionButton?.state == .on)
        }
        if let host = NSApp.keyWindow {
            alert.beginSheetModal(for: host, completionHandler: respond)
        } else {
            respond(alert.runModal())
        }
    }
}
#endif

/// Accepts capture files dropped anywhere on the window; each file opens as a new analysis.
struct CaptureDropDelegate: DropDelegate {
    let window: WindowModel
    let library: LibraryModel

    func validateDrop(info: DropInfo) -> Bool { info.hasItemsConforming(to: [.fileURL, .data]) }

    func dropEntered(info: DropInfo) {
        let providers = info.itemProviders(for: [.fileURL, .data])
        window.dropCount = providers.count
        window.dropNames = providers.compactMap(\.suggestedName)
    }

    func dropExited(info: DropInfo) {
        window.dropCount = 0
        window.dropNames = []
    }

    func dropUpdated(info: DropInfo) -> DropProposal? { DropProposal(operation: .copy) }

    func performDrop(info: DropInfo) -> Bool {
        let providers = info.itemProviders(for: [.fileURL, .data])
        window.dropCount = 0
        window.dropNames = []
        guard !providers.isEmpty else { return false }
        let window = self.window, library = self.library
        Task { @MainActor in
            var urls: [URL] = []
            for provider in providers {
                if let url = await DroppedFile.load(provider) { urls.append(url) }
            }
            let items = library.importCaptures(urls)
            if let first = items.first { window.select(first) }
        }
        return true
    }
}

/// Resolves a dropped item to a readable file URL.
enum DroppedFile {
    @MainActor static func load(_ provider: NSItemProvider) async -> URL? {
        #if os(macOS)
        return await withCheckedContinuation { continuation in
            _ = provider.loadObject(ofClass: URL.self) { url, _ in continuation.resume(returning: url) }
        }
        #else
        // iPadOS: prefer opening in place (Files providers that support it); otherwise the system hands us
        // a temporary copy that must be moved into the app container before the callback returns.
        let type = provider.registeredTypeIdentifiers.first ?? UTType.data.identifier
        return await withCheckedContinuation { continuation in
            provider.loadInPlaceFileRepresentation(forTypeIdentifier: type) { url, inPlace, _ in
                guard let url else { continuation.resume(returning: nil); return }
                if inPlace {
                    continuation.resume(returning: url)
                } else {
                    continuation.resume(returning: ImportedFiles.keepCopy(of: url))
                }
            }
        }
        #endif
    }
}

/// Copies of captures that the system only lends temporarily (drops, Share Sheet/Open In without
/// open-in-place) are kept in the app container so the Packet Inspector can read them later.
public enum ImportedFiles {
    public static var directory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("WirePath/Imported", isDirectory: true)
    }

    public static func keepCopy(of url: URL) -> URL? {
        let destination = directory.appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent(url.lastPathComponent)
        do {
            try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: url, to: destination)
            return destination
        } catch {
            Log.ui.error("Could not keep a copy of a dropped capture: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }
}
